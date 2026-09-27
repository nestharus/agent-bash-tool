"""Fork-local Linux keyring fixture; owns and reaps its async descendants."""
import ctypes
import json
import os
import platform
import signal
import subprocess
import sys
import time
import uuid

case, binary = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
keyctl_nr = {"x86_64": 250, "aarch64": 219}[platform.machine()]
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
if case != "default":
    name = {
        "paired": "oulipoly-paired-original-work-v1:" + str(uuid.uuid4()),
        "orphan": "oulipoly-paired-original-work-v1:" + str(uuid.uuid4()),
        "invalid": "oulipoly-paired-original-work-v1:not-a-uuid",
        "independent": "an-unrelated-test-session-ring:" + str(uuid.uuid4()),
    }[case]
    ring = libc.syscall(keyctl_nr, 1, ctypes.c_char_p(name.encode()), 0, 0, 0)
    if ring < 0:
        raise OSError(ctypes.get_errno(), "KEYCTL_JOIN_SESSION_KEYRING")


def run():
    env = os.environ.copy()
    for key in (
        "OULIPOLY_ORIGINAL_WORK_REQUIRED_V1", "OULIPOLY_ROOT_AUTHORITY_V1",
        "OULIPOLY_COMPLETION_ENDPOINT", "OULIPOLY_PARENT_INVOCATION",
        "OULIPOLY_DATA_DIR", "AGENT_BASH_OWNER_SESSION_ID",
        "AGENT_BASH_OWNER_INVOCATION_UUID", "AGENT_BASH_CONSUMER_GRACE_MS",
    ):
        env.pop(key, None)
    result = subprocess.run(
        [binary, "run", "--delivery", "async", "--", "/bin/sh", "-c",
         'printf effect > "$AGENT_BASH_TEST_EFFECT"; printf source-evidence'],
        env=env, capture_output=True, text=True, timeout=15,
    )
    return {"rc": result.returncode, "stdout": result.stdout,
            "stderr": result.stderr, "ppid": os.getppid()}


def reap_exited():
    reaped = []
    while True:
        try:
            child = os.waitid(os.P_ALL, 0, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        except ChildProcessError:
            return reaped, True
        if child is None:
            return reaped, False
        pid = child.si_pid
        with open(f"/proc/{pid}/stat") as stat:
            fields = stat.read().rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])
        _, status = os.waitpid(pid, 0)
        reaped.append({"pid": pid, "start_ticks": start_ticks, "status": status})


def direct_children():
    with open(f"/proc/self/task/{os.getpid()}/children") as children:
        return [int(pid) for pid in children.read().split()]


def retire_on_failure():
    # Only our direct children (including adopted descendants) are eligible.
    # A pidfd pins each identity, so PID reuse cannot redirect either signal.
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        _, empty = reap_exited()
        if empty:
            return
        for pid in direct_children():
            try:
                fd = os.pidfd_open(pid)
            except ProcessLookupError:
                continue
            try:
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            except ProcessLookupError:
                pass
            finally:
                os.close(fd)
        time.sleep(0.02)
    raise RuntimeError(f"fixture descendants failed to retire: {direct_children()}")


def settled_source(report):
    if report["rc"] != 0:
        return False
    try:
        state_dir = json.loads(report["stdout"])["state_dir"]
        with open(os.path.join(state_dir, "meta.json")) as file:
            meta = json.load(file)
        with open(os.path.join(state_dir, "rc"), "rb") as file:
            rc = file.read()
        with open(os.path.join(state_dir, "log"), "rb") as file:
            source = file.read()
        with open(os.environ["AGENT_BASH_TEST_EFFECT"], "rb") as file:
            effect = file.read()
    except (FileNotFoundError, KeyError, ValueError):
        return False
    delivery = meta["delivery"]
    return (effect == b"effect" and source == b"source-evidence"
            and rc == b"0\n" and meta["state"] == "DONE"
            and meta["completion_reason"] == "exit"
            and delivery["attempted"] is True
            and delivery["exit_code"] == 0
            and delivery["lifecycle"] == "admitted_outcome")


def wait_for_settlement(report):
    deadline = time.monotonic() + 10
    reaped = []
    while time.monotonic() < deadline:
        newly_reaped, empty = reap_exited()
        reaped.extend(newly_reaped)
        if settled_source(report) and empty:
            assert reaped, "accepted async run had no adopted guardian to reap"
            assert all(child["status"] == 0 for child in reaped), reaped
            return reaped
        time.sleep(0.02)  # Bounded condition poll, never a completion delay.
    raise RuntimeError(f"async source/delivery or descendants did not settle: {report}, {reaped}")


try:
    if case == "orphan":
        parent_pid = os.getpid()
        ready_read, ready_write = os.pipe()
        nearer = os.fork()
        if nearer == 0:
            os.close(ready_write)
            orphan = os.fork()
            if orphan == 0:
                os.setsid()
                os.read(ready_read, 1)
                os.close(ready_read)
                assert os.getppid() == parent_pid, "descendant did not reparent to subreaper"
                print(json.dumps(run()), flush=True)
                os._exit(0)
            os._exit(0)  # nearer worker is gone before Bash runs
        os.close(ready_read)
        os.waitpid(nearer, 0)
        os.write(ready_write, b"1")
        os.close(ready_write)
        _, status = os.wait()
        if status != 0:
            raise RuntimeError(f"orphan status {status}")
        _, empty = reap_exited()
        assert empty, "orphan case left a descendant"
    else:
        report = run()
        if case in ("independent", "default"):
            report["retired"] = wait_for_settlement(report)
        else:
            _, empty = reap_exited()
            assert empty, "rejected case left a descendant"
        print(json.dumps(report), flush=True)
except BaseException:
    retire_on_failure()
    raise
