"""Fork-local Linux keyring fixture; never changes the test runner's ring."""
import ctypes
import json
import os
import platform
import subprocess
import sys
import uuid

case, binary = sys.argv[1:]
libc = ctypes.CDLL(None, use_errno=True)
keyctl_nr = {"x86_64": 250, "aarch64": 219}[platform.machine()]
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
         'printf effect > "$AGENT_BASH_TEST_EFFECT"'],
        env=env, capture_output=True, text=True, timeout=15,
    )
    print(json.dumps({"rc": result.returncode, "stdout": result.stdout,
                      "stderr": result.stderr, "ppid": os.getppid()}), flush=True)

if case == "orphan":
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise OSError(ctypes.get_errno(), "PR_SET_CHILD_SUBREAPER")
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
            run()
            os._exit(0)
        os._exit(0)  # nearer worker is gone before Bash runs
    os.close(ready_read)
    os.waitpid(nearer, 0)
    os.write(ready_write, b"1")
    os.close(ready_write)
    _, status = os.wait()
    if status != 0:
        raise RuntimeError(f"orphan status {status}")
else:
    run()
