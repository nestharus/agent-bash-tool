"""Private tiny process experiment; no runner, database, or machine configuration."""
import array
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

SCRIPT = str(Path(__file__).resolve())
BIN = str(Path(sys.argv[2]).resolve())
SEALS = 15


def stat(pid):
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return int(fields[1]), int(fields[19])


def endpoint(pid):
    return f"\0agent-bash-image-v1-{os.geteuid()}-{pid}-{stat(pid)[1]}"


def ancestors():
    pid = os.getpid()
    result = []
    while pid > 1:
        result.append(pid)
        pid = stat(pid)[0]
    return result


def connection(owner):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    s.settimeout(3)
    s.connect(endpoint(owner))
    return s


def acquire(owner, source):
    with open(source, "rb") as f, connection(owner) as s:
        data = f.read()
        s.sendmsg([struct.pack("<Q", len(data)) + hashlib.sha256(data).hexdigest().encode()],
                  [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [f.fileno()]))])
        payload, control, flags, _ = s.recvmsg(512, socket.CMSG_SPACE(4), socket.MSG_CMSG_CLOEXEC)
        assert payload == b"I1" and flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) == 0, (payload, flags)
        assert len(control) == 1
        fds = array.array("i"); fds.frombytes(control[0][2])
        assert len(fds) == 1
        fd = fds[0]
        assert fcntl.fcntl(fd, fcntl.F_GET_SEALS) & SEALS == SEALS
        assert os.pread(fd, len(data) + 1, 0) == data
        assert fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC
        alias = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY | os.O_CLOEXEC)
        assert (os.fstat(alias).st_dev, os.fstat(alias).st_ino) == (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        os.close(fd)
        return alias


def wait(predicate, seconds=10):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        result = predicate()
        if result:
            return result
        time.sleep(.02)
    raise AssertionError("private fixture deadline")


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def run(env, *args):
    p = subprocess.run([BIN, *args], env=env, capture_output=True, timeout=8)
    assert p.returncode == 0, (p.returncode, p.stdout, p.stderr)
    return p.stdout


def workload(directory, helper):
    directory = Path(directory)
    owner = next(pid for pid in reversed(ancestors()) if probe(pid))
    custodian = wait(lambda: next((int(p) for p in Path(f"/proc/{owner}/task/{owner}/children").read_text().split()
                                  if b"--internal-image-custodian-v1" in Path(f"/proc/{p}/cmdline").read_bytes()), None))
    assert Path(f"/proc/{custodian}/environ").read_bytes() == b""
    descriptors = wait(lambda: (fds if len(fds := list(Path(f"/proc/{custodian}/fd").iterdir())) == 4 else None))
    assert {p.name for p in descriptors} == {"0", "1", "2", "3"}, descriptors
    assert all(os.readlink(f"/proc/{custodian}/fd/{i}") == "/dev/null" for i in range(3))
    # Two simultaneously held, independently requested SCM_RIGHTS references.
    clients = [subprocess.Popen([sys.executable, SCRIPT, "client", BIN, str(owner), helper, str(i + 7)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True) for i in range(2)]
    try:
        inodes = [int(p.stdout.readline()) for p in clients]
        assert inodes[0] == inodes[1]
        for p in clients:
            p.communicate("release\n", timeout=4)
            assert p.returncode == 0
    finally:
        for p in clients:
            if p.poll() is None: p.kill()
            p.wait()
    # Actual independent handles preserve their environments and registration-only token.
    records = []
    for i in range(2):
        env = os.environ.copy()
        log = directory / f"routing-{i}"
        env.update(XDG_STATE_HOME=str(directory / f"spool-{i}"), AGENT_BASH_AGENT_RUNNER_BIN=helper, IMAGE_FIXTURE_LOG=str(log),
                   OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY="synthetic-private-token")
        item = json.loads(run(env, "run", "--", "/bin/true"))
        meta = wait(lambda: terminal_delivery(item["meta"]))
        assert meta["delivery"].get("error") is None, meta
        lines = log.read_text().splitlines()
        assert any("agent-bash-register authority" in line for line in lines), lines
        assert any("agent-bash-complete no-authority" in line for line in lines), lines
        assert all(line.split()[0] == str(inodes[0]) for line in lines), lines
        assert all("authority" not in line or "register" in line or "no-authority" in line for line in lines)
        records.append(lines)
    # A warm content hit must not hide in-place handle tampering with restored metadata.
    release = directory / "tamper-release"
    env = os.environ.copy(); env["AGENT_BASH_AGENT_RUNNER_BIN"] = helper; env["XDG_STATE_HOME"] = str(directory / "tamper-spool")
    item = json.loads(run(env, "run", "--", "/bin/sh", "-c",
                          'while [ ! -f "$1" ]; do sleep .02; done', "fixture", str(release)))
    snapshot = Path(item["state_dir"]) / "delivery-helper"
    old = snapshot.stat()
    try:
        snapshot.chmod(0o700)
        with snapshot.open("r+b") as f:
            f.write(b"not-ELF!")
        os.utime(snapshot, ns=(old.st_atime_ns, old.st_mtime_ns))
        snapshot.chmod(old.st_mode & 0o777)
    finally:
        release.touch()
    def changed_snapshot():
        meta = read_json(item["meta"])
        error = meta.get("delivery", {}).get("error") if meta else None
        return error if error and "delivery_helper_changed" in error else None
    try:
        wait(changed_snapshot, 5)
    except Exception:
        print("TAMPER META", Path(item["meta"]).read_text(), flush=True)
        raise
    # Malformed/extra/truncated requests close their received descriptors, then recover.
    for extra, size in [(0, 72), (2, 72), (1, 513)]:
        with open(helper, "rb") as f, connection(owner) as sock:
            rights = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array("i", [f.fileno()] * extra))] if extra else []
            sock.sendmsg([b"x" * size], rights)
            assert sock.recv(512) != b"I1"
    fd = acquire(owner, helper); assert os.fstat(fd).st_ino == inodes[0]; os.close(fd)
    wait(lambda: len(list(Path(f"/proc/{custodian}/fd").iterdir())) == 5)
    images = [os.readlink(p) for p in Path(f"/proc/{custodian}/fd").iterdir()]
    assert sum("memfd:agent-bash-delivery-helper" in p for p in images) == 1, images
    (directory / "ready").write_text(json.dumps(dict(owner=owner, custodian=custodian, inode=inodes[0], records=records)))
    # Parent cancels one independent root while the other remains usable.
    end = time.monotonic() + 12
    while not (directory / "release").exists():
        assert time.monotonic() < end
        if (directory / "again").exists() and not (directory / "again-result").exists():
            fd = acquire(owner, helper)
            (directory / "again-result").write_text(str(os.fstat(fd).st_ino)); os.close(fd)
        time.sleep(.02)


def probe(pid):
    try:
        with connection(pid):
            return True
    except (OSError, FileNotFoundError):
        return False


def terminal_delivery(path):
    meta = read_json(path)
    return meta if meta and meta.get("delivery", {}).get("exit_code") is not None else None


def client(owner, source, offset):
    fd = acquire(owner, source)
    try:
        os.lseek(fd, offset, os.SEEK_SET)
        print(os.fstat(fd).st_ino, flush=True)
        sys.stdin.readline()
        assert os.lseek(fd, 0, os.SEEK_CUR) == offset
    finally:
        os.close(fd)


def descendants(root):
    result = []
    for item in Path("/proc").iterdir():
        if not item.name.isdigit(): continue
        try:
            pid = int(item.name); parent = stat(pid)[0]
            seen = set()
            while parent > 1 and parent not in seen:
                if parent == root:
                    result.append(pid); break
                seen.add(parent); parent = stat(parent)[0]
        except (FileNotFoundError, ProcessLookupError):
            pass
    return result


def cleanup():
    for pid in descendants(os.getpid()):
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    end = time.monotonic() + 3
    while time.monotonic() < end:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
            if pid == 0: time.sleep(.01)
        except ChildProcessError:
            return
    raise AssertionError("fixture cleanup did not reap private tree")


def retired_epoch(root, helper):
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    listener.bind(endpoint(os.getpid())); listener.listen(4)
    def bootstrap():
        if listener.fileno() != 3:
            os.dup2(listener.fileno(), 3)
            os.set_inheritable(listener.fileno(), False)
    def launch(epoch):
        return subprocess.Popen([BIN, "--internal-image-custodian-v1", str(os.getpid()),
                                 str(stat(os.getpid())[1]), str(1024*1024), "1", "1000", str(epoch)],
                                env={}, pass_fds=tuple({3, listener.fileno()}), preexec_fn=bootstrap, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    server = launch(1000)
    wake = None
    try:
        fd = acquire(os.getpid(), helper)
        old_inode = os.fstat(fd).st_ino
        wake = subprocess.Popen([f"/proc/self/fd/{fd}", "self-exec", "fixture"], pass_fds=(fd,),
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env={})
        assert int(wake.stdout.readline()) == old_inode
        os.close(fd)
        assert server.wait(timeout=3) == 70  # bounded epoch retirement, not a delivery outcome
        assert os.stat(f"/proc/{wake.pid}/exe").st_ino == old_inode
        server = launch(10000)
        fd = acquire(os.getpid(), helper)
        assert os.fstat(fd).st_ino != old_inode
        os.close(fd)
        # Distinct version cannot evict the retained image or wait for an opaque helper.
        other = root / "other"; other.write_bytes(b"other"); other.chmod(0o500)
        try:
            acquire(os.getpid(), other)
            raise AssertionError("expected capacity rejection")
        except AssertionError as error:
            assert "capacity exhausted" in str(error), str(error)
        server.kill(); server.wait(timeout=3)
        # Existing held executable still works; failed acquisition is not retried as notify.
        assert os.stat(f"/proc/{wake.pid}/exe").st_ino == old_inode
        wake.communicate("release", timeout=3); assert wake.returncode == 0
    finally:
        if server.poll() is None: server.kill()
        server.wait()
        if wake is not None:
            if wake.poll() is None: wake.kill()
            wake.wait()
        listener.close()
    print("PASS: finite epoch, retained self-exec mapping, explicit restart duplicate, capacity rejection, custodian death after receipt")


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0  # own/reap detached fixture trees
    def interrupted(signum, frame):
        raise RuntimeError("private fixture interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    try:
        with tempfile.TemporaryDirectory(prefix="age357-") as tmp:
            root = Path(tmp)
            helper = root / "helper"
            subprocess.run(["cc", "-O2", "-Wall", "-Wextra", str(Path(SCRIPT).with_name("image_helper.c")), "-o", str(helper)], check=True, timeout=10)
            env = {k: v for k, v in os.environ.items() if not k.startswith(("AGENT_BASH_", "OULIPOLY_", "IMAGE_FIXTURE_"))}
            env.update(XDG_STATE_HOME=str(root / "state"), XDG_CONFIG_HOME=str(root / "config"),
                       AGENT_BASH_AGENT_RUNNER_BIN="/bin/true", AGENT_BASH_IMAGE_BYTES=str(1024*1024),
                       AGENT_BASH_IMAGE_DEADLINE_MS="3000")
            items = []
            for name in ["a", "b"]:
                directory = root / name; directory.mkdir()
                item = json.loads(run(env, "run", "--delivery", "sync", "--", sys.executable, SCRIPT, "workload", BIN, str(directory), str(helper)))
                items.append(item)
            try:
                a, b = [wait(lambda name=name: read_json(root / name / "ready")) for name in ["a", "b"]]
            except Exception:
                for item in items:
                    print(Path(item["log"]).read_text(), file=sys.stderr)
                    print(Path(item["meta"]).read_text(), file=sys.stderr)
                raise
            assert a["owner"] != b["owner"] and a["custodian"] != b["custodian"]
            assert a["inode"] != b["inode"], "independent roots must not borrow founding service"
            # Knowing another tree's socket name is not acquisition authority.
            with connection(a["owner"]) as outsider:
                try:
                    outsider.send(b"not-a-descendant")
                    assert outsider.recv(512) == b""
                except ConnectionResetError:
                    pass
            run(env, "cancel", items[0]["handle"])
            wait(lambda: not Path(f"/proc/{a['custodian']}").exists())
            (root / "b" / "again").touch()
            observed = wait(lambda: (root / "b" / "again-result").read_text() if (root / "b" / "again-result").exists() else None)
            assert int(observed) == b["inode"]
            (root / "b" / "release").touch()
            wait(lambda: not Path(f"/proc/{b['custodian']}").exists())
            wait(lambda: not Path(f"/proc/{b['owner']}").exists())
            # Loss of the private founding supervisor kills its exact custodian even
            # when the guardian is also lost; no host session is targeted.
            directory = root / "loss"; directory.mkdir()
            item = json.loads(run(env, "run", "--delivery", "sync", "--", sys.executable, SCRIPT, "workload", BIN, str(directory), str(helper)))
            lost = wait(lambda: read_json(directory / "ready"))
            guardian = stat(lost["owner"])[0]
            os.kill(guardian, signal.SIGKILL)
            assert Path(f"/proc/{lost['custodian']}").exists()
            os.kill(lost["owner"], signal.SIGKILL)
            def reap_fixture_zombies():
                try:
                    while os.waitpid(-1, os.WNOHANG)[0]: pass
                except ChildProcessError: pass
                return not Path(f"/proc/{lost['custodian']}").exists()
            wait(reap_fixture_zombies)
            (directory / "release").touch()
            cleanup()
            retired_epoch(root, str(helper))
            print("PASS: clean exec; two-client inode/offset sharing; per-handle authority/routing; one retained image; independent-root cancellation; exact infrastructure cleanup")
    finally:
        cleanup()


if __name__ == "__main__":
    mode = sys.argv[1]
    if mode == "suite": suite()
    elif mode == "workload": workload(sys.argv[3], sys.argv[4])
    elif mode == "client": client(int(sys.argv[3]), sys.argv[4], int(sys.argv[5]))
