"""AGE362: actual pending-transfer orderings and role continuity; private native helper."""
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location('fixture', HERE.with_name('image_custody.py'))
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)


def wait_file(path):
    return f.wait(lambda: int(path.read_text()) if path.exists() and path.read_text().strip() else None)


def workload(d):
    d = Path(d)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    child = subprocess.Popen(['sleep', '25'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    (d / 'workload-leaf').write_text(str(child.pid))
    (d / 'supervisor').write_text(str(os.getppid()))
    f.wait(lambda: (d / 'release-root').exists())
    sys.exit(7)


def exited(fd):
    poll = select.poll(); poll.register(fd, select.POLLIN)
    return bool(poll.poll(0))


def cleanup():
    # Private subreaper tree: pin, revalidate fixture ancestry, check liveness,
    # then signal only the captured descriptor. No numeric or group signals.
    for pid in f.descendants(os.getpid()):
        try:
            fd = os.pidfd_open(pid)
            if pid in f.descendants(os.getpid()) and not exited(fd):
                signal.pidfd_send_signal(fd, signal.SIGKILL)
            os.close(fd)
        except ProcessLookupError:
            pass
    end = time.monotonic() + 3
    while time.monotonic() < end:
        try:
            if not os.waitpid(-1, os.WNOHANG)[0]: time.sleep(.01)
        except ChildProcessError:
            return
    raise AssertionError('private cleanup incomplete')


def case(root, helper, mode):
    d = root / mode; d.mkdir()
    env = dict(PYTHONDONTWRITEBYTECODE='1', PATH='/usr/bin:/bin', HOME=str(d), XDG_STATE_HOME=str(d / 'state'),
               XDG_CONFIG_HOME=str(d / 'config'), AGENT_BASH_AGENT_RUNNER_BIN=str(helper), AGE362_DIR=str(d))
    item = json.loads(f.run(env, 'run', '--delivery', 'async', '--completion-scope', 'root', '--',
                           sys.executable, str(HERE), 'workload', f.BIN, str(d)))
    sd = Path(item['state_dir']); fds = {}
    def pin(name, pid):
        fds[name] = os.pidfd_open(pid); return pid
    supervisor = pin('supervisor', wait_file(d / 'supervisor'))
    guardian = pin('guardian', f.stat(supervisor)[0])
    leaf = pin('workload', wait_file(d / 'workload-leaf'))
    lock = open(sd / 'delivery.lock', 'a')
    if mode == 'accept-before-transfer': fcntl.flock(lock, fcntl.LOCK_EX)
    (d / 'release-root').touch()
    before = f.wait(lambda: (m if (m := f.read_json(item['meta'])) and m.get('completion_reason') == 'exit' else None))
    assert before['rc'] == 7 and before['completion_reason'] == 'exit', before
    rc = (sd / 'rc').read_bytes()
    def cancel():
        start = time.monotonic()
        result = json.loads(f.run(env, 'cancel', item['handle']))
        assert time.monotonic() - start < 2, 'cancel waited on the unfinished helper'
        return result
    if mode == 'accept-before-transfer':
        assert not (d / 'helper').exists()
        assert cancel()['requested']
        assert not (d / 'helper').exists(), 'ordering witness lost'
        fcntl.flock(lock, fcntl.LOCK_UN)
    helper_pid = pin('helper', wait_file(d / 'helper'))
    helper_leaf = pin('helper-leaf', wait_file(d / 'helper-leaf'))
    worker = pin('worker', wait_file(d / 'worker'))
    role = pin('role', f.stat(worker)[0])
    assert f.stat(role)[0] == supervisor
    f.wait(lambda: f.stat(helper_leaf)[0] == role)
    assert f.read_json(item['meta'])['delivery']['lifecycle'] == 'provisional_transfer'
    assert not exited(fds['workload'])
    if mode in ['worker-loss', 'worker-and-supervisor-loss']:
        signal.pidfd_send_signal(fds['worker'], signal.SIGKILL)
        f.wait(lambda: exited(fds['worker']) and f.stat(helper_pid)[0] == role)
    if mode in ['supervisor-loss', 'worker-and-supervisor-loss']:
        signal.pidfd_send_signal(fds['supervisor'], signal.SIGKILL)
        f.wait(lambda: exited(fds['supervisor']) and f.stat(role)[0] == guardian)
    if mode == 'custodian-loss':
        signal.pidfd_send_signal(fds['role'], signal.SIGKILL)
        f.wait(lambda: exited(fds['role']) and f.stat(helper_leaf)[0] == supervisor)
    if mode != 'accept-before-transfer': assert cancel()['requested']
    marker = (sd / 'cancel-requested').stat().st_ino
    assert not cancel()['requested']
    assert (sd / 'cancel-requested').stat().st_ino == marker
    if mode == 'custodian-loss':
        # Negative control: unknown role is retained, not guessed. This is NOT
        # evidence of product workload cessation. Release/cleanup below is ours.
        time.sleep(2.5)
        assert not exited(fds['workload'])
    else:
        f.wait(lambda: exited(fds['workload']), 6)
    assert not exited(fds['helper']) and not exited(fds['helper-leaf'])
    assert exited(fds['role']) == (mode == 'custodian-loss')
    assert (sd / 'physical-custody').exists()
    assert not (sd / 'cancel-workload-drained').exists(), 'unfinished role falsely drained'
    held = f.read_json(item['meta'])
    for key in ['rc', 'state', 'completion_reason', 'completed_at_unix_ms']:
        assert held[key] == before[key], (key, before, held)
    expected_held = 'non_replayable_unknown_transfer' if 'worker' in mode or mode == 'custodian-loss' else 'provisional_transfer'
    assert held['delivery']['lifecycle'] == expected_held, held
    assert (sd / 'rc').read_bytes() == rc
    (d / 'release-helper').touch()
    if mode == 'custodian-loss':
        f.wait(lambda: exited(fds['helper']) and exited(fds['helper-leaf']))
        assert (sd / 'physical-custody').exists()
        assert not (sd / 'cancel-workload-drained').exists()
        signal.pidfd_send_signal(fds['workload'], signal.SIGKILL) # exact fixture cleanup, not product proof
    f.wait(lambda: all(exited(fds[n]) for n in ['helper', 'helper-leaf', 'role', 'supervisor', 'guardian']))
    f.wait(lambda: not (sd / 'physical-custody').exists())
    assert (d / 'helper-finished').exists(), 'helper did not continue to its real outcome'
    assert (sd / 'cancel-workload-drained').exists()
    after = f.read_json(item['meta'])
    expected = 'non_replayable_unknown_transfer' if 'worker' in mode else 'admitted_outcome'
    assert after['delivery']['lifecycle'] == expected, after
    for key in ['rc', 'state', 'completion_reason', 'completed_at_unix_ms']:
        assert after[key] == before[key], (key, before, after)
    assert not cancel()['requested']
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); lock.close()
    os.waitpid(guardian, 0)
    assert not f.descendants(os.getpid()), f.descendants(os.getpid())
    for fd in fds.values(): os.close(fd)
    observation = ('unknown retained; workload cessation required exact fixture cleanup'
                   if mode == 'custodian-loss' else 'workload ceased with helper AND adopted session-leaf preserved')
    print(mode, observation, '; released and settled;', expected, flush=True)


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    try:
        with tempfile.TemporaryDirectory(prefix='age362-role-') as tmp:
            root = Path(tmp); helper = root / 'helper'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(HERE.with_name('age362_role_helper.c')), '-o', str(helper)], check=True, timeout=10)
            for mode in ['accept-before-transfer', 'transfer-before-accept', 'worker-loss', 'supervisor-loss', 'worker-and-supervisor-loss', 'custodian-loss']:
                case(root, helper, mode)
    finally:
        cleanup()

if __name__ == '__main__':
    if sys.argv[1] == 'suite': suite()
    else: workload(sys.argv[3])
