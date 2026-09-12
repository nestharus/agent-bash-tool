"""Private, bounded loss schedules for the last physical owner."""
import importlib.util
import ctypes
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location('role_fixture', HERE.with_name('age362_role_boundary.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
f = r.f


def case(root, helper, mode):
    d = root / mode; d.mkdir()
    env = dict(PYTHONDONTWRITEBYTECODE='1', PATH='/usr/bin:/bin', HOME=str(d), XDG_STATE_HOME=str(d / 'state'),
               XDG_CONFIG_HOME=str(d / 'config'), AGENT_BASH_AGENT_RUNNER_BIN=str(helper), AGE362_DIR=str(d))
    external = mode == 'external-reconciliation'
    item = json.loads(f.run(env, 'run', '--delivery', 'async', '--completion-scope', 'tree' if external else 'root', '--',
                           sys.executable, str(r.HERE), 'workload', f.BIN, str(d)))
    sd = Path(item['state_dir']); fds = {}
    def pin(name, pid):
        fds[name] = os.pidfd_open(pid); return pid
    supervisor = pin('supervisor', r.wait_file(d / 'supervisor'))
    guardian = pin('guardian', f.stat(supervisor)[0])
    workload = pin('workload', r.wait_file(d / 'workload-leaf'))
    lock = open(sd / 'delivery.lock', 'a'); fcntl.flock(lock, fcntl.LOCK_EX)
    # Freeze only our exact guardian to let the external reconciler win the lock.
    if external:
        setup_recon = open(sd / 'reconciliation.lock', 'a')
        fcntl.flock(setup_recon, fcntl.LOCK_EX)
    pin('root', f.read_json(item['meta'])['workload_pid'])
    (d / 'release-root').touch()
    f.wait(lambda: r.exited(fds['root']))
    if not external:
        f.wait(lambda: f.read_json(item['meta'])['completion_reason'] == 'exit')
    signal.pidfd_send_signal(fds['supervisor'], signal.SIGKILL)
    f.wait(lambda: r.exited(fds['supervisor']))
    if external:
        f.wait(lambda: not Path('/proc/' + str(supervisor)).exists())
        signal.pidfd_send_signal(fds['guardian'], signal.SIGSTOP)
        fcntl.flock(setup_recon, fcntl.LOCK_UN); setup_recon.close()
        status = subprocess.Popen([f.BIN, 'status', item['handle']], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    else:
        f.wait(lambda: f.stat(workload)[0] == guardian)
    fcntl.flock(lock, fcntl.LOCK_UN)
    helper_pid = pin('helper', r.wait_file(d / 'helper'))
    helper_leaf = pin('helper-leaf', r.wait_file(d / 'helper-leaf'))
    worker = pin('worker', r.wait_file(d / 'worker'))
    if external:
        assert f.stat(worker)[0] == status.pid, 'external reconciler did not own transfer'
        recon = open(sd / 'reconciliation.lock', 'a')
        try:
            fcntl.flock(recon, fcntl.LOCK_EX | fcntl.LOCK_NB)
            raise AssertionError('external reconciliation lock not held')
        except BlockingIOError: pass
        recon.close()
        signal.pidfd_send_signal(fds['guardian'], signal.SIGCONT)
        f.wait(lambda: f.stat(workload)[0] == guardian)
        time.sleep(.3) # guardian encounters the held lock before cancellation
    else:
        role = pin('role', f.stat(worker)[0])
        assert f.stat(role)[0] == guardian
        (d / 'release-helper').touch()
        f.wait(lambda: r.exited(fds['helper']) and f.read_json(item['meta'])['delivery']['lifecycle'] == 'admitted_outcome')
        f.wait(lambda: r.exited(fds['worker']))
        if mode == 'guardian-integration-read-error':
            saved_meta = Path(item['meta']).read_bytes()
            Path(item['meta']).write_bytes(b'injected-private-read-error')
        signal.pidfd_send_signal(fds['role'], signal.SIGKILL)
        f.wait(lambda: r.exited(fds['role']) and f.stat(helper_leaf)[0] == guardian)
        time.sleep(.3) # guardian integrates failed status while workload is live
        if mode == 'guardian-integration-read-error':
            assert not r.exited(fds['guardian']) and (sd / 'physical-custody').exists()
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                raise AssertionError('failed integration released its transfer lock')
            except BlockingIOError: pass
            Path(item['meta']).write_bytes(saved_meta)
    before = f.read_json(item['meta']); rc = (sd / 'rc').read_bytes()
    assert not r.exited(fds['guardian']), 'last owner exited on transfer failure'
    start = time.monotonic()
    assert json.loads(f.run(env, 'cancel', item['handle']))['requested']
    assert time.monotonic() - start < 2
    if external:
        f.wait(lambda: r.exited(fds['workload']), 6)
        assert not r.exited(fds['helper']) and status.poll() is None
        (d / 'release-helper').touch()
        status.communicate(timeout=5); assert status.returncode == 0
    else:
        time.sleep(2.5)
        assert not r.exited(fds['workload']), 'unknown role guessed as workload'
        assert not r.exited(fds['guardian']), 'last owner abandoned adopted tree'
        assert (sd / 'physical-custody').exists()
        assert not (sd / 'cancel-workload-drained').exists()
    assert not r.exited(fds['helper-leaf'])
    assert (d / 'helper-signals').read_bytes() == b'' and (d / 'leaf-signals').read_bytes() == b''
    (d / 'release-leaf').touch()
    f.wait(lambda: r.exited(fds['helper-leaf']))
    if not external:
        assert not r.exited(fds['guardian']) and (sd / 'physical-custody').exists()
        signal.pidfd_send_signal(fds['workload'], signal.SIGKILL) # fixture cleanup, NOT cancellation settlement
    f.wait(lambda: r.exited(fds['guardian']) and not (sd / 'physical-custody').exists())
    assert (sd / 'cancel-workload-drained').exists()
    after = f.read_json(item['meta'])
    assert after['delivery']['lifecycle'] == 'admitted_outcome'
    for key in ['state', 'rc', 'completion_reason', 'completed_at_unix_ms']:
        assert before[key] == after[key], (key, before, after)
    assert (sd / 'rc').read_bytes() == rc
    assert (d / 'helper-finished').exists() and (d / 'leaf-finished').exists()
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); lock.close()
    os.waitpid(guardian, 0)
    # External helper leaf belongs to the fixture subreaper, not product custody.
    if external: os.waitpid(helper_leaf, 0)
    assert not f.descendants(os.getpid()), f.descendants(os.getpid())
    for fd in fds.values(): os.close(fd)
    print(mode, 'settled; cancellation during external helper' if external else
          'recorded outcome retained; last owner survived loss; unknown workload required exact fixture cleanup', flush=True)


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    try:
        with tempfile.TemporaryDirectory(prefix='age362-guardian-') as tmp:
            root = Path(tmp); helper = root / 'helper'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(HERE.with_name('age362_role_helper.c')), '-o', str(helper)], check=True, timeout=10)
            for mode in ['external-reconciliation', 'guardian-recorded-outcome-loss', 'guardian-integration-read-error']:
                case(root, helper, mode)
    finally: r.cleanup()

if __name__ == '__main__': suite()
