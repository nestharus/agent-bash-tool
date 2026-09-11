"""Private completion ownership checks; bounded native helper, no real runner."""
import ctypes
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
FIXTURE = Path(__file__).with_name('image_custody.py')
spec = importlib.util.spec_from_file_location('custody', FIXTURE)
f = importlib.util.module_from_spec(spec); spec.loader.exec_module(f)
BIN = f.BIN


def children(pid):
    try:
        return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
    except FileNotFoundError:
        return []


def active_transfer(owner):
    for parent in children(owner):
        for child in children(parent):
            try:
                args = Path(f'/proc/{child}/cmdline').read_bytes().split(b'\0')
                if args[1:3] == [b'notify', b'agent-bash-complete']:
                    return parent, child
            except FileNotFoundError:
                pass
    return None


def workload(mode, directory, helper):
    d = Path(directory)
    owner = next(pid for pid in reversed(f.ancestors()) if f.probe(pid))
    custodian = f.wait(lambda: next((p for p in children(owner) if b'--internal-image-custodian-v1' in Path(f'/proc/{p}/cmdline').read_bytes()), None))
    (d / 'identity').write_text(json.dumps(dict(owner=owner, custodian=custodian, root=os.getpid())))
    if mode == 'acquisition-loss':
        os.kill(custodian, signal.SIGSTOP)
        return
    if mode == 'lock-busy':
        subprocess.Popen([sys.executable, str(HERE), 'after-root', BIN, str(d), str(helper)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        f.wait(lambda: (d / 'root-end').exists())
        return
    if mode.startswith('worker-loss-aged'):
        subprocess.Popen([sys.executable, '-c', 'import pathlib,time,sys; p=pathlib.Path(sys.argv[1]); exec("while not p.exists(): time.sleep(.02)")', str(d / 'descendant-end')], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    if mode in ['normal-held', 'loss-held', 'worker-loss']:
        return
    if mode in ['cancel-complete', 'cancel-complete-loss']:
        f.wait(lambda: (d / 'end').exists())
        return
    print('FIXTURE_READY', flush=True)
    f.wait(lambda: (d / 'hold.admitted').exists())
    if mode == 'ready-root-exit':
        # Remain a descendant after root exit, without keeping the output pipes.
        subprocess.Popen([sys.executable, str(HERE), 'after-root', BIN, str(d), str(helper)], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    f.wait(lambda: (d / 'end').exists())


def after_root(directory, helper):
    d = Path(directory); identity = f.read_json(d / 'identity')
    f.wait(lambda: not Path(f"/proc/{identity['root']}").exists())
    os.kill(identity['custodian'], signal.SIGKILL)
    fd = f.acquire(identity['owner'], helper); os.close(fd)
    (d / 'acquired-after-root').touch()
    f.wait(lambda: (d / 'end').exists())


def owned_launcher(directory, helper):
    d = Path(directory)
    item = f.run(os.environ.copy(), 'run', '--cancel-on-owner-exit', '--owner-pid', str(os.getpid()), '--ready-sentinel', 'FIXTURE_READY', '--', sys.executable, str(HERE), 'owner-cancel', BIN, str(d), helper)
    (d / 'item').write_bytes(item)
    f.wait(lambda: (d / 'owner-end').exists())


def count(d):
    return sum('agent-bash-complete' in line for line in (d / 'helper-log').read_text().splitlines())


def locked(item):
    with open(Path(item['state_dir']) / 'delivery.lock', 'a') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return False
        except BlockingIOError:
            return True


def wait_settled(item, identity, guardian, transfer, helper_pid, guardian_reaped=False, seconds=10):
    # Publication precedes worker exit and guardian reconciliation. Reap the exact
    # private guardian before probing freedom, so its later lock acquisition cannot
    # race the assertion. Metadata (including absence) is not a settlement witness.
    def settled():
        nonlocal guardian_reaped
        if not guardian_reaped:
            guardian_reaped = os.waitpid(guardian, os.WNOHANG)[0] == guardian
        return (guardian_reaped
                and all(not Path(f"/proc/{pid}").exists()
                        for pid in [identity['owner'], transfer, helper_pid])
                and not locked(item))
    try:
        f.wait(settled, seconds)
    except Exception:
        print("SETTLEMENT TIMEOUT/FAILURE", dict(seconds=seconds, guardian_reaped=guardian_reaped,
              processes=f.process_evidence([identity['owner'], guardian, transfer, helper_pid]),
              locked=locked(item), meta=f.read_json(item['meta'])), file=sys.stderr, flush=True)
        raise


def acquiring_worker(identity):
    for pid in children(identity['owner']):
        if pid in [identity['custodian'], identity['root']] or children(pid):
            continue
        try:
            if any(os.readlink(fd).startswith('socket:') for fd in Path(f'/proc/{pid}/fd').iterdir()):
                return pid
        except FileNotFoundError:
            pass
    return None


def check_acquisition_loss(env, item, d, identity, guardian):
    worker = f.wait(lambda: acquiring_worker(identity))
    assert count(d) == 0
    assert f.read_json(item['meta'])['delivery']['lifecycle'] == 'unclaimed'
    assert locked(item)
    os.kill(worker, signal.SIGKILL)
    f.wait(lambda: not Path(f"/proc/{identity['owner']}").exists())
    meta = f.read_json(item['meta'])
    assert meta['delivery']['lifecycle'] == 'retryable_pre_admission_failure', meta
    assert meta['delivery']['attempted'] is False
    assert count(d) == 0 and not locked(item)
    (d / 'hold').touch()
    f.run(env, 'status', item['handle'])
    assert f.read_json(item['meta'])['delivery']['exit_code'] == 0
    assert count(d) == 1
    f.run(env, 'status', item['handle'])
    assert count(d) == 1
    f.wait(lambda: os.waitpid(guardian, os.WNOHANG)[0] == guardian)
    assert not f.descendants(os.getpid())
    print('acquisition-loss', json.dumps(meta['delivery']), 'zero admissions before authorized retry; one after; exact cleanup', flush=True)


def expire_and_scan(env, item):
    # Logical timestamps, not sleeps or fabricated process identity/death.
    meta = f.read_json(item['meta'])
    meta['completed_at_unix_ms'] = 1
    meta['updated_at_unix_ms'] = 1
    staged = Path(item['meta'] + '.aged')
    staged.write_text(json.dumps(meta))
    staged.replace(item['meta'])
    scan_env = dict(env, AGENT_BASH_STATE_TTL_SECS='10', AGENT_BASH_STATE_REAP_SHARDS='1')
    scan_env.pop('IMAGE_FIXTURE_HOLD', None)
    scan_env['IMAGE_FIXTURE_LOG'] = env['IMAGE_FIXTURE_LOG'] + '-scan'
    before = set(children(os.getpid()))
    f.run(scan_env, 'run', '--delivery', 'sync', '--', '/bin/true')
    for pid in set(children(os.getpid())) - before:
        f.wait(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid)


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    try:
        with tempfile.TemporaryDirectory(prefix='age357-ownership-') as tmp:
            root = Path(tmp); helper = root / 'helper'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(FIXTURE.with_name('image_helper.c')), '-o', str(helper)], check=True, timeout=10)
            for mode in ['normal-held', 'ready-root-exit', 'lock-busy', 'cancel-complete', 'owner-cancel', 'loss-held', 'worker-loss', 'worker-loss-aged', 'worker-loss-aged-guardian-loss', 'worker-loss-aged-supervisor-loss', 'cancel-complete-loss', 'acquisition-loss']:
                d = root / mode; d.mkdir()
                env = {k: v for k, v in os.environ.items() if not k.startswith(('AGENT_BASH_', 'OULIPOLY_', 'IMAGE_FIXTURE_'))}
                env.update(XDG_STATE_HOME=str(d / 'state'), XDG_CONFIG_HOME=str(d / 'config'), AGENT_BASH_AGENT_RUNNER_BIN=str(helper), AGENT_BASH_IMAGE_BYTES=str(1024*1024), AGENT_BASH_IMAGE_DEADLINE_MS='5000', IMAGE_FIXTURE_LOG=str(d / 'helper-log'), IMAGE_FIXTURE_HOLD=str(d / 'hold'))
                launcher = None
                if mode == 'owner-cancel':
                    launcher = subprocess.Popen([sys.executable, str(HERE), 'launcher', BIN, str(d), str(helper)], env=env)
                    item = f.wait(lambda: f.read_json(d / 'item'))
                else:
                    args = ['run', '--delivery', 'async']
                    if mode in ['normal-held', 'worker-loss', 'lock-busy'] or mode.startswith('worker-loss-aged'): args += ['--completion-scope', 'root']
                    if mode == 'ready-root-exit': args += ['--ready-sentinel', 'FIXTURE_READY']
                    item = json.loads(f.run(env, *args, '--', sys.executable, str(HERE), mode, BIN, str(d), str(helper)))
                identity = f.wait(lambda: f.read_json(d / 'identity'))
                guardian = f.stat(identity['owner'])[0]
                if mode == 'acquisition-loss':
                    check_acquisition_loss(env, item, d, identity, guardian)
                    continue
                if mode == 'lock-busy':
                    with open(Path(item['state_dir']) / 'delivery.lock', 'a') as lock:
                        fcntl.flock(lock, fcntl.LOCK_EX)
                        (d / 'root-end').touch()
                        f.wait(lambda: (d / 'acquired-after-root').exists(), 5)
                        assert Path(f"/proc/{identity['owner']}").exists()
                        assert f.read_json(item['meta']).get('workload_rc') is None
                        (d / 'end').touch()
                if mode in ['cancel-complete', 'cancel-complete-loss']:
                    result = json.loads(f.run(env, 'cancel', item['handle']))
                    assert result['requested']
                f.wait(lambda: (d / 'hold.admitted').exists())
                meta = f.read_json(item['meta'])
                assert meta['delivery']['lifecycle'] == 'provisional_transfer', meta
                assert locked(item), 'active transfer has no lock'
                transfer, helper_pid = f.wait(lambda: active_transfer(identity['owner']))
                assert children(transfer) == [helper_pid], children(transfer)
                assert f.stat(helper_pid)[0] == transfer
                if mode == 'ready-root-exit':
                    f.wait(lambda: (d / 'acquired-after-root').exists(), 5)
                    # Still admitted/held after the root was reaped: no self-lock wait.
                    assert f.read_json(item['meta'])['delivery']['lifecycle'] == 'provisional_transfer'
                    (d / 'end').touch()
                elif mode == 'owner-cancel':
                    (d / 'owner-end').touch(); launcher.wait(timeout=3)
                elif mode in ['loss-held', 'cancel-complete-loss']:
                    os.kill(identity['owner'], signal.SIGKILL)
                elif mode == 'worker-loss' or mode.startswith('worker-loss-aged'):
                    os.kill(transfer, signal.SIGKILL)
                unknown = mode in ['owner-cancel', 'worker-loss'] or mode.startswith('worker-loss-aged')
                if not unknown:
                    # More than a supervisor tick; pending delivery must keep its owner
                    # alive, and post-cancellation completion must not be cancelled anew.
                    time.sleep(.4)
                    if mode not in ['loss-held', 'cancel-complete-loss']: assert Path(f"/proc/{identity['owner']}").exists()
                    assert Path(f'/proc/{helper_pid}').exists()
                    (d / 'hold').touch()
                meta = f.wait(lambda: (m if (m := f.read_json(item['meta'])) and m.get('delivery', {}).get('lifecycle') in ['admitted_outcome', 'non_replayable_unknown_transfer', 'retryable_pre_admission_failure', 'closed_pre_admission_failure'] else None))
                if unknown:
                    assert meta['delivery']['lifecycle'] == 'non_replayable_unknown_transfer', meta
                    assert not meta['delivery']['retryable']
                    if mode == 'worker-loss':
                        time.sleep(.4)
                        assert Path(f"/proc/{identity['owner']}").exists(), 'unknown helper was orphaned by Root scope'
                    if mode.startswith('worker-loss-aged'):
                        if mode.endswith('supervisor-loss'):
                            os.kill(identity['owner'], signal.SIGKILL)
                            f.wait(lambda: not Path(f"/proc/{identity['owner']}").exists())
                        if mode.endswith('guardian-loss'):
                            os.kill(guardian, signal.SIGKILL)
                            f.wait(lambda: os.waitpid(guardian, os.WNOHANG)[0] == guardian)
                        expire_and_scan(env, item)
                        assert Path(item['state_dir']).exists(), 'TTL removed active unknown custody'
                        (d / 'hold').touch()
                        f.wait(lambda: not Path(f'/proc/{helper_pid}').exists())
                        expire_and_scan(env, item)
                        assert Path(item['state_dir']).exists(), 'TTL removed surviving adopted Root tree'
                        (d / 'descendant-end').touch()
                    (d / 'hold').touch()
                else:
                    assert meta['delivery'].get('exit_code') == 0, meta
                if mode.endswith('guardian-loss'):
                    f.wait(lambda: os.waitpid(identity['owner'], os.WNOHANG)[0] == identity['owner'])
                else:
                    f.wait(lambda: not Path(f"/proc/{identity['owner']}").exists())
                wait_settled(item, identity, guardian, transfer, helper_pid,
                             guardian_reaped=mode.endswith('guardian-loss'))
                final = f.read_json(item['meta'])
                if mode in ['ready-root-exit', 'lock-busy']:
                    assert final['workload_rc'] == 0 and final['rc'] == 0, final
                if mode in ['cancel-complete', 'cancel-complete-loss']:
                    assert final['rc'] == 143 and final['completion_reason'] == 'cancel-request', final
                assert count(d) == 1
                assert not locked(item), 'settled transfer retained delivery lock'
                f.run(env, 'status', item['handle'])
                assert count(d) == 1
                if mode.startswith('worker-loss-aged'):
                    expire_and_scan(env, item)
                    assert not Path(item['state_dir']).exists(), 'ended custody leaked expired state'
                assert not f.descendants(os.getpid()), f.descendants(os.getpid())
                print(mode, json.dumps(final['delivery']), 'one invocation; locks released; exact cleanup', flush=True)
    finally:
        f.cleanup()

if __name__ == '__main__':
    mode = sys.argv[1]
    if mode == 'suite': suite()
    elif mode == 'after-root': after_root(sys.argv[3], sys.argv[4])
    elif mode == 'launcher': owned_launcher(sys.argv[3], sys.argv[4])
    else: workload(mode, sys.argv[3], sys.argv[4])
