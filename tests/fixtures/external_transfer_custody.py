"""External transfer retention: tiny private helpers, exact harness-owned reaping."""
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve()
spec = importlib.util.spec_from_file_location('ownership', HERE.with_name('completion_ownership.py'))
o = importlib.util.module_from_spec(spec); spec.loader.exec_module(o)
f = o.f
BIN = f.BIN


def transfer(caller, operation):
    for worker in o.children(caller):
        for helper in o.children(worker):
            try:
                if Path(f'/proc/{helper}/cmdline').read_bytes().split(b'\0')[1:3] == [b'notify', operation.encode()]:
                    return worker, helper
            except FileNotFoundError:
                pass
    return None


def reap(pid):
    f.wait(lambda: os.waitpid(pid, os.WNOHANG)[0] == pid)


def operation_count(d, operation):
    return sum(operation in line for line in (d / 'helper-log').read_text().splitlines())


def ended_handle(env, d, helper, operation):
    if operation == 'agent-bash-activate':
        before = set(o.children(os.getpid()))
        item = json.loads(f.run(env, 'run', '--delivery', 'sync', '--', '/bin/true'))
        for pid in set(o.children(os.getpid())) - before:
            reap(pid)
    else:
        item = json.loads(f.run(env, 'run', '--delivery', 'async', '--', sys.executable, str(o.HERE), 'acquisition-loss', BIN, str(d), str(helper)))
        identity = f.wait(lambda: f.read_json(d / 'identity'))
        guardian = f.stat(identity['owner'])[0]
        worker = f.wait(lambda: o.acquiring_worker(identity))
        os.kill(worker, signal.SIGKILL)
        reap(guardian)
        assert f.read_json(item['meta'])['delivery']['lifecycle'] == 'retryable_pre_admission_failure'
    assert not f.descendants(os.getpid()), f.descendants(os.getpid())
    assert not (Path(item['state_dir']) / 'physical-custody').exists()
    return item


def check_case(env, d, helper, operation, mode):
    item = ended_handle(env, d, helper, operation)
    state = Path(item['state_dir']); marker = state / 'external-transfer-custody'
    artifacts = {p.name for p in state.iterdir()}
    before = operation_count(d, operation)
    command = 'status' if operation == 'agent-bash-complete' else 'detach'
    caller = subprocess.Popen([BIN, command, item['handle']], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    f.wait(lambda: (d / 'hold.admitted').exists())
    worker, helper_pid = f.wait(lambda: transfer(caller.pid, operation))
    assert marker.exists() and o.locked(item)
    evidence = marker.read_bytes()
    if mode in ['worker-loss', 'successor-loss']:
        if mode == 'successor-loss':
            caller.kill(); caller.wait(timeout=3)
        os.kill(worker, signal.SIGKILL)
        if mode == 'successor-loss':
            reap(worker)
        else:
            caller.wait(timeout=3)
        assert Path(f'/proc/{helper_pid}').exists() and f.stat(helper_pid)[0] == os.getpid()
        # Exercise startup cleanup before successor conversion as well as after.
        o.expire_and_scan(env, item)
        assert state.exists() and artifacts <= {p.name for p in state.iterdir()}
        for _ in range(2):
            result = subprocess.run([BIN, command, item['handle']], env=env, capture_output=True, timeout=5)
            if command == 'detach': assert result.returncode != 0
        if command == 'status':
            assert f.read_json(item['meta'])['delivery']['lifecycle'] == 'non_replayable_unknown_transfer'
        else:
            assert (state / 'activation-outcome').read_text() == 'transfer_outcome_unknown\n'
        assert marker.read_bytes() == evidence and not o.locked(item)
        o.expire_and_scan(env, item)
        assert state.exists() and artifacts <= {p.name for p in state.iterdir()}
        assert Path(f'/proc/{helper_pid}').exists()
        (d / 'hold').touch(); reap(helper_pid)
        # Harness observes actual end, but production has no discharge witness.
        o.expire_and_scan(env, item)
        assert marker.read_bytes() == evidence
        assert state.exists()
    else:
        (d / 'hold').touch(); caller.wait(timeout=3)
        assert not marker.exists(), 'conclusive helper exit retained own marker'
        if command == 'detach':
            expected = 'succeeded\n' if mode == 'normal' else 'failed:'
            assert (state / 'activation-outcome').read_text().startswith(expected)
        else:
            assert f.read_json(item['meta'])['delivery']['exit_code'] == (0 if mode == 'normal' else 7)
        o.expire_and_scan(env, item)
        assert not state.exists(), 'conclusively ended control transfer did not expire'
    assert operation_count(d, operation) == before + 1
    assert not f.descendants(os.getpid()), f.descendants(os.getpid())
    print(operation, mode, 'one admission; aged startup retention/ended control; exact harness reaping', flush=True)


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    try:
        with tempfile.TemporaryDirectory(prefix='age357-external-') as tmp:
            root = Path(tmp); helper = root / 'helper'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(HERE.with_name('image_helper.c')), '-o', str(helper)], check=True, timeout=10)
            for operation in ['agent-bash-complete', 'agent-bash-activate']:
                for mode in ['worker-loss', 'successor-loss', 'normal', 'nonzero']:
                    d = root / (operation + '-' + mode); d.mkdir()
                    env = {k: v for k, v in os.environ.items() if not k.startswith(('AGENT_BASH_', 'OULIPOLY_', 'IMAGE_FIXTURE_'))}
                    env.update(XDG_STATE_HOME=str(d / 'state'), XDG_CONFIG_HOME=str(d / 'config'), AGENT_BASH_AGENT_RUNNER_BIN=str(helper), AGENT_BASH_IMAGE_BYTES=str(1024*1024), AGENT_BASH_IMAGE_DEADLINE_MS='5000', IMAGE_FIXTURE_LOG=str(d / 'helper-log'), IMAGE_FIXTURE_HOLD=str(d / 'hold'), IMAGE_FIXTURE_HOLD_OPERATION=operation)
                    if mode == 'nonzero': env['IMAGE_FIXTURE_EXIT_CODE'] = '7'
                    check_case(env, d, helper, operation, mode)
    finally:
        f.cleanup()


if __name__ == '__main__':
    suite()
