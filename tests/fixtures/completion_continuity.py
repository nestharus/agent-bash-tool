"""Candidate check of the retained three founding-owner continuity stimuli. Tiny/private, no runner."""
import ctypes
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


def workload(mode, directory, helper):
    directory = Path(directory)
    owner = next(pid for pid in reversed(f.ancestors()) if f.probe(pid))
    custodian = f.wait(lambda: next((int(p) for p in Path(f'/proc/{owner}/task/{owner}/children').read_text().split()
                          if b'--internal-image-custodian-v1' in Path(f'/proc/{p}/cmdline').read_bytes()), None))
    (directory / 'identity').write_text(json.dumps(dict(owner=owner, custodian=custodian)))
    if mode == 'admitted':
        print('FIXTURE_READY', flush=True)
        f.wait(lambda: (directory / 'hold.admitted').exists())
        os.kill(custodian, signal.SIGKILL)
        before = time.monotonic()
        try:
            fd = f.acquire(owner, helper)
            os.close(fd)
            result = dict(acquired=True)
        except Exception as error:
            result = dict(acquired=False, error=str(error), elapsed=time.monotonic() - before)
        (directory / 'acquisition').write_text(json.dumps(result))
        (directory / 'hold').touch()
        return
    # Freeze event-loop progress, establish dead service and pending readiness/exit,
    # then an external private harness resumes the exact founding supervisor.
    os.kill(owner, signal.SIGSTOP)
    os.kill(custodian, signal.SIGKILL)
    (directory / 'killed').touch()
    if mode == 'ready':
        print('FIXTURE_READY', flush=True)
        f.wait(lambda: (directory / 'end').exists())


def suite():
    assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
    failures = []
    try:
        with tempfile.TemporaryDirectory(prefix='age357-continuity-') as tmp:
            root = Path(tmp); helper = root / 'helper'
            subprocess.run(['cc', '-O2', '-Wall', '-Wextra', str(FIXTURE.with_name('image_helper.c')), '-o', str(helper)], check=True, timeout=10)
            for mode in ['exit', 'ready', 'admitted']:
                d = root / mode; d.mkdir()
                env = {k: v for k, v in os.environ.items() if not k.startswith(('AGENT_BASH_', 'OULIPOLY_', 'IMAGE_FIXTURE_'))}
                env.update(XDG_STATE_HOME=str(d / 'state'), XDG_CONFIG_HOME=str(d / 'config'),
                           AGENT_BASH_AGENT_RUNNER_BIN=str(helper), AGENT_BASH_IMAGE_BYTES=str(1024*1024),
                           AGENT_BASH_IMAGE_DEADLINE_MS='5000', IMAGE_FIXTURE_LOG=str(d / 'helper-log'))
                args = ['run', '--delivery', 'async']
                if mode != 'exit': args += ['--ready-sentinel', 'FIXTURE_READY']
                if mode == 'admitted': env['IMAGE_FIXTURE_HOLD'] = str(d / 'hold')
                item = json.loads(f.run(env, *args, '--', sys.executable, str(HERE), mode, BIN, str(d), str(helper)))
                identity = f.wait(lambda: f.read_json(d / 'identity'))
                if mode != 'admitted':
                    f.wait(lambda: (d / 'killed').exists())
                    os.kill(identity['owner'], signal.SIGCONT)
                    meta = f.wait(lambda: (m if (m := f.read_json(item['meta'])) and m.get('delivery', {}).get('lifecycle') not in [None, 'unclaimed', 'provisional_transfer'] else None), 8)
                    print(mode, json.dumps(meta['delivery']), flush=True)
                    assert meta['delivery'].get('exit_code') == 0, meta
                    assert sum('agent-bash-complete' in line for line in (d / 'helper-log').read_text().splitlines()) == 1
                    (d / 'end').touch()
                else:
                    result = f.wait(lambda: f.read_json(d / 'acquisition'), 6)
                    meta = f.wait(lambda: f.terminal_delivery(item['meta']))
                    lines = (d / 'helper-log').read_text().splitlines()
                    assert sum('agent-bash-complete' in line for line in lines) == 1
                    print(mode, json.dumps(result), 'completion executed once', flush=True)
                    if not result['acquired']: failures.append(mode + ': descendant acquisition failed during admitted founding wait')
                f.wait(lambda: not Path(f"/proc/{identity['owner']}").exists())
            f.cleanup()
            print('exact private cleanup/reaping completed; failures:', failures, flush=True)
    finally:
        f.cleanup()
    return bool(failures)


if sys.argv[1] == 'suite':
    sys.exit(suite())
else:
    workload(sys.argv[1], sys.argv[3], sys.argv[4])
