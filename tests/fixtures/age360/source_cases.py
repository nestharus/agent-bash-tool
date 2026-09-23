"""Bash-only native process experiments with an explicitly simulated runner.
Private re-exec namespace is supplied by Rust; deadlines below are test-only.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import image_custody as f
BIN = sys.argv[2]
CASE = sys.argv[1]
D = '11111111-1111-4111-8111-111111111111'
P = 'completion-continuation-v2'

def identity(pid):
    return dict(pid=pid, starttime_ticks=f.stat(pid)[1], boot_id=Path('/proc/sys/kernel/random/boot_id').read_text().strip())
def read(path):
    return f.read_json(path)
def run(env, *args):
    return subprocess.run([BIN, *args], env=env, capture_output=True, timeout=20)
def wait(fn):
    return f.wait(fn, 20)
def common(path):
    return read(path/'fixture-admission.json')
def reconcile(path, env):
    confirmation = common(path)
    confirmation.update(status='exact_committed', authority='completion_only', registration_committed=True)
    (path/'confirmation.json').write_text(json.dumps(confirmation))
    reg = read(path/'source-registration-v2.json')
    return subprocess.run([reg['recovery']['path'], 'completion-reconcile-v2', '--registration-file', str(path/'source-registration-v2.json'), '--confirmation', str(path/'confirmation.json'), '--json'], env=env, capture_output=True, timeout=20)

def assert_registration_mode(path, expected):
    # Observe the original producer bytes without modifying fixture registration.
    registration = read(path/'source-registration-v2.json')
    assert registration['completion_kind'] == expected, registration
    assert read(path/'meta.json')['mode'] == ('sentinel' if expected == 'ready' else 'exit')

def publication_second(root, env):
    fault = {'recovery-lock': 'during-output-hash',
             'header-only-loss': 'selection-error'}.get(CASE, 'before-output-capture')
    env['AGENT_BASH_SOURCE_FAULT'] = fault
    env['AGENT_BASH_LOG_MAX_BYTES'] = str(8*1024*1024 if CASE == 'recovery-lock' else 65536)
    original = b'a' * (2*1024*1024 if CASE == 'recovery-lock' else 32768) + b'READY\n'
    script = root/'second-writer.py'
    script.write_text("import os,time\nos.write(1,b'a'*%d+b'READY\\n')\nwhile not os.path.exists(%r): time.sleep(.01)\nfor _ in range(128): os.write(1,b'z'*8192)\nos.write(1,b'AFTER-ROLLOVER\\n')\nopen(%r,'w').write('done')\nwhile True: time.sleep(1)\n" % (len(original)-6, str(root/'write-more'), str(root/'writer-done')))
    result = run(env, 'run', '--ready-sentinel', 'READY', '--', '/usr/bin/python3', str(script))
    assert result.returncode == 0, result.stderr
    item = json.loads(result.stdout); path = Path(item['state_dir'])
    reached = wait(lambda: read(path/f'fault-{fault}.reached.json'))
    header = wait(lambda: read(path/'source-observation-v2.json'))
    assert header['outcome']['observer'] == reached
    assert header['outcome']['kind'] == 'ready'
    workload = read(path/'source-launch-v2.json')['workload_identity']
    guardian = f.stat(reached['pid'])[0]
    assert (path/'physical-custody').exists()
    assert not (path/'completion-snapshot-v2.json').exists()
    recovery = None
    if CASE == 'recovery-lock':
        assert (path/'completion-output-v2.bin').read_bytes() == original
        confirmation = common(path)
        confirmation.update(status='exact_committed', authority='completion_only', registration_committed=True)
        (path/'confirmation.json').write_text(json.dumps(confirmation))
        reg = read(path/'source-registration-v2.json')
        # Recovery image verifies its saved environment. Set only the test hook
        # in that already-selected recovery invocation, not production state.
        recovery_env = env.copy(); recovery_env['AGENT_BASH_SOURCE_FAULT'] = 'recovery-lock'
        recovery = subprocess.Popen([reg['recovery']['path'], 'completion-reconcile-v2',
            '--registration-file', str(path/'source-registration-v2.json'),
            '--confirmation', str(path/'confirmation.json'), '--json'], env=recovery_env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        recovery_identity = wait(lambda: read(path/'fault-recovery-lock.reached.json'))
        assert recovery_identity == identity(recovery.pid)
        wait(lambda: Path(f'/proc/{recovery.pid}/stat').read_text().split(') ')[1][0] == 'T')
    else:
        assert not (path/'completion-output-v2.bin').exists(), 'fault must precede body capture'
    if CASE == 'header-only-loss':
        pending = reconcile(path, env)
        assert pending.returncode == 0, pending.stderr
        assert json.loads(pending.stdout)['status'] == 'pending', pending.stdout
        assert not (path/'missing-output-observation-v2.json').exists()
        assert not (path/'completion-snapshot-v2.json').exists()
    (root/'write-more').touch()
    wait(lambda: (root/'writer-done').exists())
    wait(lambda: b'AFTER-ROLLOVER' in (path/'log').read_bytes())
    assert identity(reached['pid']) == reached, 'original observer must service output'
    if CASE != 'recovery-lock':
        assert b'READY' not in (path/'log').read_bytes(), 'must actually evict original selection'
        assert (path/'log').stat().st_size <= 65536
    if CASE in ['header-only-loss', 'pre-capture-owner-loss', 'transient-read-loss']:
        os.kill(reached['pid'], signal.SIGKILL)
    result = run(env, 'cancel', item['handle'])
    assert result.returncode == 0 and json.loads(result.stdout)['requested'], result.stdout
    wait(lambda: not Path(f"/proc/{workload['pid']}").exists())
    wait(lambda: (path/'cancel-workload-drained').exists())
    if CASE == 'header-only-loss':
        wait(lambda: not (path/'physical-custody').exists())
        wait(lambda: not Path(f'/proc/{guardian}').exists() or Path(f'/proc/{guardian}/stat').read_text().split(') ')[1][0] == 'Z')
        result = reconcile(path, env)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['status'] == 'source_output_missing', result.stdout
        snapshot = read(path/'completion-snapshot-v2.json')
        assert snapshot['status'] == 'original_output_unavailable'
        assert snapshot['output']['reason'] == 'original_selection_not_retained'
        assert snapshot['output']['original_observer'] == header['outcome']['observer']
        assert read(path/'source-outcome-v2.json') == header['outcome']
        assert not (path/'fixture-acceptance.json').exists()
        assert not (path/'completion-output-v2.bin').exists()
        assert read(path/'source-observation-v2.json') == header
        assert read(path/'continuation-v2.json')['registration'] == 'completion_only_confirmed'
        assert 'registered native continuation' in (path/'source-publication-error.txt').read_text()
    else:
        if CASE == 'transient-read-loss':
            selected = path/'selected-log-v2.bin'
            # A real access error remains uncertainty, not proof of loss.
            selected.chmod(0)
            result = reconcile(path, env)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['status'] == 'pending', result.stdout
            assert not (path/'missing-output-observation-v2.json').exists()
            assert not (path/'completion-snapshot-v2.json').exists()
            assert not (path/'completion-output-v2.bin').exists()
            selected.chmod(0o600)
            # Recover a validated managed alias without canonical-path repair.
            selected.rename(path/'preserved-original-alias')
        (path/f'fault-{fault}.release').touch()
        if CASE in ['pre-capture-owner-loss', 'transient-read-loss']:
            # The original pin+boundary, not its later mutable pathname, can be
            # recovered after original observer death and real guardian drain.
            result = reconcile(path, env)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['status'] == 'source_ready', result.stdout
        wait(lambda: (path/'completion-snapshot-v2.json').exists())
        assert (path/'completion-output-v2.bin').read_bytes() == original
        assert read(path/'source-outcome-v2.json') == header['outcome']
        if recovery:
            assert Path(f'/proc/{recovery.pid}/stat').read_text().split(') ')[1][0] == 'T'
            os.kill(recovery.pid, signal.SIGCONT)
            stdout, stderr = recovery.communicate(timeout=20)
            assert recovery.returncode == 0, stderr
            assert json.loads(stdout)['status'] == 'source_ready', stdout
        wait(lambda: not (path/'physical-custody').exists())
    print(json.dumps(dict(case=CASE, original_selected_bytes=len(original),
        capture_missing=CASE=='header-only-loss', guardian_pid=guardian,
        actual_cancel_drain=True, physical_custody_discharged=True,
        original_output_resampled=False, native_notification_delivery_exercised=False)), flush=True)

def capture_schedule(root, env):
    preheader = CASE == 'selection-before-header'
    occupied = CASE.startswith('capture-occupied-')
    stage = CASE.replace('capture-occupied-', 'capture-') if occupied else CASE
    fault = stage if preheader else 'guardian-' + stage
    env['AGENT_BASH_SOURCE_FAULT'] = fault
    env['AGENT_BASH_LOG_MAX_BYTES'] = '65536'
    original = b'a'*32768 + b'READY\n'
    script = root/'capture-writer.py'
    script.write_text("import os,time\nos.write(1,b'a'*32768+b'READY\\n')\nwhile not os.path.exists(%r): time.sleep(.01)\nfor _ in range(128): os.write(1,b'z'*8192)\nopen(%r,'w').write('done')\nwhile True: time.sleep(1)\n" % (str(root/'write-more'), str(root/'writer-done')))
    result = run(env, 'run', '--ready-sentinel', 'READY', '--', '/usr/bin/python3', str(script))
    assert result.returncode == 0, result.stderr
    item = json.loads(result.stdout); path = Path(item['state_dir'])
    marker = 'selection-before-header' if preheader else 'before-output-capture'
    observer = wait(lambda: read(path/f'fault-{marker}.reached.json'))
    selection = read(path/'output-selection-v2.json')
    original_event = selection['observation']
    selected_record = (path/'output-selection-v2.json').read_bytes()
    if occupied:
        unknown = path / ('.completion-output-' + hashlib.sha256(selected_record).hexdigest() + '.tmp')
        unknown.write_bytes(b'unknown retained capture evidence')
    assert original_event['outcome']['observer'] == observer
    assert original_event['outcome']['kind'] == 'ready'
    if preheader:
        assert not (path/'source-observation-v2.json').exists()
    (root/'write-more').touch()
    wait(lambda: (root/'writer-done').exists())
    wait(lambda: b'READY' not in (path/'log').read_bytes())
    os.kill(observer['pid'], signal.SIGKILL)
    result = run(env, 'cancel', item['handle'])
    assert result.returncode == 0 and json.loads(result.stdout)['requested'], result.stdout
    wait(lambda: (path/'cancel-workload-drained').exists())
    if preheader:
        assert not (path/'source-observation-v2.json').exists()
        (path/'fault-selection-before-header.release').touch()
        wait(lambda: (path/'completion-snapshot-v2.json').exists())
    else:
        capturer = wait(lambda: read(path/f'fault-{stage}.reached.json'))
        assert capturer != observer
        wait(lambda: Path(f"/proc/{capturer['pid']}/stat").read_text().split(') ')[1][0] == 'T')
        if not occupied:
            (path/'selected-log-v2.bin').unlink()
        # Original observer gone and live log rolled. Original loss schedules
        # remove the pin; occupied-slot progress schedules retain that source.
        # A stopped cooperating guardian still excludes loss inventory.
        result = reconcile(path, env)
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)['status'] == 'pending', result.stdout
        assert not (path/'missing-output-observation-v2.json').exists()
        assert not (path/'completion-snapshot-v2.json').exists()
        if CASE == 'capture-open':
            assert not list(path.glob('.completion-output-*.tmp'))
            os.kill(capturer['pid'], signal.SIGCONT)
            wait(lambda: (path/'completion-snapshot-v2.json').exists())
        else:
            os.kill(capturer['pid'], signal.SIGKILL)
            wait(lambda: not Path(f"/proc/{capturer['pid']}").exists() or
                 Path(f"/proc/{capturer['pid']}/stat").read_text().split(') ')[1][0] == 'Z')
            # The fixture is the actual adopting subreaper. Reap this exact
            # killed child; a retained zombie is intentionally not Gone evidence.
            waited, status = os.waitpid(capturer['pid'], 0)
            assert waited == capturer['pid'] and os.WIFSIGNALED(status)
            retry_env = env.copy()
            if occupied:
                retry_env.pop('AGENT_BASH_SOURCE_FAULT', None)
            result = reconcile(path, retry_env)
            assert result.returncode == 0, result.stderr
            expected = 'source_output_missing' if CASE == 'capture-partial' else 'source_ready'
            assert json.loads(result.stdout)['status'] == expected, result.stdout
    assert read(path/'source-outcome-v2.json') == original_event['outcome']
    assert read(path/'source-observation-v2.json') == original_event
    assert (path/'output-selection-v2.json').read_bytes() == selected_record
    if occupied:
        assert unknown.read_bytes() == b'unknown retained capture evidence'
        assert list(path.glob('.completion-output-*.tmp')) == [unknown]
        assert (path/'selected-log-v2.bin').read_bytes().startswith(original)
    if CASE == 'capture-partial':
        snapshot = read(path/'completion-snapshot-v2.json')
        assert snapshot['output']['reason'] == 'selected_storage_lost'
        assert not (path/'completion-output-v2.bin').exists()
        assert len(list(path.glob('.completion-output-*.tmp'))) == 1
        assert list(path.glob('.completion-output-*.tmp'))[0].stat().st_size == 4096
    else:
        assert (path/'completion-output-v2.bin').read_bytes() == original
        assert read(path/'completion-snapshot-v2.json')['rc'] == 0
    print(json.dumps(dict(case=CASE, original_event_preserved=True,
        original_selected_bytes=len(original), actual_guardian_drain=True,
        missing_while_capture_owned=False, occupied_slot=occupied,
        native_notification_delivery_exercised=False)), flush=True)

def suite(root):
    endpoint = root/'owner.sock'
    stop = threading.Event()
    listener = socket.socket(socket.AF_UNIX)
    listener.bind(str(endpoint)); listener.listen(); listener.settimeout(.1)
    def serve():
        while not stop.is_set():
            try: conn, _ = listener.accept()
            except socket.timeout: continue
            with conn:
                assert conn.recv(6) == b'hello\n'
                hello = dict(protocol=P,domain_id=D,owner_generation='fixture',endpoint=str(endpoint),guardian_identity=identity(os.getpid()),driver_identity=identity(os.getpid()))
                conn.sendall(json.dumps(hello).encode())
    thread = threading.Thread(target=serve); thread.start()
    env = os.environ.copy()
    env.update(XDG_STATE_HOME=str(root/'state'), XDG_CONFIG_HOME=str(root/'config'),
               AGENT_BASH_AGENT_RUNNER_BIN=str(Path(__file__).with_name('helper.py')),
               AGENT_BASH_OWNER_SESSION_ID='fixture-session',
               AGENT_BASH_OWNER_INVOCATION_UUID='55555555-5555-4555-8555-555555555555',
               OULIPOLY_PARENT_INVOCATION=json.dumps(dict(id='55555555-5555-4555-8555-555555555555')),
               OULIPOLY_COMPLETION_ENDPOINT=str(endpoint))
    try:
        if CASE in ['selection-before-header', 'capture-open', 'capture-complete', 'capture-partial', 'capture-occupied-partial', 'capture-occupied-complete']:
            return capture_schedule(root, env)
        if CASE in ['recovery-lock', 'header-only-loss', 'pre-capture-rollover', 'pre-capture-owner-loss', 'transient-read-loss']:
            publication_second(root, env)
            return
        if CASE in ['large-escaped', 'large-raw', 'large-hash']:
            env['AGENT_BASH_LOG_MAX_BYTES'] = str(32*1024*1024)
            blocks = 512 if CASE in ['large-escaped', 'large-hash'] else 2560
            if CASE == 'large-hash': env['AGENT_BASH_SOURCE_FAULT'] = 'during-output-hash'
            byte = b'\0' if CASE == 'large-escaped' else b'\xff'
            script = root/'large-writer.py'
            script.write_text("import os,time\nfor _ in range(%d): os.write(1,%r*8192)\nos.write(1,b'READY\\n')\nwhile not os.path.exists(%r): time.sleep(.01)\nfor _ in range(128): os.write(1,b'x'*8192)\nos.write(1,b'LARGE-WRITER-ALIVE\\n')\nopen(%r,'w').write('done')\ntime.sleep(60)\n" % (blocks, byte, str(root/'write-more'), str(root/'writer-done')))
            result = run(env, 'run', '--ready-sentinel', 'READY', '--', '/usr/bin/python3', str(script))
            assert result.returncode == 0, result.stderr
            item = json.loads(result.stdout); path = Path(item['state_dir'])
            assert_registration_mode(path, 'ready')
            wait(lambda: (path/'completion-output-v2.bin').exists())
            if CASE == 'large-hash':
                reached = wait(lambda: read(path/'fault-during-output-hash.reached.json'))
                assert reached == identity(read(path/'meta.json')['supervisor_pid'])
                (root/'write-more').touch()
                wait(lambda: (root/'writer-done').exists())
                wait(lambda: b'LARGE-WRITER-ALIVE' in (path/'log').read_bytes())
                result = run(env, 'cancel', item['handle'])
                assert result.returncode == 0 and json.loads(result.stdout)['requested'], result.stdout
                workload = read(path/'source-launch-v2.json')['workload_identity']
                wait(lambda: not Path(f"/proc/{workload['pid']}").exists())
                assert identity(reached['pid']) == reached
                assert not (path/'completion-snapshot-v2.json').exists()
                (path/'fault-during-output-hash.release').touch()
            wait(lambda: read(path/'fixture-acceptance.json'))
            frozen = (path/'completion-output-v2.bin').read_bytes()
            assert frozen == byte*(blocks*8192) + b'READY\n'
            snapshot_bytes = (path/'completion-snapshot-v2.json').read_bytes()
            snapshot = json.loads(snapshot_bytes)
            expected_descriptor = dict(representation='retained-output-v1',relative='completion-output-v2.bin',
                sha256=hashlib.sha256(frozen).hexdigest(),byte_len=len(frozen),encoding='raw')
            assert snapshot['output'] == expected_descriptor, snapshot
            assert len(snapshot_bytes) < 4096
            assert read(path/'source-outcome-v2.json')['kind'] == 'ready'
            original = identity(read(path/'meta.json')['supervisor_pid']) if CASE != 'large-hash' else reached
            workload = read(path/'source-launch-v2.json')['workload_identity']
            (root/'write-more').touch()
            wait(lambda: (root/'writer-done').exists())
            wait(lambda: b'LARGE-WRITER-ALIVE' in (path/'log').read_bytes())
            if CASE != 'large-hash': assert identity(original['pid']) == original
            assert (path/'completion-output-v2.bin').read_bytes() == frozen
            assert (path/'completion-snapshot-v2.json').read_bytes() == snapshot_bytes
            if CASE != 'large-hash':
                result = run(env, 'cancel', item['handle'])
                assert result.returncode == 0 and json.loads(result.stdout)['requested'], result.stdout
            wait(lambda: not Path(f"/proc/{workload['pid']}").exists())
            wait(lambda: not (path/'physical-custody').exists())
            print(json.dumps(dict(case=CASE, raw_bytes=len(frozen), escaped_json_bytes=blocks*8192*6+9,
                original_observer_alive=True, further_output_bytes=1024*1024, workload_cancelled=True,
                source_publication_accepted_by_simulated_runner=True, snapshot_bytes=len(snapshot_bytes), output_descriptor=expected_descriptor,
                native_attachment_delivery_exercised=False)), flush=True)
            return
        if CASE == 'resources':
            fd_before = len(list(Path('/proc/self/fd').iterdir()))
            sources = []
            for index in range(4):
                result = run(env, 'run', '--delivery', 'sync', '--', '/bin/sh', '-c', f'echo source-{index}')
                assert result.returncode == 0, result.stderr
                sources.append(Path(json.loads(result.stdout)['state_dir']))
            for path in sources:
                wait(lambda: read(path/'fixture-acceptance.json'))
                wait(lambda: not (path/'physical-custody').exists())
            print(json.dumps(dict(case=CASE, handles=len(sources),
                fixture_fd_before=fd_before,fixture_fd_after=len(list(Path('/proc/self/fd').iterdir())),
                pinned_bash_images=len(sources),pinned_bash_bytes=sum((p/'agent-bash-recovery-v2').stat().st_size for p in sources),
                source_snapshots=len([p for p in sources if (p/'completion-snapshot-v2.json').exists()]),
                source_snapshot_bytes=sum((p/'completion-snapshot-v2.json').stat().st_size for p in sources),
                source_body_bytes=sum((p/'completion-output-v2.bin').stat().st_size for p in sources),
                attempt_intents=sum(len(list(p.glob('continuation-*.intent.json'))) for p in sources),
                retained_files=sum(len(list(p.iterdir())) for p in sources),
                native_listener_ACKs_exercised=0)),flush=True)
            return
        if CASE == 'dead-endpoint':
            stop.set(); thread.join(); listener.close()
            side_effect = root/'must-not-run'
            result = run(env,'run','--','/bin/sh','-c',f'touch {side_effect}')
            assert result.returncode != 0, result.stdout
            assert not side_effect.exists()
            assert not list((root/'state'/'agent-bash').glob('ab_*/fixture-admission.json'))
            print('dead endpoint refused new work before admission; side effects=0',flush=True)
            return
        if CASE in ['lost-reply', 'channel-loss', 'blocked-registration']:
            env['AGE360_FIXTURE_FAULT'] = CASE
        side_effect = root/'workload-ran'
        command = ['run','--delivery','sync','--','/bin/sh','-c',f'echo ran > {side_effect}; echo fixture-output']
        if CASE == 'early-ready-exit':
            command = ['run','--ready-sentinel','READY','--','/bin/sh','-c','echo not-ready; exit 7']
        if CASE == 'ready':
            command = ['run','--ready-sentinel','READY','--','/bin/sh','-c','echo READY; exec sleep 60']
        if CASE in ['root', 'publication-race']:
            command = ['run','--completion-scope','root','--','/bin/sh','-c',f'sleep 60 >/dev/null 2>&1 & echo child=$!; echo fixture-output']
        if CASE == 'guardian':
            command = ['run','--','/bin/sh','-c',f'echo started > {side_effect}; sleep 60']
        if CASE == 'publication-race':
            env['AGENT_BASH_SOURCE_FAULT'] = 'after-terminal-metadata'
        if CASE in ['publication-error', 'publication-io-error']:
            env['AGENT_BASH_SOURCE_FAULT'] = 'publication-error'
            script = root/'writer.py'
            script.write_text("import os,time\nos.write(1,b'READY\\n')\nwhile not os.path.exists(%r): time.sleep(.01)\nfor _ in range(128): os.write(1,b'x'*8192)\nos.write(1,b'WRITER-STILL-ALIVE\\n')\nopen(%r,'w').write('done')\ntime.sleep(60)\n" % (str(root/'write-more'), str(root/'writer-done')))
            command = ['run','--ready-sentinel','READY','--','/usr/bin/python3',str(script)]
        if CASE == 'blocked-registration':
            caller = subprocess.Popen([BIN,*command], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            path = wait(lambda: next((p for p in (root/'state'/'agent-bash').glob('ab_*') if (p/'fixture-helper-identity.json').exists()), None))
            result = reconcile(path, env)
            assert result.returncode == 0, result.stderr
            assert json.loads(result.stdout)['status'] == 'pending', result.stdout
            assert not side_effect.exists()
            (path/'fixture-release').touch()
            stdout, stderr = caller.communicate(timeout=20)
            assert caller.returncode == 0, stderr
            item = json.loads(stdout)
        else:
            result = run(env, *command)
            if CASE == 'channel-loss':
                assert result.returncode != 0, result.stdout
                path = wait(lambda: next((p for p in (root/'state'/'agent-bash').glob('ab_*') if (p/'fixture-admission.json').exists()),None))
            else:
                assert result.returncode == 0, result.stderr
                item = json.loads(result.stdout); path = Path(item['state_dir'])
        assert_registration_mode(path, 'ready' if CASE in ['early-ready-exit', 'ready', 'publication-error', 'publication-io-error'] else 'exit')
        if CASE in ['lost-reply','channel-loss']:
            assert not side_effect.exists()
            # Reap only this fixture's already-dead adopted original worker before
            # requiring exact-gone evidence; no PID absence shortcut in product.
            while True:
                try:
                    if os.waitpid(-1, os.WNOHANG)[0] == 0: break
                except ChildProcessError: break
            result = reconcile(path, env)
            assert result.returncode == 0, result.stderr
            reply = json.loads(result.stdout)
            assert reply['status'] == 'source_ready', result.stdout
            for field, name in [('snapshot_sha256','completion-snapshot-v2.json'), ('outcome_sha256','source-outcome-v2.json')]:
                assert reply[field] == hashlib.sha256((path/name).read_bytes()).hexdigest(), reply
            assert read(path/'source-outcome-v2.json')['kind'] == 'never_launched'
            assert read(path/'source-launch-v2.json')['phase'] == 'revoked_never_launched'
            assert not side_effect.exists()
            assert not (path/'registration-receipt-v2.json').exists()
        else:
            if CASE in ['publication-race', 'publication-error', 'publication-io-error']:
                fault = env['AGENT_BASH_SOURCE_FAULT']
                reached = wait(lambda: read(path/f'fault-{fault}.reached.json'))
                assert reached == identity(read(path/'meta.json')['supervisor_pid']), reached
                assert (path/'physical-custody').exists()
                assert not (path/'completion-snapshot-v2.json').exists()
                if CASE == 'publication-race':
                    # Real terminal metadata -> accepted cancellation -> source lock.
                    result = run(env, 'cancel', item['handle'])
                    assert result.returncode == 0 and json.loads(result.stdout)['requested'], result.stdout
                    assert (path/'cancel-requested').exists()
                else:
                    frozen = (path/'completion-output-v2.bin').read_bytes()
                    assert frozen == b'READY\n', frozen
                    if CASE == 'publication-io-error':
                        # Force the real immutable publication syscall/read path to
                        # fail, beyond the injected staging fault.
                        (path/'source-outcome-v2.json').mkdir()
                        (path/f'fault-{fault}.release').touch()
                        wait(lambda: (path/'completion-source-bundle-v2.json').exists())
                        wait(lambda: (path/'source-publication-error.txt').exists() and 'bounded regular file' in (path/'source-publication-error.txt').read_text())
                    (root/'write-more').touch()
                    wait(lambda: (root/'writer-done').exists())
                    wait(lambda: b'WRITER-STILL-ALIVE' in (path/'log').read_bytes())
                    assert identity(reached['pid']) == reached
                    assert not (path/'completion-snapshot-v2.json').exists()
                    assert (path/'completion-output-v2.bin').read_bytes() == frozen
                    if CASE == 'publication-io-error':
                        (path/'source-outcome-v2.json').rmdir()
                (path/f'fault-{fault}.release').touch()
            if CASE == 'guardian':
                wait(lambda: side_effect.exists())
                meta = read(path/'meta.json')
                original = identity(meta['supervisor_pid'])
                os.kill(original['pid'], signal.SIGKILL)
                time.sleep(.15)
                assert not (path/'source-outcome-v2.json').exists(), 'rc70 is not cessation'
                result = run(env,'cancel',item['handle']); assert result.returncode == 0, result.stderr
                assert json.loads(result.stdout)['requested'], result.stdout
            acceptance = wait(lambda: read(path/'fixture-acceptance.json'))
            local = wait(lambda: (v if (v:=read(path/'continuation-v2.json')) and v['enqueue']=='accepted' else None))
            outcome = read(path/'source-outcome-v2.json')
            assert acceptance['source_id'] == outcome['source_id']
            if CASE in ['ready', 'publication-error', 'publication-io-error']:
                assert outcome['kind']=='ready' and not outcome['original_tree_drained'] and not outcome['output_closed'], outcome
            elif CASE in ['root', 'publication-race']:
                assert outcome['kind']=='exit_root' and not outcome['original_tree_drained'], outcome
            elif CASE == 'early-ready-exit':
                assert outcome['kind']=='exit_tree' and outcome['root_wait_status']==7 << 8, outcome
                assert read(path/'completion-snapshot-v2.json')['rc']==7
                assert outcome['ready_sentinel'] is None
            elif CASE == 'guardian':
                assert outcome['kind']=='cancelled' and outcome['original_tree_drained'], outcome
            else:
                assert outcome['kind']=='exit_tree' and outcome['root_wait_status']==0 and outcome['original_tree_drained'], outcome
                output = run(env,'snapshot', item['handle']); assert output.returncode==0,output.stderr
                prefix = json.loads(output.stdout)
                receipt = run(env, 'accept-output', item['handle'], '--snapshot', json.dumps(prefix['snapshot']))
                assert receipt.returncode == 0, receipt.stderr
                assert json.loads(receipt.stdout)['remote_ack'] == 'unconfirmed'
                assert (path/'completion-snapshot-v2.json').read_bytes() != json.dumps(prefix['snapshot']).encode()
                assert local['enqueue']=='accepted'
                assert 'acknowledged' not in local, 'byte acquisition must not invent event ACK'
            if CASE in ['publication-error', 'publication-io-error']:
                selected = read(path/'completion-snapshot-v2.json')['output']
                assert selected['encoding'] == 'raw'
                assert selected['sha256'] == hashlib.sha256(b'READY\n').hexdigest()
                assert (path/'completion-output-v2.bin').read_bytes() == b'READY\n'
                reply = reconcile(path, env)
                assert reply.returncode == 0, reply.stderr
                recovered = json.loads(reply.stdout)
                assert recovered['status'] == 'source_ready', recovered
                for key, name in [('snapshot_sha256','completion-snapshot-v2.json'), ('outcome_sha256','source-outcome-v2.json')]:
                    assert recovered[key] == hashlib.sha256((path/name).read_bytes()).hexdigest()
            if CASE in ['ready','root','publication-error','publication-io-error']:
                result = run(env,'cancel',item['handle']); assert result.returncode==0,result.stderr
            wait(lambda: not (path/'physical-custody').exists())
        print(json.dumps(dict(case=CASE, source=read(path/'source-registration-v2.json')['source_id'], fence=read(path/'source-launch-v2.json'), outcome=read(path/'source-outcome-v2.json'), retained_files=len(list(path.iterdir())))),flush=True)
    except Exception:
        for directory in (root/'state'/'agent-bash').glob('ab_*'):
            print('FAILURE_SOURCE', directory, file=sys.stderr)
            for name in ['meta.json','continuation-v2.json','source-outcome-v2.json','source-launch-v2.json','cancel-requested','cancel-workload-drained']:
                try: print(name, (directory/name).read_text(), file=sys.stderr)
                except OSError as error: print(name, error, file=sys.stderr)
            print('files', [p.name for p in directory.iterdir()], file=sys.stderr)
        print('processes', f.process_evidence(f.descendants(os.getpid())), file=sys.stderr)
        raise
    finally:
        stop.set(); thread.join(); listener.close()
        # Actual fixture subreaper cleans its own children BEFORE temp teardown.
        f.cleanup()

assert ctypes.CDLL(None).prctl(36,1,0,0,0)==0
with tempfile.TemporaryDirectory(prefix='a360-') as tmp:
    suite(Path(tmp))
