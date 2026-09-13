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
        if CASE == 'ready':
            command = ['run','--ready-sentinel','READY','--','/bin/sh','-c','echo READY; exec sleep 60']
        if CASE == 'root':
            command = ['run','--completion-scope','root','--','/bin/sh','-c',f'sleep 60 >/dev/null 2>&1 & echo child=$!; echo fixture-output']
        if CASE == 'guardian':
            command = ['run','--','/bin/sh','-c',f'echo started > {side_effect}; sleep 60']
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
            assert json.loads(result.stdout)['status'] == 'source_ready', result.stdout
            assert read(path/'source-outcome-v2.json')['kind'] == 'never_launched'
            assert read(path/'source-launch-v2.json')['phase'] == 'revoked_never_launched'
            assert not side_effect.exists()
            assert not (path/'registration-receipt-v2.json').exists()
        else:
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
            if CASE == 'ready':
                assert outcome['kind']=='ready' and not outcome['original_tree_drained'] and not outcome['output_closed'], outcome
            elif CASE == 'root':
                assert outcome['kind']=='exit_root' and not outcome['original_tree_drained'], outcome
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
            if CASE in ['ready','root']:
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
