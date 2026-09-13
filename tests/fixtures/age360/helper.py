#!/usr/bin/python3
"""Structured fault helper, NOT native State admission or paired ACK evidence."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time

P = 'completion-continuation-v2'
D = '11111111-1111-4111-8111-111111111111'
def arg(name):
    return sys.argv[sys.argv.index(name) + 1]
def sha(data):
    return hashlib.sha256(data).hexdigest()
def save(path, value):
    path.write_text(json.dumps(value))

op = sys.argv[2]
if log := os.environ.get('AGE360_FIXTURE_LOG'):
    with open(log, 'a') as output:
        output.write(f"{os.environ.get('AGENT_BASH_FAKE_ROUTE','unset')}:{op}:{'present' if os.environ.get('OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY') else 'absent'}\n")
if sys.argv[1:3] == ['session', 'of-pid']:
    print(json.dumps(dict(found=True, invocation_uuid=os.environ.get('AGE360_FIXTURE_INVOCATION','55555555-5555-4555-8555-555555555555'), session_id=os.environ.get('AGE360_FIXTURE_SESSION','fixture-session'))))
    sys.exit(0)
if op == 'agent-bash-capability':
    print(json.dumps(dict(protocol=P, domain_id=D)))
    sys.exit(0)
if op == 'agent-bash-register':
    path = Path(arg('--registration-file'))
    raw = path.read_bytes()
    reg = json.loads(raw)
    common = {k: reg[k] for k in ['protocol','domain_id','source_id','handle','registration_id']}
    common['registration_digest'] = sha(raw)
    save(path.parent / 'fixture-admission.json', common)
    fault = os.environ.get('AGE360_FIXTURE_FAULT')
    if fault == 'lost-reply':
        sys.exit(70)
    if fault == 'channel-loss':
        # Exact original worker only; the committed fixture row survives it.
        os.kill(os.getppid(), signal.SIGKILL)
        sys.exit(70)
    if fault == 'blocked-registration':
        save(path.parent / 'fixture-helper-identity.json', dict(pid=os.getpid()))
        while not (path.parent / 'fixture-release').exists():
            time.sleep(.02)
    common.update(status='registered', registration_committed=True,
                  continuation_owner_domain=D, listeners=reg['listeners'], listener_revision=1)
    print(json.dumps(common))
elif op == 'agent-bash-complete':
    assert '--consumed' not in sys.argv
    path = Path(arg('--registration-file'))
    common = json.loads((path.parent / 'fixture-admission.json').read_text())
    snapshot = Path(arg('--snapshot')).read_bytes()
    parsed = json.loads(snapshot)
    outcome = (path.parent / 'source-outcome-v2.json').read_bytes()
    assert parsed['outcome_sha256'] == sha(outcome)
    if isinstance(parsed['output'], dict):
        descriptor = parsed['output']
        assert descriptor['representation'] == 'retained-output-v1'
        assert descriptor['relative'] == 'completion-output-v2.bin'
        assert descriptor['encoding'] == 'utf8-lossy'
        artifact = path.parent / descriptor['relative']
        assert not artifact.is_symlink() and artifact.is_file()
        assert artifact.stat().st_size == descriptor['byte_len'] <= 1073741824
        digest = hashlib.sha256()
        with artifact.open('rb') as body:
            while chunk := body.read(65536): digest.update(chunk)
        assert descriptor['sha256'] == digest.hexdigest()
    payload = b'fixture retained notification'
    common.update(status='accepted', snapshot_sha256=sha(snapshot), outcome_sha256=sha(outcome),
                  payload_sha256=sha(payload), payload_byte_len=len(payload), listener_revision=1)
    save(path.parent / 'fixture-acceptance.json', common)
    print(json.dumps(common))
elif op == 'agent-bash-activate':
    print('{}')
else:
    sys.exit(64)
