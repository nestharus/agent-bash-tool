"""Offline adapter boundary tests: BUN=/absolute/bun python3 tests/test_opencode_workdir.py.

Real Bun subprocesses execute only a synthetic spooler, never the installed stack.
The plugin shim follows tests/spooler_cli.rs; no package installation is needed.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ADAPTER = Path(__file__).resolve().parents[1] / 'integrations/opencode/tools/bash.ts'
BUN = shutil.which(os.environ.get('BUN', 'bun'))
DRIVER = '''import { mock } from "bun:test"
const tool = Object.assign(d => d, { schema: { string: () => ({ describe: () => ({ optional: () => ({}) }) }) } })
mock.module("@opencode-ai/plugin", () => ({ tool }))
const adapter = (await import(process.argv[2])).default
const args = JSON.parse(process.argv[3])
const abort = new AbortController()
if (process.env.TEST_ABORT_AFTER_MS) setTimeout(() => abort.abort(), Number(process.env.TEST_ABORT_AFTER_MS))
try {
  const result = await adapter.execute(args, {sessionID: "private-owner", abort: abort.signal})
  console.log(JSON.stringify({result, fields: Object.keys(adapter.args)}))
} catch (error) { console.log(JSON.stringify({error: String(error)})) }
'''
FAKE = '''#!/usr/bin/python3
import hashlib, json, os, sys, time
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'args': args, 'cwd': os.getcwd(), 'owner': os.environ.get('AGENT_BASH_OWNER_SESSION_ID'), 'custom': os.environ.get('TEST_CUSTOM')}) + '\\n')
mode = os.environ.get('FAKE_MODE', '')
if args[0] == 'run':
    if os.environ.get('FAKE_RESPONSE_FILE'):
        with open(os.environ['FAKE_RESPONSE_FILE'], 'rb') as response:
            sys.stdout.buffer.write(response.read())
        sys.stderr.write(os.environ.get('FAKE_RESPONSE_STDERR', ''))
        sys.exit(int(os.environ.get('FAKE_RESPONSE_EXIT', '0')))
    if mode == 'slow-dispatch': time.sleep(0.05)
    dispatch = mode if mode in ('root-accepted', 'effects-possible-no-replay', 'registration-outcome-unknown') else 'running'
    print(json.dumps({'handle': 'ab_fixture', 'dispatch_state': dispatch,
                      'retry_safe': False, 'effects_possible': dispatch != 'running'}))
elif args[0] == 'status':
    if mode in ('cancel-pending', 'cancel-rejected', 'cancel-accepted'): time.sleep(0.1)
    if mode == 'progress-failure' and '--observe-only' not in args: sys.exit(42)
    print('DONE rc=0 handle=ab_fixture')
elif args[0] == 'snapshot':
    data = b'private retained output\\n'
    snap = dict(version=1, handle='ab_fixture', created_at_unix_ms=1, bytes=len(data), sha256=hashlib.sha256(data).hexdigest(), encoding='hex')
    if mode == 'bad-hash': snap['sha256'] = '0' * 64
    print(json.dumps(dict(snapshot=snap, status='DONE rc=0 handle=ab_fixture', output=data.hex())))
elif args[0] == 'accept-output':
    if mode == 'receipt-failure': sys.exit(43)
    print(json.dumps(dict(version=1, handle='ab_fixture', local_receipt='durable', receipt_updated=True, snapshot=json.loads(args[3]), remote_ack='unconfirmed', physical_drain='unconfirmed')))
elif args[0] == 'cancel':
    status = {'cancel-pending': 'cancellation_pending_receipt', 'cancel-rejected': 'rejected', 'cancel-accepted': 'cancellation_accepted'}[mode]
    print(json.dumps(dict(handle='ab_fixture', requested=status == 'cancellation_accepted', root_status=status, root_detail='fixture')))
else: sys.exit(99)
'''


class WorkdirTest(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(BUN, 'Bun is required; no installed stack fallback')
        self.temp = tempfile.TemporaryDirectory(prefix='adapter-workdir-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ('home', 'config', 'data', 'state', 'cache', 'tmp', "requested cwd 'quoted'", 'launch'):
            (self.root / name).mkdir()
        self.cwd = self.root / "requested cwd 'quoted'"
        self.log = self.root / 'calls.jsonl'
        fake = self.root / 'fake-spooler'
        fake.write_text(FAKE)
        fake.chmod(0o700)
        self.driver = self.root / 'driver.ts'
        self.driver.write_text(DRIVER)
        # Allowlist only: no ambient credentials, binding sockets, provider or DB paths.
        self.env = dict(PATH='/usr/bin:/bin', HOME=str(self.root / 'home'),
                        XDG_CONFIG_HOME=str(self.root / 'config'), XDG_DATA_HOME=str(self.root / 'data'),
                        XDG_STATE_HOME=str(self.root / 'state'), XDG_CACHE_HOME=str(self.root / 'cache'),
                        TMPDIR=str(self.root / 'tmp'), AGENT_BASH_BIN=str(fake),
                        AGENT_BASH_AGENT_RUNNER_BIN=str(self.root / 'absent-runner'),
                        FAKE_LOG=str(self.log), TEST_CUSTOM='preserved')

    def execute(self, args, mode='', abort_delay=None, extra_env=None):
        self.log.write_text('')
        result = subprocess.run([BUN, '--no-install', str(self.driver), str(ADAPTER), json.dumps(args)],
                                cwd=self.root / 'launch', env={**self.env, 'FAKE_MODE': mode,
                                    **({'TEST_ABORT_AFTER_MS': str(abort_delay)} if abort_delay is not None else {}),
                                    **(extra_env or {})},
                                text=True, capture_output=True, check=True)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        reply = json.loads(result.stdout)
        summary = reply if len(result.stdout) < 2000 else {'result_bytes': len(result.stdout)}
        print(json.dumps(dict(request=args, mode=mode, reply=summary, calls=calls, stderr=result.stderr)), flush=True)
        return reply, calls

    def version31(self, stdout=b'first\x00\xff', stderr=b'second\x00\xfe', outcome='exited', code=0):
        digest = lambda data: hashlib.sha256(data).hexdigest()
        child = dict(request_id='request-one', d_key='d-key', invocation_uuid='invocation-one',
                     handle='ab30_child-one', root_handoff_id='handoff-one', root_id='root-one',
                     parent_invocation_uuid='parent-one', parent_work_grant_id='parent-grant',
                     parent_work_id='parent-work', registration_authority='authority-one',
                     actor=dict(host_pid=123, boot_id='boot-one', starttime_ticks=100,
                                pidns_dev=1, pidns_ino=2),
                     session=dict(lane_id='lane-one', source_generation='generation-one',
                                  session_id='session-one', request_id='d-key',
                                  allocation_id='allocation-one'))
        status = code << 8 if outcome == 'exited' else 15 if outcome == 'signaled' else 9
        event = dict(request_id=child['request_id'], source_id=child['handle'],
                     attempt_id='invocation-one', state_admission_id='admission-one',
                     registration_digest=digest(b'registration'), lane_id='lane-one',
                     source_generation='generation-one', session_id='session-one',
                     root_id='root-one', owner_generation='owner-one',
                     parent_work_grant_id='parent-grant', parent_work_id='parent-work',
                     physical_grant_id='physical-grant', physical_work_id='physical-work',
                     completion_policy='tree', selected_kind='cancelled' if outcome == 'cancelled' else 'tree_drained',
                     wait_status=status,
                     cancelled=outcome == 'cancelled',
                     cancel_grant_id='cancel-grant' if outcome == 'cancelled' else None,
                     tree_drained=True, output_closed=True,
                     stdout_sha256=digest(stdout), stdout_len=len(stdout),
                     stderr_sha256=digest(stderr), stderr_len=len(stderr))
        publication = dict(version=1, child=child, event=event, phase='unknown',
                           outcome=outcome, exit_code=code if outcome == 'exited' else None,
                           signal=15 if outcome == 'signaled' else None)
        return dict(schema_version=31, dispatch_state='sync-child-result', publication=publication,
                    stdout_encoding='base64', stdout_base64=base64.b64encode(stdout).decode(),
                    stderr_encoding='base64', stderr_base64=base64.b64encode(stderr).decode())

    def execute_wire(self, wire, command='printf probe', exit_code=0, stderr=''):
        path = self.root / 'response.json'
        path.write_bytes(wire if isinstance(wire, bytes) else json.dumps(wire).encode())
        return self.execute(dict(command=command), extra_env={
            'FAKE_RESPONSE_FILE': str(path), 'FAKE_RESPONSE_EXIT': str(exit_code),
            'FAKE_RESPONSE_STDERR': stderr,
        })

    def test_direct_and_wrapped_sync_workdir_and_retained_output(self):
        for command in ('printf probe', 'agent-bash run -- printf probe'):
            with self.subTest(command=command):
                reply, calls = self.execute(dict(command=command, workdir=str(self.cwd)))
                self.assertEqual(calls[0]['cwd'], str(self.cwd))
                self.assertEqual(calls[0]['owner'], 'private-owner')
                self.assertEqual(calls[0]['custom'], 'preserved')
                self.assertEqual(calls[0]['args'][-4:] == ['--', 'bash', '-lc', command], command == 'printf probe')
                self.assertIn('workdir', reply['fields'])
                self.assertIn('private retained output\n', reply['result'])
                self.assertIn('remote ACK: unconfirmed; physical drain: unconfirmed', reply['result'])
                self.assertEqual([c['args'][0] for c in calls], ['run', 'status', 'snapshot', 'accept-output', 'status'])
                self.assertTrue(all(c['cwd'] == str(self.root / 'launch') for c in calls[1:]))

    def test_async_direct_and_wrapped_workdir(self):
        for command in ('printf probe', 'agent-bash run -- printf probe'):
            with self.subTest(command=command):
                reply, calls = self.execute(dict(command=command, delivery='async', workdir=str(self.cwd)))
                self.assertIn('Running asynchronously', reply['result'])
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]['cwd'], str(self.cwd))

    def test_omitted_and_relative_workdir(self):
        for extra, expected in (({}, self.root / 'launch'), ({'workdir': "../requested cwd 'quoted'"}, self.cwd)):
            with self.subTest(extra=extra):
                reply, calls = self.execute(dict(command='printf probe', **extra))
                self.assertNotIn('error', reply)
                self.assertEqual(calls[0]['cwd'], str(expected))

    def test_invalid_workdir_does_not_dispatch(self):
        reply, calls = self.execute(dict(command='printf probe', workdir=str(self.root / 'absent')))
        self.assertIn('error', reply)
        self.assertEqual(calls, [])

    def test_control_failures_preserve_acquired_output(self):
        for mode in ('receipt-failure', 'progress-failure'):
            with self.subTest(mode=mode):
                reply, calls = self.execute(dict(command='printf probe', workdir=str(self.cwd)), mode)
                self.assertIn('private retained output\n', reply['result'])
                self.assertIn('progression: unconfirmed:', reply['result'])
                self.assertNotIn('consume', [c['args'][0] for c in calls])

    def test_invalid_snapshot_is_not_receipted(self):
        reply, calls = self.execute(dict(command='printf probe', workdir=str(self.cwd)), 'bad-hash')
        self.assertIn('hash mismatch', reply['error'])
        self.assertEqual([c['args'][0] for c in calls], ['run', 'status', 'snapshot'])

    def test_root_acceptance_and_ambiguous_no_replay_are_agent_visible(self):
        accepted, calls = self.execute(dict(command='printf probe', delivery='async'), 'root-accepted')
        self.assertIn('Dispatch accepted by root guardian', accepted['result'])
        self.assertIn('retry safe: no', accepted['result'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])

        ambiguous, calls = self.execute(dict(command='printf probe'), 'effects-possible-no-replay')
        self.assertIn('root acceptance reply was lost or ambiguous', ambiguous['result'])
        self.assertIn('Effects possible: yes; retry safe: no', ambiguous['result'])
        self.assertIn('Do not replay', ambiguous['result'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])

    def test_sync_abort_uses_actual_cancellation_receipt(self):
        for mode, expected in (
            ('cancel-pending', 'Cancellation pending durable receipt'),
            ('cancel-rejected', 'Cancellation rejected'),
            ('cancel-accepted', 'Cancellation accepted'),
        ):
            with self.subTest(mode=mode):
                reply, calls = self.execute(dict(command='printf probe'), mode, abort_delay=20)
                self.assertIn(expected, reply['result'])
                self.assertIn('"requested": false' if mode != 'cancel-accepted' else '"requested": true', reply['result'])
                self.assertEqual(calls[-1]['args'][0], 'cancel')

    def test_submission_has_no_fixed_process_deadline(self):
        reply, calls = self.execute(
            dict(command='printf probe', delivery='async'), 'slow-dispatch',
            extra_env={'AGENT_BASH_TOOL_PROCESS_TIMEOUT_MS': '10'},
        )
        self.assertIn('Running asynchronously', reply['result'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])

    def test_version31_separate_binary_streams_and_direct_run(self):
        for command in ('printf probe', 'agent-bash run -- printf probe'):
            with self.subTest(command=command):
                reply, calls = self.execute_wire(self.version31(), command)
                result = reply['result']
                self.assertIn('stdout: 7 bytes', result)
                self.assertIn('representation=hex\n--- stdout ---\n666972737400ff', result)
                self.assertIn('stderr: 8 bytes', result)
                self.assertIn('representation=hex\n--- stderr ---\n7365636f6e6400fe', result)
                self.assertIn('exited with code 0', result)
                self.assertIn('consumer ACK: unconfirmed; remote ACK: unconfirmed', result)
                self.assertEqual([c['args'][0] for c in calls], ['run'])

    def test_version31_large_complete_output(self):
        data = b'A' * 200011
        reply, calls = self.execute_wire(self.version31(stdout=data, stderr=b''))
        result = reply['result']
        self.assertIn('stdout: 200011 bytes', result)
        self.assertIn('representation=utf8\n--- stdout ---\n' + data.decode() + '\nstderr:', result)
        self.assertIn('stderr: 0 bytes', result)
        self.assertEqual(len(calls), 1)

    def test_version31_valid_utf8_with_nul_is_visible_as_hex(self):
        reply, calls = self.execute_wire(self.version31(stdout=b'A\x00B', stderr=b'plain text'))
        self.assertIn('representation=hex\n--- stdout ---\n410042', reply['result'])
        self.assertIn('representation=utf8\n--- stderr ---\nplain text', reply['result'])
        self.assertEqual(len(calls), 1)

    def test_version31_source_outcomes(self):
        for outcome, code, expected in (
            ('exited', 27, 'exited with code 27'),
            ('signaled', 0, 'signaled with signal 15'),
            ('cancelled', 0, 'cancelled (source wait status 9)'),
        ):
            with self.subTest(outcome=outcome):
                reply, calls = self.execute_wire(self.version31(outcome=outcome, code=code))
                self.assertIn(expected, reply['result'])
                self.assertEqual(len(calls), 1)

    def test_version31_unknown_never_becomes_a_result(self):
        wire = self.version31()
        wire['dispatch_state'] = 'sync-publication-unknown'
        for key in ('stdout_encoding', 'stdout_base64', 'stderr_encoding', 'stderr_base64'):
            del wire[key]
        reply, calls = self.execute_wire(wire)
        self.assertIn('publication unresolved', reply['result'])
        self.assertIn('Do not replay', reply['result'])
        self.assertNotIn('--- stdout ---', reply['result'])
        self.assertEqual(len(calls), 1)

    def test_version31_bad_wire_fails_without_followup_or_retry(self):
        variants = {}
        missing = self.version31(); del missing['stderr_base64']; variants['missing stream'] = missing
        invalid = self.version31(); invalid['stdout_base64'] = 'AQ==junk'; variants['bad base64'] = invalid
        digest = self.version31(); digest['publication']['event']['stdout_sha256'] = '0' * 64; variants['bad digest'] = digest
        length = self.version31(); length['publication']['event']['stderr_len'] += 1; variants['bad length'] = length
        binding = self.version31(); binding['publication']['event']['source_id'] = 'other'; variants['bad binding'] = binding
        disposition = self.version31(); disposition['publication']['exit_code'] = 1; variants['bad disposition'] = disposition
        phase = self.version31(); phase['publication']['phase'] = 'delivered'; variants['bad phase'] = phase
        for label, wire in variants.items():
            with self.subTest(label=label):
                reply, calls = self.execute_wire(wire)
                self.assertIn('unresolved', reply['error'])
                self.assertEqual([c['args'][0] for c in calls], ['run'])
        partial, calls = self.execute_wire(b'{"schema_version":31,"dispatch_state":"sync-child-result"')
        self.assertIn('incomplete or malformed', partial['error'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])
        failed, calls = self.execute_wire(b'{"schema_version":31,', exit_code=70, stderr='write failed')
        self.assertIn('exited 70; child publication unresolved', failed['error'])
        self.assertIn('stdout:', failed['error'])
        self.assertIn('stderr: write failed', failed['error'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])
        invalid_bytes, calls = self.execute_wire(b'{"schema_version":31,\xff}')
        self.assertIn('stdout was not UTF-8; raw hex:', invalid_bytes['error'])
        self.assertIn('do not replay', invalid_bytes['error'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])

    def test_version30_async_broker_handle(self):
        wire = dict(schema_version=30, dispatch_state='broker-k-consumed', handle='ab30_child-one',
                    request_id='request-one', physical_grant_id='physical-grant',
                    delivery_mode='async', effects_possible=True)
        path = self.root / 'response.json'
        path.write_text(json.dumps(wire))
        reply, calls = self.execute(dict(command='printf probe', delivery='async'),
                                    extra_env={'FAKE_RESPONSE_FILE': str(path)})
        self.assertIn('Running asynchronously (handle=ab30_child-one)', reply['result'])
        self.assertEqual([c['args'][0] for c in calls], ['run'])

    def test_private_sync_selector_only_changes_opted_in_call(self):
        wire = self.root / 'response.json'
        wire.write_text(json.dumps(self.version31()))
        command = 'agent-bash run --completion-scope tree -- printf probe'
        for selected in (False, True):
            with self.subTest(selected=selected):
                reply, calls = self.execute(dict(command=command), extra_env={
                    'FAKE_RESPONSE_FILE': str(wire),
                    **({'AGENT_BASH_PRIVATE_V31_SYNC': '1'} if selected else {}),
                })
                self.assertIn('Sync child result', reply['result'])
                self.assertEqual('--cancel-on-owner-exit' in calls[0]['args'], not selected)
                self.assertEqual([c['args'][0] for c in calls], ['run'])

if __name__ == '__main__':
    unittest.main(verbosity=2)
