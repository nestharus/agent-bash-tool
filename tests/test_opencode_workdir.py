"""Offline adapter boundary tests: BUN=/absolute/bun python3 tests/test_opencode_workdir.py.

Real Bun subprocesses execute only a synthetic spooler, never the installed stack.
The plugin shim follows tests/spooler_cli.rs; no package installation is needed.
"""
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
try {
  const result = await adapter.execute(args, {sessionID: "private-owner", abort: new AbortController().signal})
  console.log(JSON.stringify({result, fields: Object.keys(adapter.args)}))
} catch (error) { console.log(JSON.stringify({error: String(error)})) }
'''
FAKE = '''#!/usr/bin/python3
import hashlib, json, os, sys
args = sys.argv[1:]
with open(os.environ['FAKE_LOG'], 'a') as f:
    f.write(json.dumps({'args': args, 'cwd': os.getcwd(), 'owner': os.environ.get('AGENT_BASH_OWNER_SESSION_ID'), 'custom': os.environ.get('TEST_CUSTOM')}) + '\\n')
mode = os.environ.get('FAKE_MODE', '')
if args[0] == 'run': print(json.dumps({'handle': 'ab_fixture', 'dispatch_state': 'running'}))
elif args[0] == 'status':
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

    def execute(self, args, mode=''):
        self.log.write_text('')
        result = subprocess.run([BUN, '--no-install', str(self.driver), str(ADAPTER), json.dumps(args)],
                                cwd=self.root / 'launch', env={**self.env, 'FAKE_MODE': mode},
                                text=True, capture_output=True, check=True)
        calls = [json.loads(line) for line in self.log.read_text().splitlines()]
        reply = json.loads(result.stdout)
        print(json.dumps(dict(request=args, mode=mode, reply=reply, calls=calls, stderr=result.stderr)), flush=True)
        return reply, calls

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


if __name__ == '__main__':
    unittest.main(verbosity=2)
