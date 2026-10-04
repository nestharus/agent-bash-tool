"""Adapter inside a root-v1 context, with the real agent-bash binary and a
configured owner socket standing in for the root's Bash ingress:

  AGENT_BASH_TEST_BIN=/abs/agent-bash BUN=/abs/bun python3 tests/test_opencode_root_v1.py

This shows the tool result built from agent-bash's root-v1 surface and that
async and child-agent requests are refused without contacting the owner. It
is not a witness of an actual root owner or root PID 1.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest

ADAPTER = Path(__file__).resolve().parents[1] / 'integrations/opencode/tools/bash.ts'
BUN = shutil.which(os.environ.get('BUN', 'bun'))
AGENT_BASH = os.environ.get('AGENT_BASH_TEST_BIN')
DRIVER = '''import { mock } from "bun:test"
const tool = Object.assign(d => d, { schema: { string: () => ({ describe: () => ({ optional: () => ({}) }) }) } })
mock.module("@opencode-ai/plugin", () => ({ tool }))
const adapter = (await import(process.argv[2])).default
try {
  const result = await adapter.execute(JSON.parse(process.argv[3]), {sessionID: "root-v1", abort: new AbortController().signal})
  console.log(JSON.stringify({result}))
} catch (error) { console.log(JSON.stringify({error: String(error)})) }
'''

ACCEPTED = {'event': 'accepted', 'work': 4, 'durable': True}
STARTED = {'event': 'started', 'work': 4, 'pid': 2}
OUTPUT = {'event': 'output', 'b64': 'aGkKZXJyCg=='}
CLOSED = {'event': 'output-closed', 'bytes': 7}
END = {'event': 'end', 'status': 'code:3', 'observer': 'work-pid1-wait',
       'output': {'state': 'closed', 'bytes': 7}}


class Owner:
    """Counts connections and answers each with the configured stage lines."""

    def __init__(self, path, reply):
        self.requests = []
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(path))
        self.server.listen()
        self.server.settimeout(0.1)
        self.reply = reply
        self.stopped = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        while not self.stopped:
            try:
                conn, _ = self.server.accept()
            except (socket.timeout, OSError):
                continue
            with conn:
                conn.settimeout(5)
                self.requests.append(json.loads(conn.makefile('r').readline()))
                conn.sendall(''.join(json.dumps(e) + '\n' for e in self.reply).encode())

    def stop(self):
        self.stopped = True
        self.thread.join()
        self.server.close()


@unittest.skipUnless(BUN and AGENT_BASH, 'requires BUN and AGENT_BASH_TEST_BIN')
class RootV1Adapter(unittest.TestCase):
    def call(self, reply, args):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            driver = temp / 'driver.ts'
            driver.write_text(DRIVER)
            owner = Owner(temp / 'bash.sock', reply)
            try:
                env = {'PATH': '/usr/bin:/bin', 'HOME': str(temp / 'home'),
                       'AGENT_BASH_BIN': AGENT_BASH, 'OULIPOLY_ROOT_BASH_V1': str(temp / 'bash.sock')}
                done = subprocess.run([BUN, '--no-install', str(driver), str(ADAPTER), json.dumps(args)],
                                      env=env, cwd=temp, capture_output=True, text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertFalse((temp / 'home').exists(), 'no legacy state')
                return json.loads(done.stdout.strip().splitlines()[-1]), owner.requests
            finally:
                owner.stop()

    def test_sync_command_returns_waited_status_and_output_from_root_stages(self):
        reply, requests = self.call([ACCEPTED, STARTED, OUTPUT, CLOSED, END], {'command': 'echo hi; exit 3'})
        result = reply['result']
        self.assertIn('Root v1 work ended: exited with code 3 (code:3, observer work-pid1-wait)', result)
        self.assertIn('output complete', result)
        self.assertIn('accepted(work=4, durable=true) -> started -> output -> output-closed(bytes=7) -> end(', result)
        self.assertTrue(result.endswith('---\nhi\nerr\n'), result)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]['argv'], ['bash', '-lc', 'echo hi; exit 3'])

    def test_output_fault_keeps_the_wait_but_says_delivery_is_unproven(self):
        bad = dict(CLOSED, bytes=6)
        result = self.call([ACCEPTED, STARTED, OUTPUT, bad, END], {'command': 'true'})[0]['result']
        self.assertIn('exited with code 3', result)
        self.assertIn('output delivery unproven', result)
        self.assertIn('output-byte-count-mismatch', result)

    def test_lost_reply_is_possible_effect_with_no_replay(self):
        reply, requests = self.call([ACCEPTED, STARTED], {'command': 'true'})
        self.assertIn('outcome unknown (accepted-end-unknown): the command may have run', reply['result'])
        self.assertIn('Do not replay', reply['result'])
        self.assertEqual(len(requests), 1)

    def test_owner_refusal_is_visible_and_nothing_else_is_tried(self):
        refused = {'event': 'refused', 'reason': 'peer-unattributed: outside-every-harness-namespace'}
        reply, requests = self.call([refused], {'command': 'true'})
        self.assertIn('Root v1 refused by root-owner (peer-unattributed', reply['result'])
        self.assertIn('Nothing was run; no other route was tried', reply['result'])
        self.assertEqual(len(requests), 1)

    def test_async_and_child_dispatch_are_refused_without_contacting_the_owner(self):
        reply, requests = self.call([ACCEPTED], {'command': 'true', 'delivery': 'async'})
        self.assertIn('Root v1 refused by agent-bash (async-delivery-unavailable-under-root-v1)', reply['result'])
        self.assertIn('not converted', reply['result'])
        reply, more = self.call([ACCEPTED], {'command': 'agents run --prompt x'})
        self.assertIn('Root v1 refused child-agent dispatch', reply['result'])
        self.assertEqual(requests + more, [])


if __name__ == '__main__':
    unittest.main()
