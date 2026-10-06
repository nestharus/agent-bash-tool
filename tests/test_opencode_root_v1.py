"""Adapter inside a root-v1 context, with the real agent-bash binary and a
configured owner socket standing in for the root's Bash ingress:

  AGENT_BASH_TEST_BIN=/abs/agent-bash BUN=/abs/bun python3 tests/test_opencode_root_v1.py

This shows the tool result built from agent-bash's root-v1 surface and that
async and child-agent requests are refused without contacting the owner. It
is not a witness of an actual root owner or root PID 1.
"""
import base64
import json
import os
from pathlib import Path
import re
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
  const args = JSON.parse(process.argv[3])
  const replies = []
  for (const item of Array.isArray(args) ? args : [args]) {
    replies.push(await adapter.execute(item, {sessionID: "root-v1", abort: new AbortController().signal}))
  }
  console.log(JSON.stringify(Array.isArray(args) ? {results: replies} : {result: replies[0]}))
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
                events = self.reply(self.requests[-1]) if callable(self.reply) else self.reply
                for event in events:
                    conn.sendall((json.dumps(event) + '\n').encode())

    def stop(self):
        self.stopped = True
        self.thread.join()
        self.server.close()


@unittest.skipUnless(BUN and AGENT_BASH, 'requires BUN and AGENT_BASH_TEST_BIN')
class RootV1Adapter(unittest.TestCase):
    def call(self, reply, args, forbid_binary=False):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            driver = temp / 'driver.ts'
            driver.write_text(DRIVER)
            trap = temp / 'legacy-trap'
            trap.write_text('#!/bin/sh\nprintf contacted > "$CONTACT_MARKER"\nexit 99\n')
            trap.chmod(0o700)
            if forbid_binary and 'command' in args:
                args = dict(args, command=args['command'].replace(AGENT_BASH, str(trap)))
            binding = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            binding.bind(str(temp / 'binding.sock'))
            binding.listen()
            binding.setblocking(False)
            owner = Owner(temp / 'bash.sock', reply)
            try:
                env = {'PATH': '/usr/bin:/bin', 'HOME': str(temp / 'home'),
                       'AGENT_BASH_BIN': str(trap) if forbid_binary else AGENT_BASH,
                       'CONTACT_MARKER': str(temp / 'contacted'),
                       'XDG_STATE_HOME': str(temp / 'state'),
                       'TMPDIR': str(temp), 'BUN_INSTALL_CACHE_DIR': str(temp / 'bun-cache'),
                       'OULIPOLY_ROOT_BASH_V1': str(temp / 'bash.sock'),
                       'OULIPOLY_LIVE_SESSION_BIND_SOCKET': str(temp / 'binding.sock'),
                       'OULIPOLY_LIVE_SESSION_BIND_TOKEN': 'public-fixture-token',
                       'OULIPOLY_PARENT_INVOCATION': '{"id":"fixture-invocation"}'}
                done = subprocess.run([BUN, '--no-install', str(driver), str(ADAPTER), json.dumps(args)],
                                      env=env, cwd=temp, capture_output=True, text=True, timeout=60)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertFalse((temp / 'state').exists(), 'no legacy state')
                # Bun's transpiler cache can create HOME/.bun even with --no-install.
                if (temp / 'home').exists():
                    self.assertEqual([p.name for p in (temp / 'home').iterdir()], ['.bun'])
                self.assertFalse((temp / 'contacted').exists(), 'no legacy binary contact')
                with self.assertRaises(BlockingIOError, msg='no binding handshake'):
                    connection, _ = binding.accept()
                    connection.close()
                result = json.loads(done.stdout.strip().splitlines()[-1])
                requests = list(owner.requests)
            finally:
                owner.stop()
                binding.close()
        evidence = os.environ.get('ROOT_V1_ADAPTER_EVIDENCE')
        if evidence:
            with open(evidence, 'a') as stream:
                stream.write(json.dumps({'args': args, 'result': result, 'requests': requests,
                                         'binary_trapped': forbid_binary, 'binding_contacts': 0,
                                         'fixture': str(temp), 'fixture_removed': not temp.exists()}) + '\n')
        self.assertFalse(temp.exists(), 'owned fixture removed')
        return result, requests

    def assert_output_view(self, result, payload, carried, mode):
        # Goal C / U40 J1-B: distinguish producer facts from the literal inline
        # prefix. The retained OpenCode 1.18.30 boundary is 50 KiB / 2000 lines;
        # neither the adapter's payload budget nor its chosen cut is an oracle.
        self.assertLessEqual(len(result.encode()), 50 * 1024)
        self.assertLessEqual(len(result.split('\n')), 2000)
        self.assertNotIn('Full output saved', result)
        self.assertNotIn('tool call succeeded', result)
        header, body = result.split('---\n', 1)
        actual = body.encode() if mode == 'utf8' else bytes.fromhex(body)
        self.assertEqual(body, actual.decode() if mode == 'utf8' else actual.hex())
        self.assertEqual(actual, payload[:len(actual)], 'literal stream prefix')
        self.assertLessEqual(len(actual), carried)
        if carried:
            self.assertGreater(len(actual), 0, 'payload remains inline')
        marker = re.search(r'--- output \(stderr joined; (\d+) bytes(?: shown inline)?, '
                           + mode + r'\) $', header)
        self.assertIsNotNone(marker)
        self.assertEqual(int(marker[1]), len(actual), 'shown matches actual stream bytes')
        if len(payload) > len(actual):
            producer = re.search(r'Producer output: (\d+) received stream bytes; '
                                 r'(\d+) stream bytes carried; (\d+) bytes omitted '
                                 r'and discarded \(not retained\)', header)
            presentation = re.search(r'OpenCode presentation: first (\d+) of (\d+) '
                                     r'producer-carried stream bytes shown inline; (\d+) '
                                     r'additional stream bytes omitted here \(not retained '
                                     r'for recovery\); (\d+) rendered UTF-8 bytes', header)
            self.assertIsNotNone(producer, 'producer layer and stream-byte units')
            self.assertIsNotNone(presentation, 'presentation layer and distinct rendered units')
            self.assertEqual(tuple(map(int, producer.groups())),
                             (len(payload), carried, len(payload) - carried))
            self.assertEqual(tuple(map(int, presentation.groups())),
                             (len(actual), carried, carried - len(actual), len(body.encode())))
            self.assertIn('output partial', header)
            self.assertNotIn('output complete', header)
        else:
            self.assertEqual(actual, payload, 'complete output includes the entire payload')
            self.assertIn('output complete', header)
            self.assertNotIn('omitted', header)

    def test_sync_command_returns_waited_status_and_output_from_root_stages(self):
        reply, requests = self.call([ACCEPTED, STARTED, OUTPUT, CLOSED, END], {'command': 'echo hi; exit 3'})
        result = reply['result']
        self.assertIn('Root v1 work ended: exited with code 3 (code:3, observer work-pid1-wait)', result)
        self.assertIn('output complete', result)
        self.assertIn('accepted(work=4, durable=true) -> started -> output(chunks=1, bytes=7) -> output-closed(bytes=7) -> end(', result)
        self.assertTrue(result.endswith('---\nhi\nerr\n'), result)
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]['argv'], ['bash', '-lc', 'echo hi; exit 3'])

    def test_large_command_is_partial_counted_closed_waited_and_next_call_works(self):
        # Local stand-in relays an actual synthetic command in 16 KiB chunks;
        # it supplies custody stages, not a real root/PID-1 witness.
        command = "python3 -c 'import sys; sys.stdout.buffer.write(b\"x\" * 33554432)' ; exit 2"

        def relay(request):
            yield ACCEPTED
            yield STARTED
            process = subprocess.Popen(request['argv'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            total = 0
            while chunk := process.stdout.read(16384):
                total += len(chunk)
                yield {'event': 'output', 'b64': base64.b64encode(chunk).decode()}
            process.stdout.close()
            status = process.wait()
            yield dict(CLOSED, bytes=total)
            yield dict(END, status=f'code:{status}', output={'state': 'closed', 'bytes': total})

        reply, requests = self.call(relay, [{'command': command}, {'command': "printf next"}])
        large, next_result = reply['results']
        self.assertIn('exited with code 2', large)
        self.assertIn('output partial; full stream counted, closed, matched by the end', large)
        self.assert_output_view(large, b'x' * 33554432, 65536, 'utf8')
        self.assertIn('33488896 bytes omitted and discarded (not retained)', large)
        self.assertIn('output-closed(bytes=33554432)', large)
        self.assertNotIn('output complete', large)
        self.assertIn('output(chunks=2048, bytes=33554432)', large)
        self.assertIn('output complete', next_result)
        self.assertTrue(next_result.endswith('---\nnext'))
        self.assertEqual(len(requests), 2)

    def test_utf8_boundary_binary_and_zero_output(self):
        for payload, carried, mode in [
            ('€'.encode() * 22000, 65535, 'utf8'),
            (b'\x00\xff' * 33000, 65536, 'hex'),
            (b'', 0, 'utf8'),
        ]:
            with self.subTest(mode=mode, bytes=len(payload)):
                total = len(payload)
                events = [ACCEPTED, STARTED,
                          {'event': 'output', 'b64': base64.b64encode(payload).decode()},
                          dict(CLOSED, bytes=total),
                          dict(END, status='code:0', output={'state': 'closed', 'bytes': total})]
                result = self.call(events, {'command': 'true'})[0]['result']
                self.assert_output_view(result, payload, carried, mode)
                self.assertIn(f', {mode})', result)
                self.assertIn('exited with code 0 (code:0, observer work-pid1-wait)', result)
                self.assertIn(f'output-closed(bytes={total})', result)

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

    def test_direct_async_spellings_and_tool_async_never_execute_as_sync(self):
        for command, delivery in [
            ('agent-bash run --delivery async -- true', None),
            ('agent-bash run --delivery=async -- true', 'sync'),
            (f"'{AGENT_BASH}' run --delivery 'async' -- true", 'sync'),
            ('agent-bash run --delivery sync -- true', 'async'),
            ('agent-bash run -- true', 'async'),
        ]:
            with self.subTest(command=command, delivery=delivery):
                args = {'command': command}
                if delivery:
                    args['delivery'] = delivery
                reply, requests = self.call([ACCEPTED, STARTED, OUTPUT, CLOSED, END], args)
                self.assertIn('async-delivery-unavailable-under-root-v1', reply['result'])
                self.assertIn('not converted', reply['result'])
                self.assertEqual(requests, [])

    def test_explicit_sync_still_reaches_owner_with_workload_mode_words_untouched(self):
        reply, requests = self.call([ACCEPTED, STARTED, OUTPUT, CLOSED, END],
                                   {'command': 'agent-bash run --delivery=sync -- echo --delivery async'})
        self.assertIn('exited with code 3', reply['result'])
        self.assertEqual([r['argv'] for r in requests], [['echo', '--delivery', 'async']])

    def test_root_sleep_reports_owner_outcome_instead_of_local_done(self):
        reply, requests = self.call([ACCEPTED, STARTED, OUTPUT, CLOSED, END], {'command': 'sleep 0'})
        self.assertIn('Root v1 work ended: exited with code 3', reply['result'])
        self.assertNotIn('DONE rc=0', reply['result'])
        self.assertEqual([r['argv'] for r in requests], [['bash', '-lc', 'sleep 0']])
        refused, requests = self.call([{'event': 'refused', 'reason': 'sleep-fixture-refusal'}],
                                     {'command': 'sleep 0'})
        self.assertIn('sleep-fixture-refusal', refused['result'])
        self.assertNotIn('DONE', refused['result'])
        self.assertEqual(len(requests), 1)

    def test_root_handles_and_controls_refuse_without_binary_binding_or_owner_contact(self):
        cases = [{'handle': 'retained-fixture'}, {'handle': 'retained-fixture', 'command': 'true'}]
        cases += [{'command': command} for command in [
            'agent-bash list --all --json', 'agent-bash cancel retained-fixture',
            'agent-bash status retained-fixture', 'agent-bash snapshot retained-fixture',
            'agent-bash mode retained-fixture', 'agent-bash detach retained-fixture',
            'agent-bash accept-output retained-fixture --snapshot fixture',
            f"'{AGENT_BASH}' list", 'agent-bash completion-reconcile-v2 --json',
        ]]
        for args in cases:
            with self.subTest(args=args):
                reply, requests = self.call([ACCEPTED], args, forbid_binary=True)
                self.assertIn('Root v1 refused legacy handle/control request', reply['result'])
                self.assertIn('No legacy state was accessed', reply['result'])
                self.assertEqual(requests, [])


if __name__ == '__main__':
    unittest.main()
