"""In-root witness: an actual root owner, root PID 1 and owned harness from an
agent-runner build, with the real OpenCode adapter and agent-bash running
inside that harness's namespace as its Bash requester.

  ROOT_V1_RUNNER_BIN_DIR=/abs/target/debug AGENT_BASH_TEST_BIN=/abs/agent-bash \\
  BUN=/abs/bun python3 tests/test_root_v1_in_root.py

The runner's deterministic ACP peer is the harness. It hands each `bash:`
prompt to the `oulipoly-root-bash` beside it; here that name is a small
wrapper that calls the adapter instead (the runner's own prototype requester
is not used). No model, provider or credential is involved. Optional
ROOT_V1_EVIDENCE names a file for the owner events and tool results.
"""
import ctypes
import json
import os
from pathlib import Path
import shutil
import signal
import stat
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ADAPTER = ROOT / 'integrations/opencode/tools/bash.ts'
BUN = shutil.which(os.environ.get('BUN', 'bun'))
AGENT_BASH = os.environ.get('AGENT_BASH_TEST_BIN')
RUNNER = Path(os.environ.get('ROOT_V1_RUNNER_BIN_DIR', '/nonexistent'))
DRIVER = '''import { mock } from "bun:test"
const tool = Object.assign(d => d, { schema: Object.fromEntries(["string", "number", "boolean"].map(k => [k, () => ({ describe: () => ({ optional: () => ({}) }) })])) })
mock.module("@opencode-ai/plugin", () => ({ tool }))
const adapter = (await import(process.argv[2])).default
let command = process.argv[3]
const context = { sessionID: "in-root", abort: new AbortController().signal }
try {
  if (command.startsWith("@completion ")) {
    // An owner completion's facts line: read every retained byte it names
    // through the adapter's output_identity, then accept that identity.
    const facts = JSON.parse(command.slice(12))
    const identity = facts.retained.identity
    let offset = 0, pages = 0, text = ""
    while (true) {
      const page = await adapter.execute({ output_identity: identity, output_offset: offset, output_length: 16384 }, context)
      const body = page.split(" bytes) ---\\n")[1]
      text += body
      offset = Number(page.match(/next_offset=(\\d+)/)[1])
      pages++
      if (page.includes("eof=true") || pages > 64) break
    }
    const accepted = await adapter.execute({ output_identity: identity, accept_output: true }, context)
    console.log(JSON.stringify({ result: { facts, text, pages, accepted } }))
  } else {
    const args = command.startsWith("@async ") ? { command: command.slice(7), delivery: "async" } : { command }
    console.log(JSON.stringify({ result: await adapter.execute(args, context) }))
  }
} catch (error) { console.log(JSON.stringify({ error: String(error) })) }
'''
SYNC = "printf 'pid=%s\\n' $$; echo err >&2; exit 3"
ASYNC = "sleep 1; printf 'background-%s\\n' done; exit 5"


@unittest.skipUnless(BUN and AGENT_BASH and (RUNNER / 'oulipoly-root-supervisor').exists(),
                     'requires BUN, AGENT_BASH_TEST_BIN and ROOT_V1_RUNNER_BIN_DIR')
class InRoot(unittest.TestCase):
    def test_sync_runs_as_root_work_async_completes_as_a_later_input_and_child_dispatch_is_refused(self):
        self.encounter()

    def test_rejected_completion_unblocks_another_without_replay_and_normal_close(self):
        self.encounter(reject=True)

    def encounter(self, reject=False):
        # Orphaned root PID 1 processes come back to this test to be reaped.
        assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0  # PR_SET_CHILD_SUBREAPER
        scratch = Path(tempfile.mkdtemp(prefix='rv1-'))
        roots = []
        try:
            bin_dir = scratch / 'bin'
            bin_dir.mkdir()
            peer = bin_dir / 'oulipoly-acp-deterministic-peer'
            shutil.copy(RUNNER / 'oulipoly-acp-deterministic-peer', peer)
            (scratch / 'driver.ts').write_text(DRIVER)
            for name in ('state', 'bun-home'):
                (scratch / name).mkdir()
            wrapper = bin_dir / 'oulipoly-root-bash'
            # The peer calls: oulipoly-root-bash -- /bin/sh -c COMMAND
            wrapper.write_text(
                '#!/bin/sh\n'
                f'export HOME={scratch}/bun-home XDG_STATE_HOME={scratch}/state '
                f'BUN_INSTALL_CACHE_DIR={scratch}/bun-home/cache AGENT_BASH_BIN={AGENT_BASH}\n'
                f'exec {BUN} --no-install {scratch}/driver.ts {ADAPTER} "$4"\n')
            wrapper.chmod(stat.S_IRWXU)
            spec = {'store': str(scratch / 'root'), 'intent': {
                'outage_closure_cap': 3, 'delivery_attempt_cap': 10, 'cwd': '/',
                'workload': {'isolation': 'unprivileged-userns'},
                'harnesses': [{'id': 'a', 'argv': [str(peer), '--state', str(scratch / 'a.json'),
                                                   *(['--reject-completion-once', '--no-dedup'] if reject else ['--exit-after-acks', '4'])],
                               'messages': [f'bash:@async {ASYNC}' if reject else f'bash:{SYNC}',
                                            f'bash:@async {ASYNC}', 'bash:agents run --prompt x']}]}}
            owner = subprocess.Popen([RUNNER / 'oulipoly-root-supervisor'], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, text=True)
            owner.stdin.write(json.dumps(spec) + '\n')
            owner.stdin.flush()
            seen = []
            for line in owner.stdout:
                event = json.loads(line)
                seen.append(event)
                if event.get('event') == 'root-pid1-started':
                    roots.append((event['pid'], os.pidfd_open(event['pid'])))
                if reject and event.get('event') == 'turn-end' and event.get('input') == 2:
                    owner.stdin.write('{"cmd":"close"}\n')
                    owner.stdin.flush()
                if event.get('event') == 'terminal':
                    break
            owner_code = owner.wait(timeout=60)
            owner.stdin.close()
            owner.stdout.close()
            replies = [json.loads(e['text'].split('stdout=', 1)[1].split('\nstderr=', 1)[0])
                       for e in seen if e.get('event') == 'agent-message']
            evidence = os.environ.get('ROOT_V1_EVIDENCE')
            if evidence:
                if reject:
                    evidence += '.rejected.json'
                Path(evidence).write_text(json.dumps({'events': seen, 'replies': replies, 'owner_exit': owner_code}, indent=1))
            self.assertEqual(owner_code, 3 if reject else 0)
            terminal = seen[-1]
            if reject:
                # Rejected durable input remains known owed in the existing
                # insertion account; async delivery debt is conclusively lost.
                self.assertEqual(terminal['status'], 'ended-owed', terminal)
                self.assertTrue(terminal['close_requested'])
                self.assertEqual((terminal['async']['accepted'], terminal['async']['turn_ended'],
                                  terminal['async']['owed']), (2, 1, 0))
                lost, = terminal['async']['undelivered']
                self.assertEqual(lost['reason'], 'not-acknowledged: rejected')
                admitted = [e for e in seen if e.get('event') == 'bash-async-completion-admitted']
                self.assertEqual(len(admitted), 2, 'each completion is admitted once')
                refused, delivered = admitted
                self.assertEqual(refused['work'], lost['work'])
                at = lambda pred: next(i for i, e in enumerate(seen) if pred(e))
                rejected = at(lambda e: e.get('event') == 'rejected' and e.get('index') == refused['input'])
                self.assertEqual(seen[rejected]['code'], -32001)
                settled = at(lambda e: e.get('event') == 'async-owed' and e.get('change') == 'undelivered')
                ack = at(lambda e: e.get('event') == 'ack' and e.get('index') == delivered['input'])
                done = at(lambda e: e.get('event') == 'turn-end' and e.get('input') == delivered['input'])
                closing = at(lambda e: e.get('event') == 'close-stopping')
                self.assertTrue(rejected < settled < seen.index(delivered) < ack < done < closing)
                self.assertFalse(any(e.get('event') == 'ack' and e.get('index') == refused['input'] for e in seen))
                peer_state = json.loads((scratch / 'a.json').read_text())
                self.assertEqual((len(peer_state['launches']), len(peer_state['prompts']),
                                  len(peer_state['insertions'])), (1, 5, 4), 'no relaunch or replay')
                completion = replies[-1]['result']
                self.assertEqual(completion['facts']['work'], delivered['work'])
                self.assertEqual(completion['text'], 'background-done\n')
                self.assertIn('durable=true; repeat=false', completion['accepted'])
                self.assertEqual(terminal['bash']['ended'], 2)
                self.assertEqual(terminal['bash']['open'], 0)
                self.assertEqual(list((scratch / 'state').iterdir()), [], 'no legacy state')
                return
            self.assertEqual(terminal['status'], 'ended', terminal)
            self.assertEqual(terminal['bash'], {'accepted': 2, 'refused': 0, 'not_run': 0,
                                                'ended': 2, 'end_unknown': 0, 'open': 0,
                                                'output_open': 0, 'output_requests': 2})
            self.assertEqual((terminal['async']['accepted'], terminal['async']['turn_ended'],
                              terminal['async']['undelivered'], terminal['async']['owed']), (1, 1, [], 0))
            accepted = [e for e in seen if e.get('event') == 'bash-accepted']
            self.assertEqual([(e['harness'], e['argv'], e.get('delivery')) for e in accepted],
                             [('a', ['bash', '-lc', SYNC], None), ('a', ['bash', '-lc', ASYNC], 'async')])
            ended = {e['work']: e for e in seen if e.get('event') == 'bash-ended'}
            sync_end, async_end = ended[accepted[0]['work']], ended[accepted[1]['work']]
            self.assertEqual((sync_end['bash'], sync_end['status'], sync_end['observer'], sync_end['requester']),
                             ('end', 'code:3', 'work-pid1-wait', 'connected'))
            self.assertEqual((async_end['status'], async_end['observer'], async_end['requester']),
                             ('code:5', 'work-pid1-wait', 'detached-async'))
            index = {id(e): i for i, e in enumerate(seen)}
            at = lambda pred: next(i for i, e in enumerate(seen) if pred(e))
            async_turn = at(lambda e: e.get('event') == 'turn-end' and e.get('input') == 1)
            self.assertLess(async_turn, index[id(async_end)], 'the async tool turn ended before its command did')
            admitted = at(lambda e: e.get('event') == 'bash-async-completion-admitted')
            self.assertEqual(seen[admitted]['input'], 3)
            ack = at(lambda e: e.get('event') == 'ack' and e.get('index') == 3)
            done = at(lambda e: e.get('event') == 'turn-end' and e.get('input') == 3)
            settled = at(lambda e: e.get('event') == 'async-owed' and e.get('change') == 'turn-ended')
            self.assertTrue(index[id(async_end)] < admitted < ack < done < settled)
            self.assertEqual(len(replies), 4, replies)
            sync, asynchronous, child, completion = (reply.get('result', reply) for reply in replies)
            # pid 2 of the work's own new PID namespace: run by the root, not locally.
            self.assertIn('Root v1 work ended: exited with code 3 (code:3, observer work-pid1-wait)', sync)
            self.assertIn('output complete', sync)
            self.assertTrue(sync.endswith('---\npid=2\nerr\n'), sync)
            self.assertIn('background work accepted and started (reference=rv1w:', asynchronous)
            self.assertIn('Root v1 refused child-agent dispatch', child)
            self.assertEqual(completion['facts']['work'], async_end['work'])
            self.assertEqual(completion['facts']['end']['status'], 'code:5')
            self.assertEqual(completion['facts']['retained']['identity'], async_end['retained']['identity'])
            self.assertEqual(completion['text'], 'background-done\n')
            self.assertIn(f"exact local acceptance: {async_end['retained']['identity']}; durable=true; repeat=false",
                          completion['accepted'])
            self.assertEqual(list((scratch / 'state').iterdir()), [], 'no legacy agent-bash state')
        finally:
            for pid, fd in roots:
                try:
                    signal.pidfd_send_signal(fd, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
                os.close(fd)
            shutil.rmtree(scratch)


if __name__ == '__main__':
    unittest.main()
