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
const args = command.startsWith("@async ") ? { command: command.slice(7), delivery: "async" } : { command }
try {
  console.log(JSON.stringify({ result: await adapter.execute(args, { sessionID: "in-root", abort: new AbortController().signal }) }))
} catch (error) { console.log(JSON.stringify({ error: String(error) })) }
'''
SYNC = "printf 'pid=%s\\n' $$; echo err >&2; exit 3"


@unittest.skipUnless(BUN and AGENT_BASH and (RUNNER / 'oulipoly-root-supervisor').exists(),
                     'requires BUN, AGENT_BASH_TEST_BIN and ROOT_V1_RUNNER_BIN_DIR')
class InRoot(unittest.TestCase):
    def test_sync_runs_as_root_work_and_async_and_child_dispatch_are_refused(self):
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
                                                   '--exit-after-acks', '3'],
                               'messages': [f'bash:{SYNC}', 'bash:@async true', 'bash:agents run --prompt x']}]}}
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
                if event.get('event') == 'terminal':
                    break
            self.assertEqual(owner.wait(timeout=60), 0)
            owner.stdin.close()
            owner.stdout.close()
            replies = [json.loads(e['text'].split('stdout=', 1)[1].split('\nstderr=', 1)[0])
                       for e in seen if e.get('event') == 'agent-message']
            evidence = os.environ.get('ROOT_V1_EVIDENCE')
            if evidence:
                Path(evidence).write_text(json.dumps({'events': seen, 'replies': replies}, indent=1))
            terminal = seen[-1]
            self.assertEqual(terminal['status'], 'ended', terminal)
            self.assertEqual(terminal['bash'], {'accepted': 1, 'refused': 0, 'not_run': 0,
                                                'ended': 1, 'end_unknown': 0, 'open': 0,
                                                'output_open': 0, 'output_requests': 0})
            accepted = [e for e in seen if e.get('event') == 'bash-accepted']
            self.assertEqual(len(accepted), 1)
            self.assertEqual(accepted[0]['harness'], 'a')
            self.assertEqual(accepted[0]['argv'], ['bash', '-lc', SYNC])
            ended = [e for e in seen if e.get('event') == 'bash-ended'][0]
            self.assertEqual((ended['bash'], ended['status'], ended['observer'], ended['requester']),
                             ('end', 'code:3', 'work-pid1-wait', 'connected'))
            self.assertEqual(len(replies), 3, replies)
            sync, asynchronous, child = (reply.get('result', reply) for reply in replies)
            # pid 2 of the work's own new PID namespace: run by the root, not locally.
            self.assertIn('Root v1 work ended: exited with code 3 (code:3, observer work-pid1-wait)', sync)
            self.assertIn('output complete', sync)
            self.assertTrue(sync.endswith('---\npid=2\nerr\n'), sync)
            self.assertIn('Root v1 refused by agent-bash (async-delivery-unavailable-under-root-v1)', asynchronous)
            self.assertIn('Root v1 refused child-agent dispatch', child)
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
