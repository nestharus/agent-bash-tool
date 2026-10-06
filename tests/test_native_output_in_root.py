"""Actual owner and root/work namespaces, real CLI, real OpenCode Bash tool
and native permission wrapper. Bun mocks only plugin tool registration and
context.ask; no provider/model/config installation. The independent oracle
is the literal binary output of the named command, not internal source.

Run under private /proc:
  timeout 120s env ROOT_V1_RUNNER_BIN_DIR=... AGENT_BASH_TEST_BIN=... \
    NATIVE_BASH_POLICY=... BUN=... unshare --user --map-current-user --net \
    --mount --pid --fork --mount-proc python3 tests/test_native_output_in_root.py
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
BUN = os.environ.get('BUN')
BASH = os.environ.get('AGENT_BASH_TEST_BIN')
RUNNER = Path(os.environ.get('ROOT_V1_RUNNER_BIN_DIR', '/nonexistent'))
POLICY = os.environ.get('NATIVE_BASH_POLICY')
COMMAND = "python3 -c 'import sys; sys.stdout.buffer.write(bytes((i * 37) % 256 for i in range(100000)))'; exit 7"
DRIVER = r'''import { mock } from "bun:test"
import { createHash } from "node:crypto"
const schema = Object.fromEntries(["string", "number", "boolean"].map(k => [k, () => ({ describe: () => ({ optional: () => ({}) }) })]))
mock.module("@opencode-ai/plugin", () => ({ tool: Object.assign(d => d, { schema }) }))
const adapter = (await import(process.argv[2])).default
const permission = []
let deny = false
const context = { sessionID: "retained-root", abort: new AbortController().signal, ask: async args => {
  permission.push(args)
  if (deny) throw new Error("fixture native permission denied")
} }
const calls = []
const call = async args => {
  const result = await adapter.execute(args, context)
  calls.push({ args, result })
  return result
}
try {
  const command = process.argv[3]
  const run = await call({ command })
  if (!run.includes("code:7, observer work-pid1-wait") || !run.includes("Owner retention: complete, 100000 bytes")) throw new Error(run)
  const identity = run.match(/identity=(rv1o:[^\s]+)/)?.[1]
  if (!identity) throw new Error("no identity")
  const chunks = []
  let offset = 0
  for (let page = 0; page < 100; page++) {
    const reference = "rv1w:" + identity.split(":").slice(1, 3).join(":")
    const result = await call({ output_identity: offset === 0 ? reference : identity, output_offset: offset, output_length: 16384 })
    if (Buffer.byteLength(result) > 51200 || result.split("\n").length > 2000) throw new Error("consumer cut")
    if (!result.includes(`identity=${identity}`) || !result.includes(`offset=${offset};`)) throw new Error("wrong returned identity/range")
    const mode = result.match(/--- retained bytes \((utf8|hex);/)[1]
    const chunk = Buffer.from(result.split(" ---\n")[1], mode === "utf8" ? "utf8" : "hex")
    const next = Number(result.match(/next_offset=(\d+)/)[1])
    if (next !== offset + chunk.length) throw new Error("nonprogressing read")
    chunks.push(chunk)
    offset = next
    if (result.includes("eof=true")) break
    if (page === 99) throw new Error("finite page limit")
  }
  const acquired = Buffer.concat(chunks)
  const expected = Buffer.from(Array.from({length: 100000}, (_, i) => i * 37 % 256))
  if (!acquired.equals(expected)) throw new Error("literal bytes differ")
  const hash = createHash("sha256").update(acquired).digest("hex")
  if (!identity.endsWith(`:100000:${hash}`)) throw new Error("full acquired identity mismatch")
  const wrong = identity.replace(/:[0-9a-f]{64}$/, ":" + "0".repeat(64))
  const refused = await call({ output_identity: wrong, accept_output: true })
  if (!refused.includes("identity-mismatch")) throw new Error("wrong identity admitted")
  // Gate refusal: it must prevent an otherwise valid acceptance request.
  deny = true
  try { await call({ output_identity: identity, accept_output: true }); throw new Error("permission unexpectedly allowed") }
  catch (error) { if (!String(error).includes("native permission denied")) throw error }
  deny = false
  const accepted = await call({ output_identity: identity, accept_output: true })
  const repeat = await call({ output_identity: identity, accept_output: true })
  if (!accepted.includes("repeat=false") || !repeat.includes("repeat=true")) throw new Error("local acceptance repeat failed")
  const receipt = text => JSON.parse(text.split("receipt=")[1].split(". Not an input ACK")[0])
  if (JSON.stringify(receipt(accepted)) !== JSON.stringify(receipt(repeat))) throw new Error("repeat receipt changed")
  const conflict = await call({ output_identity: identity, command: "touch should-not-run" })
  if (!conflict.includes("Nothing sent")) throw new Error("ambiguous request sent")
  console.log(JSON.stringify({ identity, bytes: acquired.length, sha256: hash, acquired_hex: acquired.toString("hex"), permission, calls, receipt: receipt(accepted) }))
} catch (error) { console.error(error); process.exitCode = 1 }
'''


@unittest.skipUnless(BUN and BASH and POLICY and (RUNNER / 'oulipoly-root-supervisor').exists(), 'requires explicit paired fixture build')
class NativeOutputInRoot(unittest.TestCase):
    def test_full_binary_output_exact_acceptance_and_permission_gate(self):
        assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
        roots = []
        with tempfile.TemporaryDirectory(prefix='native-output-') as name:
            scratch = Path(name)
            bin_dir = scratch / 'bin'
            bin_dir.mkdir()
            peer = bin_dir / 'oulipoly-acp-deterministic-peer'
            shutil.copy(RUNNER / 'oulipoly-acp-deterministic-peer', peer)
            config = scratch / 'config'
            (config / 'tool').mkdir(parents=True)
            (config / 'agent-bash').mkdir()
            shutil.copy(POLICY, config / 'tool/bash.ts')
            shutil.copy(ROOT / 'integrations/opencode/tools/bash.ts', config / 'agent-bash/bash.ts')
            (scratch / 'driver.ts').write_text(DRIVER)
            wrapper = bin_dir / 'oulipoly-root-bash'
            wrapper.write_text('#!/bin/sh\n' +
                f'export HOME={scratch}/bun-home XDG_STATE_HOME={scratch}/state BUN_INSTALL_CACHE_DIR={scratch}/cache AGENT_BASH_BIN={BASH}\n' +
                f'exec {BUN} --no-install {scratch}/driver.ts {config}/tool/bash.ts "$4"\n')
            wrapper.chmod(0o700)
            spec = {'store': str(scratch / 'store'), 'intent': {'outage_closure_cap': 1, 'delivery_attempt_cap': 1,
                'cwd': str(scratch), 'workload': {'isolation': 'unprivileged-userns'}, 'harnesses': [{'id': 'native', 'argv': [str(peer), '--state', str(scratch / 'peer.json'), '--exit-after-acks', '1'],
                                                  'messages': [f'bash:{COMMAND}']}]}}
            owner = subprocess.Popen([RUNNER / 'oulipoly-root-supervisor'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            owner.stdin.write(json.dumps(spec) + '\n')
            owner.stdin.flush()
            seen = []
            try:
                for line in owner.stdout:
                    value = json.loads(line)
                    seen.append(value)
                    if value.get('event') == 'root-pid1-started':
                        roots.append((value['pid'], os.pidfd_open(value['pid'])))
                    if value.get('event') == 'terminal':
                        break
                self.assertEqual(owner.wait(timeout=15), 0, seen)
                terminal = seen[-1]
                self.assertEqual(terminal['status'], 'ended')
                self.assertEqual(terminal['bash']['accepted'], 1)
                self.assertEqual(terminal['bash']['ended'], 1)
                self.assertEqual(terminal['bash']['open'], 0)
                self.assertEqual(terminal['bash']['output_open'], 0)
                self.assertEqual(terminal['bash']['output_requests'], 10) # 7 ranges, wrong identity, first and repeat
                message = next(e['text'] for e in seen if e.get('event') == 'agent-message')
                reply = json.loads(message.split('stdout=', 1)[1].split('\nstderr=', 1)[0])
                expected = bytes(i * 37 % 256 for i in range(100000))
                self.assertEqual(bytes.fromhex(reply['acquired_hex']), expected)
                ended = next(e for e in seen if e.get('event') == 'bash-ended')
                self.assertEqual(ended['status'], 'code:7')
                self.assertEqual(ended['output'], {'state': 'closed', 'bytes': 100000})
                self.assertEqual(reply['identity'], ended['retained']['identity'])
                self.assertEqual(reply['sha256'], hashlib.sha256(expected).hexdigest())
                self.assertEqual(reply['receipt']['work'], ended['work'])
                self.assertEqual(reply['receipt']['bytes'], len(expected))
                self.assertEqual(reply['receipt']['sha256'], reply['sha256'])
                self.assertEqual(len(reply['permission']), 13) # run/read/bad/denied/first/repeat/conflict
                for asked in reply['permission']:
                    self.assertEqual(asked['permission'], 'bash')
                    self.assertEqual(asked['patterns'], asked['always'])
                self.assertEqual(reply['permission'][0]['patterns'], [COMMAND])
                self.assertIn('native-accept ' + reply['identity'], reply['permission'][-2]['patterns'])
                conn = sqlite3.connect(scratch / 'store/intent.sqlite3')
                self.assertEqual(conn.execute('SELECT count(*) FROM bash_output_accept').fetchone()[0], 1)
                conn.close()
                self.assertFalse((scratch / 'should-not-run').exists())
                self.assertFalse((scratch / 'state').exists())
                evidence = os.environ.get('NATIVE_OUTPUT_EVIDENCE')
                if evidence:
                    Path(evidence).write_text(json.dumps({'events': seen, 'reply': reply}, indent=2))
            finally:
                if owner.poll() is None:
                    owner.kill()
                    owner.wait(timeout=10)
                owner.stdin.close()
                owner.stdout.close()
                for pid, fd in roots:
                    try: signal.pidfd_send_signal(fd, signal.SIGKILL)
                    except ProcessLookupError: pass
                    try: os.waitpid(pid, 0)
                    except ChildProcessError: pass
                    os.close(fd)


if __name__ == '__main__':
    unittest.main()
