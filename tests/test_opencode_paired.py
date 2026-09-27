"""Real Bun adapter, Bash source image, and cumulative Runner private broker fixture.

Requires built exact images; compiles only a provider fixture variant under this
repository's target tree. The Runner source/worktree is read without editing it.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNNER = Path('/home/nes/projects/agent-runner/worktrees/AGE-319-ordinary-script-sync-join')
FIXTURE_SOURCE = RUNNER / 'crates/oulipoly-kernel-broker/src/fresh_provider_fixture.rs'
RUNNER_IMAGE = RUNNER / 'src-tauri/target/debug/oulipoly-agent-runner'
BROKER_IMAGE = RUNNER / 'src-tauri/target/debug/oulipoly-kernel-broker'
FIXTURE_TEST = RUNNER / 'src-tauri/target/debug/deps/private_root_join-48ead8afb6cc4d18'
BASH_IMAGE = ROOT / 'target/debug/agent-bash'
ADAPTER = ROOT / 'integrations/opencode/tools/bash.ts'
DRIVER = ROOT / 'tests/fixtures/age319_opencode_paired_driver.ts'
TAP = ROOT / 'tests/fixtures/age319_opencode_wire_tap.py'
BUN = shutil.which('bun')
TARGET = ROOT / 'target/age319-opencode-paired'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def provider_source():
    source = FIXTURE_SOURCE.read_text()
    start = source.index('                let mut command = Command::new(&args[1]);',
                         source.index('                let script = format!('))
    end = source.index('                if args[5] == "ordinary-copy" && status.success() {', start)
    # Keep the fixture's process ancestry, original script bytes, and all
    # broker assertions. Only replace its immediate Bash call with Bun.
    replacement = f'''                let argv = vec![
                    "sh".to_owned(), "-c".to_owned(), script.clone(),
                    "sh".to_owned(), gate.join("ordinary-effect").display().to_string(),
                    gate.join("ordinary-background").display().to_string(), String::new(),
                ];
                let encoded = serde_json::to_string(&argv)?;
                let mut command = Command::new({json.dumps(BUN)});
                command.args(["--no-install", {json.dumps(str(DRIVER))},
                              {json.dumps(str(ADAPTER))}, &encoded]);
                let mut child = command
                    .env_clear()
                    .env("HOME", gate)
                    .env("PATH", "/usr/bin:/bin")
                    .env("AGENT_BASH_BIN", {json.dumps(str(TAP))})
                    .env("AGENT_BASH_PRIVATE_V31_SYNC", "1")
                    .env("AGE319_PAIRED_REAL_BASH", &args[1])
                    .env("AGE319_PAIRED_GATE", gate)
                    .env("AGE319_PAIRED_ADAPTER_RESULT", gate.join("opencode-adapter-result.json"))
                    .env("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1", &args[2])
                    .env("AGE319_ORDINARY_EFFECTIVE_ENV", "original-value")
                    .env("AGE319_ORDINARY_SECRET_SENTINEL", "age319-secret-must-stay-in-memfd-319")
                    .envs((args[5] == "ordinary-sync-reply-loss")
                        .then_some(("AGE319_PRIVATE_SYNC_DROP_BEGIN_REPLY_V1", "1")))
                    .stdin(Stdio::null())
                    .stdout(Stdio::from(std::fs::File::create(gate.join("adapter-process-output"))?))
                    .stderr(Stdio::from(std::fs::File::create(gate.join("bash-causal-error"))?))
                    .spawn()?;
                std::fs::write(gate.join("causal-bash-pid"), child.id().to_string())?;
                let status = child.wait()?;
                std::fs::write(gate.join("ordinary-bash-status"),
                               status.code().unwrap_or(70).to_string())?;
                let evidence = std::path::Path::new({json.dumps(str(TARGET / 'evidence'))}).join(&args[5]);
                std::fs::create_dir_all(&evidence)?;
                for name in ["bash-causal-output", "opencode-adapter-result.json",
                             "adapter-bash-calls.jsonl", "bash-causal-error"] {{
                    let path = gate.join(name);
                    if path.exists() {{ std::fs::copy(&path, evidence.join(name))?; }}
                }}
                let physical = gate.parent().unwrap().join("broker-state/v30/fresh-provider");
                let consumed = std::fs::read_dir(physical)?
                    .filter_map(Result::ok)
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".consumed.json"))
                    .count();
                std::fs::write(evidence.join("consumed-k-count"), consumed.to_string())?;
'''
    return source[:start] + replacement + source[end:]


def build_provider():
    TARGET.mkdir(parents=True, exist_ok=True)
    project = TARGET / 'provider'
    (project / 'src').mkdir(parents=True, exist_ok=True)
    (project / 'Cargo.toml').write_text('''[package]
name = "age319-opencode-paired-provider"
version = "0.1.0"
edition = "2021"
[dependencies]
libc = "0.2"
serde_json = "1"
''')
    (project / 'src/main.rs').write_text(provider_source())
    subprocess.run(['cargo', 'build', '--offline', '-j2', '--manifest-path',
                    str(project / 'Cargo.toml'), '--target-dir', str(TARGET / 'cargo')],
                   check=True, env={**os.environ, 'CARGO_BUILD_JOBS': '2'})
    return TARGET / 'cargo/debug/age319-opencode-paired-provider'


class PairedConsumerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        assert BUN, 'Bun required'
        for image in (RUNNER_IMAGE, BROKER_IMAGE, FIXTURE_TEST, BASH_IMAGE):
            assert image.is_file(), f'built image absent: {image}'
        assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=RUNNER,
                                       text=True).strip() == 'aa25ffd7e761c428a3e1230c6b7261c55af8704b'
        cls.provider = build_provider()
        print('images ' + json.dumps({str(path): sha(path.read_bytes()) for path in
                                     (RUNNER_IMAGE, BROKER_IMAGE, FIXTURE_TEST, BASH_IMAGE,
                                      cls.provider, ADAPTER)}), flush=True)

    def paired(self, mode):
        evidence = TARGET / 'evidence' / mode.removeprefix('normal_model_provider_bash_').replace('_', '-')
        if evidence.exists():
            shutil.rmtree(evidence)
        env = {**os.environ, 'OULIPOLY_AGE319_RUNNER_IMAGE': str(RUNNER_IMAGE),
               'OULIPOLY_AGE319_BROKER_IMAGE': str(BROKER_IMAGE),
               'OULIPOLY_AGE319_BASH_IMAGE': str(BASH_IMAGE),
               'OULIPOLY_AGE319_PROVIDER_IMAGE': str(self.provider),
               'AGE319_PRIVATE_JOIN_ONLY_MODE': mode}
        result = subprocess.run([str(FIXTURE_TEST), '--exact',
                                 'original_runner_joins_once_behind_persistent_root_pid1',
                                 '--nocapture'], env=env, text=True, capture_output=True)
        print(json.dumps(dict(mode=mode, status=result.returncode, stdout=result.stdout,
                              stderr=result.stderr)), flush=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        wire = json.loads((evidence / 'bash-causal-output').read_bytes())
        reply = json.loads((evidence / 'opencode-adapter-result.json').read_text())
        calls = [json.loads(line) for line in
                 (evidence / 'adapter-bash-calls.jsonl').read_text().splitlines()]
        self.assertEqual(len(calls), 1, 'adapter dispatched more than one Bash run')
        self.assertEqual((evidence / 'consumed-k-count').read_text(), '2',
                         'parent and child must consume exactly one K each')
        self.assertEqual(calls[0][:5], ['run', '--delivery', 'sync',
                                       '--completion-scope', 'tree'])
        self.assertNotIn('--cancel-on-owner-exit', calls[0])
        self.assertEqual(wire['schema_version'], 31)
        self.assertEqual(wire['publication']['phase'], 'unknown')
        self.assertEqual(wire['publication']['child']['session']['request_id'],
                         wire['publication']['child']['d_key'])
        self.assertEqual(wire['publication']['event']['request_id'],
                         wire['publication']['child']['request_id'])
        self.assertEqual(wire['publication']['event']['source_id'],
                         wire['publication']['child']['handle'])
        self.assertEqual(wire['publication']['event']['tree_drained'], True)
        self.assertEqual(wire['publication']['event']['output_closed'], True)
        self.assertNotIn('error', reply, reply)
        self.assertIn('consumer ack: unconfirmed; remote ack: unconfirmed',
                      reply['result'].lower())
        if wire['dispatch_state'] == 'sync-child-result':
            for name, expected in [('stdout', b'\x01\xffordinary\x00'),
                                   ('stderr', b'err\x00\xfe')]:
                raw = base64.b64decode(wire[f'{name}_base64'], validate=True)
                self.assertEqual(raw, expected)
                self.assertEqual(wire['publication']['event'][f'{name}_len'], len(raw))
                self.assertEqual(wire['publication']['event'][f'{name}_sha256'], sha(raw))
                self.assertIn(f'{name}: {len(raw)} bytes, sha256={sha(raw)}, '
                              'representation=hex', reply['result'])
                self.assertIn(f'--- {name} ---\n{raw.hex()}', reply['result'])
        else:
            self.assertEqual(wire['dispatch_state'], 'sync-publication-unknown')
            self.assertNotIn('stdout_base64', wire)
            self.assertNotIn('stderr_base64', wire)
            for name, expected in [('stdout', b'\x01\xffordinary\x00'),
                                   ('stderr', b'err\x00\xfe')]:
                self.assertEqual(wire['publication']['event'][f'{name}_len'], len(expected))
                self.assertEqual(wire['publication']['event'][f'{name}_sha256'], sha(expected))
            self.assertIn('publication unresolved', reply['result'])
            self.assertIn('Do not replay', reply['result'])
            self.assertNotIn('--- stdout ---', reply['result'])
            self.assertNotIn('--- stderr ---', reply['result'])
        return wire, reply

    def test_exact_binary_sync(self):
        wire, reply = self.paired('normal_model_provider_bash_ordinary_sync')
        self.assertEqual(wire['publication']['exit_code'], 0)
        self.assertIn('exited with code 0', reply['result'])

    def test_nonzero_child_exit(self):
        wire, reply = self.paired('normal_model_provider_bash_ordinary_failure')
        self.assertEqual(wire['publication']['exit_code'], 37)
        self.assertEqual(wire['publication']['event']['wait_status'], 37 << 8)
        self.assertIn('exited with code 37', reply['result'])

    def test_unknown_publications_do_not_replay(self):
        for mode in ('normal_model_provider_bash_ordinary_sync_reply_loss',
                     'normal_model_provider_bash_ordinary_sync_socket_partial'):
            with self.subTest(mode=mode):
                self.paired(mode)


if __name__ == '__main__':
    unittest.main(verbosity=2)
