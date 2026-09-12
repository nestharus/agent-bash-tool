use super::*;

fn snapshot(temp: &tempfile::TempDir, handle: &str) -> Value {
    let output = agent_bash(temp)
        .args(["snapshot", handle])
        .output()
        .unwrap();
    assert_command_success(&output);
    parse_stdout_json(&output)
}

fn consume(temp: &tempfile::TempDir, handle: &str, identity: &Value) -> Output {
    agent_bash(temp)
        .args(["consume", handle, "--snapshot", &identity.to_string()])
        .output()
        .unwrap()
}

#[test]
fn exact_prefix_survives_append_restart_duplicate_and_rejects_stale_source() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_prefix";
    let dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    let bytes = [
        b" \n\t".as_slice(),
        &vec![b'x'; 70_123],
        &[0xff, 0, 0xe2, 0x82],
        b" \n\n",
    ]
    .concat();
    fs::write(dir.join("log"), &bytes).unwrap();
    let acquired = snapshot(&temp, handle);
    let identity = &acquired["snapshot"];
    assert_eq!(identity["bytes"], bytes.len());
    assert_eq!(identity["sha256"], format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(
        acquired["output"],
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    fs::OpenOptions::new()
        .append(true)
        .open(dir.join("log"))
        .unwrap()
        .write_all(b"later append")
        .unwrap();
    let recovered = agent_bash(&temp)
        .args(["snapshot", handle, "--bytes", &bytes.len().to_string()])
        .output()
        .unwrap();
    assert_command_success(&recovered);
    assert_eq!(parse_stdout_json(&recovered)["snapshot"], *identity);
    // Separate processes model restart between acquisition/acceptance and a lost reply.
    let first = consume(&temp, handle, identity);
    assert_command_success(&first);
    assert_eq!(parse_stdout_json(&first)["consumed"], true);
    let second = consume(&temp, handle, identity);
    assert_command_success(&second);
    let reply = parse_stdout_json(&second);
    assert_eq!(reply["consumed"], false);
    assert_eq!(reply["snapshot"], *identity);
    assert_eq!(reply["remote_ack"], "unconfirmed");
    assert_eq!(reply["physical_drain"], "unconfirmed");
    assert!(
        snapshot(&temp, handle)["snapshot"]["bytes"]
            .as_u64()
            .unwrap()
            > bytes.len() as u64
    );
    let mut replacement = bytes.clone();
    replacement[0] = b'!';
    fs::write(dir.join("log"), &replacement).unwrap();
    assert!(!consume(&temp, handle, identity).status.success());
    fs::write(dir.join("log"), b"truncated").unwrap();
    assert!(!consume(&temp, handle, identity).status.success());
    let short = agent_bash(&temp)
        .args(["snapshot", handle, "--bytes", &bytes.len().to_string()])
        .output()
        .unwrap();
    assert!(!short.status.success());
    assert!(short.stdout.is_empty());
    // No promise of recovery after the existing retained source is removed.
    fs::remove_dir_all(&dir).unwrap();
    assert!(!consume(&temp, handle, identity).status.success());
    assert!(!dir.exists());
}

#[test]
fn rejects_malformed_wrong_identity_unacquired_bytes_and_malformed_marker() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_invalid";
    let dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    fs::write(dir.join("log"), b"prefix\n").unwrap();
    let acquired = snapshot(&temp, handle);
    for (key, value) in [
        ("handle", json!("ab_wrong")),
        ("created_at_unix_ms", json!(0)),
        ("bytes", json!(999)),
        ("sha256", json!("bad")),
        ("version", json!(2)),
        ("encoding", json!("utf8")),
    ] {
        let mut identity = acquired["snapshot"].clone();
        identity[key] = value;
        assert!(!consume(&temp, handle, &identity).status.success());
        assert!(!dir.join("consumed").exists());
    }
    assert!(!consume(&temp, handle, &json!({})).status.success());
    let bare = agent_bash(&temp)
        .args(["consume", handle])
        .output()
        .unwrap();
    assert!(!bare.status.success());
    assert!(!dir.join("consumed").exists());
    let partial = agent_bash(&temp)
        .args(["snapshot", handle, "--bytes", "3"])
        .output()
        .unwrap();
    assert_command_success(&partial);
    assert_eq!(parse_stdout_json(&partial)["snapshot"]["bytes"], 3);
    assert_command_success(&consume(
        &temp,
        handle,
        &parse_stdout_json(&partial)["snapshot"],
    ));
    fs::remove_file(dir.join("consumed")).unwrap();
    std::os::unix::fs::symlink("missing", dir.join("consumed")).unwrap();
    assert!(
        !consume(&temp, handle, &acquired["snapshot"])
            .status
            .success()
    );
}

#[test]
fn read_authority_is_not_acceptance_authority_and_session_recovery_still_works() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_authority";
    let dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    let (helper, route) = routed_owner_resolving_fake_agents(&temp);
    write_delivery_helper_provenance(&dir, &helper, &[("AGENT_BASH_FAKE_ROUTE", &route)]);
    let path = dir.join("meta.json");
    let mut meta = read_meta(&path);
    meta["owner_session_id"] = json!("ses_owner");
    // Current helper resolves a different invocation in the same session: authorized recovery.
    meta["owner_invocation_uuid"] = json!("22222222-2222-4222-8222-222222222222");
    fs::write(&path, format_seeded_meta(&meta)).unwrap();
    fs::write(&route, "ses_other\n").unwrap();
    let acquired = snapshot(&temp, handle);
    assert_eq!(
        consume(&temp, handle, &acquired["snapshot"]).status.code(),
        Some(77)
    );
    assert!(!dir.join("consumed").exists());
    fs::write(&route, "ses_owner\n").unwrap();
    assert_command_success(&consume(&temp, handle, &acquired["snapshot"]));
    meta["handle"] = json!("ab_mismatched_metadata");
    fs::write(&path, format_seeded_meta(&meta)).unwrap();
    assert!(
        !consume(&temp, handle, &acquired["snapshot"])
            .status
            .success()
    );
}

#[test]
fn parallel_duplicate_acceptance_publishes_once() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_duplicate";
    seed_done_state_dir(&temp, handle, unix_ms(), false);
    let acquired = snapshot(&temp, handle);
    let replies = std::thread::scope(|scope| {
        let first = scope.spawn(|| consume(&temp, handle, &acquired["snapshot"]));
        let second = scope.spawn(|| consume(&temp, handle, &acquired["snapshot"]));
        [first.join().unwrap(), second.join().unwrap()]
    });
    for reply in &replies {
        assert_command_success(reply);
    }
    assert_eq!(
        replies
            .iter()
            .filter(|reply| parse_stdout_json(reply)["consumed"] == true)
            .count(),
        1
    );
}

fn proxy(temp: &tempfile::TempDir) -> PathBuf {
    let path = temp.path().join("snapshot-proxy.py");
    fs::write(
        &path,
        r#"#!/usr/bin/python3
import json, os, subprocess, sys, time
args = sys.argv[1:]
mode = os.environ['AGE363_FAULT']
with open(os.environ['AGE363_CALLS'], 'a') as f: f.write(args[0] + '\n')
if args[0] == 'run': raise SystemExit('workload replay forbidden')
if args[0] == 'status' and '--tail-bytes' in args and mode == 'running-partial':
    print('RUNNING handle=' + args[-1] + '\n--- output ---')
    raise SystemExit(0)
if args[0] == 'status' and '--observe-only' not in args: raise SystemExit(74)
if args[0] == 'consume' and mode == 'timeout': time.sleep(10)
if args[0] == 'consume' and mode in ('error', 'reject'):
    raise SystemExit(77 if mode == 'reject' else 74)
p = subprocess.run([os.environ['AGE363_REAL'], *args], capture_output=True)
if p.returncode: sys.stderr.buffer.write(p.stderr); raise SystemExit(p.returncode)
out = p.stdout
if args[0] == 'snapshot' and mode.endswith('partial'):
    out = out[:-12]
if args[0] == 'snapshot' and mode.startswith('snapshot-'):
    value = json.loads(out)
    if mode == 'snapshot-wrong': value['snapshot']['handle'] += '_wrong'
    elif mode == 'snapshot-hash': value['snapshot']['sha256'] = '0' * 64
    elif mode == 'snapshot-bytes': value['snapshot']['bytes'] += 1
    out = json.dumps(value).encode()
if args[0] == 'consume':
    if mode == 'lost': out = b''
    elif mode == 'malformed': out = b'not-json'
    elif mode in ('wrong', 'stale', 'bytes', 'rejected-reply'):
        value = json.loads(out)
        if mode == 'wrong': value['handle'] += '_wrong'
        elif mode == 'stale': value['snapshot']['created_at_unix_ms'] += 1
        elif mode == 'bytes': value['snapshot']['bytes'] += 1
        else: value['local_acceptance'] = 'rejected'
        out = json.dumps(value).encode()
sys.stdout.buffer.write(out)
"#,
    )
    .unwrap();
    set_executable(&path);
    path
}

#[test]
fn real_adapter_keeps_full_exact_output_across_consume_faults_and_progress_failure() {
    if test_support::private_case() {
        return;
    }
    assert_bun_available();
    let temp = tempfile::tempdir().unwrap();
    let driver = write_adapter_driver(&temp);
    let wrapper = proxy(&temp);
    let bytes = format!(" \n\t{}\n \n", "retained-prefix-".repeat(5000));
    for fault in [
        "error",
        "reject",
        "lost",
        "malformed",
        "wrong",
        "stale",
        "bytes",
        "rejected-reply",
        "progress",
        "partial",
        "snapshot-wrong",
        "snapshot-hash",
        "snapshot-bytes",
        "timeout",
        "running-partial",
    ] {
        let handle = format!("ab_age363_{fault}");
        let dir = seed_done_state_dir(&temp, &handle, unix_ms(), false);
        fs::write(dir.join("log"), &bytes).unwrap();
        let calls = temp.path().join(format!("{fault}.calls"));
        let output = adapter_driver_command(&temp, &driver, "poll", Some(&handle))
            .env("AGENT_BASH_BIN", &wrapper)
            .env("AGE363_REAL", assert_cmd::cargo::cargo_bin("agent-bash"))
            .env("AGE363_FAULT", fault)
            .env("AGENT_BASH_TOOL_PROCESS_TIMEOUT_MS", "1000")
            .env("AGE363_CALLS", &calls)
            .output()
            .unwrap();
        let calls = fs::read_to_string(&calls).unwrap();
        assert!(!calls.lines().any(|line| line == "run"));
        if fault == "partial" || fault.starts_with("snapshot-") {
            assert!(!output.status.success());
            assert!(!dir.join("consumed").exists());
            assert!(!calls.lines().any(|line| line == "consume"));
            continue;
        }
        assert_command_success(&output);
        let result = parse_stdout_json(&output);
        let text = result["result"].as_str().unwrap();
        let observed = if fault == "running-partial" {
            &bytes[bytes.len() - 65_536..]
        } else {
            &bytes
        };
        assert_eq!(
            text.split_once("--- output ---\n").unwrap().1,
            observed,
            "{fault}"
        );
        assert!(text.contains("remote ACK: unconfirmed"));
        assert!(text.contains("physical drain: unconfirmed"));
        assert_eq!(
            text.contains("local acceptance: accepted bounded snapshot"),
            fault == "progress"
        );
        assert_eq!(
            dir.join("consumed").exists(),
            !matches!(fault, "error" | "reject" | "timeout" | "running-partial")
        );
        if fault == "running-partial" {
            assert_eq!(calls, "status\nstatus\nsnapshot\n");
            assert!(text.contains("textual observation only"));
        } else {
            assert!(calls.starts_with("status\nsnapshot\nconsume\n"), "{calls}");
        }
    }
}

#[test]
fn real_adapter_preserves_non_utf8_output_as_explicit_hex() {
    if test_support::private_case() {
        return;
    }
    assert_bun_available();
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_encoding";
    let dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    fs::write(
        dir.join("log"),
        [0xef, 0xbb, 0xbf, 0xff, 0xe2, 0x82, 0, 32, 10],
    )
    .unwrap();
    let driver = write_adapter_driver(&temp);
    let result = run_adapter_driver(&temp, &driver, "poll", Some(handle));
    let text = result["result"].as_str().unwrap();
    assert!(text.contains("output representation: hex"));
    assert!(text.ends_with("efbbbfffe28200200a"));
    assert!(dir.join("consumed").exists());
}

// Exact-owned cleanup also runs when the regression oracle fails.
struct AbortFixtureCleanup(Vec<OwnedProcess>);

impl Drop for AbortFixtureCleanup {
    fn drop(&mut self) {
        terminate_owned_processes(&self.0);
    }
}

#[test]
fn post_acquisition_consume_abort_cancels_exact_live_descendants_and_retains_result() {
    if test_support::private_case() {
        return;
    }
    assert_post_acquisition_abort("consume");
}

#[test]
fn post_acquisition_progress_abort_cancels_exact_live_descendants_and_retains_result() {
    if test_support::private_case() {
        return;
    }
    assert_post_acquisition_abort("progress");
}

fn assert_post_acquisition_abort(stage: &str) {
    assert_bun_available();
    {
        let temp = tempfile::tempdir().unwrap();
        let driver = write_adapter_driver(&temp);
        let source = fs::read_to_string(&driver)
            .unwrap()
            .replace(
                "const result = await mod.default.execute(args, context)",
                r#"const abortWatcher = (async () => {
  while (!await Bun.file(process.env.AGE363_ABORT).exists()) await Bun.sleep(10)
  controller.abort()
})()
const result = await mod.default.execute(args, context)"#,
            )
            .replace(
                "if (request?.lingerMs)",
                r#"while (!await Bun.file(process.env.AGE363_RELEASE).exists()) await Bun.sleep(10)
if (request?.lingerMs)"#,
            );
        fs::write(&driver, source).unwrap();
        let wrapper = temp.path().join("abort-proxy.py");
        fs::write(&wrapper, r#"#!/usr/bin/python3
import json, os, sys, time
args = sys.argv[1:]
with open(os.environ['AGE363_CALLS'], 'a') as f: f.write(json.dumps(args) + '\n')
stage = os.environ['AGE363_STAGE']
if (stage == 'consume' and args[0] == 'consume') or (stage == 'progress' and args[0] == 'status' and '--observe-only' not in args):
    handle = args[1] if stage == 'consume' else args[-1]
    with open(os.environ['AGE363_PENDING'], 'w') as f: f.write(handle)
    time.sleep(60)
    raise SystemExit('barrier was not aborted')
os.execv(os.environ['AGE363_REAL'], [os.environ['AGE363_REAL'], *args])
"#).unwrap();
        set_executable(&wrapper);
        let pending = temp.path().join("pending");
        let abort = temp.path().join("abort");
        let release = temp.path().join("release");
        let calls = temp.path().join("calls");
        let pids = temp.path().join("pids");
        let bytes = " \nretained post-acquisition abort\n \n";
        let request = json!({"args": {"command": format!(
            "sleep 60 >/dev/null 2>&1 & first=$!; sleep 60 >/dev/null 2>&1 & second=$!; printf '%s\\n%s\\n' \"$first\" \"$second\" > '{}'; printf ' \\nretained post-acquisition abort\\n \\n'", pids.display())}});
        let stderr = temp.path().join("driver.stderr");
        let mut child =
            adapter_driver_command(&temp, &driver, "request", Some(&request.to_string()))
                .env("AGENT_BASH_BIN", &wrapper)
                .env("AGE363_REAL", assert_cmd::cargo::cargo_bin("agent-bash"))
                .env("AGE363_STAGE", stage)
                .env("AGE363_CALLS", &calls)
                .env("AGE363_PENDING", &pending)
                .env("AGE363_ABORT", &abort)
                .env("AGE363_RELEASE", &release)
                .stdout(Stdio::piped())
                .stderr(fs::File::create(&stderr).unwrap())
                .spawn()
                .unwrap();
        let mut cleanup = AbortFixtureCleanup(vec![
            OwnedProcess::capture_current(child.id() as libc::pid_t, None).unwrap(),
        ]);
        let deadline = Instant::now() + FIXTURE_DEADLINE;
        let handle = loop {
            if let Some(handle) = fs::read_to_string(&pending).ok().filter(|s| !s.is_empty()) {
                break handle;
            }
            if Instant::now() > deadline || child.try_wait().unwrap().is_some() {
                let _ = cleanup.0[0].signal(libc::SIGKILL);
                panic!(
                    "barrier not reached: stderr={} calls={}",
                    fs::read_to_string(&stderr).unwrap(),
                    fs::read_to_string(&calls).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let dir = temp.path().join("agent-bash").join(&handle);
        let descendants: Vec<_> = fs::read_to_string(&pids)
            .unwrap()
            .lines()
            .map(|pid| {
                OwnedProcess::capture_current(pid.parse().unwrap(), None)
                    .expect("actual live descendant")
            })
            .collect();
        assert_eq!(descendants.len(), 2);
        cleanup.0.extend(descendants);
        let descendants = &cleanup.0[1..];
        assert!(descendants.iter().all(|p| !p.exited()));
        assert!(dir.join("physical-custody").exists());
        assert!(!dir.join("cancel-requested").exists());
        assert_eq!(dir.join("consumed").exists(), stage == "progress");
        let acquired = snapshot(&temp, &handle);
        assert_eq!(acquired["snapshot"]["bytes"], bytes.len());
        fs::write(&abort, "abort now").unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let result: Value = serde_json::from_str(&line).expect("retained adapter return");
        let text = result["result"].as_str().unwrap();
        assert!(text.ends_with(bytes), "{text}");
        assert_eq!(text.matches(bytes).count(), 1);
        assert!(
            text.contains("cancellation after acquisition: Cancellation requested"),
            "{text}"
        );
        assert!(text.contains("subprocess aborted"), "{text}");
        assert_eq!(
            text.contains("local acceptance: accepted bounded snapshot"),
            stage == "progress"
        );
        assert!(text.contains("remote ACK: unconfirmed; physical drain: unconfirmed"));
        assert!(text.contains(&acquired["snapshot"].to_string()));
        assert!(
            text.contains(r#""requested":true"#),
            "actual cancellation was not accepted; live_descendants={}\n{text}",
            descendants.iter().filter(|p| !p.exited()).count()
        );
        wait_until(FIXTURE_DEADLINE, || {
            (descendants.iter().all(OwnedProcess::exited) && !dir.join("physical-custody").exists())
                .then_some(())
        });
        // The adapter stays alive until after exact pidfd exit and guardian drain:
        // owner-exit cancellation cannot explain the observed cancellation/drain.
        assert!(!cleanup.0[0].exited());
        assert!(dir.join("cancel-requested").exists());
        let calls: Vec<Value> = fs::read_to_string(&calls)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let cancels: Vec<_> = calls.iter().filter(|args| args[0] == "cancel").collect();
        assert_eq!(cancels, vec![&json!(["cancel", handle])]);
        assert_eq!(calls.iter().filter(|args| args[0] == "run").count(), 1);
        fs::write(&release, "exit now").unwrap();
        assert_command_success(&child.wait_with_output().unwrap());
    }
}

#[test]
fn running_poll_reads_tail_but_terminal_acquires_complete_bounded_bytes() {
    if test_support::private_case() {
        return;
    }
    assert_bun_available();
    let temp = tempfile::tempdir().unwrap();
    let handle = "ab_age363_running_tail";
    let dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    let bytes = format!("omitted-prefix:{}:retained-end\n", "x".repeat(100_000));
    fs::write(dir.join("log"), &bytes).unwrap();
    let path = dir.join("meta.json");
    let terminal_meta = fs::read_to_string(&path).unwrap();
    let mut meta: Value = serde_json::from_str(&terminal_meta).unwrap();
    meta["state"] = json!("RUNNING");
    fs::write(&path, format_seeded_meta(&meta)).unwrap();
    let driver = write_adapter_driver(&temp);
    let running = run_adapter_driver(&temp, &driver, "poll", Some(handle));
    let text = running["result"].as_str().unwrap();
    assert!(text.starts_with("RUNNING"), "{text}");
    let tail = text.split_once("--- output ---\n").unwrap().1;
    assert_eq!(tail.as_bytes(), &bytes.as_bytes()[bytes.len() - 65_536..]);
    assert!(!text.contains("omitted-prefix:"));
    assert!(!dir.join("consumed").exists());
    fs::write(&path, terminal_meta).unwrap();
    let terminal = run_adapter_driver(&temp, &driver, "poll", Some(handle));
    let text = terminal["result"].as_str().unwrap();
    assert_eq!(text.split_once("--- output ---\n").unwrap().1, bytes);
    assert!(text.contains("local acceptance: accepted bounded snapshot"));
    assert!(text.contains(&format!("\"bytes\":{}", bytes.len())));
    assert!(dir.join("consumed").exists());
}
