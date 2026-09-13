use super::*;

struct Cleanup(Vec<OwnedProcess>);
impl Drop for Cleanup {
    fn drop(&mut self) {
        terminate_owned_processes(&self.0);
    }
}

#[test]
fn terminal_live_descendants_cancel_without_rewriting_root_or_delivery() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let pids = temp.path().join("pids");
    // TERM is inherited as ignored by both exact children, forcing escalation.
    let output = agent_bash(&temp)
        .env("PIDS", &pids)
        .args(["run", "--delivery", "sync", "--completion-scope", "root", "--", "bash", "-c",
            "trap '' TERM; sleep 60 >/dev/null 2>&1 & first=$!; sleep 60 >/dev/null 2>&1 & second=$!; printf '%s\\n%s\\n' \"$first\" \"$second\" > \"$PIDS\"; printf 'root output\\n'; exit 7"])
        .output().unwrap();
    let run = parse_run_output(&output);
    let handle = run["handle"].as_str().unwrap();
    wait_for_terminal_status(&temp, handle);
    let dir = state_dir_path(&run);
    let cleanup = Cleanup(
        fs::read_to_string(&pids)
            .unwrap()
            .lines()
            .map(|pid| OwnedProcess::capture_current(pid.parse().unwrap(), None).unwrap())
            .collect(),
    );
    assert_eq!(cleanup.0.len(), 2);
    assert!(cleanup.0.iter().all(|child| !child.exited()));
    assert!(dir.join("physical-custody").exists());
    assert!(!dir.join("cancel-requested").exists());
    wait_for_fixture_delivery(&run);
    let before = read_meta(&meta_path(&run));
    let rc = fs::read(dir.join("rc")).unwrap();
    // AGE-363 requires acquisition of the actual bounded output before acceptance.
    let acquired = agent_bash(&temp)
        .args(["snapshot", handle])
        .output()
        .unwrap();
    assert_command_success(&acquired);
    let acquired = parse_stdout_json(&acquired);
    let identity = &acquired["snapshot"];
    let bytes = b"root output\n";
    assert_eq!(identity["handle"], handle);
    assert_eq!(identity["created_at_unix_ms"], before["created_at_unix_ms"]);
    assert_eq!(identity["bytes"], bytes.len());
    assert_eq!(identity["sha256"], format!("{:x}", Sha256::digest(bytes)));
    assert_eq!(identity["encoding"], "hex");
    assert_eq!(
        acquired["output"],
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let consume = agent_bash(&temp)
        .args(["accept-output", handle, "--snapshot", &identity.to_string()])
        .output()
        .unwrap();
    assert_command_success(&consume);
    assert_eq!(parse_stdout_json(&consume)["snapshot"], *identity);
    assert_eq!(parse_stdout_json(&consume)["receipt_updated"], true);
    let consumed = fs::metadata(dir.join("output-receipt.json")).unwrap().ino();
    let start = Instant::now();
    let cancel = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
    assert_command_success(&cancel);
    assert_eq!(
        parse_stdout_json(&cancel)["requested"],
        true,
        "{}",
        command_failure_message(&cancel)
    );
    assert!(!dir.join("cancel-workload-drained").exists());
    let marker = fs::metadata(dir.join("cancel-requested")).unwrap().ino();
    let duplicate = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
    assert_command_success(&duplicate);
    assert_eq!(parse_stdout_json(&duplicate)["requested"], false);
    assert_eq!(
        fs::metadata(dir.join("cancel-requested")).unwrap().ino(),
        marker
    );
    wait_until(FIXTURE_DEADLINE, || {
        cleanup.0.iter().all(OwnedProcess::exited).then_some(())
    });
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "TERM-ignoring children require grace/escalation"
    );
    wait_until(FIXTURE_DEADLINE, || {
        (!dir.join("physical-custody").exists()).then_some(())
    });
    assert!(dir.join("cancel-workload-drained").exists());
    let after = read_meta(&meta_path(&run));
    for field in [
        "state",
        "rc",
        "signal",
        "completion_reason",
        "completed_at_unix_ms",
        "delivery",
    ] {
        assert_eq!(after[field], before[field], "changed {field}");
    }
    assert_eq!(fs::read(dir.join("rc")).unwrap(), rc);
    assert_eq!(
        fs::metadata(dir.join("output-receipt.json")).unwrap().ino(),
        consumed
    );
    let drained = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
    assert_command_success(&drained);
    assert_eq!(parse_stdout_json(&drained)["requested"], false);
}

#[test]
fn actually_drained_terminal_cancel_is_noop() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let (output, _) = run_cmd(
        &temp,
        &[
            "run",
            "--delivery",
            "sync",
            "--completion-scope",
            "root",
            "--",
            "true",
        ],
    );
    let run = parse_run_output(&output);
    let handle = run["handle"].as_str().unwrap();
    wait_for_terminal_status(&temp, handle);
    let dir = state_dir_path(&run);
    wait_until(FIXTURE_DEADLINE, || {
        (!dir.join("physical-custody").exists()).then_some(())
    });
    wait_for_fixture_delivery(&run);
    let before = fs::read(meta_path(&run)).unwrap();
    for _ in 0..2 {
        let cancel = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
        assert_command_success(&cancel);
        assert_eq!(parse_stdout_json(&cancel)["requested"], false);
        assert_eq!(parse_stdout_json(&cancel)["wake"], "not-requested");
    }
    assert!(!dir.join("cancel-requested").exists());
    assert!(!dir.join("cancel-workload-drained").exists());
    assert_eq!(fs::read(meta_path(&run)).unwrap(), before);
}

#[test]
fn terminal_cancel_retries_after_intermediate_parent_exits_and_leaf_is_adopted() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let pids = temp.path().join("pids");
    let leaf_ready = temp.path().join("leaf-ready");
    let output = agent_bash(&temp)
        .env("PIDS", &pids)
        .env("LEAF_READY", &leaf_ready)
        .args([
            "run",
            "--delivery",
            "sync",
            "--completion-scope",
            "root",
            "--",
            "bash",
            "-c",
            r#"
bash -c '
    trap "exit 0" TERM
    bash -c '\''trap "" TERM; touch "$LEAF_READY"; exec sleep 60'\'' &
    leaf=$!
    while [ ! -e "$LEAF_READY" ]; do sleep 0.01; done
    printf "%s\n%s\n" "$$" "$leaf" > "$PIDS"
    wait "$leaf"
' >/dev/null 2>&1 &
while [ ! -s "$PIDS" ]; do sleep 0.01; done
exit 7
"#,
        ])
        .output()
        .unwrap();
    let run = parse_run_output(&output);
    let handle = run["handle"].as_str().unwrap();
    wait_for_terminal_status(&temp, handle);
    let pids: Vec<libc::pid_t> = fs::read_to_string(pids)
        .unwrap()
        .lines()
        .map(|pid| pid.parse().unwrap())
        .collect();
    assert_eq!(pids.len(), 2);
    let cleanup = Cleanup(
        pids.iter()
            .map(|pid| OwnedProcess::capture_current(*pid, None).unwrap())
            .collect(),
    );
    assert_eq!(proc_identity(pids[1]).unwrap().1, pids[0]);
    let dir = state_dir_path(&run);
    wait_for_fixture_delivery(&run);
    let before = fs::read(meta_path(&run)).unwrap();
    let cancel = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    wait_until(FIXTURE_DEADLINE, || {
        (cleanup.0[0].exited()
            && !cleanup.0[1].exited()
            && proc_identity(pids[1]).is_some_and(|(_, parent)| parent != pids[0]))
        .then_some(())
    });
    assert!(!dir.join("cancel-workload-drained").exists());
    wait_until(FIXTURE_DEADLINE, || {
        cleanup.0.iter().all(OwnedProcess::exited).then_some(())
    });
    wait_until(FIXTURE_DEADLINE, || {
        (!dir.join("physical-custody").exists()).then_some(())
    });
    assert!(dir.join("cancel-workload-drained").exists());
    assert_eq!(fs::read(meta_path(&run)).unwrap(), before);
}

struct OwnerShell(Child);
impl Drop for OwnerShell {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn terminal_live_custody_wrong_owner_cannot_accept_or_signal() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let run_path = temp.path().join("run.json");
    let ready = temp.path().join("ready");
    let release = temp.path().join("release");
    let pids = temp.path().join("pids");
    let result = temp.path().join("cancel.json");
    let mut owner = OwnerShell(StdCommand::new("bash")
        .env_clear().env("PATH", "/usr/bin:/bin")
        .env("XDG_STATE_HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("BIN", assert_cmd::cargo::cargo_bin("agent-bash"))
        .env("RUN", &run_path).env("READY", &ready).env("RELEASE", &release)
        .env("PIDS", &pids).env("RESULT", &result)
        .args(["-c", r#"
set -eu
"$BIN" run --delivery sync --completion-scope root -- bash -c 'trap "" TERM; sleep 60 >/dev/null 2>&1 & echo $! > "$PIDS"; exit 7' > "$RUN"
handle=$(python3 -c 'import json,os; print(json.load(open(os.environ["RUN"]))["handle"])')
touch "$READY"
while [ ! -e "$RELEASE" ]; do sleep 0.01; done
"$BIN" cancel "$handle" > "$RESULT"
:
"#]).spawn().unwrap());
    wait_until(FIXTURE_DEADLINE, || ready.exists().then_some(()));
    let run: Value = serde_json::from_slice(&fs::read(run_path).unwrap()).unwrap();
    wait_for_terminal_status(&temp, run["handle"].as_str().unwrap());
    let pid = fs::read_to_string(pids).unwrap().trim().parse().unwrap();
    let cleanup = Cleanup(vec![OwnedProcess::capture_current(pid, None).unwrap()]);
    let dir = state_dir_path(&run);
    wait_for_fixture_delivery(&run);
    let before = fs::read(meta_path(&run)).unwrap();
    assert!(dir.join("physical-custody").exists());
    let handle = run["handle"].as_str().unwrap();
    let denied = agent_bash(&temp).args(["cancel", handle]).output().unwrap();
    assert_eq!(denied.status.code(), Some(77));
    assert!(!dir.join("cancel-requested").exists());
    assert!(!cleanup.0[0].exited());
    assert_eq!(fs::read(meta_path(&run)).unwrap(), before);
    fs::write(release, b"").unwrap();
    wait_until(FIXTURE_DEADLINE, || owner.0.try_wait().unwrap());
    let accepted: Value = serde_json::from_slice(&fs::read(result).unwrap()).unwrap();
    assert_eq!(accepted["requested"], true);
    wait_until(FIXTURE_DEADLINE, || cleanup.0[0].exited().then_some(()));
    wait_until(FIXTURE_DEADLINE, || {
        (!dir.join("physical-custody").exists()).then_some(())
    });
    assert_eq!(fs::read(meta_path(&run)).unwrap(), before);
}

// Logical terminal publication can precede /bin/true helper handback. Do not
// mistake that independent, legitimate delivery update for cancellation damage.
fn wait_for_fixture_delivery(run: &Value) {
    wait_until(FIXTURE_DEADLINE, || {
        (read_meta(&meta_path(run))["delivery"]["lifecycle"] == "admitted_outcome").then_some(())
    });
}
