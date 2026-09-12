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
    let before = read_meta(&meta_path(&run));
    let rc = fs::read(dir.join("rc")).unwrap();
    let consume = agent_bash(&temp)
        .args(["consume", handle])
        .output()
        .unwrap();
    assert_command_success(&consume);
    let consumed = fs::metadata(dir.join("consumed")).unwrap().ino();
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
    assert_eq!(fs::metadata(dir.join("consumed")).unwrap().ino(), consumed);
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
