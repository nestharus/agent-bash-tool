//! Real supervised processes with optional live capture absent, roomy and
//! overflowing. Only the explicit fixture build can enable capture or read it back.
#![cfg(feature = "source-fault-tests")]

#[path = "../src/test_support.rs"]
mod test_support;

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::Value;

const DEADLINE: Duration = Duration::from_secs(30);
// Matches live_capture::RECORD_CHARGE; the fixture export reports the charge.
const RECORD_CHARGE: u64 = 64;

struct Workload {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

// Disjoint parity alphabets keep both channels raw binary (NUL, high bytes,
// invalid UTF-8) while letting the merged retained log be split exactly.
fn workload(dir: &Path) -> (Workload, Vec<String>) {
    let stdout: Vec<u8> = (0..300_000_u32).map(|i| (i * 2 % 256) as u8).collect();
    let stderr: Vec<u8> = (0..70_000_u32).map(|i| (i * 2 % 256) as u8 | 1).collect();
    let (first, second) = stdout.split_at(170_001);
    for (name, bytes) in [("out-a", first), ("err", &stderr[..]), ("out-b", second)] {
        fs::write(dir.join(name), bytes).unwrap();
    }
    let script = r#"cat "$1"; cat "$2" >&2; cat "$3"; exit 7"#;
    let argv = ["sh", "-c", script, "sh"]
        .into_iter()
        .map(str::to_string)
        .chain(["out-a", "err", "out-b"].map(|n| dir.join(n).display().to_string()))
        .collect();
    (Workload { stdout, stderr }, argv)
}

fn agent_bash(temp: &tempfile::TempDir, fault: Option<&str>) -> Command {
    let mut cmd = Command::cargo_bin("agent-bash").unwrap();
    cmd.env("XDG_STATE_HOME", temp.path())
        .env("XDG_CONFIG_HOME", temp.path().join("config"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env_remove("AGENT_BASH_SOURCE_FAULT")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .env_remove("AGENT_BASH_OWNER_SESSION_ID")
        .env_remove("OULIPOLY_PARENT_INVOCATION")
        .env_remove("OULIPOLY_DATA_DIR");
    if let Some(fault) = fault {
        cmd.env("AGENT_BASH_SOURCE_FAULT", fault);
    }
    cmd
}

struct Outcome {
    retained: Vec<u8>,
    state_dir: PathBuf,
}

/// Runs to terminal state and discharged physical custody, then reads the
/// retained output through the ordinary terminal snapshot surface.
fn run(temp: &tempfile::TempDir, fault: Option<&str>, argv: &[String]) -> Outcome {
    let output = agent_bash(temp, fault)
        .args(["run", "--delivery", "async", "--"])
        .args(argv)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let run: Value = serde_json::from_slice(&output.stdout).unwrap();
    let handle = run["handle"].as_str().unwrap().to_string();
    let state_dir = PathBuf::from(run["state_dir"].as_str().unwrap());
    let start = Instant::now();
    loop {
        let meta: Value =
            serde_json::from_slice(&fs::read(state_dir.join("meta.json")).unwrap()).unwrap();
        if meta["state"] != "RUNNING" && !state_dir.join("physical-custody").exists() {
            assert_eq!(meta["state"], "DONE", "{meta}");
            assert_eq!(meta["completion_reason"], "exit", "{meta}");
            assert_eq!(meta["rc"], 7, "{meta}");
            assert!(meta["error"].is_null(), "{meta}");
            break;
        }
        assert!(start.elapsed() < DEADLINE, "not terminal: {meta}");
        std::thread::sleep(Duration::from_millis(25));
    }
    assert!(!state_dir.join("output-capture-error.txt").exists());
    let snapshot = agent_bash(temp, None)
        .args(["snapshot", &handle])
        .output()
        .unwrap();
    assert!(snapshot.status.success(), "{snapshot:?}");
    let snapshot: Value = serde_json::from_slice(&snapshot.stdout).unwrap();
    let hex = snapshot["output"].as_str().unwrap();
    let retained = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect();
    Outcome {
        retained,
        state_dir,
    }
}

fn assert_retained_is_exact_interleaving(retained: &[u8], workload: &Workload) {
    let (even, odd): (Vec<u8>, Vec<u8>) = retained.iter().partition(|byte| *byte % 2 == 0);
    assert_eq!(even, workload.stdout, "retained stdout");
    assert_eq!(odd, workload.stderr, "retained stderr");
}

fn export(outcome: &Outcome) -> Value {
    serde_json::from_slice(&fs::read(outcome.state_dir.join("fixture-live-capture.json")).unwrap())
        .unwrap()
}

fn records(export: &Value) -> Vec<(u64, String, Vec<u8>)> {
    export["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|record| {
            let bytes = record["bytes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|b| b.as_u64().unwrap() as u8)
                .collect();
            (
                record["start"]["seq"].as_u64().unwrap(),
                record["channel"].as_str().unwrap().to_string(),
                bytes,
            )
        })
        .collect()
}

fn channel(records: &[(u64, String, Vec<u8>)], name: &str) -> Vec<u8> {
    records
        .iter()
        .filter(|(_, channel, _)| channel == name)
        .flat_map(|(_, _, bytes)| bytes.iter().copied())
        .collect()
}

fn n(value: &Value) -> u64 {
    value.as_u64().unwrap()
}

#[test]
fn absent_capture_keeps_raw_drain_retention_terminal_and_custody() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let (workload, argv) = workload(temp.path());
    let outcome = run(&temp, None, &argv);
    assert_retained_is_exact_interleaving(&outcome.retained, &workload);
    assert!(!outcome.state_dir.join("fixture-live-capture.json").exists());
}

#[test]
fn roomy_capture_mirrors_retained_order_without_gap() {
    if test_support::private_case() {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let (workload, argv) = workload(temp.path());
    let outcome = run(&temp, Some("live-capture:16777216"), &argv);
    assert_retained_is_exact_interleaving(&outcome.retained, &workload);
    let export = export(&outcome);
    assert!(export["gap"].is_null(), "{}", export["gap"]);
    let records = records(&export);
    // Same supervisor read order as the retained log, chunk by chunk.
    let mirrored: Vec<u8> = records.iter().flat_map(|r| r.2.iter().copied()).collect();
    assert_eq!(mirrored, outcome.retained);
    for (index, record) in records.iter().enumerate() {
        assert_eq!(record.0, index as u64);
    }
    assert_eq!(channel(&records, "stdout"), workload.stdout);
    assert_eq!(channel(&records, "stderr"), workload.stderr);
    assert_eq!(n(&export["next"]["seq"]), records.len() as u64);
}

#[test]
fn overflowing_capture_reports_exact_gap_and_never_touches_custody() {
    if test_support::private_case() {
        return;
    }
    // Smaller than one 8 KiB drain chunk, then a few chunks, then 64 KiB.
    for budget in [1_000_u64, 20_000, 65_536] {
        let temp = tempfile::tempdir().unwrap();
        let (workload, argv) = workload(temp.path());
        let outcome = run(&temp, Some(&format!("live-capture:{budget}")), &argv);
        assert_retained_is_exact_interleaving(&outcome.retained, &workload);
        let export = export(&outcome);
        let records = records(&export);
        let gap = &export["gap"];
        assert_eq!(n(&gap["from"]["seq"]), 0, "{budget}: {gap}");
        let next = &export["next"];
        assert_eq!(
            n(&gap["to"]["seq"]) + records.len() as u64,
            n(&next["seq"]),
            "{budget}"
        );
        let charged: u64 = records
            .iter()
            .map(|r| r.2.len() as u64 + RECORD_CHARGE)
            .sum();
        assert_eq!(charged, n(&export["charged"]));
        assert!(charged <= budget, "{budget}: {charged}");
        let lost_out = n(&gap["to"]["stdout_bytes"]) as usize;
        let lost_err = n(&gap["to"]["stderr_bytes"]) as usize;
        assert!(lost_out + lost_err > 0, "{budget}");
        assert_eq!(channel(&records, "stdout"), workload.stdout[lost_out..]);
        assert_eq!(channel(&records, "stderr"), workload.stderr[lost_err..]);
        assert_eq!(n(&next["stdout_bytes"]), workload.stdout.len() as u64);
        assert_eq!(n(&next["stderr_bytes"]), workload.stderr.len() as u64);
        let mirrored: Vec<u8> = records.iter().flat_map(|r| r.2.iter().copied()).collect();
        assert!(outcome.retained.ends_with(&mirrored), "{budget}");
    }
}
