use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::Value;

fn agent_bash(temp: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("agent-bash").expect("agent-bash binary");
    cmd.env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true");
    cmd
}

fn run_cmd(temp: &tempfile::TempDir, args: &[&str]) -> (Output, Duration) {
    let start = Instant::now();
    let output = agent_bash(temp).args(args).output().expect("run command");
    (output, start.elapsed())
}

fn parse_run_output(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("run JSON")
}

fn status_text(temp: &tempfile::TempDir, handle: &str, full: bool) -> String {
    let mut cmd = agent_bash(temp);
    cmd.arg("status");
    if full {
        cmd.arg("--full");
    }
    let output = cmd.arg(handle).output().expect("status command");
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("status utf8")
}

fn wait_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert!(Instant::now() < deadline, "timed out after {timeout:?}");
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn wait_for_status_prefix(temp: &tempfile::TempDir, handle: &str, prefix: &str) -> String {
    wait_until(Duration::from_secs(6), || {
        let text = status_text(temp, handle, true);
        if text.starts_with(prefix) {
            Some(text)
        } else {
            None
        }
    })
}

fn meta_path(run_json: &Value) -> PathBuf {
    PathBuf::from(run_json["meta"].as_str().expect("meta path"))
}

fn rc_path(run_json: &Value) -> PathBuf {
    PathBuf::from(run_json["rc"].as_str().expect("rc path"))
}

fn read_meta(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read meta")).expect("meta json")
}

fn kill_process_group(meta: &Value) {
    if let Some(pgid) = meta["workload_pgid"].as_i64() {
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
    }
}

#[test]
fn list_attached_empty_state_is_json_array() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = agent_bash(&temp)
        .args(["list", "--json"])
        .output()
        .expect("list");
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8"), "[]\n");
}

#[test]
fn attached_guard_rejects_detached_invocation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let out = temp.path().join("out");
    let err = temp.path().join("err");
    let bin = assert_cmd::cargo::cargo_bin("agent-bash");
    let script = r#"
(
  (
    trap '' HUP
    sleep 0.2
    XDG_STATE_HOME="$4" AGENT_BASH_AGENT_RUNNER_BIN=/bin/true exec "$3" list --json >"$1" 2>"$2"
  ) &
  exit 0
)
for _ in {1..50}; do
  if [ -s "$2" ]; then exit 0; fi
  sleep 0.1
done
exit 0
"#;
    let status = std::process::Command::new("bash")
        .arg("-c")
        .arg(script)
        .arg("agent-bash-detached-test")
        .arg(&out)
        .arg(&err)
        .arg(&bin)
        .arg(temp.path())
        .status()
        .expect("bash detached helper");
    assert!(status.success(), "detached helper did not finish");
    let stderr = fs::read_to_string(&err).unwrap_or_default();
    if stderr.is_empty() {
        // Some test supervisors are subreapers. The guard cannot prove that case,
        // which is the documented limitation; pure guard tests cover the PID-1 path.
        return;
    }
    assert_eq!(
        stderr,
        "agent-bash: must be called as an attached subprocess\n"
    );
}

#[test]
fn run_returns_immediately_and_later_completes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, elapsed) = run_cmd(&temp, &["run", "--", "bash", "-lc", "sleep 2; echo late"]);
    assert!(elapsed < Duration::from_secs(1), "run took {elapsed:?}");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let immediate = status_text(&temp, handle, false);
    assert!(immediate.starts_with("RUNNING handle="), "{immediate}");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("late\n"), "{final_status}");
}

#[test]
fn exit_mode_completion_rc_and_captured_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(
        &temp,
        &["run", "--", "bash", "-lc", "echo out; echo err >&2; exit 7"],
    );
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=7 handle={handle}"));
    assert!(final_status.contains("out\n"), "{final_status}");
    assert!(final_status.contains("err\n"), "{final_status}");
    assert_eq!(fs::read_to_string(rc_path(&json)).expect("rc"), "7\n");
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["state"], "DONE");
    assert_eq!(meta["completion_reason"], "exit");
    assert_eq!(meta["rc"], 7);
    assert!(
        meta["caller_chain"]
            .as_array()
            .is_some_and(|chain| !chain.is_empty())
    );
}

#[test]
fn ready_sentinel_reports_done_without_killing_workload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(
        &temp,
        &[
            "run",
            "--ready-sentinel",
            "READY:[0-9]+",
            "--",
            "bash",
            "-lc",
            "echo boot; echo READY:123; while true; do sleep 1; done",
        ],
    );
    let json = parse_run_output(&output);
    assert_eq!(json["mode"], "sentinel");
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(
        &temp,
        handle,
        &format!("DONE rc=0 handle={handle} reason=ready-sentinel workload=running"),
    );
    assert!(final_status.contains("boot\n"), "{final_status}");
    assert!(final_status.contains("READY:123\n"), "{final_status}");
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["completion_reason"], "ready-sentinel");
    assert_eq!(meta["rc"], 0);
    assert!(meta["ready_at_unix_ms"].is_number());
    assert!(meta["workload_rc"].is_null());
    kill_process_group(&meta);
}

#[test]
fn tree_capture_waits_for_setsid_detached_grandchild_via_subreaper() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("grandchild-marker");
    let script =
        "(setsid sh -c 'sleep 2; printf grandchild > \"$MARKER\"' >/dev/null 2>&1 &) ; exit 0";
    let mut cmd = agent_bash(&temp);
    cmd.env("MARKER", &marker)
        .args(["run", "--", "bash", "-lc", script]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);

    wait_until(Duration::from_millis(1500), || {
        let meta = read_meta(&meta_path);
        if meta["workload_rc"].as_i64() == Some(0) {
            Some(())
        } else {
            None
        }
    });
    assert!(
        !marker.exists(),
        "grandchild marker appeared before root-only window"
    );
    let running = status_text(&temp, handle, false);
    assert!(running.starts_with("RUNNING handle="), "{running}");

    wait_until(Duration::from_secs(5), || marker.exists().then_some(()));
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.starts_with(&format!("DONE rc=0 handle={handle}")));
    let meta = read_meta(&meta_path);
    assert!(matches!(
        meta["cgroup"]["mode"].as_str(),
        Some("subreaper-only" | "v2")
    ));
}

#[test]
fn cgroup_v2_live_set_path_runs_when_delegated_and_skips_otherwise() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", "sleep 1.5"]);
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    if meta["cgroup"]["mode"] == "subreaper-only" {
        return;
    }
    assert_eq!(meta["cgroup"]["mode"], "v2");
    assert_eq!(meta["cgroup"]["delegated"], true);
    assert_eq!(meta["cgroup"]["events_watch"], true);
    let cgroup_path = PathBuf::from(meta["cgroup"]["path"].as_str().expect("cgroup path"));
    let procs = fs::read_to_string(cgroup_path.join("cgroup.procs")).expect("cgroup.procs");
    let workload_pid = meta["workload_pid"]
        .as_i64()
        .expect("workload pid")
        .to_string();
    assert!(procs.lines().any(|line| line == workload_pid));
}

#[test]
fn cgroup_disable_uses_subreaper_only_without_degradation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_DISABLE_CGROUP", "1")
        .args(["run", "--", "bash", "-lc", "echo ok"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("ok\n"));
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["cgroup"]["mode"], "subreaper-only");
    assert!(meta["cgroup"]["degraded_reason"].is_null());
}

#[test]
fn delivery_seam_records_invocation_outcome() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake = temp.path().join("fake-agents");
    let delivery_log = temp.path().join("delivery.log");
    fs::write(
        &fake,
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$AGENT_BASH_FAKE_DELIVERY_LOG\"\nexit 0\n",
    )
    .expect("write fake");
    let mut perms = fs::metadata(&fake).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake, perms).expect("chmod fake");

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "bash", "-lc", "echo delivered"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    let delivered = wait_until(Duration::from_secs(2), || {
        fs::read_to_string(&delivery_log).ok()
    });
    let lines: Vec<_> = delivered.lines().collect();
    assert_eq!(lines[0], "notify");
    assert_eq!(lines[1], "agent-bash-complete");
    assert!(lines.contains(&"--caller-ppid"));
    assert!(lines.contains(&"--handle"));
    assert!(lines.contains(&handle));
    assert!(lines.contains(&"--meta"));
    assert!(lines.contains(&json["meta"].as_str().expect("meta")));
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
}
