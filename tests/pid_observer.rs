use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

const TEST: &str = "cross_pid_namespace_parent_uses_observer_identity";
const INVOCATION: &str = "11111111-1111-4111-8111-111111111111";

#[test]
fn cross_pid_namespace_parent_uses_observer_identity() {
    match env::var("AGE319_PID_OBSERVER_STAGE").ok().as_deref() {
        Some("pid1") => pid1_case(),
        Some("driver") => driver_case(),
        Some("sibling") => sibling_case(),
        None => outer_case(),
        _ => panic!("unexpected PID observer fixture stage"),
    }
}

fn outer_case() {
    let home = tempfile::tempdir().unwrap();
    let helper = home.path().join("helper");
    fs::write(
        &helper,
        r#"#!/bin/sh
if [ "${1:-}" = session ] && [ "${2:-}" = of-pid ]; then
    printf '%s\n' "${3:-}" >> "$AGE319_HELPER_LOG"
    if [ "${3:-}" = "$AGE319_EXPECTED_PARENT" ]; then
        printf '{"found":true,"invocation_uuid":"11111111-1111-4111-8111-111111111111","session_id":"session-root"}\n'
        exit 0
    fi
    printf '{"found":false,"invocation_uuid":null,"session_id":null}\n'
    exit 1
fi
exit 0
"#,
    )
    .unwrap();
    let mut perms = fs::metadata(&helper).unwrap().permissions();
    perms.set_mode(0o700);
    fs::set_permissions(&helper, perms).unwrap();
    let output = Command::new("timeout")
        .args([
            "--kill-after=5s",
            "45s",
            "unshare",
            "--user",
            "--map-current-user",
            "--pid",
            "--fork",
            "--",
        ])
        .arg(env::current_exe().unwrap())
        .args(["--exact", TEST, "--nocapture"])
        .env("AGE319_PID_OBSERVER_STAGE", "pid1")
        .env("AGE319_PID_OBSERVER_HOME", home.path())
        .env("AGE319_PID_OBSERVER_HELPER", &helper)
        .env("AGE319_PID_OBSERVER_BASH", env!("CARGO_BIN_EXE_agent-bash"))
        .output()
        .unwrap();
    assert_success(&output);
}

fn pid1_case() {
    let home = fixture_home();
    let helper_log = home.join("helper.log");
    // PID1 has no attached local parent. It must refuse before helper lookup.
    let unattached = bash_command(&home)
        .env("AGE319_HELPER_LOG", &helper_log)
        .args(["run", "--", "/bin/true"])
        .output()
        .unwrap();
    assert!(!unattached.status.success());
    assert!(!helper_log.exists());

    let mut driver = stage_command("driver").spawn().unwrap();
    wait_for(&home.join("handle"));
    let sibling = stage_command("sibling").output().unwrap();
    assert_success(&sibling);
    fs::write(home.join("release"), "").unwrap();
    assert!(driver.wait().unwrap().success());
}

fn driver_case() {
    let home = fixture_home();
    let local_parent = std::process::id();
    let observer_parent = observer_self_pid();
    assert_ne!(
        local_parent, observer_parent,
        "fixture must cross PID domains"
    );
    fs::write(home.join("expected-parent"), observer_parent.to_string()).unwrap();
    let helper_log = home.join("helper.log");
    let output = bash_command(&home)
        .env("AGE319_HELPER_LOG", &helper_log)
        .env("AGE319_EXPECTED_PARENT", observer_parent.to_string())
        .env("AGENT_BASH_OWNER_SESSION_ID", "session-root")
        .env("AGENT_BASH_OWNER_INVOCATION_UUID", INVOCATION)
        .env("OULIPOLY_ORIGINAL_WORK_REQUIRED_V1", "1")
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            format!(r#"{{"source":"fixture","id":"{INVOCATION}"}}"#),
        )
        .args([
            "run",
            "--delivery",
            "async",
            "--cancel-on-owner-exit",
            "--owner-pid",
            &local_parent.to_string(),
            "--",
            "/bin/sleep",
            "30",
        ])
        .output()
        .unwrap();
    // A required paired source with no grant refuses after caller identity
    // and owner lookup. This fixture cannot claim broker admission.
    assert!(
        !output.status.success(),
        "unexpected standalone launch: {output:?}"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("paired original-work context is required"),
        "{output:?}"
    );
    let state_root = home.join("agent-bash");
    let handle_dir = fs::read_dir(&state_root)
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("ab_")
        })
        .unwrap();
    let meta: Value =
        serde_json::from_slice(&fs::read(handle_dir.join("meta.json")).unwrap()).unwrap();
    assert_eq!(meta["caller_ppid"], observer_parent);
    assert_eq!(meta["caller_chain"][0]["pid"], observer_parent);
    assert_eq!(meta["cancel_owner"]["pid"], observer_parent);
    assert_eq!(meta["owner_session_id"], "session-root");
    assert_eq!(
        fs::read_to_string(&helper_log).unwrap().trim(),
        observer_parent.to_string()
    );
    fs::write(home.join("handle"), meta["handle"].as_str().unwrap()).unwrap();
    wait_for(&home.join("release"));
}

fn sibling_case() {
    let home = fixture_home();
    let handle = fs::read_to_string(home.join("handle")).unwrap();
    let output = bash_command(&home)
        .args(["cancel", &handle])
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "sibling controlled handle: {output:?}"
    );
    assert!(String::from_utf8_lossy(&output.stderr).contains("not eligible"));
}

fn bash_command(home: &Path) -> Command {
    let mut command = Command::new(env::var_os("AGE319_PID_OBSERVER_BASH").unwrap());
    command
        .env("XDG_STATE_HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env(
            "AGENT_BASH_AGENT_RUNNER_BIN",
            env::var_os("AGE319_PID_OBSERVER_HELPER").unwrap(),
        );
    command
}

fn stage_command(stage: &str) -> Command {
    let mut command = Command::new(env::current_exe().unwrap());
    command.args(["--exact", TEST, "--nocapture"]);
    command.env("AGE319_PID_OBSERVER_STAGE", stage);
    command
}

fn fixture_home() -> PathBuf {
    PathBuf::from(env::var_os("AGE319_PID_OBSERVER_HOME").unwrap())
}

fn observer_self_pid() -> u32 {
    fs::read_to_string("/proc/self/stat")
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap()
}

fn wait_for(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for {}",
            path.display()
        );
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "status={} stdout={} stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
