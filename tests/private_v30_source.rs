#![cfg(all(target_os = "linux", feature = "private-v30-admission"))]

use std::path::Path;
use std::process::{Command, Output};

fn private_entry(root: &Path, nested_parent: bool, helper: &Path) -> Output {
    let binary = env!("CARGO_BIN_EXE_agent-bash");
    let direct = r#""$1" __age319-private-v30-source-prep-v1 "$2" -- /bin/true; true"#;
    let script = if nested_parent {
        r#"sh -c '"$1" __age319-private-v30-source-prep-v1 "$2" -- /bin/true; true' sh "$1" "$2"; true"#
    } else {
        direct
    };
    Command::new("unshare")
        .args(["-Urpfm", "--mount-proc", "sh", "-c", script, "sh", binary])
        .arg(root)
        .env("XDG_STATE_HOME", root)
        .env("XDG_CONFIG_HOME", root)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", helper)
        .env_remove("OULIPOLY_KERNEL_EXPECTED_ROOT_V1")
        .env_remove("OULIPOLY_KERNEL_OWNER_ENDPOINT_V1")
        .env_remove("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1")
        .output()
        .expect("run private namespace source control")
}

fn assert_refusal(output: &Output, root: &Path, reason: &str) {
    assert!(
        output.status.success(),
        "namespace wrapper failed: {output:?}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains(reason), "{output:?}");
    assert!(
        !root.join("agent-bash").exists(),
        "refusal allocated a handle"
    );
    assert!(!root.join("source-ready").exists());
}

#[test]
fn private_source_requires_direct_work_pid1_before_handle() {
    let root = tempfile::tempdir().unwrap();
    let output = private_entry(root.path(), true, Path::new("/bin/true"));
    assert_refusal(&output, root.path(), "direct child of work PID1");
}

#[test]
fn private_source_rejects_unpinned_helper_before_handle() {
    let root = tempfile::tempdir().unwrap();
    let output = private_entry(root.path(), false, Path::new("/bin/true"));
    assert_refusal(&output, root.path(), "Runner helper image is not pinned");
}

#[test]
fn private_source_rejects_missing_selector_and_endpoint_before_handle() {
    let Some(helper) = std::env::var_os("AGE319_PRIVATE_V30_PINNED_RUNNER_IMAGE") else {
        return;
    };
    let root = tempfile::tempdir().unwrap();
    let output = private_entry(root.path(), false, Path::new(&helper));
    assert_refusal(&output, root.path(), "EXPECTED_ROOT_V1 absent");

    let output = Command::new("unshare")
        .args([
            "-Urpfm",
            "--mount-proc",
            "sh",
            "-c",
            r#""$1" __age319-private-v30-source-prep-v1 "$2" -- /bin/true; true"#,
            "sh",
            env!("CARGO_BIN_EXE_agent-bash"),
        ])
        .arg(root.path())
        .env("XDG_STATE_HOME", root.path())
        .env("XDG_CONFIG_HOME", root.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", helper)
        .env(
            "OULIPOLY_KERNEL_EXPECTED_ROOT_V1",
            "11111111-1111-4111-8111-111111111111",
        )
        .env(
            "OULIPOLY_KERNEL_OWNER_ENDPOINT_V1",
            root.path().join("absent-guardian.sock"),
        )
        .env(
            "OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1",
            root.path().join("absent-broker.sock"),
        )
        .output()
        .unwrap();
    assert_refusal(&output, root.path(), "challenged capability refused");
}
