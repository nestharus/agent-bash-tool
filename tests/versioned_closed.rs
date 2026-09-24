#[cfg(feature = "age319-closed-fresh")]
#[test]
fn fresh_staging_image_refuses_all_entries_before_state_or_child_effect() {
    use std::fs;
    use std::process::Command;

    let root = tempfile::tempdir().unwrap();
    let marker = root.path().join("child-was-run");
    let binary = env!("CARGO_BIN_EXE_agent-bash");
    for arguments in [
        vec!["run", "--", "/bin/sh", "-c", "touch child-was-run"],
        vec!["list", "--all", "--json"],
        vec!["status", "ab_0123456789abcdef0123456789abcdef"],
        vec!["__root-original-work-v1"],
        vec!["--internal-image-custodian-v1"],
        vec!["__age319-private-admit-child-v1"],
    ] {
        let output = Command::new(binary)
            .args(&arguments)
            .current_dir(root.path())
            .env("XDG_STATE_HOME", root.path())
            .env("AGE319_PRIVATE_BASH_EFFECT_MARKER", &marker)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(69), "{arguments:?}: {output:?}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("AGE-319 fresh entry closed"),
            "{arguments:?}: {output:?}"
        );
        assert!(output.stdout.is_empty());
        assert!(!marker.exists());
        assert!(!root.path().join("agent-bash").exists());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
