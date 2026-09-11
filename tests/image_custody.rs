use std::process::Command;

#[test]
fn tiny_private_tree_custody_and_delivery_processes() {
    // Two readiness rounds (76s each), 10s compile, six 10s teardown/control
    // allowances and 18s cleanup/scheduling headroom. Inner deadlines still apply.
    run_private_fixture("240", "tests/fixtures/image_custody.py");
}

#[test]
fn founding_completion_preserves_image_recovery() {
    run_private_fixture("40", "tests/fixtures/completion_continuity.py");
}

#[test]
fn asynchronous_completion_retains_transfer_and_cleanup_ownership() {
    run_private_fixture("65", "tests/fixtures/completion_ownership.py");
}

#[test]
fn external_completion_and_activation_retain_uncertain_custody() {
    run_private_fixture("65", "tests/fixtures/external_transfer_custody.py");
}

fn run_private_fixture(seconds: &str, fixture: &str) {
    let output = Command::new("timeout")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .args([
            seconds,
            "python3",
            fixture,
            "suite",
            env!("CARGO_BIN_EXE_agent-bash"),
        ])
        .output()
        .expect("run private image fixture");
    assert!(
        output.status.success(),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    println!("{}", String::from_utf8_lossy(&output.stdout));
}
