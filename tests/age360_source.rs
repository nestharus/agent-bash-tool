#[path = "../src/test_support.rs"]
mod test_support;

fn case(name: &str) {
    if test_support::private_case() {
        return;
    }
    let output = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/age360/source_cases.py"
        ))
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(name)
        .arg(assert_cmd::cargo::cargo_bin("agent-bash"))
        .output()
        .expect("private source experiment");
    assert!(
        output.status.success(),
        "{}\nstdout={}\nstderr={}",
        name,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    print!("{}", String::from_utf8_lossy(&output.stdout));
}
#[test]
fn normal_source_acceptance() {
    case("normal");
}
#[test]
fn admitted_lost_reply_never_replays() {
    case("lost-reply");
}
#[test]
fn registration_channel_loss_retains_source() {
    case("channel-loss");
}
#[test]
fn live_registration_worker_cannot_be_revoked() {
    case("blocked-registration");
}
#[test]
fn root_completion_retains_descendant_cancellation() {
    case("root");
}
#[test]
fn ready_is_not_tree_cessation() {
    case("ready");
}
#[test]
fn guardian_cannot_certify_rc70_before_original_drain() {
    case("guardian");
}

#[test]
fn dead_endpoint_rejects_before_admission() {
    case("dead-endpoint");
}
#[test]
fn bounded_source_resource_inventory() {
    case("resources");
}
