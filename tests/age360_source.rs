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

#[test]
#[cfg(feature = "source-fault-tests")]
fn cancellation_between_metadata_and_source_publication() {
    case("publication-race");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn publication_failure_keeps_live_observer_and_original_ready_output() {
    case("publication-error");
}
#[test]
fn ready_exit_before_sentinel_preserves_raw_wait() {
    case("early-ready-exit");
}

#[test]
#[cfg(feature = "source-fault-tests")]
fn real_publication_io_failure_keeps_live_output_and_recovers_hashes() {
    case("publication-io-error");
}

#[test]
fn large_escaped_output_publishes_full_artifact_and_keeps_live_observer() {
    case("large-escaped");
}

#[test]
fn configured_large_invalid_utf8_output_publishes_exact_full_raw_artifact() {
    case("large-raw");
}

#[test]
#[cfg(feature = "source-fault-tests")]
fn hashing_yields_to_live_output_and_cancellation_without_relabeling_ready() {
    case("large-hash");
}

#[test]
#[cfg(feature = "source-fault-tests")]
fn stopped_recovery_does_not_block_original_output_publication_or_cancel() {
    case("recovery-lock");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn header_only_owner_loss_records_actual_guardian_drain_not_delivery() {
    case("header-only-loss");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn pre_capture_retry_keeps_original_selection_across_rollover() {
    case("pre-capture-rollover");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn pre_capture_owner_loss_recovers_pinned_original_selection() {
    case("pre-capture-owner-loss");
}

#[test]
#[cfg(feature = "source-fault-tests")]
fn transient_selected_read_denial_after_owner_loss_remains_pending_then_recovers() {
    case("transient-read-loss");
}

#[test]
#[cfg(feature = "source-fault-tests")]
fn selection_without_header_preserves_original_event_after_guardian_drain() {
    case("selection-before-header");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn guardian_open_descriptor_excludes_loss_proof_without_blocking_recovery() {
    case("capture-open");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn dead_guardian_completed_copy_recovers_without_selected_path() {
    case("capture-complete");
}
#[test]
#[cfg(feature = "source-fault-tests")]
fn dead_guardian_partial_copy_is_not_complete_or_permanent_pending() {
    case("capture-partial");
}
