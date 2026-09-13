//! Source custody for the runner-owned notification continuation. No workload
//! argv or launch operation is reachable from completion-only recovery.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::state::{self, CallerChainEntry, Meta, StatePaths};

pub(crate) const PROTOCOL: &str = "completion-continuation-v2";
pub(crate) const REGISTRATION: &str = "source-registration-v2.json";
pub(crate) const OUTCOME: &str = "source-outcome-v2.json";
pub(crate) const SNAPSHOT: &str = "completion-snapshot-v2.json";
const FENCE: &str = "source-launch-v2.json";
const CONFIRMATION: &str = "registration-confirmation-v2.json";
const LOCAL: &str = "continuation-v2.json";
const MAX_SOURCE: u64 = 1024 * 1024;

pub(crate) fn error(detail: impl Into<String>) -> io::Error {
    io::Error::other(detail.into())
}
pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
pub(crate) fn bytes(value: &Value) -> io::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}
pub(crate) fn read(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > max {
        return Err(error("source is not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err(error("source exceeds bound"));
    }
    Ok(bytes)
}
fn value(path: &Path) -> io::Result<Value> {
    Ok(serde_json::from_slice(&read(path, MAX_SOURCE)?)?)
}
fn save(paths: &StatePaths, name: &str, value: &Value) -> io::Result<()> {
    state::atomic_write(&paths.state_dir.join(name), &bytes(value)?)
}
fn immutable(paths: &StatePaths, name: &str, data: &[u8]) -> io::Result<()> {
    let destination = paths.state_dir.join(name);
    if destination.try_exists()? {
        if read(&destination, 32 * MAX_SOURCE)? == data {
            return Ok(());
        }
        return Err(error(format!("immutable source conflict: {name}")));
    }
    let temp = paths.state_dir.join(format!(
        ".{name}.{}",
        state::generate_handle().map_err(io::Error::other)?
    ));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    file.write_all(data)?;
    file.sync_all()?;
    let linked = fs::hard_link(&temp, &destination);
    fs::remove_file(temp)?;
    if let Err(err) = linked
        && (err.kind() != io::ErrorKind::AlreadyExists
            || read(&destination, 32 * MAX_SOURCE)? != data)
    {
        return Err(err);
    }
    File::open(&paths.state_dir)?.sync_all()
}
pub(crate) fn enabled(paths: &StatePaths) -> bool {
    // Any unreadable registration is retained, not mistaken for legacy state.
    !matches!(fs::symlink_metadata(paths.state_dir.join(REGISTRATION)), Err(e) if e.kind() == io::ErrorKind::NotFound)
}
fn lock(paths: &StatePaths) -> io::Result<File> {
    named_lock(paths, "launch.lock")
}
fn named_lock(paths: &StatePaths, name: &str) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(paths.state_dir.join(name))?;
    loop {
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(file);
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
}
fn identity(pid: i32) -> io::Result<CallerChainEntry> {
    let boot_id = state::current_boot_id();
    let starttime_ticks =
        state::process_starttime_ticks(pid).ok_or_else(|| error("process identity unavailable"))?;
    if boot_id.is_empty() {
        return Err(error("boot identity unavailable"));
    }
    Ok(CallerChainEntry {
        pid,
        boot_id,
        starttime_ticks,
    })
}
fn uuid() -> io::Result<String> {
    Ok(fs::read_to_string("/proc/sys/kernel/random/uuid")?
        .trim()
        .to_owned())
}
fn common(registration: &Value, digest: &str) -> Value {
    let mut result = json!({"registration_digest": digest});
    for key in [
        "protocol",
        "domain_id",
        "source_id",
        "handle",
        "registration_id",
    ] {
        result[key] = registration[key].clone();
    }
    result
}
fn binding(paths: &StatePaths) -> io::Result<(Value, Value)> {
    let data = read(&paths.state_dir.join(REGISTRATION), MAX_SOURCE)?;
    let registration: Value = serde_json::from_slice(&data)?;
    if registration["protocol"] != PROTOCOL
        || registration["handle"] != paths.handle
        || registration["handle_dir"].as_str() != paths.state_dir.to_str()
    {
        return Err(error("registration source binding conflict"));
    }
    for (key, expected) in [
        ("meta_relative", "meta.json"),
        ("log_relative", "log"),
        ("rc_relative", "rc"),
        ("registration_relative", REGISTRATION),
        ("outcome_relative", OUTCOME),
        ("snapshot_relative", SNAPSHOT),
    ] {
        if registration[key] != expected {
            return Err(error(format!("source path conflict: {key}")));
        }
    }
    if registration["spool_root"].as_str() != paths.root.to_str()
        || registration["source_evidence_protocol"] != PROTOCOL
    {
        return Err(error("source root/protocol conflict"));
    }
    let common = common(&registration, &digest(&data));
    exact(&common, &common)?;
    Ok((registration, common))
}
fn exact(common: &Value, reply: &Value) -> io::Result<()> {
    for (key, expected) in common
        .as_object()
        .ok_or_else(|| error("invalid identity"))?
    {
        if expected.is_null() || reply.get(key) != Some(expected) {
            return Err(error(format!("continuation identity conflict: {key}")));
        }
    }
    Ok(())
}

/// Called in the original registration worker, before admitting its helper.
pub(crate) fn prepare(
    paths: &StatePaths,
    meta: &Meta,
    domain: &str,
    scope: &str,
) -> io::Result<()> {
    let helper = meta
        .delivery_helper
        .as_ref()
        .ok_or_else(|| error("missing pinned helper"))?;
    let session = meta
        .owner_session_id
        .as_ref()
        .ok_or_else(|| error("missing owner session"))?;
    let invocation = meta
        .owner_invocation_uuid
        .as_ref()
        .ok_or_else(|| error("missing owner invocation"))?;
    if fs::canonicalize(&paths.state_dir)? != paths.state_dir
        || !helper
            .environment_sha256
            .as_deref()
            .is_some_and(valid_digest)
    {
        return Err(error(
            "noncanonical source directory or missing sealed environment",
        ));
    }
    let recovery_path = paths.state_dir.join("agent-bash-recovery-v2");
    // /proc/self/exe pins the actually executing image, not a mutable PATH name.
    let mut source = File::open("/proc/self/exe")?;
    let mut recovery = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o500)
        .open(&recovery_path)?;
    io::copy(&mut source, &mut recovery)?;
    recovery.sync_all()?;
    let recovery_hash = digest(&read(&recovery_path, 512 * MAX_SOURCE)?);
    let worker = identity(unsafe { libc::getpid() })?;
    let registration = json!({
        "protocol": PROTOCOL, "domain_id": domain, "source_id": uuid()?, "registration_id": uuid()?,
        "handle": paths.handle, "handle_dir": paths.state_dir, "spool_root": paths.state_dir.parent(),
        "meta_relative": "meta.json", "log_relative": "log", "rc_relative": "rc",
        "registration_relative": REGISTRATION, "outcome_relative": OUTCOME, "snapshot_relative": SNAPSHOT,
        "owner_session_id": session, "owner_invocation_uuid": invocation, "registering_caller": worker,
        "delivery_mode": meta.delivery_mode.as_str(), "completion_kind": meta.mode, "completion_scope": scope,
        "helper": {"path":helper.path, "sha256":helper.sha256, "environment_sha256":helper.environment_sha256},
        "recovery": {"path":recovery_path, "sha256":recovery_hash, "environment_sha256":helper.environment_sha256},
        "source_evidence_protocol": PROTOCOL, "listener_revision":1,
        "listeners":[{"listener_id":invocation,"session_id":session,"owner_invocation_uuid":invocation}]
    });
    let data = bytes(&registration)?;
    let mut fence = common(&registration, &digest(&data));
    fence["revision"] = json!(0);
    fence["phase"] = json!("unreleased");
    fence["registration_worker"] = json!(worker);
    fence["workload_identity"] = Value::Null;
    let _lock = lock(paths)?;
    immutable(paths, REGISTRATION, &data)?;
    immutable(paths, FENCE, &bytes(&fence)?)?;
    let mut local = common(&registration, &digest(&data));
    local["registration"] = json!("intent");
    local["enqueue"] = json!("waiting_evidence");
    save(paths, LOCAL, &local)
}

pub(crate) fn confirm_launch(paths: &StatePaths, reply: &Value) -> io::Result<()> {
    let (registration, common) = binding(paths)?;
    exact(&common, reply)?;
    if !matches!(
        reply["status"].as_str(),
        Some("registered" | "already_registered")
    ) || reply["registration_committed"] != true
        || reply["continuation_owner_domain"] != common["domain_id"]
        || reply["listener_revision"] != registration["listener_revision"]
        || reply["listeners"] != registration["listeners"]
    {
        return Err(error("not an exact committed registration receipt"));
    }
    let _lock = lock(paths)?;
    let mut fence = value(&paths.state_dir.join(FENCE))?;
    exact(&common, &fence)?;
    let worker: CallerChainEntry = serde_json::from_value(fence["registration_worker"].clone())?;
    if worker != identity(unsafe { libc::getpid() })? || fence["phase"] != "unreleased" {
        return Err(error("original launch authority is not spendable"));
    }
    immutable(paths, "registration-receipt-v2.json", &bytes(reply)?)?;
    transition(paths, &mut fence, "may_launch")?;
    let _local_lock = named_lock(paths, "continuation.lock")?;
    let mut local = value(&paths.state_dir.join(LOCAL))?;
    local["registration"] = json!("confirmed");
    save(paths, LOCAL, &local)
}
fn transition(paths: &StatePaths, fence: &mut Value, phase: &str) -> io::Result<()> {
    let revision = fence["revision"]
        .as_u64()
        .ok_or_else(|| error("invalid launch revision"))?;
    fence["revision"] = json!(
        revision
            .checked_add(1)
            .ok_or_else(|| error("launch revision overflow"))?
    );
    fence["phase"] = json!(phase);
    save(paths, FENCE, fence)
}
pub(crate) fn abandon(paths: &StatePaths) -> io::Result<()> {
    if !enabled(paths) {
        return Ok(());
    }
    let _lock = lock(paths)?;
    let (_, common) = binding(paths)?;
    let mut fence = value(&paths.state_dir.join(FENCE))?;
    exact(&common, &fence)?;
    let worker: CallerChainEntry = serde_json::from_value(fence["registration_worker"].clone())?;
    if worker == identity(unsafe { libc::getpid() })? && fence["phase"] == "unreleased" {
        transition(paths, &mut fence, "revoked_never_launched")?;
    }
    Ok(())
}
pub(crate) fn launched(paths: &StatePaths, pid: i32) -> io::Result<()> {
    if !enabled(paths) {
        return Ok(());
    }
    let _lock = lock(paths)?;
    let (_, common) = binding(paths)?;
    let mut fence = value(&paths.state_dir.join(FENCE))?;
    exact(&common, &fence)?;
    if fence["phase"] != "may_launch" {
        return Err(error("launch fence conflict"));
    }
    fence["workload_identity"] = json!(identity(pid)?);
    transition(paths, &mut fence, "launched")
}

/// Evidence supplied only by the original live loop or actual adopting guardian.
pub(crate) struct Observation<'a> {
    pub(crate) kind: &'a str,
    pub(crate) root_wait_status: Option<i32>,
    pub(crate) tree_drained: bool,
    pub(crate) output_closed: bool,
    pub(crate) ready_sentinel: Option<&'a str>,
}
pub(crate) fn publish(
    paths: &StatePaths,
    meta: &Meta,
    observation: Observation<'_>,
) -> io::Result<()> {
    if !enabled(paths) {
        return Ok(());
    }
    // Caller owns completion.lock. A prior original observation is immutable;
    // diagnostic metadata and subsequent cancellation never relabel that event.
    if paths
        .state_dir
        .join("completion-source-bundle-v2.json")
        .try_exists()?
    {
        return finish_snapshot(paths);
    }
    let (_, common) = binding(paths)?;
    let fence = value(&paths.state_dir.join(FENCE))?;
    exact(&common, &fence)?;
    let mut outcome = common;
    outcome["completion_revision"] = json!(1);
    outcome["launch_fence_revision"] = fence["revision"].clone();
    outcome["kind"] = json!(observation.kind);
    outcome["root_wait_status"] = json!(observation.root_wait_status);
    outcome["original_tree_drained"] = json!(observation.tree_drained);
    outcome["output_closed"] = json!(observation.output_closed);
    outcome["observer"] = json!(identity(unsafe { libc::getpid() })?);
    outcome["ready_sentinel"] = json!(observation.ready_sentinel);
    outcome["cancellation_id"] = if observation.kind == "cancelled" {
        json!(cancellation_identity(paths, meta)?)
    } else {
        Value::Null
    };
    // Retain the snapshot's event data before publishing its outcome. Recovery
    // must not reconstruct it from mutable list/status metadata or a changing log.
    let output = read(&paths.log, 16 * MAX_SOURCE)?;
    let mut snapshot = outcome_identity(&outcome);
    snapshot["rc"] = json!(meta.rc);
    snapshot["status"] = json!(if observation.kind == "ready" {
        "ready"
    } else if matches!(
        observation.kind,
        "never_launched" | "ceased_status_unknown" | "cancelled"
    ) {
        "error"
    } else {
        "completed"
    });
    snapshot["output"] = json!(String::from_utf8_lossy(&output));
    let outcome_bytes = bytes(&outcome)?;
    snapshot["outcome_sha256"] = json!(digest(&outcome_bytes));
    snapshot["outcome_byte_len"] = json!(outcome_bytes.len());
    if bytes(&snapshot)?.len() as u64 > 16 * MAX_SOURCE {
        return Err(error(
            "full event snapshot exceeds paired bound; retained source needs disposition",
        ));
    }
    immutable(
        paths,
        "completion-source-bundle-v2.json",
        &bytes(&json!({
            "outcome_bytes_utf8": String::from_utf8(outcome_bytes).map_err(io::Error::other)?,
            "snapshot_bytes_utf8": String::from_utf8(bytes(&snapshot)?).map_err(io::Error::other)?
        }))?,
    )?;
    finish_snapshot(paths)
}
fn cancellation_identity(paths: &StatePaths, meta: &Meta) -> io::Result<String> {
    let (_, mut receipt) = binding(paths)?;
    if state::durable_marker_exists(&paths.accepted_cancel)? {
        receipt["basis"] = json!("explicit_request");
        receipt["request_sha256"] = json!(digest(&read(&paths.accepted_cancel, MAX_SOURCE)?));
    } else if meta.completion_reason.as_deref() == Some("owner-exit") && meta.cancel_owner.is_some()
    {
        // The founding observer accepted the already registered owner lease.
        // Do not fabricate an explicit user cancellation marker for this cause.
        receipt["basis"] = json!("registered_owner_lease");
        receipt["owner_identity"] = json!(meta.cancel_owner);
    } else {
        return Err(error("missing accepted cancellation basis"));
    }
    let data = bytes(&receipt)?;
    immutable(paths, "source-cancellation-v2.json", &data)?;
    Ok(digest(&data))
}

fn outcome_identity(outcome: &Value) -> Value {
    let mut identity = json!({});
    for key in [
        "protocol",
        "domain_id",
        "source_id",
        "handle",
        "registration_id",
        "registration_digest",
        "completion_revision",
    ] {
        identity[key] = outcome[key].clone();
    }
    identity
}
fn finish_snapshot(paths: &StatePaths) -> io::Result<()> {
    let bundle: Value = serde_json::from_slice(&read(
        &paths.state_dir.join("completion-source-bundle-v2.json"),
        32 * MAX_SOURCE,
    )?)?;
    let outcome = bundle["outcome_bytes_utf8"]
        .as_str()
        .ok_or_else(|| error("missing bundled outcome"))?
        .as_bytes();
    let snapshot = bundle["snapshot_bytes_utf8"]
        .as_str()
        .ok_or_else(|| error("missing bundled snapshot"))?
        .as_bytes();
    let parsed: Value = serde_json::from_slice(snapshot)?;
    let outcome_value: Value = serde_json::from_slice(outcome)?;
    let (_, common) = binding(paths)?;
    exact(&common, &parsed)?;
    exact(&common, &outcome_value)?;
    if parsed["outcome_sha256"] != digest(outcome) || parsed["outcome_byte_len"] != outcome.len() {
        return Err(error("snapshot/outcome conflict"));
    }
    immutable(paths, OUTCOME, outcome)?;
    immutable(paths, SNAPSHOT, snapshot)
}

/// Local enqueue duty may end at durable runner custody, never at listener ACK.
pub(crate) fn handed_off(paths: &StatePaths) -> io::Result<bool> {
    let (_, common) = binding(paths)?;
    let local = value(&paths.state_dir.join(LOCAL))?;
    exact(&common, &local)?;
    Ok(matches!(
        local["registration"].as_str(),
        Some("confirmed" | "completion_only_confirmed")
    ) && paths.state_dir.join(SNAPSHOT).try_exists()?)
}
pub(crate) fn accept(paths: &StatePaths, reply: &Value) -> io::Result<()> {
    let (registration, common) = binding(paths)?;
    exact(&common, reply)?;
    if !matches!(
        reply["status"].as_str(),
        Some("accepted" | "already_accepted")
    ) || reply["snapshot_sha256"]
        != digest(&read(&paths.state_dir.join(SNAPSHOT), 16 * MAX_SOURCE)?)
        || reply["outcome_sha256"] != digest(&read(&paths.state_dir.join(OUTCOME), MAX_SOURCE)?)
        || !reply["payload_sha256"].as_str().is_some_and(valid_digest)
        || reply["payload_byte_len"].as_u64().is_none()
        || reply["listener_revision"].as_u64().is_none_or(|revision| {
            revision
                < registration["listener_revision"]
                    .as_u64()
                    .unwrap_or(u64::MAX)
        })
    {
        return Err(error("not an exact completion acceptance receipt"));
    }
    let _local_lock = named_lock(paths, "continuation.lock")?;
    let mut local = value(&paths.state_dir.join(LOCAL))?;
    for key in [
        "snapshot_sha256",
        "outcome_sha256",
        "payload_sha256",
        "payload_byte_len",
    ] {
        if local.get(key).is_some_and(|prior| prior != &reply[key]) {
            return Err(error("accepted payload conflict"));
        }
        local[key] = reply[key].clone();
    }
    local["enqueue"] = json!("accepted");
    save(paths, LOCAL, &local)
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(crate) fn reconcile(registration_file: &Path, confirmation_file: &Path) -> io::Result<Value> {
    let parent = registration_file
        .parent()
        .ok_or_else(|| error("missing source directory"))?;
    let directory = fs::canonicalize(parent)?;
    if directory != parent
        || registration_file.file_name().and_then(|p| p.to_str()) != Some(REGISTRATION)
    {
        return Err(error("noncanonical registration path"));
    }
    let registration = value(registration_file)?;
    let handle = registration["handle"]
        .as_str()
        .ok_or_else(|| error("missing handle"))?;
    let paths = StatePaths::new(
        directory
            .parent()
            .ok_or_else(|| error("missing spool root"))?
            .to_path_buf(),
        handle.to_owned(),
    );
    let (registration, common) = binding(&paths)?;
    let confirmation = value(confirmation_file)?;
    exact(&common, &confirmation)?;
    if confirmation["status"] != "exact_committed"
        || confirmation["authority"] != "completion_only"
        || confirmation["registration_committed"] != true
    {
        return Err(error("no completion-only authority"));
    }
    if registration["recovery"]["sha256"] != digest(&fs::read("/proc/self/exe")?)
        || registration["recovery"]["environment_sha256"]
            != digest(&read(&paths.delivery_helper_environment, MAX_SOURCE)?)
    {
        return Err(error("pinned recovery identity conflict"));
    }
    {
        let _lock = lock(&paths)?;
        let mut fence = value(&paths.state_dir.join(FENCE))?;
        exact(&common, &fence)?;
        if fence["phase"] == "unreleased" {
            let worker: CallerChainEntry =
                serde_json::from_value(fence["registration_worker"].clone())?;
            if !matches!(
                state::process_identity_evidence(&worker),
                state::ProcessIdentityEvidence::Gone | state::ProcessIdentityEvidence::Mismatch
            ) {
                let mut pending = common.clone();
                pending["status"] = json!("pending");
                pending["reason"] = json!("registration_worker_not_proven_gone");
                return Ok(pending);
            }
            transition(&paths, &mut fence, "revoked_never_launched")?;
        }
        immutable(&paths, CONFIRMATION, &bytes(&confirmation)?)?;
    }
    let _completion = state::lock_completion(&paths)?;
    let local_lock = named_lock(&paths, "continuation.lock")?;
    let mut local = value(&paths.state_dir.join(LOCAL))?;
    local["registration"] = json!("completion_only_confirmed");
    save(&paths, LOCAL, &local)?;
    drop(local_lock);
    let fence = value(&paths.state_dir.join(FENCE))?;
    if fence["phase"] == "revoked_never_launched" && !paths.state_dir.join(OUTCOME).try_exists()? {
        let mut meta = state::read_meta(&paths)?;
        meta.schema_version = 4;
        meta.state = "ERROR".into();
        meta.rc = Some(70);
        meta.completion_reason = Some("registration-never-launched".into());
        meta.completed_at_unix_ms = Some(state::unix_ms());
        publish(
            &paths,
            &meta,
            Observation {
                kind: "never_launched",
                root_wait_status: None,
                tree_drained: true,
                output_closed: true,
                ready_sentinel: None,
            },
        )?;
        state::write_rc_atomic(&paths, 70)?;
        state::write_meta_atomic(&paths, &meta)?;
    }
    if paths
        .state_dir
        .join("completion-source-bundle-v2.json")
        .try_exists()?
    {
        finish_snapshot(&paths)?;
    }
    let mut result = common;
    result["status"] = json!(if paths.state_dir.join(SNAPSHOT).try_exists()? {
        "source_ready"
    } else {
        "pending"
    });
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/age360/paired-wire.json")).unwrap()
    }
    fn source() -> (tempfile::TempDir, StatePaths, Value) {
        let temp = tempfile::tempdir().unwrap();
        let paths = StatePaths::new(temp.path().to_path_buf(), "ab_fixture".into());
        fs::create_dir(&paths.state_dir).unwrap();
        let mut registration = fixture()["registration"].clone();
        registration["handle_dir"] = json!(paths.state_dir);
        registration["spool_root"] = json!(paths.root);
        immutable(&paths, REGISTRATION, &bytes(&registration).unwrap()).unwrap();
        let common = binding(&paths).unwrap().1;
        (temp, paths, common)
    }
    #[test]
    fn canonical_revision_two_exact_byte_digests() {
        let fixture = fixture();
        assert_eq!(fixture["fixture_revision"], 2);
        for (key, receipt, field) in [
            (
                "registration_bytes_utf8",
                "common_identity",
                "registration_digest",
            ),
            ("outcome_bytes_utf8", "accept_response", "outcome_sha256"),
            ("snapshot_bytes_utf8", "accept_response", "snapshot_sha256"),
        ] {
            let data = fixture[key].as_str().unwrap().as_bytes();
            assert_eq!(digest(data), fixture[receipt][field]);
            let parsed: Value = serde_json::from_slice(data).unwrap();
            assert_eq!(bytes(&parsed).unwrap(), data);
        }
        assert_eq!(
            fixture["registration"]["listeners"][0]["listener_id"],
            fixture["registration"]["owner_invocation_uuid"]
        );
    }
    #[test]
    fn every_common_identity_field_is_required() {
        let fixture = fixture();
        let common = &fixture["common_identity"];
        exact(common, &fixture["register_response"]).unwrap();
        for key in common.as_object().unwrap().keys() {
            let mut reply = fixture["register_response"].clone();
            reply.as_object_mut().unwrap().remove(key);
            assert!(exact(common, &reply).is_err(), "missing {key}");
            reply[key] = json!("different");
            assert!(exact(common, &reply).is_err(), "changed {key}");
        }
    }
    #[test]
    fn immutable_publication_does_not_replace_evidence() {
        let (_temp, paths, _) = source();
        immutable(&paths, "evidence", b"first").unwrap();
        immutable(&paths, "evidence", b"first").unwrap();
        assert!(immutable(&paths, "evidence", b"second").is_err());
        assert_eq!(
            read(&paths.state_dir.join("evidence"), 64).unwrap(),
            b"first"
        );
    }
    #[test]
    fn source_reads_reject_symlink_directory_and_oversize() {
        let (_temp, paths, _) = source();
        let link = paths.state_dir.join("link");
        std::os::unix::fs::symlink(paths.state_dir.join(REGISTRATION), &link).unwrap();
        assert!(read(&link, MAX_SOURCE).is_err());
        assert!(read(&paths.state_dir, MAX_SOURCE).is_err());
        assert!(read(&paths.state_dir.join(REGISTRATION), 8).is_err());
    }
    fn fence(paths: &StatePaths, common: &Value, phase: &str) {
        let mut fence = common.clone();
        fence["phase"] = json!(phase);
        fence["revision"] = json!(0);
        fence["registration_worker"] = json!(identity(unsafe { libc::getpid() }).unwrap());
        save(paths, FENCE, &fence).unwrap();
        let mut local = common.clone();
        local["registration"] = json!("intent");
        save(paths, LOCAL, &local).unwrap();
    }
    fn registration_reply(paths: &StatePaths, common: &Value) -> Value {
        let (registration, _) = binding(paths).unwrap();
        let mut reply = common.clone();
        reply["status"] = json!("registered");
        reply["registration_committed"] = json!(true);
        reply["continuation_owner_domain"] = common["domain_id"].clone();
        reply["listener_revision"] = registration["listener_revision"].clone();
        reply["listeners"] = registration["listeners"].clone();
        reply
    }
    #[test]
    fn revoked_fence_blocks_late_successful_worker() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "unreleased");
        abandon(&paths).unwrap();
        let reply = registration_reply(&paths, &common);
        assert!(confirm_launch(&paths, &reply).is_err());
        assert_eq!(
            value(&paths.state_dir.join(FENCE)).unwrap()["phase"],
            "revoked_never_launched"
        );
    }
    #[test]
    fn may_launch_cannot_be_revoked_or_spent_twice() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "unreleased");
        let reply = registration_reply(&paths, &common);
        confirm_launch(&paths, &reply).unwrap();
        abandon(&paths).unwrap();
        assert_eq!(
            value(&paths.state_dir.join(FENCE)).unwrap()["phase"],
            "may_launch"
        );
        assert!(confirm_launch(&paths, &reply).is_err());
    }
    #[test]
    fn registration_rc_zero_or_inexact_listener_is_not_admission() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "unreleased");
        assert!(confirm_launch(&paths, &json!({})).is_err());
        let mut reply = registration_reply(&paths, &common);
        reply["listeners"][0]["listener_id"] = json!("wrong");
        assert!(confirm_launch(&paths, &reply).is_err());
        assert_eq!(
            value(&paths.state_dir.join(FENCE)).unwrap()["phase"],
            "unreleased"
        );
    }
    #[test]
    fn acceptance_binds_full_snapshot_and_payload_not_exit_code() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "may_launch");
        immutable(&paths, OUTCOME, b"outcome").unwrap();
        immutable(&paths, SNAPSHOT, b"snapshot").unwrap();
        let mut reply = common.clone();
        reply["status"] = json!("accepted");
        reply["snapshot_sha256"] = json!(digest(b"snapshot"));
        reply["outcome_sha256"] = json!(digest(b"outcome"));
        reply["payload_sha256"] = json!(digest(b"payload"));
        reply["payload_byte_len"] = json!(7);
        reply["listener_revision"] = json!(1);
        accept(&paths, &reply).unwrap();
        reply["status"] = json!("already_accepted");
        accept(&paths, &reply).unwrap();
        reply["payload_sha256"] = json!(digest(b"changed"));
        assert!(accept(&paths, &reply).is_err());
        assert!(
            !handed_off(&paths).unwrap(),
            "acceptance does not fake registration authority"
        );
    }
    fn recovery_source(phase: &str) -> (tempfile::TempDir, StatePaths, Value) {
        let (temp, paths, _) = source();
        let mut registration = value(&paths.state_dir.join(REGISTRATION)).unwrap();
        fs::write(&paths.delivery_helper_environment, b"{}\n").unwrap();
        registration["recovery"]["sha256"] = json!(digest(&fs::read("/proc/self/exe").unwrap()));
        registration["recovery"]["environment_sha256"] = json!(digest(b"{}\n"));
        // Fixture construction only; production immutable admission never rewrites.
        fs::write(
            paths.state_dir.join(REGISTRATION),
            bytes(&registration).unwrap(),
        )
        .unwrap();
        let common = binding(&paths).unwrap().1;
        fence(&paths, &common, phase);
        let mut confirmation = common.clone();
        confirmation["status"] = json!("exact_committed");
        confirmation["authority"] = json!("completion_only");
        confirmation["registration_committed"] = json!(true);
        save(&paths, "fixture-confirmation.json", &confirmation).unwrap();
        (temp, paths, common)
    }
    #[test]
    fn recovery_live_worker_and_may_launch_both_remain_pending() {
        for phase in ["unreleased", "may_launch", "launched"] {
            let (_temp, paths, common) = recovery_source(phase);
            let reply = reconcile(
                &paths.state_dir.join(REGISTRATION),
                &paths.state_dir.join("fixture-confirmation.json"),
            )
            .unwrap();
            exact(&common, &reply).unwrap();
            assert_eq!(reply["status"], "pending");
            assert_eq!(value(&paths.state_dir.join(FENCE)).unwrap()["phase"], phase);
            assert!(!paths.state_dir.join(OUTCOME).exists());
            assert!(!paths.state_dir.join(SNAPSHOT).exists());
        }
    }
    #[test]
    fn wrong_completion_only_confirmation_never_changes_fence() {
        let (_temp, paths, _) = recovery_source("unreleased");
        let confirmation_path = paths.state_dir.join("fixture-confirmation.json");
        let before = read(&paths.state_dir.join(FENCE), MAX_SOURCE).unwrap();
        let original = value(&confirmation_path).unwrap();
        for (key, invalid) in [
            ("source_id", json!("other")),
            ("status", json!("absent")),
            ("authority", json!("launch")),
            ("registration_committed", json!(false)),
        ] {
            let mut confirmation = original.clone();
            confirmation[key] = invalid;
            fs::write(&confirmation_path, bytes(&confirmation).unwrap()).unwrap();
            assert!(reconcile(&paths.state_dir.join(REGISTRATION), &confirmation_path).is_err());
            assert_eq!(
                read(&paths.state_dir.join(FENCE), MAX_SOURCE).unwrap(),
                before
            );
        }
    }
    #[test]
    fn exact_source_bundle_recovers_interrupted_two_file_publication() {
        let (_temp, paths, common) = source();
        let mut outcome = common.clone();
        outcome["completion_revision"] = json!(1);
        let data = bytes(&outcome).unwrap();
        let mut snapshot = outcome.clone();
        snapshot["outcome_sha256"] = json!(digest(&data));
        snapshot["outcome_byte_len"] = json!(data.len());
        let snapshot_data = bytes(&snapshot).unwrap();
        save(&paths, "completion-source-bundle-v2.json", &json!({"outcome_bytes_utf8":String::from_utf8(data.clone()).unwrap(),"snapshot_bytes_utf8":String::from_utf8(snapshot_data.clone()).unwrap()})).unwrap();
        finish_snapshot(&paths).unwrap();
        assert_eq!(
            read(&paths.state_dir.join(OUTCOME), MAX_SOURCE).unwrap(),
            data
        );
        assert_eq!(
            read(&paths.state_dir.join(SNAPSHOT), MAX_SOURCE).unwrap(),
            snapshot_data
        );
        finish_snapshot(&paths).unwrap();
    }
    #[test]
    fn durable_runner_handoff_preserves_unknown_local_transfer() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "may_launch");
        let mut local = common;
        local["registration"] = json!("confirmed");
        save(&paths, LOCAL, &local).unwrap();
        immutable(&paths, SNAPSHOT, b"retained-source").unwrap();
        let mut meta = Meta::new(
            paths.handle.clone(),
            1,
            1,
            vec![],
            paths.root.clone(),
            "exit",
            state::DeliveryMode::Sync,
            None,
            vec![],
            None,
        );
        meta.delivery.attempted = true;
        meta.delivery.error_code = Some(state::DELIVERY_ATTEMPT_IN_PROGRESS.into());
        state::write_meta_atomic(&paths, &meta).unwrap();
        state::write_delivery_mode_atomic(&paths, state::DeliveryMode::Sync).unwrap();
        assert!(matches!(
            crate::delivery::try_start_completion_delivery(&paths, &mut meta).unwrap(),
            crate::delivery::CompletionStart::Settled
        ));
        assert_eq!(
            meta.delivery.completion_lifecycle(),
            state::CompletionDeliveryLifecycle::NonReplayableUnknownTransfer
        );
        assert_eq!(
            state::read_meta(&paths)
                .unwrap()
                .delivery
                .error_code
                .as_deref(),
            Some(state::DELIVERY_TRANSFER_OUTCOME_UNKNOWN)
        );
    }
}
