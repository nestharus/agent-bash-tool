//! Source custody for the runner-owned notification continuation. No workload
//! argv or launch operation is reachable from completion-only recovery.
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

mod capture;
mod missing_output;
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
pub(crate) const RETENTION_RELEASE: &str = "source-retention-release-v1.json";
const MAX_SOURCE: u64 = 1024 * 1024;
const MAX_OUTPUT: u64 = 1024 * MAX_SOURCE;
const INLINE_OUTPUT: u64 = 64 * 1024;
const OUTPUT: &str = "completion-output-v2.bin";
const SELECTION: &str = "output-selection-v2.json";
const SELECTED_LOG: &str = "selected-log-v2.bin";

/// Select once, in the original event turn, before any retry can collect output.
/// The logger replaces (never truncates) an inode pinned by this hard link.
/// A failed selection is explicit missing evidence, not permission to resample.
#[cfg(test)]
fn select_output(paths: &StatePaths) -> io::Result<()> {
    select_event_output(paths, None)
}
fn select_event_output(paths: &StatePaths, observation: Option<&Value>) -> io::Result<()> {
    if !enabled(paths) || paths.state_dir.join(SELECTION).try_exists()? {
        return Ok(());
    }
    let directory = fs::metadata(&paths.state_dir)?;
    let mut selection = match pin_output(paths) {
        Ok(selection) => selection,
        Err(err) => json!({"missing": err.to_string()}),
    };
    if let Some(observation) = observation {
        selection["observation"] = observation.clone();
    }
    selection["directory"] = json!({"device": directory.dev(), "inode": directory.ino()});
    immutable(paths, SELECTION, &bytes(&selection)?)
}
fn pin_output(paths: &StatePaths) -> io::Result<Value> {
    fault_barrier(paths, "selection-error")?;
    let destination = paths.state_dir.join(SELECTED_LOG);
    // Never adopt an orphaned pin whose original boundary was not committed.
    fs::hard_link(&paths.log, &destination)?;
    let metadata = fs::symlink_metadata(&destination)?;
    if !metadata.is_file() || metadata.len() > MAX_OUTPUT {
        return Err(error(
            "selected log is not a supported bounded regular file",
        ));
    }
    File::open(&paths.state_dir)?.sync_all()?;
    Ok(
        json!({"byte_len": metadata.len(), "device": metadata.dev(), "inode": metadata.ino(), "link_count": metadata.nlink()}),
    )
}

pub(crate) fn output_unavailable(paths: &StatePaths) -> io::Result<bool> {
    if paths.state_dir.join(OUTPUT).try_exists()? {
        return Ok(false);
    }
    if !paths
        .state_dir
        .join("source-observation-v2.json")
        .try_exists()?
    {
        return Ok(false);
    }
    let selection = paths.state_dir.join(SELECTION);
    if !selection.try_exists()? {
        return Ok(true);
    }
    let Some(length) = value(&selection)?["byte_len"].as_u64() else {
        return Ok(true);
    };
    match fs::symlink_metadata(paths.state_dir.join(SELECTED_LOG)) {
        Ok(meta) => Ok(!meta.is_file() || meta.len() < length || length > MAX_OUTPUT),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(err) => Err(err),
    }
}

/// Registration owns notification recovery even when no successful source body
/// exists. This is NOT handed_off(), acceptance, delivery, or listener ACK.
pub(crate) fn notification_owned(paths: &StatePaths) -> io::Result<bool> {
    let (_, common) = binding(paths)?;
    let local = value(&paths.state_dir.join(LOCAL))?;
    exact(&common, &local)?;
    Ok(matches!(
        local["registration"].as_str(),
        Some("confirmed" | "completion_only_confirmed")
    ))
}

pub(crate) fn record_missing_output(paths: &StatePaths) -> io::Result<()> {
    state::atomic_write(&paths.state_dir.join("source-publication-error.txt"),
        b"original_output_capture_incomplete: original selection unavailable; registered native continuation retains notification duty; capture remains pending unless attributable permanent-loss evidence can be published\n")
}

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
fn identity() -> io::Result<CallerChainEntry> {
    state::observer_self_identity()
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

// Local CLI metadata uses "sentinel"; the continuation wire uses "ready".
// Translate only at the producer boundary, never in retained source evidence.
fn completion_kind(mode: &str) -> io::Result<&'static str> {
    match mode {
        "exit" => Ok("exit"),
        "sentinel" => Ok("ready"),
        _ => Err(error("invalid local completion mode")),
    }
}

/// Called in the original registration worker, before admitting its helper.
pub(crate) fn prepare(
    paths: &StatePaths,
    meta: &Meta,
    domain: &str,
    scope: &str,
) -> io::Result<()> {
    let kind = completion_kind(&meta.mode)?;
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
    let worker = identity()?;
    let registration = json!({
        "protocol": PROTOCOL, "domain_id": domain, "source_id": uuid()?, "registration_id": uuid()?,
        "handle": paths.handle, "handle_dir": paths.state_dir, "spool_root": paths.state_dir.parent(),
        "meta_relative": "meta.json", "log_relative": "log", "rc_relative": "rc",
        "registration_relative": REGISTRATION, "outcome_relative": OUTCOME, "snapshot_relative": SNAPSHOT,
        "owner_session_id": session, "owner_invocation_uuid": invocation, "registering_caller": worker,
        "delivery_mode": meta.delivery_mode.as_str(), "completion_kind": kind, "completion_scope": scope,
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
    if worker != identity()? || fence["phase"] != "unreleased" {
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
    if worker == identity()? && fence["phase"] == "unreleased" {
        transition(paths, &mut fence, "revoked_never_launched")?;
    }
    Ok(())
}
pub(crate) fn launched(paths: &StatePaths, pid: i32) -> io::Result<Option<CallerChainEntry>> {
    if !enabled(paths) {
        return Ok(None);
    }
    let _lock = lock(paths)?;
    let (_, common) = binding(paths)?;
    let mut fence = value(&paths.state_dir.join(FENCE))?;
    exact(&common, &fence)?;
    if fence["phase"] != "may_launch" {
        return Err(error("launch fence conflict"));
    }
    let identity = state::observer_direct_child_identity(pid)?;
    fence["workload_identity"] = json!(identity);
    transition(paths, &mut fence, "launched")?;
    Ok(Some(identity))
}

/// Evidence supplied only by the original live loop or actual adopting guardian.
#[derive(Clone, Copy)]
pub(crate) struct Observation<'a> {
    pub(crate) kind: &'a str,
    pub(crate) root_wait_status: Option<i32>,
    pub(crate) tree_drained: bool,
    pub(crate) output_closed: bool,
    pub(crate) ready_sentinel: Option<&'a str>,
}
/// Incremental publication work belongs to the surviving live observer, not a
/// new workload or helper tree. Each quantum yields back to cancellation/I/O.
#[derive(Default)]
pub(crate) struct Publication {
    hasher: Option<OutputHasher>,
    descriptor: Option<Value>,
}

pub(crate) fn advance_publication(
    paths: &StatePaths,
    meta: &Meta,
    observation: Observation<'_>,
    progress: &mut Publication,
) -> io::Result<bool> {
    if !enabled(paths) {
        return Ok(true);
    }
    if paths
        .state_dir
        .join("completion-source-bundle-v2.json")
        .try_exists()?
    {
        finish_snapshot(paths)?;
        return Ok(true);
    }
    capture_observation(paths, meta, observation)?;
    fault_barrier(paths, "publication-error")?;
    if progress.descriptor.is_none() {
        if progress.hasher.is_none() {
            progress.hasher = Some(OutputHasher::new(paths)?);
        }
        let hasher = progress.hasher.as_mut().expect("initialized hasher");
        if hasher.count >= 1024 * 1024 {
            fault_barrier(paths, "during-output-hash")?;
        }
        progress.descriptor = hasher.advance()?;
        if progress.descriptor.is_none() {
            return Ok(false);
        }
        progress.hasher = None;
    }
    finish_observation_with_output(
        paths,
        progress
            .descriptor
            .as_ref()
            .expect("completed descriptor")
            .clone(),
    )?;
    Ok(true)
}

pub(crate) fn publish(
    paths: &StatePaths,
    meta: &Meta,
    observation: Observation<'_>,
) -> io::Result<()> {
    if !enabled(paths) {
        return Ok(());
    }
    if paths
        .state_dir
        .join("completion-source-bundle-v2.json")
        .try_exists()?
    {
        return finish_snapshot(paths);
    }
    capture_observation(paths, meta, observation)?;
    finish_observation(paths)
}

fn capture_observation(
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
    retain_event(paths, meta, observation)?;
    if !paths
        .state_dir
        .join("completion-output-v2.bin")
        .try_exists()?
    {
        fault_barrier(paths, "before-output-capture")?;
        freeze_output(paths)?;
    }
    Ok(())
}

// Retain selection and its original event in one immutable record. The public
// header is a recoverable projection; a later observer never supplies its label.
pub(crate) fn retain_event(
    paths: &StatePaths,
    meta: &Meta,
    observation: Observation<'_>,
) -> io::Result<()> {
    select_observed_event(paths, meta, observation)?;
    if !paths
        .state_dir
        .join("source-observation-v2.json")
        .try_exists()?
    {
        restore_selected_event(paths)?;
    }
    Ok(())
}

pub(crate) fn select_observed_event(
    paths: &StatePaths,
    meta: &Meta,
    observation: Observation<'_>,
) -> io::Result<()> {
    if !enabled(paths)
        || paths
            .state_dir
            .join("source-observation-v2.json")
            .try_exists()?
    {
        return Ok(());
    }
    if !paths.state_dir.join(SELECTION).try_exists()? {
        let (_, common) = binding(paths)?;
        let fence = value(&paths.state_dir.join(FENCE))?;
        exact(&common, &fence)?;
        if observation.kind == "cancelled"
            && (!observation.tree_drained || !observation.output_closed)
        {
            return Err(error(
                "cancellation observation requires original drain and output close",
            ));
        }
        let mut outcome = common;
        outcome["completion_revision"] = json!(1);
        outcome["launch_fence_revision"] = fence["revision"].clone();
        outcome["kind"] = json!(observation.kind);
        outcome["root_wait_status"] = json!(observation.root_wait_status);
        outcome["original_tree_drained"] = json!(observation.tree_drained);
        outcome["output_closed"] = json!(observation.output_closed);
        outcome["observer"] = json!(identity()?);
        outcome["ready_sentinel"] = json!(observation.ready_sentinel);
        outcome["cancellation_id"] = if observation.kind == "cancelled" {
            json!(cancellation_identity(paths, meta)?)
        } else {
            Value::Null
        };
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
        let staged = json!({"outcome": outcome, "snapshot": snapshot});
        select_event_output(paths, Some(&staged))?;
    }
    Ok(())
}

fn restore_selected_event(paths: &StatePaths) -> io::Result<()> {
    let selection = value(&paths.state_dir.join(SELECTION))?;
    let staged = selection
        .get("observation")
        .ok_or_else(|| error("original selection has no retained event; cannot relabel"))?;
    let (_, common) = binding(paths)?;
    exact(&common, &staged["outcome"])?;
    exact(&common, &staged["snapshot"])?;
    fault_barrier(paths, "selection-before-header")?;
    immutable(paths, "source-observation-v2.json", &bytes(staged)?)
}

fn freeze_output(paths: &StatePaths) -> io::Result<()> {
    let _capture = capture::lock(paths)?;
    capture::freeze(paths)
}

// Wire revision 4: complete raw body, fixed buffers and one MiB CPU/I/O quanta.
// No worker/thread is forked into original custody and no workload deadline exists.
struct OutputHasher {
    file: File,
    expected_len: u64,
    hash: Sha256,
    count: u64,
}
impl OutputHasher {
    fn new(paths: &StatePaths) -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(paths.state_dir.join(OUTPUT))?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > MAX_OUTPUT {
            return Err(error(
                "output artifact is not a supported bounded regular file",
            ));
        }
        Ok(Self {
            file,
            expected_len: metadata.len(),
            hash: Sha256::new(),
            count: 0,
        })
    }
    fn advance(&mut self) -> io::Result<Option<Value>> {
        let mut buffer = [0u8; 64 * 1024];
        let mut quantum = 0;
        while quantum < 1024 * 1024 {
            let length = match self.file.read(&mut buffer) {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                other => other?,
            };
            if length == 0 {
                return self.finish().map(Some);
            }
            self.count += length as u64;
            quantum += length;
            if self.count > MAX_OUTPUT {
                return Err(error("output artifact grew beyond bound"));
            }
            self.hash.update(&buffer[..length]);
        }
        Ok(None)
    }
    fn finish(&self) -> io::Result<Value> {
        if self.count != self.expected_len || self.file.metadata()?.len() != self.count {
            return Err(error("output artifact length changed while hashing"));
        }
        Ok(
            json!({"representation":"retained-output-v1", "relative":OUTPUT,
            "sha256":format!("{:x}", self.hash.clone().finalize()), "byte_len":self.count, "encoding":"utf8-lossy"}),
        )
    }
}
fn output_descriptor(paths: &StatePaths) -> io::Result<Value> {
    let mut hasher = OutputHasher::new(paths)?;
    loop {
        if let Some(descriptor) = hasher.advance()? {
            return Ok(descriptor);
        }
        recovery_hash_barrier(paths)?;
    }
}

fn finish_observation(paths: &StatePaths) -> io::Result<()> {
    fault_barrier(paths, "publication-error")?;
    finish_observation_with_output(paths, output_descriptor(paths)?)
}
fn finish_observation_with_output(paths: &StatePaths, descriptor: Value) -> io::Result<()> {
    let staged = value(&paths.state_dir.join("source-observation-v2.json"))?;
    let outcome = &staged["outcome"];
    let mut snapshot = staged["snapshot"].clone();
    let (_, common) = binding(paths)?;
    exact(&common, outcome)?;
    exact(&common, &snapshot)?;
    if descriptor["representation"] == "missing-original-output-v1" {
        snapshot["status"] = json!("original_output_unavailable");
    }
    snapshot["output"] = if descriptor["byte_len"].as_u64().unwrap_or(u64::MAX) <= INLINE_OUTPUT {
        json!(String::from_utf8_lossy(&read(
            &paths.state_dir.join(OUTPUT),
            INLINE_OUTPUT
        )?))
    } else {
        descriptor
    };
    let outcome_bytes = bytes(outcome)?;
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

#[cfg(feature = "source-fault-tests")]
fn recovery_hash_barrier(paths: &StatePaths) -> io::Result<()> {
    if std::env::var("AGENT_BASH_SOURCE_FAULT").as_deref() == Ok("recovery-lock")
        && !paths
            .state_dir
            .join("fault-recovery-lock.reached.json")
            .try_exists()?
    {
        // If recovery regresses to owning completion.lock here, the source test
        // cannot progress while this exact actor is stopped.
        immutable(
            paths,
            "fault-recovery-lock.reached.json",
            &bytes(&json!(identity()?))?,
        )?;
        unsafe {
            libc::raise(libc::SIGSTOP);
        }
    }
    Ok(())
}
#[cfg(not(feature = "source-fault-tests"))]
fn recovery_hash_barrier(_paths: &StatePaths) -> io::Result<()> {
    Ok(())
}

/// Nonblocking deterministic fixture barriers. Never a workload timeout or proof
/// supplied by a harness: the source reaches this point and writes its identity.
#[cfg(feature = "source-fault-tests")]
pub(crate) fn fault_barrier(paths: &StatePaths, name: &str) -> io::Result<()> {
    let configured = std::env::var("AGENT_BASH_SOURCE_FAULT").unwrap_or_default();
    let guardian_capture = configured.starts_with("guardian-capture-")
        && name == "before-output-capture"
        && value(&paths.state_dir.join("source-observation-v2.json"))?["outcome"]["observer"]
            == json!(identity()?);
    if configured != name && !guardian_capture {
        return Ok(());
    }
    let reached = format!("fault-{name}.reached.json");
    if !paths.state_dir.join(&reached).try_exists()? {
        immutable(paths, &reached, &bytes(&json!(identity()?))?)?;
    }
    if paths
        .state_dir
        .join(format!("fault-{name}.release"))
        .try_exists()?
    {
        return Ok(());
    }
    Err(io::Error::from_raw_os_error(
        if name == "publication-error" {
            libc::ENOSPC
        } else {
            libc::EAGAIN
        },
    ))
}
#[cfg(not(feature = "source-fault-tests"))]
pub(crate) fn fault_barrier(_paths: &StatePaths, _name: &str) -> io::Result<()> {
    Ok(())
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
    } else if matches!(
        meta.completion_reason.as_deref(),
        Some("causal-parent-cancelled" | "root-authority-lost")
    ) {
        let intent = read(
            &paths.state_dir.join("root-work-intent-v1.json"),
            MAX_SOURCE,
        )?;
        let accepted = read(
            &paths.state_dir.join(crate::root_work::ACCEPTED_FILE),
            MAX_SOURCE,
        )?;
        let intent_value: Value = serde_json::from_slice(&intent)?;
        let accepted_value: Value = serde_json::from_slice(&accepted)?;
        if intent_value["protocol"] != crate::root_work::PROTOCOL
            || accepted_value["protocol"] != crate::root_work::PROTOCOL
            || intent_value["work_id"] != paths.handle
            || accepted_value["work_id"] != paths.handle
            || intent_value["root_id"] != accepted_value["root_id"]
            || accepted_value["request_sha256"] != digest(&intent)
        {
            return Err(error("paired cancellation acceptance identity conflict"));
        }
        receipt["accepted_work_sha256"] = json!(digest(&accepted));
        receipt["root_id"] = accepted_value["root_id"].clone();
        if meta.completion_reason.as_deref() == Some("causal-parent-cancelled") {
            let causal = read(
                &paths.state_dir.join("root-work-cancel-v1.json"),
                MAX_SOURCE,
            )?;
            let causal_value: Value = serde_json::from_slice(&causal)?;
            if causal_value["protocol"] != crate::root_work::PROTOCOL
                || causal_value["work_id"] != paths.handle
                || causal_value["root_id"] != accepted_value["root_id"]
                || causal_value["cause"] != "causal_parent_cancelled"
                || !causal_value["requester"].is_null()
            {
                return Err(error("causal cancellation receipt identity conflict"));
            }
            receipt["basis"] = json!("root_causal_receipt");
            receipt["root_cancel_sha256"] = json!(digest(&causal));
        } else {
            // A dead guardian cannot create a later root-side receipt. The
            // paired worker's original, immutable source observation is the
            // witness that its control authority was lost or sent F.
            receipt["basis"] = json!("paired_worker_root_loss_observation");
            receipt["guardian_identity"] = intent_value["guardian_identity"].clone();
        }
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
    save(paths, LOCAL, &local)?;

    // This separate artifact is the serialized source-release boundary.  It
    // deliberately does not change any completion-continuation-v2 schema: the
    // source remains retained until an exact durable acceptance receipt has
    // been validated and its local state has been fsynced.
    let mut release = common;
    release["release_protocol"] = json!("source-retention-release-v1");
    for key in [
        "snapshot_sha256",
        "outcome_sha256",
        "payload_sha256",
        "payload_byte_len",
    ] {
        release[key] = local[key].clone();
    }
    immutable(paths, RETENTION_RELEASE, &bytes(&release)?)
}

/// True only after the runner has durably accepted the exact v2 source
/// snapshot and the source has serialized that receipt into a distinct release
/// record.  Invalid or incomplete evidence fails closed and remains retained.
pub(crate) fn retention_released(paths: &StatePaths) -> io::Result<bool> {
    let (_, common) = binding(paths)?;
    let local = value(&paths.state_dir.join(LOCAL))?;
    exact(&common, &local)?;
    if local["enqueue"] != "accepted" {
        return Ok(false);
    }
    let release = value(&paths.state_dir.join(RETENTION_RELEASE))?;
    exact(&common, &release)?;
    if release["release_protocol"] != "source-retention-release-v1" {
        return Ok(false);
    }
    for key in [
        "snapshot_sha256",
        "outcome_sha256",
        "payload_sha256",
        "payload_byte_len",
    ] {
        if release[key] != local[key] {
            return Ok(false);
        }
    }
    Ok(release["snapshot_sha256"]
        == digest(&read(&paths.state_dir.join(SNAPSHOT), 16 * MAX_SOURCE)?)
        && release["outcome_sha256"] == digest(&read(&paths.state_dir.join(OUTCOME), MAX_SOURCE)?))
}

#[cfg(test)]
pub(crate) fn seed_exact_retention_release(paths: &StatePaths) {
    let registration = json!({
        "protocol": PROTOCOL,
        "domain_id": "test-domain",
        "source_id": "test-source",
        "handle": paths.handle,
        "registration_id": "test-registration",
        "handle_dir": paths.state_dir,
        "spool_root": paths.root,
        "meta_relative": "meta.json",
        "log_relative": "log",
        "rc_relative": "rc",
        "registration_relative": REGISTRATION,
        "outcome_relative": OUTCOME,
        "snapshot_relative": SNAPSHOT,
        "source_evidence_protocol": PROTOCOL,
        "listener_revision": 1,
    });
    immutable(paths, REGISTRATION, &bytes(&registration).unwrap()).unwrap();
    let common = binding(paths).unwrap().1;
    let mut local = common.clone();
    local["registration"] = json!("confirmed");
    local["enqueue"] = json!("waiting_evidence");
    save(paths, LOCAL, &local).unwrap();
    immutable(paths, OUTCOME, b"test-outcome").unwrap();
    immutable(paths, SNAPSHOT, b"test-snapshot").unwrap();
    let mut reply = common;
    reply["status"] = json!("accepted");
    reply["snapshot_sha256"] = json!(digest(b"test-snapshot"));
    reply["outcome_sha256"] = json!(digest(b"test-outcome"));
    reply["payload_sha256"] = json!(digest(b"test-payload"));
    reply["payload_byte_len"] = json!(12);
    reply["listener_revision"] = json!(1);
    accept(paths, &reply).unwrap();
}
/// Readback proves a prior explicit original-listener request, not ACK, source
/// acceptance, or local Async. Runner owns request admission and idempotency.
pub(crate) fn activation_committed(paths: &StatePaths, reply: &Value) -> io::Result<bool> {
    let (registration, common) = binding(paths)?;
    exact(&common, reply)?;
    if reply["status"] != "exact_committed" || reply["registration_committed"] != true {
        return Ok(false);
    }
    let owner = registration["owner_invocation_uuid"]
        .as_str()
        .filter(|owner| !owner.is_empty())
        .ok_or_else(|| error("missing original activation listener"))?;
    let Some(dispositions) = reply["notification_dispositions"].as_array() else {
        return Ok(false);
    };
    let mut original = dispositions
        .iter()
        .filter(|row| row["listener_id"] == owner);
    let Some(request) = original.next() else {
        return Ok(false);
    };
    Ok(original.next().is_none()
        && request["requested_at"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
        && request["request_basis"] == "explicit_listener_activation_unattributed")
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

fn recover_output(paths: &StatePaths) -> io::Result<bool> {
    if paths
        .state_dir
        .join("completion-source-bundle-v2.json")
        .try_exists()?
    {
        finish_snapshot(paths)?;
        return Ok(true);
    }
    let _capture = match capture::lock(paths) {
        Ok(lock) => lock,
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(false),
        Err(err) => return Err(err),
    };
    // A read error is not a loss attestation. The independent inventory below
    // must establish permanent loss before any public missing snapshot exists.
    let Err(capture_error) = capture::freeze(paths) else {
        return Ok(true);
    };
    state::atomic_write(
        &paths.state_dir.join("source-capture-error.txt"),
        capture_error.to_string().as_bytes(),
    )?;
    record_missing_output(paths)?;
    if let Some(proof) = missing_output::observe(paths)? {
        finish_observation_with_output(paths, proof)?;
        return Ok(true);
    }
    Ok(false)
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
    // Serialize recoveries (including never-launched staging), never the live
    // observer. In particular two recoveries cannot race a new selection pin.
    let _recovery = named_lock(&paths, "source-recovery.lock")?;
    // Recovery never owns the live observer's completion lock. Staged evidence
    // and final publications use immutable compare/link; hashing touches only
    // the retained body. A stopped recovery cannot stop I/O/reaping.
    let local_lock = named_lock(&paths, "continuation.lock")?;
    let mut local = value(&paths.state_dir.join(LOCAL))?;
    local["registration"] = json!("completion_only_confirmed");
    save(&paths, LOCAL, &local)?;
    drop(local_lock);
    let fence = value(&paths.state_dir.join(FENCE))?;
    if !paths
        .state_dir
        .join("source-observation-v2.json")
        .try_exists()?
        && paths.state_dir.join(SELECTION).try_exists()?
        && let Err(err) = restore_selected_event(&paths)
    {
        let mut pending = common;
        pending["status"] = json!("pending");
        pending["reason"] = json!(err.to_string());
        return Ok(pending);
    }
    if paths
        .state_dir
        .join("source-observation-v2.json")
        .try_exists()?
    {
        if !paths
            .state_dir
            .join("completion-output-v2.bin")
            .try_exists()?
            && !recover_output(&paths)?
        {
            let mut pending = common;
            pending["status"] = json!("pending");
            pending["reason"] = json!("original_output_capture_incomplete");
            return Ok(pending);
        }
        if !paths
            .state_dir
            .join("completion-source-bundle-v2.json")
            .try_exists()?
        {
            finish_observation(&paths)?;
        }
    }
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
    if paths.state_dir.join(SNAPSHOT).try_exists()? {
        result["snapshot_sha256"] = json!(digest(&read(
            &paths.state_dir.join(SNAPSHOT),
            16 * MAX_SOURCE
        )?));
        result["outcome_sha256"] =
            json!(digest(&read(&paths.state_dir.join(OUTCOME), MAX_SOURCE)?));
        result["status"] = json!(
            if value(&paths.state_dir.join(SNAPSHOT))?["output"]["representation"]
                == "missing-original-output-v1"
            {
                "source_output_missing"
            } else {
                "source_ready"
            }
        );
    } else {
        result["status"] = json!("pending");
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;
    fn fixture() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/age360/paired-wire.json")).unwrap()
    }
    pub(super) fn source() -> (tempfile::TempDir, StatePaths, Value) {
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
    fn launch_fence_requires_exact_live_direct_child_in_observer_domain() {
        const STAGE: &str = "AGE319_LAUNCH_OBSERVER_CHILD";
        if std::env::var_os(STAGE).is_none() {
            launch_observer_case(false);
            let output = Command::new("timeout")
                .args([
                    "--kill-after=5s", "30s", "unshare", "--user", "--map-current-user",
                    "--pid", "--fork", "--",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "continuation::tests::launch_fence_requires_exact_live_direct_child_in_observer_domain",
                ])
                .env(STAGE, "1")
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
            return;
        }
        launch_observer_case(true);
    }

    fn launch_observer_case(cross_domain: bool) {
        let worker = identity().unwrap();
        assert_eq!(worker.pid != unsafe { libc::getpid() }, cross_domain);
        let temp = tempfile::tempdir().unwrap();
        let paths = StatePaths::new(fs::canonicalize(temp.path()).unwrap(), "ab_observer".into());
        fs::create_dir(&paths.state_dir).unwrap();
        let meta = registration_meta(&paths, "exit", state::DeliveryMode::Async);
        prepare(
            &paths,
            &meta,
            "11111111-1111-4111-8111-111111111111",
            "tree",
        )
        .unwrap();
        let registration = value(&paths.state_dir.join(REGISTRATION)).unwrap();
        assert_eq!(registration["registering_caller"], json!(worker));
        let common = binding(&paths).unwrap().1;
        let recorded: CallerChainEntry = serde_json::from_value(
            value(&paths.state_dir.join(FENCE)).unwrap()["registration_worker"].clone(),
        )
        .unwrap();
        assert_eq!(recorded, worker);
        let mut stale_fence = value(&paths.state_dir.join(FENCE)).unwrap();
        stale_fence["registration_worker"]["starttime_ticks"] = json!(worker.starttime_ticks + 1);
        save(&paths, FENCE, &stale_fence).unwrap();
        assert!(confirm_launch(&paths, &registration_reply(&paths, &common)).is_err());
        assert_eq!(
            value(&paths.state_dir.join(FENCE)).unwrap()["phase"],
            "unreleased"
        );
        stale_fence["registration_worker"] = json!(worker);
        save(&paths, FENCE, &stale_fence).unwrap();
        confirm_launch(&paths, &registration_reply(&paths, &common)).unwrap();
        assert_eq!(
            value(&paths.state_dir.join(FENCE)).unwrap()["phase"],
            "may_launch"
        );

        let (pid_sender, pid_receiver) = std::sync::mpsc::channel();
        let (done_sender, done_receiver) = std::sync::mpsc::channel();
        let sibling = std::thread::spawn(move || {
            let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
            pid_sender.send(child.id() as i32).unwrap();
            done_receiver.recv().unwrap();
            child.kill().unwrap();
            child.wait().unwrap();
        });
        let sibling_pid = pid_receiver.recv().unwrap();
        assert!(launched(&paths, unsafe { libc::getpid() }).is_err());
        assert!(launched(&paths, sibling_pid).is_err());
        assert!(value(&paths.state_dir.join(FENCE)).unwrap()["workload_identity"].is_null());

        let mut child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
        let local_child = child.id() as i32;
        launched(&paths, local_child).unwrap();
        let launch = value(&paths.state_dir.join(FENCE)).unwrap();
        assert_eq!(launch["phase"], "launched");
        let observed: CallerChainEntry =
            serde_json::from_value(launch["workload_identity"].clone()).unwrap();
        assert_eq!(observed.pid != local_child, cross_domain);
        assert_eq!(observed.boot_id, worker.boot_id);
        assert_eq!(
            state::process_starttime_ticks(observed.pid),
            Some(observed.starttime_ticks)
        );
        assert_eq!(
            state::local_pid_for_observer_pid(observed.pid),
            Some(local_child)
        );
        assert_eq!(state::process_parent_pid(observed.pid), Some(worker.pid));
        let mut reused = observed.clone();
        reused.starttime_ticks += 1;
        assert!(matches!(
            state::process_identity_evidence(&reused),
            state::ProcessIdentityEvidence::Mismatch
        ));

        child.kill().unwrap();
        // An exited, unreaped child still has a procfs entry; it cannot become
        // positive launch identity after its pidfd reports death.
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::waitid(
                    libc::P_PID,
                    local_child as libc::id_t,
                    &mut info,
                    libc::WEXITED | libc::WNOWAIT,
                )
            },
            0
        );
        let (_dead_temp, dead_paths, dead_common) = source();
        fence(&dead_paths, &dead_common, "may_launch");
        assert!(launched(&dead_paths, local_child).is_err());
        assert!(value(&dead_paths.state_dir.join(FENCE)).unwrap()["workload_identity"].is_null());
        child.wait().unwrap();
        let (_stale_temp, stale_paths, stale_common) = source();
        fence(&stale_paths, &stale_common, "may_launch");
        assert!(launched(&stale_paths, local_child).is_err());
        assert!(value(&stale_paths.state_dir.join(FENCE)).unwrap()["workload_identity"].is_null());
        done_sender.send(()).unwrap();
        sibling.join().unwrap();
    }
    #[test]
    fn paired_causal_and_root_loss_cancellation_have_distinct_exact_bases() {
        let (_temp, paths, common) = source();
        let mut meta = registration_meta(&paths, "exit", state::DeliveryMode::Sync);
        meta.completion_reason = Some("causal-parent-cancelled".into());
        let intent = json!({
            "protocol": crate::root_work::PROTOCOL,
            "work_id": paths.handle,
            "root_id": "root-fixture",
            "guardian_identity": {"pid": 123, "boot_id": "boot", "starttime_ticks": 456}
        });
        let intent_bytes = bytes(&intent).unwrap();
        fs::write(
            paths.state_dir.join("root-work-intent-v1.json"),
            &intent_bytes,
        )
        .unwrap();
        let accepted = json!({
            "protocol": crate::root_work::PROTOCOL,
            "work_id": paths.handle,
            "root_id": "root-fixture",
            "request_sha256": digest(&intent_bytes)
        });
        fs::write(
            paths.state_dir.join(crate::root_work::ACCEPTED_FILE),
            bytes(&accepted).unwrap(),
        )
        .unwrap();
        assert!(cancellation_identity(&paths, &meta).is_err());
        let mut causal = json!({
            "protocol": crate::root_work::PROTOCOL,
            "work_id": paths.handle,
            "root_id": "root-fixture",
            "cause": "causal_parent_cancelled",
            "requester": null
        });
        fs::write(
            paths.state_dir.join("root-work-cancel-v1.json"),
            bytes(&causal).unwrap(),
        )
        .unwrap();
        let causal_id = cancellation_identity(&paths, &meta).unwrap();
        let causal_source: Value =
            value(&paths.state_dir.join("source-cancellation-v2.json")).unwrap();
        assert_eq!(causal_source["basis"], "root_causal_receipt");
        assert_eq!(causal_id, digest(&bytes(&causal_source).unwrap()));
        fence(&paths, &common, "may_launch");
        fs::write(&paths.log, b"").unwrap();
        retain_event(
            &paths,
            &meta,
            Observation {
                kind: "cancelled",
                root_wait_status: None,
                tree_drained: true,
                output_closed: true,
                ready_sentinel: None,
            },
        )
        .unwrap();
        let selected = value(&paths.state_dir.join("source-observation-v2.json")).unwrap();
        assert_eq!(selected["outcome"]["kind"], "cancelled");
        assert_eq!(selected["outcome"]["cancellation_id"], causal_id);
        causal["root_id"] = json!("other-root");
        fs::write(
            paths.state_dir.join("root-work-cancel-v1.json"),
            bytes(&causal).unwrap(),
        )
        .unwrap();
        assert!(cancellation_identity(&paths, &meta).is_err());

        let (_other_temp, other_paths, _) = source();
        fs::write(
            other_paths.state_dir.join("root-work-intent-v1.json"),
            &intent_bytes,
        )
        .unwrap();
        fs::write(
            other_paths.state_dir.join(crate::root_work::ACCEPTED_FILE),
            bytes(&accepted).unwrap(),
        )
        .unwrap();
        meta.completion_reason = Some("root-authority-lost".into());
        let root_loss_id = cancellation_identity(&other_paths, &meta).unwrap();
        let root_loss = value(&other_paths.state_dir.join("source-cancellation-v2.json")).unwrap();
        assert_eq!(root_loss["basis"], "paired_worker_root_loss_observation");
        assert_eq!(root_loss_id, digest(&bytes(&root_loss).unwrap()));
    }
    #[test]
    fn activation_readback_requires_exact_original_explicit_request() {
        let (_temp, paths, mut reply) = source();
        let registration = value(&paths.state_dir.join(REGISTRATION)).unwrap();
        reply["status"] = json!("exact_committed");
        reply["registration_committed"] = json!(true);
        reply["notification_dispositions"] = json!([{
            "listener_id": registration["owner_invocation_uuid"],
            "requested_at": "2026-09-13T00:00:00Z",
            "request_basis": "explicit_listener_activation_unattributed",
            "disposition": "handled"
        }]);
        assert!(activation_committed(&paths, &reply).unwrap());
        // No active owner or current mailbox sequence is needed to read a
        // prior committed request, even after genuine handling/retirement.
        for (key, replacement) in [
            ("listener_id", json!("independent-listener")),
            ("requested_at", Value::Null),
            ("requested_at", json!("")),
            (
                "request_basis",
                json!("explicit_event_activation_unattributed"),
            ),
            ("request_basis", Value::Null),
        ] {
            let mut invalid = reply.clone();
            invalid["notification_dispositions"][0][key] = replacement;
            assert!(!activation_committed(&paths, &invalid).unwrap());
        }
        for key in [
            "protocol",
            "domain_id",
            "source_id",
            "handle",
            "registration_id",
            "registration_digest",
        ] {
            let mut invalid = reply.clone();
            invalid[key] = json!("foreign");
            assert!(activation_committed(&paths, &invalid).is_err());
        }
        for status in ["absent", "unavailable", "conflict"] {
            let mut invalid = reply.clone();
            invalid["status"] = json!(status);
            assert!(!activation_committed(&paths, &invalid).unwrap());
        }
        let mut duplicate = reply.clone();
        duplicate["notification_dispositions"]
            .as_array_mut()
            .unwrap()
            .push(reply["notification_dispositions"][0].clone());
        assert!(!activation_committed(&paths, &duplicate).unwrap());
        reply["registration_committed"] = json!(false);
        assert!(!activation_committed(&paths, &reply).unwrap());
    }

    fn registration_meta(paths: &StatePaths, mode: &str, delivery: state::DeliveryMode) -> Meta {
        let mut meta = Meta::new(
            paths.handle.clone(),
            1,
            1,
            vec![],
            paths.root.clone(),
            mode,
            delivery,
            (mode == "sentinel").then(|| "READY".into()),
            vec![],
            None,
        );
        meta.owner_session_id = Some("fixture-session".into());
        meta.owner_invocation_uuid = Some("55555555-5555-4555-8555-555555555555".into());
        meta.delivery_helper = Some(state::DeliveryHelperProvenance {
            schema_version: 5,
            path: paths.state_dir.join("helper").display().to_string(),
            device: 0,
            inode: 0,
            size: 0,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            mode: 0o500,
            sha256: "a".repeat(64),
            environment: Default::default(),
            environment_sha256: Some("b".repeat(64)),
            interpreter: None,
        });
        meta
    }

    #[test]
    fn unlinked_legacy_selection_cannot_inherit_later_guardian_event() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "launched");
        fs::write(&paths.log, b"original selection").unwrap();
        select_output(&paths).unwrap();
        let meta = registration_meta(&paths, "exit", state::DeliveryMode::Async);
        let result = retain_event(
            &paths,
            &meta,
            Observation {
                kind: "ceased_status_unknown",
                root_wait_status: None,
                tree_drained: true,
                output_closed: true,
                ready_sentinel: None,
            },
        );
        assert!(result.unwrap_err().to_string().contains("cannot relabel"));
        assert!(!paths.state_dir.join("source-observation-v2.json").exists());
        assert!(!paths.state_dir.join(SNAPSHOT).exists());
    }

    #[test]
    fn prepare_translates_local_mode_into_canonical_registration_kind() {
        for (mode, expected) in [("exit", "exit"), ("sentinel", "ready")] {
            for scope in ["root", "tree"] {
                for delivery in [state::DeliveryMode::Sync, state::DeliveryMode::Async] {
                    let temp = tempfile::tempdir().unwrap();
                    let root = fs::canonicalize(temp.path()).unwrap();
                    let paths = StatePaths::new(root, "ab_registration".into());
                    fs::create_dir(&paths.state_dir).unwrap();
                    let meta = registration_meta(&paths, mode, delivery);
                    prepare(&paths, &meta, "11111111-1111-4111-8111-111111111111", scope).unwrap();
                    // Inspect actual producer bytes, not an imported or repaired fixture.
                    let raw = read(&paths.state_dir.join(REGISTRATION), MAX_SOURCE).unwrap();
                    let registration: Value = serde_json::from_slice(&raw).unwrap();
                    assert_eq!(registration["completion_kind"], expected);
                    assert_eq!(registration["completion_scope"], scope);
                    assert_eq!(registration["delivery_mode"], delivery.as_str());
                    assert_eq!(
                        meta.mode, mode,
                        "local metadata must not become wire vocabulary"
                    );
                    let fence = value(&paths.state_dir.join(FENCE)).unwrap();
                    assert_eq!(fence["registration_digest"], digest(&raw));
                    assert_eq!(fence["phase"], "unreleased");
                    assert!(fence["workload_identity"].is_null());
                }
            }
        }
    }

    #[test]
    fn prepare_rejects_unknown_local_modes_before_retaining_source() {
        for mode in ["ready", "", "unknown"] {
            let temp = tempfile::tempdir().unwrap();
            let paths =
                StatePaths::new(fs::canonicalize(temp.path()).unwrap(), "ab_invalid".into());
            fs::create_dir(&paths.state_dir).unwrap();
            let meta = registration_meta(&paths, mode, state::DeliveryMode::Async);
            let err = prepare(
                &paths,
                &meta,
                "11111111-1111-4111-8111-111111111111",
                "tree",
            )
            .unwrap_err();
            assert_eq!(err.to_string(), "invalid local completion mode");
            assert_eq!(fs::read_dir(&paths.state_dir).unwrap().count(), 0);
        }
    }

    #[test]
    fn supported_one_gib_output_publication_uses_bounded_memory() {
        if crate::test_support::private_case() {
            return;
        }
        let (_temp, paths, common) = source();
        fence(&paths, &common, "launched");
        File::create(&paths.log)
            .unwrap()
            .set_len(MAX_OUTPUT)
            .unwrap();
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
        meta.rc = Some(0);
        // Source publisher unit exercise, not an actual original-work wait proof.
        let start = std::time::Instant::now();
        let mut progress = Publication::default();
        let mut steps = 0;
        let mut max_step = std::time::Duration::ZERO;
        loop {
            let step = std::time::Instant::now();
            let done = advance_publication(
                &paths,
                &meta,
                Observation {
                    kind: "exit_tree",
                    root_wait_status: Some(0),
                    tree_drained: true,
                    output_closed: true,
                    ready_sentinel: None,
                },
                &mut progress,
            )
            .unwrap();
            max_step = max_step.max(step.elapsed());
            steps += 1;
            if done {
                break;
            }
        }
        assert!(steps >= 1024, "large hash did not yield between quanta");
        let data = read(&paths.state_dir.join(SNAPSHOT), MAX_SOURCE).unwrap();
        let snapshot: Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(snapshot["output"]["byte_len"], MAX_OUTPUT);
        // Independently computed with Python hashlib over 1024 x 1MiB zero chunks.
        assert_eq!(
            snapshot["output"]["sha256"],
            "49bc20df15e412a64472421e13fe86ff1c5165e18b2afccf160d4dc19fe68a14"
        );
        assert!(data.len() < 4096);
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let peak = status
            .lines()
            .find(|line| line.starts_with("VmHWM:"))
            .unwrap();
        let kib: u64 = peak.split_whitespace().nth(1).unwrap().parse().unwrap();
        assert!(
            kib < 128 * 1024,
            "source publisher allocated proportional to output: {peak}"
        );
        println!(
            "publisher-unit only: raw={} snapshot={} elapsed_ms={} hash_steps={} max_step_ms={} {peak}",
            MAX_OUTPUT,
            data.len(),
            start.elapsed().as_millis(),
            steps,
            max_step.as_millis()
        );
    }

    #[test]
    fn artifact_descriptor_rejects_symlinks_directories_and_unsupported_size() {
        let (_temp, paths, _) = source();
        let output = paths.state_dir.join(OUTPUT);
        fs::create_dir(&output).unwrap();
        assert!(output_descriptor(&paths).is_err());
        fs::remove_dir(&output).unwrap();
        std::os::unix::fs::symlink(&paths.log, &output).unwrap();
        assert!(output_descriptor(&paths).is_err());
        fs::remove_file(&output).unwrap();
        File::create(&output)
            .unwrap()
            .set_len(MAX_OUTPUT + 1)
            .unwrap();
        assert!(output_descriptor(&paths).is_err());
    }

    #[test]
    fn undrained_cancellation_cannot_freeze_source_evidence() {
        let (_temp, paths, common) = source();
        fence(&paths, &common, "launched");
        let meta = Meta::new(
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
        for (tree_drained, output_closed) in [(false, true), (true, false)] {
            let result = publish(
                &paths,
                &meta,
                Observation {
                    kind: "cancelled",
                    root_wait_status: Some(0),
                    tree_drained,
                    output_closed,
                    ready_sentinel: None,
                },
            );
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("requires original drain")
            );
            assert!(!paths.state_dir.join("source-observation-v2.json").exists());
            assert!(!paths.state_dir.join(OUTCOME).exists());
        }
    }
    #[test]
    fn canonical_wire_exact_byte_digests() {
        let fixture = fixture();
        assert_eq!(fixture["fixture_revision"], 4);
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
            digest(
                fixture["artifact_snapshot_bytes_utf8"]
                    .as_str()
                    .unwrap()
                    .as_bytes()
            ),
            fixture["artifact_snapshot_sha256"]
        );
        let (_temp, paths, _) = source();
        fs::write(
            paths.state_dir.join(OUTPUT),
            fixture["artifact_output_bytes_utf8"].as_str().unwrap(),
        )
        .unwrap();
        assert_eq!(
            output_descriptor(&paths).unwrap(),
            fixture["output_artifact_example"]
        );
        let parsed: Value =
            serde_json::from_str(fixture["artifact_snapshot_bytes_utf8"].as_str().unwrap())
                .unwrap();
        assert_eq!(
            bytes(&parsed).unwrap(),
            fixture["artifact_snapshot_bytes_utf8"]
                .as_str()
                .unwrap()
                .as_bytes()
        );
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
        fence["registration_worker"] = json!(identity().unwrap());
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
        assert!(retention_released(&paths).unwrap());
        assert!(paths.state_dir.join(RETENTION_RELEASE).exists());
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
    fn recovery_never_captures_mutable_log_for_an_incomplete_original_snapshot() {
        let (_temp, paths, common) = recovery_source("launched");
        save(
            &paths,
            "source-observation-v2.json",
            &json!({"outcome": common}),
        )
        .unwrap();
        fs::write(&paths.log, b"later mutable output").unwrap();
        let reply = reconcile(
            &paths.state_dir.join(REGISTRATION),
            &paths.state_dir.join("fixture-confirmation.json"),
        )
        .unwrap();
        assert_eq!(reply["status"], "pending");
        assert_eq!(reply["reason"], "original_output_capture_incomplete");
        assert!(!paths.state_dir.join("completion-output-v2.bin").exists());
        assert!(!paths.state_dir.join(SNAPSHOT).exists());
    }
    #[test]
    fn selected_prefix_does_not_include_later_appends() {
        let (_temp, paths, _) = source();
        fs::write(&paths.log, b"original").unwrap();
        select_output(&paths).unwrap();
        OpenOptions::new()
            .append(true)
            .open(&paths.log)
            .unwrap()
            .write_all(b"later")
            .unwrap();
        select_output(&paths).unwrap();
        freeze_output(&paths).unwrap();
        assert_eq!(fs::read(paths.state_dir.join(OUTPUT)).unwrap(), b"original");
    }

    #[test]
    fn lost_selection_is_missing_not_reselected_from_new_log() {
        let (_temp, paths, common) = recovery_source("launched");
        fs::write(&paths.log, b"original").unwrap();
        select_output(&paths).unwrap();
        save(
            &paths,
            "source-observation-v2.json",
            &json!({"outcome":common}),
        )
        .unwrap();
        // Private fault: loss of retained selected storage, not workload replay.
        fs::remove_file(paths.state_dir.join(SELECTED_LOG)).unwrap();
        fs::write(&paths.log, b"new log").unwrap();
        assert!(output_unavailable(&paths).unwrap());
        let reply = reconcile(
            &paths.state_dir.join(REGISTRATION),
            &paths.state_dir.join("fixture-confirmation.json"),
        )
        .unwrap();
        assert_eq!(reply["reason"], "original_output_capture_incomplete");
        assert!(!paths.state_dir.join(OUTPUT).exists());
        assert!(!paths.state_dir.join(SELECTED_LOG).exists());
    }

    #[test]
    fn publication_lock_attempt_does_not_join_another_actor() {
        let (_temp, paths, _) = source();
        let held = state::lock_completion(&paths).unwrap();
        assert!(state::try_lock_completion(&paths).unwrap().is_none());
        drop(held);
        assert!(state::try_lock_completion(&paths).unwrap().is_some());
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
