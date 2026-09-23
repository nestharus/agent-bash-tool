//! Paired original-work-v1 client and root-owned execution entry.
//!
//! The public launcher creates the ordinary handle and immutable completion
//! binding first, then durably records this intent before the root can accept
//! it.  A lost/ambiguous response is never retried.  The internal executor is
//! a short-lived worker under the runner's existing root authority; it does not
//! daemonize another guardian/supervisor pair.

use crate::delivery;
use crate::state::{self, CallerChainEntry, Meta, StatePaths};
use crate::supervisor::{self, CompletionScope, StartupOutcome, SupervisorConfig};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub(crate) const PROTOCOL: &str = "original-work-v1";
const ROOT_PROTOCOL: &str = "root-authority-v1";
const LEGACY_CONTROL_PROTOCOL: &str = "stream-control-v1";
const SOURCE_CONTROL_PROTOCOL: &str = "source-control-v2";
const BROKER_SOCKET: &str = "/run/oulipoly-kernel-broker/control.sock";
pub(crate) const EXECUTOR_ARG: &str = "__root-original-work-v1";
pub(crate) const ROOT_AUTHORITY_ENV: &str = "OULIPOLY_ROOT_AUTHORITY_V1";
pub(crate) const ROOT_WORK_ID_ENV: &str = "OULIPOLY_ROOT_WORK_ID";
pub(crate) const ROOT_PARENT_CAPABILITY_ENV: &str = "OULIPOLY_ROOT_PARENT_CAPABILITY_V1";
const ENDPOINT_ENV: &str = "OULIPOLY_COMPLETION_ENDPOINT";
const REQUIRED_ENV: &str = "OULIPOLY_ORIGINAL_WORK_REQUIRED_V1";
const INTENT_FILE: &str = "root-work-intent-v1.json";
pub(crate) const ACCEPTED_FILE: &str = "root-work-accepted-v1.json";

pub(crate) struct CompletionOwnerWitness {
    pub(crate) session_id: String,
    pub(crate) invocation_uuid: String,
    pub(crate) registration_authority: OsString,
}

/// Restore only the witness that H pinned from this exact accepted intent.
/// The helper receives it transiently; the broker still checks the live V
/// caller against the consumed K grant and sealed image.
pub(crate) fn completion_owner_witness(
    paths: &StatePaths,
    meta: &Meta,
    helper_sha256: &str,
) -> io::Result<Option<CompletionOwnerWitness>> {
    let intent_path = paths.state_dir.join(INTENT_FILE);
    let accepted_path = paths.state_dir.join(ACCEPTED_FILE);
    if !intent_path.exists() {
        if accepted_path.exists() {
            return Err(io::Error::other("accepted work has no original intent"));
        }
        return Ok(None);
    }
    let intent_bytes = crate::continuation::read(&intent_path, 1024 * 1024)?;
    let intent: WorkIntent = serde_json::from_slice(&intent_bytes)?;
    let accepted: serde_json::Value =
        serde_json::from_slice(&crate::continuation::read(&accepted_path, 1024 * 1024)?)?;
    if intent.protocol != PROTOCOL
        || intent.handle != paths.handle
        || intent.work_id != paths.handle
        || intent.state_root != paths.root
        || accepted["protocol"] != PROTOCOL
        || accepted["work_id"] != paths.handle
        || accepted["root_id"] != intent.root_id
        || accepted["supervisor_authority_id"] != intent.supervisor_authority_id
        || accepted["request_sha256"] != hex_digest(&intent_bytes)
    {
        return Err(io::Error::other("accepted owner intent binding conflict"));
    }
    let (Some(session), Some(invocation), Some(authority), Some(helper)) = (
        intent.meta.owner_session_id.as_deref(),
        intent.meta.owner_invocation_uuid.as_deref(),
        intent.registration_authority.as_deref(),
        intent.meta.delivery_helper.as_ref(),
    ) else {
        return Err(io::Error::other("accepted owner witness is incomplete"));
    };
    if session.is_empty()
        || invocation.is_empty()
        || authority.len() != 64
        || !authority
            .iter()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || meta.owner_session_id.as_deref() != Some(session)
        || meta.owner_invocation_uuid.as_deref() != Some(invocation)
        || meta
            .delivery_helper
            .as_ref()
            .map(|helper| helper.sha256.as_str())
            != Some(helper_sha256)
        || helper.sha256 != helper_sha256
        || helper.path != paths.delivery_helper.to_string_lossy()
    {
        return Err(io::Error::other(
            "accepted owner witness differs from handle",
        ));
    }
    crate::continuation::confirmed_owner_binding(paths, session, invocation, helper_sha256)?;
    Ok(Some(CompletionOwnerWitness {
        session_id: session.to_owned(),
        invocation_uuid: invocation.to_owned(),
        registration_authority: OsString::from_vec(authority.to_vec()),
    }))
}
const DIAGNOSTIC_FILE: &str = "root-work-diagnostic-v1.jsonl";
const DIAGNOSTIC_LOCK_FILE: &str = "root-work-diagnostic-v1.lock";
const DIAGNOSTIC_ROTATED_FILE: &str = "root-work-diagnostic-v1.jsonl.1";
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
const MAX_DIAGNOSTIC_RECORD_BYTES: usize = 128 * 1024;
const FD_COUNT: usize = 4;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_SOURCE_WITNESS_BYTES: usize = 2048;
const MAX_WORK_FRAME_BYTES: usize = 64 * 1024;
const PAIRED_RING_PREFIX: &str = "oulipoly-paired-original-work-v1:";
const MAX_KEY_DESCRIPTION_BYTES: usize = 256;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProcessIdentity {
    pid: i64,
    boot_id: String,
    starttime_ticks: u64,
}

impl From<&CallerChainEntry> for ProcessIdentity {
    fn from(value: &CallerChainEntry) -> Self {
        Self {
            pid: i64::from(value.pid),
            boot_id: value.boot_id.clone(),
            starttime_ticks: value.starttime_ticks,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RootAuthorityGrant {
    protocol: String,
    #[serde(default = "legacy_control_protocol")]
    control_protocol: String,
    completion_protocol: String,
    domain_id: String,
    supervisor_authority_id: String,
    root_id: String,
    capability: String,
    root_identity: ProcessIdentity,
    guardian_identity: ProcessIdentity,
}

fn legacy_control_protocol() -> String {
    LEGACY_CONTROL_PROTOCOL.into()
}

#[derive(Serialize)]
struct ProcessWitness<'a> {
    host_pid: i32,
    boot_id: &'a str,
    starttime_ticks: u64,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum SourceScope<'a> {
    Root,
    Nested { parent_work_id: &'a str },
    CancelOutside { work_id: &'a str },
}

#[derive(Serialize)]
struct SourceSocketWitness<'a> {
    root_id: &'a str,
    domain_id: &'a str,
    supervisor_id: &'a str,
    guardian: ProcessWitness<'a>,
    source: ProcessWitness<'a>,
    scope: SourceScope<'a>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum WorkRegistration {
    Root,
    Nested {
        parent_work_id: String,
        parent_capability: String,
    },
}

impl<'de> Deserialize<'de> for WorkRegistration {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let mut object = serde_json::Map::<String, serde_json::Value>::deserialize(deserializer)?;
        let kind = object
            .remove("kind")
            .and_then(|value| value.as_str().map(str::to_owned))
            .ok_or_else(|| serde::de::Error::custom("work registration kind is required"))?;
        match kind.as_str() {
            "root" if object.is_empty() => Ok(Self::Root),
            "nested" => {
                let parent_work_id = object
                    .remove("parent_work_id")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| serde::de::Error::custom("nested parent_work_id is required"))?;
                let parent_capability = object
                    .remove("parent_capability")
                    .and_then(|value| value.as_str().map(str::to_owned))
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        serde::de::Error::custom("nested parent_capability is required")
                    })?;
                if !object.is_empty() {
                    return Err(serde::de::Error::custom(
                        "unknown nested work registration field",
                    ));
                }
                Ok(Self::Nested {
                    parent_work_id,
                    parent_capability,
                })
            }
            "root" => Err(serde::de::Error::custom(
                "root work registration has conflicting fields",
            )),
            _ => Err(serde::de::Error::custom("unknown work registration kind")),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkSubmission {
    protocol: String,
    root_authority: RootAuthorityGrant,
    work_id: String,
    request_sha256: String,
    registration: WorkRegistration,
    cancel_capability: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CancelSubmission {
    protocol: String,
    root_id: String,
    supervisor_authority_id: String,
    work_id: String,
    cancel_capability: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkResponse {
    pub(crate) protocol: String,
    pub(crate) work_id: String,
    pub(crate) status: String,
    pub(crate) root_id: String,
    pub(crate) supervisor_authority_id: String,
    worker_identity: Option<ProcessIdentity>,
    pub(crate) detail: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkIntent {
    protocol: String,
    work_id: String,
    root_id: String,
    #[serde(default)]
    domain_id: String,
    #[serde(default = "legacy_control_protocol")]
    control_protocol: String,
    #[serde(default)]
    root_identity: Option<ProcessIdentity>,
    root_endpoint: Vec<u8>,
    supervisor_authority_id: String,
    guardian_identity: ProcessIdentity,
    cancel_capability: String,
    handle: String,
    state_root: PathBuf,
    meta: Meta,
    argv: Vec<String>,
    completion_scope: String,
    ready_sentinel: Option<String>,
    registration_authority: Option<Vec<u8>>,
    environment: Vec<EnvironmentEntry>,
    cancel_owner: Option<ProcessIdentity>,
}

#[derive(Debug, Serialize)]
struct Diagnostic<'a> {
    protocol: &'a str,
    work_id: &'a str,
    phase: &'a str,
    initiator_pid: u32,
    root_id: Option<&'a str>,
    supervisor_authority_id: Option<&'a str>,
    worker_pid: Option<i64>,
    worker_starttime_ticks: Option<u64>,
    detail: Option<&'a str>,
}

pub(crate) fn selected(paths: &StatePaths, meta: &Meta) -> io::Result<bool> {
    let required = match std::env::var_os(REQUIRED_ENV) {
        None => false,
        Some(value) if value == "1" => true,
        Some(_) => {
            return Err(preaccept_failure(
                paths,
                meta,
                io::Error::other("paired original-work requirement marker is invalid"),
            ));
        }
    };
    // The session ring is inherited across fork/exec, setsid, and reparenting.
    // It only vetoes standalone admission; it never supplies submit authority.
    // Inspect it even for endpoint-only legacy callers, before ancestry can
    // incorrectly declare an orphaned paired descendant independent.
    if !required && std::env::var_os(ROOT_AUTHORITY_ENV).is_none() {
        match inherited_paired_session_ring() {
            Ok(true) => {
                return Err(preaccept_failure(
                    paths,
                    meta,
                    io::Error::other(
                        "inherited paired session keyring but original-work authority is missing",
                    ),
                ));
            }
            Err(error) => return Err(preaccept_failure(paths, meta, error)),
            Ok(false) => {}
        }
    }
    // A wrapper can erase its own environment while remaining a descendant
    // of the accepted paired worker. In that case standalone would create a
    // second owner. Inspect the live, incarnation-stable ancestor chain before
    // treating missing ambient grant/marker as genuine standalone entry.
    if !required && std::env::var_os(ROOT_AUTHORITY_ENV).is_none() {
        match has_paired_custodian_ancestor() {
            Ok(true) => {
                return Err(preaccept_failure(
                    paths,
                    meta,
                    io::Error::other(
                        "paired worker or guardian ancestor is live but inherited original-work authority is missing",
                    ),
                ));
            }
            Err(error) => return Err(preaccept_failure(paths, meta, error)),
            Ok(false) => {}
        }
    }
    match (
        std::env::var_os(ENDPOINT_ENV),
        std::env::var_os(ROOT_AUTHORITY_ENV),
    ) {
        (None, None) if !required => Ok(false),
        (Some(_), None) if !required => Ok(false),
        (Some(_), Some(_)) => Ok(true),
        (None, None) => Err(preaccept_failure(
            paths,
            meta,
            io::Error::other(
                "paired original-work context is required but endpoint and root authority are missing",
            ),
        )),
        (Some(_), None) => Err(preaccept_failure(
            paths,
            meta,
            io::Error::other(
                "paired root endpoint is present but root authority is missing; standalone fallback is forbidden",
            ),
        )),
        (None, Some(_)) => Err(preaccept_failure(
            paths,
            meta,
            io::Error::other(
                "paired root authority is present but endpoint is missing; standalone fallback is forbidden",
            ),
        )),
    }
}

// KEYCTL_GET_KEYRING_ID with create=0 does not join or create a ring. The
// kernel description is a bounded, NUL-terminated
// `keyring;uid;gid;permissions;name` record. Never interpret a failed query,
// truncated description, changed ring, or malformed identity as independence.
fn inherited_paired_session_ring() -> io::Result<bool> {
    let session_id = session_ring_id()?;
    let mut description = [0u8; MAX_KEY_DESCRIPTION_BYTES];
    let length = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_DESCRIBE,
            session_id,
            description.as_mut_ptr(),
            description.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    let length = usize::try_from(length).map_err(io::Error::other)?;
    if length == 0 || length > description.len() || description[length - 1] != 0 {
        return Err(io::Error::other(
            "session keyring description is missing or truncated",
        ));
    }
    if session_ring_id()? != session_id {
        return Err(io::Error::other(
            "session keyring identity changed during classification",
        ));
    }
    parse_session_ring_description(&description[..length - 1], unsafe { libc::geteuid() })
}

fn session_ring_id() -> io::Result<libc::c_long> {
    let id = unsafe {
        libc::syscall(
            libc::SYS_keyctl,
            libc::KEYCTL_GET_KEYRING_ID,
            libc::KEY_SPEC_SESSION_KEYRING,
            0,
        )
    };
    if id < 0 {
        return Err(io::Error::last_os_error());
    }
    if id == 0 || id > i32::MAX.into() {
        return Err(io::Error::other("invalid session keyring identifier"));
    }
    Ok(id)
}

fn parse_session_ring_description(
    description: &[u8],
    effective_uid: libc::uid_t,
) -> io::Result<bool> {
    let record = std::str::from_utf8(description)
        .map_err(|_| io::Error::other("invalid session keyring description encoding"))?;
    let mut fields = record.split(';');
    let (Some("keyring"), Some(uid), Some(gid), Some(permissions), Some(name), None) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(io::Error::other(
            "invalid session keyring description fields",
        ));
    };
    let canonical_decimal = |value: &str| -> io::Result<u32> {
        let parsed: u32 = value
            .parse()
            .map_err(|_| io::Error::other("invalid session keyring owner"))?;
        if parsed.to_string() != value {
            return Err(io::Error::other("noncanonical session keyring owner"));
        }
        Ok(parsed)
    };
    if canonical_decimal(uid)? != effective_uid {
        return Err(io::Error::other(
            "session keyring owner UID differs from caller",
        ));
    }
    canonical_decimal(gid)?;
    if permissions.len() != 8 || !permissions.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(io::Error::other(
            "invalid session keyring permission description",
        ));
    }
    if name.is_empty() || !name.is_ascii() || name.bytes().any(|b| b == 0 || b.is_ascii_control()) {
        return Err(io::Error::other("invalid session keyring name"));
    }
    if let Some(uuid) = name.strip_prefix(PAIRED_RING_PREFIX) {
        if !valid_paired_ring_uuid(uuid) {
            return Err(io::Error::other("invalid paired session keyring UUID"));
        }
        return Ok(true);
    }
    Ok(false)
}

fn valid_paired_ring_uuid(uuid: &str) -> bool {
    let bytes = uuid.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(byte),
        })
        // Random v4 UUID, RFC 4122 variant. This is a lineage discriminator,
        // not a secret and not proof of permission to submit paired work.
        && bytes[14] == b'4'
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

fn has_paired_custodian_ancestor() -> io::Result<bool> {
    let own_image = std::fs::metadata("/proc/self/exe")?;
    // The guardian is the kernel subreaper for an accepted worker. A child
    // adopted after worker exit retains this ancestor even if its session
    // keyring was replaced by keyctl session or PAM keyinit.
    let uid = unsafe { libc::geteuid() };
    let socket_prefix = format!("/tmp/oulipoly-completion-{uid}-");
    let guardian_sockets: std::collections::HashSet<String> =
        std::fs::read_to_string("/proc/net/unix")?
            .lines()
            .filter_map(|line| {
                let fields: Vec<_> = line.split_whitespace().collect();
                let path = fields.get(7)?;
                let domain = path
                    .strip_prefix(&socket_prefix)?
                    .strip_suffix("/owner.sock")?;
                if !valid_paired_ring_uuid(domain) {
                    return None;
                }
                Some(fields.get(6)?.to_string())
            })
            .collect();
    let mut pid = state::observer_parent_pid()?;
    for _ in 0..256 {
        if pid <= 1 {
            return Ok(false);
        }
        let before = state::process_starttime_ticks(pid).ok_or_else(|| {
            io::Error::other("ancestor identity unavailable during paired classification")
        })?;
        let parent = state::process_parent_pid(pid).ok_or_else(|| {
            io::Error::other("ancestor parent unavailable during paired classification")
        })?;
        if std::fs::metadata(format!("/proc/{pid}"))?.uid() != unsafe { libc::geteuid() } {
            // The paired worker is a same-UID ancestor. An older, different
            // UID process cannot be that worker in this one-user topology.
            return Ok(false);
        }
        let mut command = Vec::new();
        File::open(format!("/proc/{pid}/cmdline"))?
            .take(4096)
            .read_to_end(&mut command)?;
        if command.split(|byte| *byte == 0).nth(1) == Some(EXECUTOR_ARG.as_bytes()) {
            // Some legitimate caller ancestors hide /proc/PID/exe under
            // non-dumpable credentials. Inspect the image only for the exact
            // internal-worker argv, which must remain readable when paired.
            let image = std::fs::metadata(format!("/proc/{pid}/exe"))?;
            if image.dev() == own_image.dev() && image.ino() == own_image.ino() {
                if state::process_starttime_ticks(pid) == Some(before) {
                    return Ok(true);
                }
                return Err(io::Error::other(
                    "paired ancestor identity changed during classification",
                ));
            }
        }
        // A bound owner.sock inode held by this exact ancestor identifies the
        // live root guardian, not a client connection or a process name.
        let fd_dir = format!("/proc/{pid}/fd");
        for fd in std::fs::read_dir(fd_dir)? {
            let fd = fd?;
            let target = std::fs::read_link(fd.path())?;
            if let Some(inode) = target
                .to_string_lossy()
                .strip_prefix("socket:[")
                .and_then(|v| v.strip_suffix(']'))
            {
                if guardian_sockets.contains(inode) {
                    if state::process_starttime_ticks(pid) == Some(before) {
                        return Ok(true);
                    }
                    return Err(io::Error::other(
                        "paired guardian identity changed during classification",
                    ));
                }
            }
        }
        if state::process_starttime_ticks(pid) != Some(before) || parent == pid {
            return Err(io::Error::other(
                "ancestor identity changed during paired classification",
            ));
        }
        pid = parent;
    }
    Err(io::Error::other(
        "paired ancestry exceeds bounded classification depth",
    ))
}

pub(crate) fn submit(
    paths: &StatePaths,
    meta: &Meta,
    argv: Vec<String>,
    completion_scope: CompletionScope,
    ready_sentinel: Option<String>,
    registration: delivery::DeliveryRegistration,
) -> io::Result<StartupOutcome> {
    let endpoint = std::env::var_os(ENDPOINT_ENV)
        .ok_or_else(|| io::Error::other("root endpoint missing; original work was not dispatched"))
        .map_err(|error| preaccept_failure(paths, meta, error))?;
    let grant = parse_grant().map_err(|error| preaccept_failure(paths, meta, error))?;
    if grant.protocol != ROOT_PROTOCOL {
        return Err(preaccept_failure(
            paths,
            meta,
            io::Error::other("unsupported root authority protocol"),
        ));
    }
    control_route(&grant.control_protocol)
        .map_err(|error| preaccept_failure(paths, meta, error))?;
    let parent = std::env::var(ROOT_WORK_ID_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let parent_capability = std::env::var(ROOT_PARENT_CAPABILITY_ENV)
        .ok()
        .filter(|value| !value.is_empty());
    let registration_mode = match (parent, parent_capability) {
        (Some(parent_work_id), Some(parent_capability)) => WorkRegistration::Nested {
            parent_work_id,
            parent_capability,
        },
        (None, None) => WorkRegistration::Root,
        _ => {
            return Err(preaccept_failure(
                paths,
                meta,
                io::Error::other("incomplete inherited causal-parent authority"),
            ));
        }
    };
    let environment = std::env::vars_os()
        .filter(|(key, _)| {
            key.as_os_str() != OsStr::new(ROOT_WORK_ID_ENV)
                && key.as_os_str() != OsStr::new(ROOT_PARENT_CAPABILITY_ENV)
        })
        .map(|(key, value)| EnvironmentEntry {
            key: key.as_os_str().as_bytes().to_vec(),
            value: value.as_os_str().as_bytes().to_vec(),
        })
        .collect();
    let cancel_capability = new_capability()?;
    let intent = WorkIntent {
        protocol: PROTOCOL.into(),
        work_id: paths.handle.clone(),
        root_id: grant.root_id.clone(),
        domain_id: grant.domain_id.clone(),
        control_protocol: grant.control_protocol.clone(),
        root_identity: Some(grant.root_identity.clone()),
        root_endpoint: endpoint.as_os_str().as_bytes().to_vec(),
        supervisor_authority_id: grant.supervisor_authority_id.clone(),
        guardian_identity: grant.guardian_identity.clone(),
        cancel_capability: cancel_capability.clone(),
        handle: paths.handle.clone(),
        state_root: paths.root.clone(),
        meta: meta.clone(),
        argv,
        completion_scope: match completion_scope {
            CompletionScope::Tree => "tree",
            CompletionScope::Root => "root",
        }
        .into(),
        ready_sentinel,
        registration_authority: registration.into_root_authority(),
        environment,
        cancel_owner: meta.cancel_owner.as_ref().map(ProcessIdentity::from),
    };
    let intent_bytes = serde_json::to_vec(&intent)
        .map_err(io::Error::other)
        .map_err(|error| preaccept_failure(paths, meta, error))?;
    if let Err(error) = state::atomic_write(&paths.state_dir.join(INTENT_FILE), &intent_bytes) {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "intent_persist_failed_preaccept",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        return Err(preaccept_failure(paths, meta, error));
    }
    append_diagnostic(
        paths,
        &Diagnostic {
            protocol: PROTOCOL,
            work_id: &paths.handle,
            phase: "initiated",
            initiator_pid: std::process::id(),
            root_id: Some(&grant.root_id),
            supervisor_authority_id: Some(&grant.supervisor_authority_id),
            worker_pid: None,
            worker_starttime_ticks: None,
            detail: None,
        },
    )
    .map_err(|error| preaccept_failure(paths, meta, error))?;
    let pinned = (|| {
        let executable = OpenOptions::new()
            .read(true)
            // `/proc/self/exe` is itself the kernel-owned magic link to the
            // executing inode. Following that one link creates the pin; the
            // root independently compares it with the peer's live image.
            .custom_flags(libc::O_CLOEXEC)
            .open("/proc/self/exe")?;
        let request = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(paths.state_dir.join(INTENT_FILE))?;
        let cwd = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&meta.cwd)?;
        let state_dir = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
            .open(&paths.state_dir)?;
        Ok::<_, io::Error>((executable, request, cwd, state_dir))
    })()
    .map_err(|error| {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "descriptor_pin_failed_preaccept",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        preaccept_failure(paths, meta, error)
    })?;
    let (executable, request, cwd, state_dir) = pinned;
    let submission = WorkSubmission {
        protocol: PROTOCOL.into(),
        root_authority: grant.clone(),
        work_id: paths.handle.clone(),
        request_sha256: hex_digest(&intent_bytes),
        registration: registration_mode,
        cancel_capability,
    };
    let mut socket = UnixStream::connect(Path::new(&endpoint)).map_err(|error| {
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "transport_failed_preaccept",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some("root endpoint connect failed"),
            },
        );
        preaccept_failure(paths, meta, error)
    })?;
    let mut frame = b"work!\n".to_vec();
    frame.extend(
        serde_json::to_vec(&submission)
            .map_err(io::Error::other)
            .map_err(|error| preaccept_failure(paths, meta, error))?,
    );
    frame.push(b'\n');
    if frame.len() >= MAX_WORK_FRAME_BYTES {
        return Err(preaccept_failure(
            paths,
            meta,
            io::Error::other("root work frame exceeds bounded size"),
        ));
    }
    let source_scope = match &submission.registration {
        WorkRegistration::Root => SourceScope::Root,
        WorkRegistration::Nested { parent_work_id, .. } => SourceScope::Nested { parent_work_id },
    };
    authenticate_control(
        &socket,
        &grant.control_protocol,
        &grant.root_id,
        &grant.domain_id,
        &grant.supervisor_authority_id,
        &grant.guardian_identity,
        source_scope,
    )
    .map_err(|error| {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "peer_identity_rejected_preaccept",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        preaccept_failure(paths, meta, error)
    })?;
    if let Err(error) = send_with_fds(
        &mut socket,
        &frame,
        &[
            executable.as_raw_fd(),
            request.as_raw_fd(),
            cwd.as_raw_fd(),
            state_dir.as_raw_fd(),
        ],
    ) {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "acceptance_outcome_unknown",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        return Ok(StartupOutcome::RootEffectsPossibleNoReplay);
    }
    if grant.control_protocol == SOURCE_CONTROL_PROTOCOL
        && socket.shutdown(Shutdown::Write).is_err()
    {
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "acceptance_outcome_unknown",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some("root frame half-close failed; replay forbidden"),
            },
        );
        return Ok(StartupOutcome::RootEffectsPossibleNoReplay);
    }
    let response: WorkResponse = match read_response(&mut socket) {
        Ok(response) => response,
        Err(_error) => {
            let _ = append_diagnostic(
                paths,
                &Diagnostic {
                    protocol: PROTOCOL,
                    work_id: &paths.handle,
                    phase: "acceptance_outcome_unknown",
                    initiator_pid: std::process::id(),
                    root_id: Some(&grant.root_id),
                    supervisor_authority_id: Some(&grant.supervisor_authority_id),
                    worker_pid: None,
                    worker_starttime_ticks: None,
                    detail: Some("root reply lost; replay forbidden"),
                },
            );
            return Ok(StartupOutcome::RootEffectsPossibleNoReplay);
        }
    };
    let response_identity = validate_response(&response, &submission);
    if let Err(error) = &response_identity {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &paths.handle,
                phase: "response_identity_conflict",
                initiator_pid: std::process::id(),
                root_id: Some(&grant.root_id),
                supervisor_authority_id: Some(&grant.supervisor_authority_id),
                worker_pid: response
                    .worker_identity
                    .as_ref()
                    .map(|identity| identity.pid),
                worker_starttime_ticks: response
                    .worker_identity
                    .as_ref()
                    .map(|identity| identity.starttime_ticks),
                detail: Some(&detail),
            },
        );
    }
    let _ = append_diagnostic(
        paths,
        &Diagnostic {
            protocol: PROTOCOL,
            work_id: &paths.handle,
            phase: &response.status,
            initiator_pid: std::process::id(),
            root_id: Some(&grant.root_id),
            supervisor_authority_id: Some(&grant.supervisor_authority_id),
            worker_pid: response
                .worker_identity
                .as_ref()
                .map(|identity| identity.pid),
            worker_starttime_ticks: response
                .worker_identity
                .as_ref()
                .map(|identity| identity.starttime_ticks),
            detail: response.detail.as_deref(),
        },
    );
    match submit_response_disposition(&response, &submission) {
        SubmitResponseDisposition::Accepted => Ok(StartupOutcome::RootAccepted),
        SubmitResponseDisposition::RejectedPreaccept => Err(preaccept_failure(
            paths,
            meta,
            io::Error::other(response.detail.unwrap_or(response.status)),
        )),
        SubmitResponseDisposition::EffectsPossibleNoReplay => {
            Ok(StartupOutcome::RootEffectsPossibleNoReplay)
        }
    }
}

pub(crate) fn cancel(paths: &StatePaths) -> io::Result<Option<WorkResponse>> {
    if !paths.state_dir.join(ACCEPTED_FILE).try_exists()? {
        return Ok(None);
    }
    let intent: WorkIntent =
        serde_json::from_slice(&std::fs::read(paths.state_dir.join(INTENT_FILE))?)?;
    control_route(&intent.control_protocol)?;
    let endpoint = OsString::from_vec(intent.root_endpoint.clone());
    let submission = CancelSubmission {
        protocol: PROTOCOL.into(),
        root_id: intent.root_id.clone(),
        supervisor_authority_id: intent.supervisor_authority_id.clone(),
        work_id: intent.work_id.clone(),
        cancel_capability: intent.cancel_capability.clone(),
    };
    append_diagnostic(
        paths,
        &Diagnostic {
            protocol: PROTOCOL,
            work_id: &submission.work_id,
            phase: "cancellation_initiated",
            initiator_pid: std::process::id(),
            root_id: Some(&submission.root_id),
            supervisor_authority_id: Some(&submission.supervisor_authority_id),
            worker_pid: None,
            worker_starttime_ticks: None,
            detail: None,
        },
    )?;
    let mut socket = UnixStream::connect(Path::new(&endpoint)).map_err(|error| {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &submission.work_id,
                phase: "cancellation_transport_failed",
                initiator_pid: std::process::id(),
                root_id: Some(&submission.root_id),
                supervisor_authority_id: Some(&submission.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        error
    })?;
    let parent_work_id = std::env::var(ROOT_WORK_ID_ENV).ok();
    let prewire = (|| {
        let frame = if intent.control_protocol == SOURCE_CONTROL_PROTOCOL {
            let mut frame = b"cancel\n".to_vec();
            frame.extend(serde_json::to_vec(&submission)?);
            frame.push(b'\n');
            if frame.len() >= MAX_WORK_FRAME_BYTES {
                return Err(io::Error::other(
                    "root cancellation frame exceeds bounded size",
                ));
            }
            Some(frame)
        } else {
            None
        };
        let scope = if intent.control_protocol == SOURCE_CONTROL_PROTOCOL {
            cancel_scope(&intent, parent_work_id.as_deref())?
        } else {
            SourceScope::CancelOutside {
                work_id: &submission.work_id,
            }
        };
        authenticate_control(
            &socket,
            &intent.control_protocol,
            &intent.root_id,
            &intent.domain_id,
            &intent.supervisor_authority_id,
            &intent.guardian_identity,
            scope,
        )?;
        Ok::<_, io::Error>(frame)
    })();
    let v2_frame = prewire.inspect_err(|error| {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &submission.work_id,
                phase: "cancellation_source_refused_pre_wire",
                initiator_pid: std::process::id(),
                root_id: Some(&submission.root_id),
                supervisor_authority_id: Some(&submission.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
    })?;
    let response_result = (|| {
        if let Some(frame) = v2_frame {
            socket.write_all(&frame)?;
            socket.shutdown(Shutdown::Write)?;
        } else {
            socket.write_all(b"cancel\n")?;
            serde_json::to_writer(&mut socket, &submission)?;
            socket.write_all(b"\n")?;
        }
        read_response(&mut socket)
    })();
    let response: WorkResponse = response_result.map_err(|error| {
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &submission.work_id,
                phase: "cancellation_outcome_unknown",
                initiator_pid: std::process::id(),
                root_id: Some(&submission.root_id),
                supervisor_authority_id: Some(&submission.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        error
    })?;
    if response.protocol != PROTOCOL
        || response.work_id != submission.work_id
        || response.root_id != submission.root_id
        || response.supervisor_authority_id != submission.supervisor_authority_id
    {
        let error = io::Error::other("root cancellation response conflict");
        let detail = error.to_string();
        let _ = append_diagnostic(
            paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: &submission.work_id,
                phase: "cancellation_response_identity_conflict",
                initiator_pid: std::process::id(),
                root_id: Some(&submission.root_id),
                supervisor_authority_id: Some(&submission.supervisor_authority_id),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: Some(&detail),
            },
        );
        return Err(error);
    }
    append_diagnostic(
        paths,
        &Diagnostic {
            protocol: PROTOCOL,
            work_id: &submission.work_id,
            phase: &response.status,
            initiator_pid: std::process::id(),
            root_id: Some(&submission.root_id),
            supervisor_authority_id: Some(&submission.supervisor_authority_id),
            worker_pid: None,
            worker_starttime_ticks: None,
            detail: response.detail.as_deref(),
        },
    )?;
    Ok(Some(response))
}

pub(crate) fn internal_main() -> Option<i32> {
    if std::env::args().nth(1).as_deref() != Some(EXECUTOR_ARG) {
        return None;
    }
    Some(run_internal().unwrap_or(70))
}

fn run_internal() -> io::Result<i32> {
    let mut args = std::env::args().skip(2);
    let request_fd = parse_fd(args.next())?;
    let cwd_fd = parse_fd(args.next())?;
    let state_dir_fd = parse_fd(args.next())?;
    let control_fd = parse_fd(args.next())?;
    let capability_fd = parse_fd(args.next())?;
    if args.next().is_some() {
        return Err(io::Error::other(
            "unexpected original-work executor argument",
        ));
    }
    let mut request = unsafe { File::from_raw_fd(request_fd) };
    let mut bytes = Vec::new();
    request.read_to_end(&mut bytes)?;
    drop(request);
    let intent: WorkIntent = serde_json::from_slice(&bytes)?;
    if intent.protocol != PROTOCOL || intent.work_id != intent.handle {
        return Err(io::Error::other("original-work executor intent mismatch"));
    }
    validate_directory_fd(state_dir_fd, &intent.state_root.join(&intent.handle))?;
    if unsafe { libc::fchdir(cwd_fd) } != 0 {
        return Err(io::Error::last_os_error());
    }
    for fd in [cwd_fd, state_dir_fd] {
        unsafe { libc::close(fd) };
    }
    let control_flags = unsafe { libc::fcntl(control_fd, libc::F_GETFD) };
    if control_flags < 0
        || unsafe { libc::fcntl(control_fd, libc::F_SETFD, control_flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let status_flags = unsafe { libc::fcntl(control_fd, libc::F_GETFL) };
    if status_flags < 0
        || unsafe { libc::fcntl(control_fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    restore_environment(&intent.environment)?;
    unsafe {
        std::env::set_var(ROOT_WORK_ID_ENV, &intent.work_id);
        std::env::remove_var(ROOT_PARENT_CAPABILITY_ENV);
    }
    let child_capability_file = unsafe { File::from_raw_fd(capability_fd) };
    let mut child_capability = String::new();
    child_capability_file
        .take(129)
        .read_to_string(&mut child_capability)?;
    if child_capability.len() != 64
        || !child_capability
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(io::Error::other("invalid causal child capability"));
    }
    let paths = StatePaths::new(intent.state_root.clone(), intent.handle.clone());
    let registration = delivery::DeliveryRegistration::from_root_request(
        &paths,
        intent.meta.delivery_helper.as_ref(),
        intent.registration_authority,
    )?;
    let completion_scope = match intent.completion_scope.as_str() {
        "tree" => CompletionScope::Tree,
        "root" => CompletionScope::Root,
        _ => return Err(io::Error::other("invalid original-work completion scope")),
    };
    let config = SupervisorConfig {
        paths,
        meta: intent.meta,
        argv: intent.argv,
        completion_scope,
        ready_sentinel: intent.ready_sentinel,
    };
    Ok(supervisor::run_root_worker(
        config,
        registration,
        control_fd,
        child_capability,
    ))
}

fn parse_grant() -> io::Result<RootAuthorityGrant> {
    let value = std::env::var(ROOT_AUTHORITY_ENV)
        .map_err(|_| io::Error::other("root authority capability missing"))?;
    serde_json::from_str(&value).map_err(io::Error::other)
}

fn control_route(protocol: &str) -> io::Result<()> {
    match protocol {
        LEGACY_CONTROL_PROTOCOL | SOURCE_CONTROL_PROTOCOL => Ok(()),
        _ => Err(io::Error::other("unsupported root control protocol")),
    }
}

fn cancel_scope<'a>(
    intent: &'a WorkIntent,
    parent_work_id: Option<&'a str>,
) -> io::Result<SourceScope<'a>> {
    if intent.domain_id.is_empty() || intent.root_identity.is_none() {
        return Err(io::Error::other(
            "pinned cancellation intent has no root/domain binding",
        ));
    }
    let current_ns = std::fs::read_link("/proc/self/ns/pid")?;
    let guardian_ns = std::fs::read_link(format!("/proc/{}/ns/pid", intent.guardian_identity.pid))?;
    Ok(scope_for_namespaces(
        &current_ns,
        &guardian_ns,
        parent_work_id,
        &intent.work_id,
    ))
}

fn scope_for_namespaces<'a>(
    current_ns: &Path,
    guardian_ns: &Path,
    parent_work_id: Option<&'a str>,
    work_id: &'a str,
) -> SourceScope<'a> {
    if current_ns == guardian_ns {
        SourceScope::CancelOutside { work_id }
    } else if let Some(parent_work_id) = parent_work_id.filter(|value| !value.is_empty()) {
        SourceScope::Nested { parent_work_id }
    } else {
        // A root Runner process can exit while its PID1 and work remain. The
        // broker verifies this candidate against the caller's current scope.
        SourceScope::Root
    }
}

fn authenticate_control(
    socket: &UnixStream,
    protocol: &str,
    root_id: &str,
    domain_id: &str,
    supervisor_id: &str,
    guardian: &ProcessIdentity,
    scope: SourceScope<'_>,
) -> io::Result<()> {
    match protocol {
        LEGACY_CONTROL_PROTOCOL => authenticate_peer(socket, guardian),
        SOURCE_CONTROL_PROTOCOL => {
            // The legacy SO_PEERCRED PID comparison crosses PID domains here.
            // Broker `s` checks this exact FD against the host guardian stamp
            // and the caller's live host-observed incarnation instead.
            let source = host_observed_source()?;
            let host_pid = i32::try_from(guardian.pid)
                .map_err(|_| io::Error::other("invalid guardian host PID"))?;
            let witness = SourceSocketWitness {
                root_id,
                domain_id,
                supervisor_id,
                guardian: ProcessWitness {
                    host_pid,
                    boot_id: &guardian.boot_id,
                    starttime_ticks: guardian.starttime_ticks,
                },
                source: ProcessWitness {
                    host_pid: source.pid,
                    boot_id: &source.boot_id,
                    starttime_ticks: source.starttime_ticks,
                },
                scope,
            };
            verify_source_socket_v2_at(&broker_socket_path(), socket, &witness, 0)
        }
        _ => Err(io::Error::other("unsupported root control protocol")),
    }
}

struct ObservedSource {
    pid: i32,
    boot_id: String,
    starttime_ticks: u64,
}

fn host_observed_source() -> io::Result<ObservedSource> {
    // getpid() is namespace-local. The first field of /proc/self/stat is a
    // key in the mounted procfs observer; the host broker authenticates this
    // assertion against the actual request sender in its own PID domain.
    let observer = std::fs::metadata("/proc")?;
    let stat = std::fs::read_to_string("/proc/self/stat")?;
    let pid = stat
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        .filter(|pid| *pid > 0)
        .ok_or_else(|| io::Error::other("invalid procfs observer source PID"))?;
    let starttime_ticks = stat_starttime(&stat)
        .ok_or_else(|| io::Error::other("invalid procfs observer source starttime"))?;
    let direct = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
    if direct
        .split_whitespace()
        .next()
        .and_then(|value| value.parse::<i32>().ok())
        != Some(pid)
        || stat_starttime(&direct) != Some(starttime_ticks)
        || std::fs::metadata("/proc")?.dev() != observer.dev()
        || std::fs::metadata("/proc")?.ino() != observer.ino()
    {
        return Err(io::Error::other("procfs source observer changed"));
    }
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
        .trim()
        .to_owned();
    if boot_id.is_empty() {
        return Err(io::Error::other("procfs source boot identity missing"));
    }
    Ok(ObservedSource {
        pid,
        boot_id,
        starttime_ticks,
    })
}

fn stat_starttime(stat: &str) -> Option<u64> {
    stat.rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
}

fn broker_socket_path() -> PathBuf {
    #[cfg(feature = "source-fault-tests")]
    if unsafe { libc::geteuid() } == 0
        && std::fs::read_to_string("/proc/self/uid_map")
            .ok()
            .is_some_and(|map| map.split_ascii_whitespace().nth(2) == Some("1"))
        && let Some(path) = std::env::var_os("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1")
    {
        return PathBuf::from(path);
    }
    PathBuf::from(BROKER_SOCKET)
}

fn verify_source_socket_v2_at(
    broker_path: &Path,
    source_socket: &UnixStream,
    witness: &SourceSocketWitness<'_>,
    expected_broker_uid: u32,
) -> io::Result<()> {
    let body = serde_json::to_vec(witness)?;
    if body.len() > MAX_SOURCE_WITNESS_BYTES {
        return Err(io::Error::other("source socket witness too large"));
    }
    let mut broker = UnixStream::connect(broker_path)?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut peer_len = std::mem::size_of_val(&peer) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            broker.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut peer_len,
        )
    } != 0
        || peer_len as usize != std::mem::size_of_val(&peer)
        || peer.uid != expected_broker_uid
    {
        return Err(io::Error::other("broker peer is not host root"));
    }
    let mut challenge = [0u8; 16];
    broker.read_exact(&mut challenge)?;
    let mut request = Vec::with_capacity(17 + body.len());
    request.push(b's');
    request.extend_from_slice(&challenge);
    request.extend_from_slice(&body);
    let mut iov = libc::iovec {
        iov_base: request.as_mut_ptr().cast(),
        iov_len: request.len(),
    };
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize;
        *libc::CMSG_DATA(header).cast::<RawFd>() = source_socket.as_raw_fd();
    }
    if unsafe { libc::sendmsg(broker.as_raw_fd(), &message, libc::MSG_NOSIGNAL) }
        != request.len() as isize
    {
        return Err(io::Error::other(
            "short source control verification request",
        ));
    }
    let mut response = Vec::new();
    (&mut broker).take(257).read_to_end(&mut response)?;
    if response != format!("verified-source-v2 {}\n", witness.root_id).as_bytes() {
        return Err(io::Error::other("host source control verification refused"));
    }
    Ok(())
}

fn parse_fd(value: Option<String>) -> io::Result<RawFd> {
    value
        .ok_or_else(|| io::Error::other("missing original-work descriptor"))?
        .parse()
        .map_err(|_| io::Error::other("invalid original-work descriptor"))
}

fn send_with_fds(socket: &mut UnixStream, bytes: &[u8], fds: &[RawFd; FD_COUNT]) -> io::Result<()> {
    let mut first = [bytes[0]];
    let mut iov = libc::iovec {
        iov_base: first.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0usize; 16];
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen =
        unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(fds.as_ptr(), libc::CMSG_DATA(header).cast(), FD_COUNT);
        if libc::sendmsg(socket.as_raw_fd(), &message, libc::MSG_NOSIGNAL) != 1 {
            return Err(io::Error::last_os_error());
        }
    }
    socket.write_all(&bytes[1..])
}

fn read_response<T: serde::de::DeserializeOwned>(socket: &mut UnixStream) -> io::Result<T> {
    let mut bytes = Vec::new();
    loop {
        if bytes.len() >= MAX_RESPONSE_BYTES {
            return Err(io::Error::other("root response exceeds bounded frame"));
        }
        let mut byte = [0];
        socket.read_exact(&mut byte)?;
        if byte == [b'\n'] {
            break;
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn validate_response(response: &WorkResponse, submission: &WorkSubmission) -> io::Result<()> {
    if response.protocol != PROTOCOL
        || response.work_id != submission.work_id
        || response.root_id != submission.root_authority.root_id
        || response.supervisor_authority_id != submission.root_authority.supervisor_authority_id
    {
        return Err(io::Error::other(
            "root original-work response identity conflict",
        ));
    }
    if response.status == "accepted" && response.worker_identity.is_none() {
        return Err(io::Error::other(
            "accepted original work has no exact worker identity",
        ));
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum SubmitResponseDisposition {
    Accepted,
    RejectedPreaccept,
    EffectsPossibleNoReplay,
}

fn submit_response_disposition(
    response: &WorkResponse,
    submission: &WorkSubmission,
) -> SubmitResponseDisposition {
    if validate_response(response, submission).is_err() {
        return SubmitResponseDisposition::EffectsPossibleNoReplay;
    }
    match response.status.as_str() {
        "accepted" | "already_accepted_no_replay" => SubmitResponseDisposition::Accepted,
        "rejected_preaccept" => SubmitResponseDisposition::RejectedPreaccept,
        // A valid but unrecognized response arrived only after the request and
        // descriptors were transferred. The root may have committed; no
        // response shape at this point can make replay safe.
        _ => SubmitResponseDisposition::EffectsPossibleNoReplay,
    }
}

fn authenticate_peer(socket: &UnixStream, expected: &ProcessIdentity) -> io::Result<()> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of_val(&credentials) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || credentials.uid != unsafe { libc::geteuid() }
        || i64::from(credentials.pid) != expected.pid
        || !process_identity_live(expected)
    {
        return Err(io::Error::other("root endpoint peer identity mismatch"));
    }
    Ok(())
}

fn process_identity_live(expected: &ProcessIdentity) -> bool {
    let Ok(stat) = std::fs::read_to_string(format!("/proc/{}/stat", expected.pid)) else {
        return false;
    };
    let Some(starttime) = stat
        .rsplit_once(')')
        .and_then(|(_, tail)| tail.split_whitespace().nth(19))
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return false;
    };
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap_or_default()
        .trim()
        .to_owned();
    starttime == expected.starttime_ticks && boot_id == expected.boot_id
}

fn validate_directory_fd(fd: RawFd, expected: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let descriptor = std::fs::metadata(format!("/proc/self/fd/{fd}"))?;
    let path = std::fs::metadata(expected)?;
    if !descriptor.is_dir() || descriptor.dev() != path.dev() || descriptor.ino() != path.ino() {
        return Err(io::Error::other(
            "original-work state directory identity mismatch",
        ));
    }
    Ok(())
}

fn restore_environment(entries: &[EnvironmentEntry]) -> io::Result<()> {
    if unsafe { libc::clearenv() } != 0 {
        return Err(io::Error::last_os_error());
    }
    for entry in entries {
        let key = OsString::from_vec(entry.key.clone());
        let value = OsString::from_vec(entry.value.clone());
        if key.as_os_str().as_bytes().contains(&0) || value.as_os_str().as_bytes().contains(&0) {
            return Err(io::Error::other("original-work environment contains NUL"));
        }
        unsafe { std::env::set_var(key, value) };
    }
    Ok(())
}

fn append_diagnostic(paths: &StatePaths, diagnostic: &Diagnostic<'_>) -> io::Result<()> {
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(paths.state_dir.join(DIAGNOSTIC_LOCK_FILE))?;
    loop {
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } == 0 {
            break;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }

    let mut value = serde_json::to_value(diagnostic)?;
    if let Some(object) = value.as_object_mut() {
        object.insert(
            "initiator_identity".into(),
            serde_json::to_value(current_process_identity()).map_err(io::Error::other)?,
        );
        object.insert(
            "root_process_identity".into(),
            serde_json::to_value(parse_grant().ok().map(|grant| grant.root_identity))
                .map_err(io::Error::other)?,
        );
    }
    let mut record = serde_json::to_vec(&value)?;
    if record.len() > MAX_DIAGNOSTIC_RECORD_BYTES {
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "detail".into(),
                serde_json::Value::String(
                    "diagnostic record exceeded the bounded record size; detail omitted".into(),
                ),
            );
        }
        record = serde_json::to_vec(&value)?;
    }
    record.push(b'\n');

    let diagnostic_path = paths.state_dir.join(DIAGNOSTIC_FILE);
    let rotated_path = paths.state_dir.join(DIAGNOSTIC_ROTATED_FILE);
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&diagnostic_path)?;
    if file.metadata()?.len().saturating_add(record.len() as u64) > MAX_DIAGNOSTIC_BYTES {
        let current_len = file.metadata()?.len();
        file.sync_data()?;
        drop(file);
        match std::fs::remove_file(&rotated_path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if current_len <= MAX_DIAGNOSTIC_BYTES {
            std::fs::rename(&diagnostic_path, &rotated_path)?;
        } else {
            std::fs::remove_file(&diagnostic_path)?;
        }
        file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&diagnostic_path)?;
    }
    file.write_all(&record)?;
    file.sync_data()?;
    File::open(&paths.state_dir)?.sync_all()
}

fn current_process_identity() -> Option<ProcessIdentity> {
    let pid = i64::from(std::process::id());
    let stat = std::fs::read_to_string("/proc/self/stat").ok()?;
    let starttime_ticks = stat
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(19)?
        .parse()
        .ok()?;
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()?
        .trim()
        .to_owned();
    Some(ProcessIdentity {
        pid,
        boot_id,
        starttime_ticks,
    })
}

fn preaccept_failure(paths: &StatePaths, meta: &Meta, error: io::Error) -> io::Error {
    let grant = parse_grant().ok();
    let detail = error.to_string();
    let _ = append_diagnostic(
        paths,
        &Diagnostic {
            protocol: PROTOCOL,
            work_id: &paths.handle,
            phase: "preaccept_failed",
            initiator_pid: std::process::id(),
            root_id: grant.as_ref().map(|grant| grant.root_id.as_str()),
            supervisor_authority_id: grant
                .as_ref()
                .map(|grant| grant.supervisor_authority_id.as_str()),
            worker_pid: None,
            worker_starttime_ticks: None,
            detail: Some(&detail),
        },
    );
    let _ = supervisor::record_root_preaccept_failure(paths, meta, &error.to_string());
    error
}

fn hex_digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
pub(crate) mod owner_witness_tests {
    use super::*;
    use crate::state::{DeliveryHelperProvenance, DeliveryMode};
    use serde_json::{Value, json};
    use std::collections::BTreeMap;

    pub(crate) fn fixture() -> (tempfile::TempDir, StatePaths, Meta, Value) {
        let temp = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temp.path()).unwrap();
        let paths = StatePaths::new(root, "ab_owner_witness".into());
        state::create_handle_state(&paths).unwrap();
        let helper_sha = "b".repeat(64);
        let provenance = DeliveryHelperProvenance {
            schema_version: 5,
            path: paths.delivery_helper.to_string_lossy().into_owned(),
            device: 1,
            inode: 2,
            size: 3,
            modified_seconds: 0,
            modified_nanoseconds: 0,
            mode: 0o500,
            sha256: helper_sha.clone(),
            environment: BTreeMap::new(),
            environment_sha256: Some("c".repeat(64)),
            interpreter: None,
        };
        let meta = Meta::new(
            paths.handle.clone(),
            1,
            1,
            vec!["true".into()],
            paths.root.clone(),
            "exit",
            DeliveryMode::Async,
            None,
            Vec::new(),
            None,
        )
        .with_owner_context(
            Some("session-original".into()),
            Some("11111111-1111-4111-8111-111111111111".into()),
        )
        .with_delivery_helper(provenance);
        crate::continuation::prepare(&paths, &meta, "domain-original", "tree").unwrap();
        let registration = crate::continuation::read(
            &paths.state_dir.join(crate::continuation::REGISTRATION),
            1024 * 1024,
        )
        .unwrap();
        let source: Value = serde_json::from_slice(&registration).unwrap();
        let receipt = json!({
            "protocol":crate::continuation::PROTOCOL,
            "domain_id":source["domain_id"],
            "source_id":source["source_id"],
            "handle":source["handle"],
            "registration_id":source["registration_id"],
            "registration_digest":crate::continuation::digest(&registration),
            "status":"registered",
            "registration_committed":true,
            "continuation_owner_domain":source["domain_id"],
            "listener_revision":source["listener_revision"],
            "listeners":source["listeners"],
        });
        crate::continuation::confirm_launch(&paths, &receipt).unwrap();
        let intent = WorkIntent {
            protocol: PROTOCOL.into(),
            work_id: paths.handle.clone(),
            root_id: "root-original".into(),
            domain_id: "domain-original".into(),
            control_protocol: SOURCE_CONTROL_PROTOCOL.into(),
            root_identity: None,
            root_endpoint: Vec::new(),
            supervisor_authority_id: "supervisor-original".into(),
            guardian_identity: ProcessIdentity {
                pid: 1,
                boot_id: "boot".into(),
                starttime_ticks: 1,
            },
            cancel_capability: "cancel".into(),
            handle: paths.handle.clone(),
            state_root: paths.root.clone(),
            meta: meta.clone(),
            argv: Vec::new(),
            completion_scope: "tree".into(),
            ready_sentinel: None,
            registration_authority: Some(vec![b'a'; 64]),
            environment: Vec::new(),
            cancel_owner: None,
        };
        let intent_bytes = serde_json::to_vec(&intent).unwrap();
        state::atomic_write(&paths.state_dir.join(INTENT_FILE), &intent_bytes).unwrap();
        let accepted = json!({
            "protocol":PROTOCOL,
            "work_id":paths.handle,
            "root_id":intent.root_id,
            "supervisor_authority_id":intent.supervisor_authority_id,
            "request_sha256":hex_digest(&intent_bytes),
        });
        state::atomic_write(
            &paths.state_dir.join(ACCEPTED_FILE),
            &serde_json::to_vec(&accepted).unwrap(),
        )
        .unwrap();
        (temp, paths, meta, accepted)
    }

    #[test]
    fn exact_committed_accepted_witness_survives_readback() {
        let (_temp, paths, meta, _) = fixture();
        let witness = completion_owner_witness(&paths, &meta, "b".repeat(64).as_str())
            .unwrap()
            .unwrap();
        assert_eq!(witness.session_id, "session-original");
        assert_eq!(
            witness.invocation_uuid,
            "11111111-1111-4111-8111-111111111111"
        );
        assert_eq!(witness.registration_authority.as_bytes(), &[b'a'; 64]);
    }

    #[test]
    fn missing_wrong_stale_and_sibling_witnesses_refuse() {
        let (_temp, paths, meta, mut accepted) = fixture();
        let good = "b".repeat(64);
        let mut wrong_meta = meta.clone();
        wrong_meta.owner_session_id = Some("session-sibling".into());
        assert!(completion_owner_witness(&paths, &wrong_meta, &good).is_err());
        assert!(completion_owner_witness(&paths, &meta, &"d".repeat(64)).is_err());
        let intent_path = paths.state_dir.join(INTENT_FILE);
        let original_intent = crate::continuation::read(&intent_path, 1024 * 1024).unwrap();
        let mut changed_intent: Value = serde_json::from_slice(&original_intent).unwrap();
        changed_intent["registration_authority"][0] = json!(b'd');
        state::atomic_write(&intent_path, &serde_json::to_vec(&changed_intent).unwrap()).unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        state::atomic_write(&intent_path, &original_intent).unwrap();
        accepted["root_id"] = json!("root-sibling");
        state::atomic_write(
            &paths.state_dir.join(ACCEPTED_FILE),
            &serde_json::to_vec(&accepted).unwrap(),
        )
        .unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        accepted["root_id"] = json!("root-original");
        accepted["request_sha256"] = json!("0".repeat(64));
        state::atomic_write(
            &paths.state_dir.join(ACCEPTED_FILE),
            &serde_json::to_vec(&accepted).unwrap(),
        )
        .unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        std::fs::remove_file(paths.state_dir.join(ACCEPTED_FILE)).unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        let intent =
            crate::continuation::read(&paths.state_dir.join(INTENT_FILE), 1024 * 1024).unwrap();
        accepted["request_sha256"] = json!(hex_digest(&intent));
        state::atomic_write(
            &paths.state_dir.join(ACCEPTED_FILE),
            &serde_json::to_vec(&accepted).unwrap(),
        )
        .unwrap();
        let receipt_path = paths.state_dir.join("registration-receipt-v2.json");
        let receipt = crate::continuation::read(&receipt_path, 1024 * 1024).unwrap();
        let mut changed_receipt: Value = serde_json::from_slice(&receipt).unwrap();
        changed_receipt["source_id"] = json!("sibling-source");
        state::atomic_write(
            &receipt_path,
            &serde_json::to_vec(&changed_receipt).unwrap(),
        )
        .unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        state::atomic_write(&receipt_path, &receipt).unwrap();
        std::fs::remove_file(receipt_path).unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_err());
        let mut confirmation: Value = serde_json::from_slice(&receipt).unwrap();
        confirmation["status"] = json!("exact_committed");
        confirmation["authority"] = json!("completion_only");
        state::atomic_write(
            &paths.state_dir.join("registration-confirmation-v2.json"),
            &serde_json::to_vec(&confirmation).unwrap(),
        )
        .unwrap();
        assert!(completion_owner_witness(&paths, &meta, &good).is_ok());
        let sibling = tempfile::tempdir().unwrap();
        let sibling_paths = StatePaths::new(
            std::fs::canonicalize(sibling.path()).unwrap(),
            paths.handle.clone(),
        );
        state::create_handle_state(&sibling_paths).unwrap();
        std::fs::copy(
            paths.state_dir.join(INTENT_FILE),
            sibling_paths.state_dir.join(INTENT_FILE),
        )
        .unwrap();
        std::fs::copy(
            paths.state_dir.join(ACCEPTED_FILE),
            sibling_paths.state_dir.join(ACCEPTED_FILE),
        )
        .unwrap();
        assert!(completion_owner_witness(&sibling_paths, &meta, &good).is_err());
    }
}

fn new_capability() -> io::Result<String> {
    let mut value = String::new();
    while value.len() < 64 {
        value.push_str(
            std::fs::read_to_string("/proc/sys/kernel/random/uuid")?
                .trim()
                .replace('-', "")
                .as_str(),
        );
    }
    value.truncate(64);
    Ok(value)
}

pub(crate) fn is_root_owned(paths: &StatePaths) -> bool {
    paths.state_dir.join(ACCEPTED_FILE).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn test_witness<'a>(
        source: &'a ObservedSource,
        scope: SourceScope<'a>,
    ) -> SourceSocketWitness<'a> {
        SourceSocketWitness {
            root_id: "root",
            domain_id: "domain",
            supervisor_id: "supervisor",
            guardian: ProcessWitness {
                host_pid: 123,
                boot_id: &source.boot_id,
                starttime_ticks: 456,
            },
            source: ProcessWitness {
                host_pid: source.pid,
                boot_id: &source.boot_id,
                starttime_ticks: source.starttime_ticks,
            },
            scope,
        }
    }

    fn broker_mock(
        listener: UnixListener,
        accepted: bool,
        expected_scope: &'static str,
        expected_fields: Vec<(&'static str, serde_json::Value)>,
    ) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let (mut broker, _) = listener.accept().unwrap();
            broker.write_all(&[7u8; 16]).unwrap();
            let mut bytes = [0u8; 4096];
            let mut iov = libc::iovec {
                iov_base: bytes.as_mut_ptr().cast(),
                iov_len: bytes.len(),
            };
            let mut control = [0usize; 8];
            let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
            message.msg_iov = &mut iov;
            message.msg_iovlen = 1;
            message.msg_control = control.as_mut_ptr().cast();
            message.msg_controllen =
                unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
            let size = unsafe { libc::recvmsg(broker.as_raw_fd(), &mut message, 0) };
            assert!(size > 17);
            assert_eq!(&bytes[..17], &[&[b's'][..], &[7u8; 16]].concat());
            let witness: serde_json::Value =
                serde_json::from_slice(&bytes[17..size as usize]).unwrap();
            assert_eq!(witness["scope"]["kind"], expected_scope);
            assert_eq!(
                witness["source"]["host_pid"],
                host_observed_source().unwrap().pid
            );
            for (pointer, value) in expected_fields {
                assert_eq!(witness.pointer(pointer), Some(&value));
            }
            let passed = unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                assert!(!header.is_null());
                assert_eq!((*header).cmsg_level, libc::SOL_SOCKET);
                assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
                assert_eq!(
                    (*header).cmsg_len,
                    libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as usize
                );
                *libc::CMSG_DATA(header).cast::<RawFd>()
            };
            let mut source_copy = unsafe { UnixStream::from_raw_fd(passed) };
            if accepted {
                source_copy
                    .write_all(&[&[b'@'][..], &[1u8; 16]].concat())
                    .unwrap();
                broker.write_all(b"verified-source-v2 root\n").unwrap();
            } else {
                broker.write_all(b"refused\n").unwrap();
            }
        })
    }

    fn receive_frame_first_byte(socket: &UnixStream, expected_fds: usize) -> u8 {
        let mut byte = [0u8];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0usize; 16];
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len() * std::mem::size_of::<usize>();
        assert_eq!(
            unsafe { libc::recvmsg(socket.as_raw_fd(), &mut message, 0) },
            1
        );
        let mut count = 0;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            if !header.is_null() {
                assert_eq!((*header).cmsg_type, libc::SCM_RIGHTS);
                count = ((*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize)
                    / std::mem::size_of::<RawFd>();
                for index in 0..count {
                    libc::close(*libc::CMSG_DATA(header).cast::<RawFd>().add(index));
                }
            }
        }
        assert_eq!(count, expected_fds);
        byte[0]
    }

    #[test]
    fn v2_challenge_one_socket_fd_and_complete_work_or_cancel_frame() {
        for cancel in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let guardian_listener = UnixListener::bind(temp.path().join("guardian.sock")).unwrap();
            let broker_listener = UnixListener::bind(temp.path().join("broker.sock")).unwrap();
            let broker = broker_mock(
                broker_listener,
                true,
                if cancel { "cancel_outside" } else { "root" },
                vec![],
            );
            let mut source = UnixStream::connect(temp.path().join("guardian.sock")).unwrap();
            let (mut guardian, _) = guardian_listener.accept().unwrap();
            let observed = host_observed_source().unwrap();
            let scope = if cancel {
                SourceScope::CancelOutside { work_id: "work" }
            } else {
                SourceScope::Root
            };
            verify_source_socket_v2_at(
                &temp.path().join("broker.sock"),
                &source,
                &test_witness(&observed, scope),
                unsafe { libc::geteuid() },
            )
            .unwrap();
            let mut marker = [0u8; 17];
            guardian.read_exact(&mut marker).unwrap();
            assert_eq!(marker, [&[b'@'][..], &[1u8; 16]].concat().as_slice());
            if cancel {
                source
                    .write_all(b"cancel\n{\"work_id\":\"work\"}\n")
                    .unwrap();
            } else {
                let files: Vec<File> = (0..4).map(|_| File::open("/dev/null").unwrap()).collect();
                send_with_fds(
                    &mut source,
                    b"work!\n{\"work_id\":\"work\"}\n",
                    &[
                        files[0].as_raw_fd(),
                        files[1].as_raw_fd(),
                        files[2].as_raw_fd(),
                        files[3].as_raw_fd(),
                    ],
                )
                .unwrap();
            }
            source.shutdown(Shutdown::Write).unwrap();
            let first = receive_frame_first_byte(&guardian, if cancel { 0 } else { 4 });
            let mut rest = Vec::new();
            guardian.read_to_end(&mut rest).unwrap();
            let mut frame = vec![first];
            frame.extend(rest);
            assert_eq!(
                frame,
                if cancel {
                    &b"cancel\n{\"work_id\":\"work\"}\n"[..]
                } else {
                    &b"work!\n{\"work_id\":\"work\"}\n"[..]
                }
            );
            broker.join().unwrap();
        }
    }

    #[test]
    fn v2_source_witness_uses_observer_pid_inside_child_pidns() {
        const CHILD: &str = "AGE319_SOURCE_WITNESS_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let output = std::process::Command::new("timeout")
                .args([
                    "--kill-after=5s",
                    "30s",
                    "unshare",
                    "--user",
                    "--map-current-user",
                    "--pid",
                    "--fork",
                    "--",
                ])
                .arg(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "root_work::tests::v2_source_witness_uses_observer_pid_inside_child_pidns",
                ])
                .env(CHILD, "1")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "stdout={} stderr={}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }
        let observed = host_observed_source().unwrap();
        assert_ne!(observed.pid, unsafe { libc::getpid() });
        let temp = tempfile::tempdir().unwrap();
        let guardian_listener = UnixListener::bind(temp.path().join("guardian.sock")).unwrap();
        let broker_listener = UnixListener::bind(temp.path().join("broker.sock")).unwrap();
        let broker = broker_mock(broker_listener, true, "root", vec![]);
        let source = UnixStream::connect(temp.path().join("guardian.sock")).unwrap();
        let (_guardian, _) = guardian_listener.accept().unwrap();
        verify_source_socket_v2_at(
            &temp.path().join("broker.sock"),
            &source,
            &test_witness(&observed, SourceScope::Root),
            unsafe { libc::geteuid() },
        )
        .unwrap();
        broker.join().unwrap();
    }

    #[test]
    fn v2_refused_or_lost_pre_wire_response_sends_no_guardian_frame() {
        for refused in [true, false] {
            let temp = tempfile::tempdir().unwrap();
            let guardian_listener = UnixListener::bind(temp.path().join("guardian.sock")).unwrap();
            let broker_listener = UnixListener::bind(temp.path().join("broker.sock")).unwrap();
            let broker = if refused {
                broker_mock(broker_listener, false, "root", vec![])
            } else {
                std::thread::spawn(move || {
                    let (mut stream, _) = broker_listener.accept().unwrap();
                    stream.write_all(&[7u8; 16]).unwrap();
                    let mut bytes = [0u8; 4096];
                    let _ = stream.read(&mut bytes).unwrap();
                })
            };
            let source = UnixStream::connect(temp.path().join("guardian.sock")).unwrap();
            let (mut guardian, _) = guardian_listener.accept().unwrap();
            let observed = host_observed_source().unwrap();
            assert!(
                verify_source_socket_v2_at(
                    &temp.path().join("broker.sock"),
                    &source,
                    &test_witness(&observed, SourceScope::Root),
                    unsafe { libc::geteuid() }
                )
                .is_err()
            );
            source.shutdown(Shutdown::Write).unwrap();
            let mut bytes = Vec::new();
            guardian.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty());
            broker.join().unwrap();
        }
    }

    #[test]
    fn v2_wrong_guardian_stale_and_sibling_witnesses_leave_guardian_unwritten() {
        for case in [
            "wrong_guardian",
            "stale_guardian",
            "sibling_root",
            "sibling_work",
        ] {
            let temp = tempfile::tempdir().unwrap();
            let guardian_listener = UnixListener::bind(temp.path().join("guardian.sock")).unwrap();
            let broker_listener = UnixListener::bind(temp.path().join("broker.sock")).unwrap();
            let source = UnixStream::connect(temp.path().join("guardian.sock")).unwrap();
            let (mut guardian, _) = guardian_listener.accept().unwrap();
            let observed = host_observed_source().unwrap();
            let mut witness = test_witness(&observed, SourceScope::Root);
            let (scope, field, value) = match case {
                "wrong_guardian" => {
                    witness.guardian.host_pid = 999;
                    ("root", "/guardian/host_pid", serde_json::json!(999))
                }
                "stale_guardian" => {
                    witness.guardian.starttime_ticks = 999;
                    ("root", "/guardian/starttime_ticks", serde_json::json!(999))
                }
                "sibling_root" => {
                    witness.root_id = "sibling-root";
                    ("root", "/root_id", serde_json::json!("sibling-root"))
                }
                _ => {
                    witness.scope = SourceScope::Nested {
                        parent_work_id: "sibling-work",
                    };
                    (
                        "nested",
                        "/scope/parent_work_id",
                        serde_json::json!("sibling-work"),
                    )
                }
            };
            let broker = broker_mock(broker_listener, false, scope, vec![(field, value)]);
            assert!(
                verify_source_socket_v2_at(
                    &temp.path().join("broker.sock"),
                    &source,
                    &witness,
                    unsafe { libc::geteuid() }
                )
                .is_err()
            );
            source.shutdown(Shutdown::Write).unwrap();
            let mut bytes = Vec::new();
            guardian.read_to_end(&mut bytes).unwrap();
            assert!(bytes.is_empty(), "{case}");
            broker.join().unwrap();
        }
    }

    #[test]
    fn v2_broker_absence_or_wrong_broker_uid_leaves_guardian_unwritten() {
        let temp = tempfile::tempdir().unwrap();
        let guardian_listener = UnixListener::bind(temp.path().join("guardian.sock")).unwrap();
        let source = UnixStream::connect(temp.path().join("guardian.sock")).unwrap();
        let (mut guardian, _) = guardian_listener.accept().unwrap();
        let observed = host_observed_source().unwrap();
        assert!(
            verify_source_socket_v2_at(
                &temp.path().join("absent.sock"),
                &source,
                &test_witness(&observed, SourceScope::Root),
                unsafe { libc::geteuid() }
            )
            .is_err()
        );
        let broker_listener = UnixListener::bind(temp.path().join("broker.sock")).unwrap();
        let broker = std::thread::spawn(move || {
            let _ = broker_listener.accept().unwrap();
        });
        assert!(
            verify_source_socket_v2_at(
                &temp.path().join("broker.sock"),
                &source,
                &test_witness(&observed, SourceScope::Root),
                unsafe { libc::geteuid() } + 1
            )
            .is_err()
        );
        source.shutdown(Shutdown::Write).unwrap();
        let mut bytes = Vec::new();
        guardian.read_to_end(&mut bytes).unwrap();
        assert!(bytes.is_empty());
        broker.join().unwrap();
    }

    #[test]
    fn versioned_grant_and_intent_binding_round_trip() {
        let identity = ProcessIdentity {
            pid: 10,
            boot_id: "boot".into(),
            starttime_ticks: 20,
        };
        let grant: RootAuthorityGrant = serde_json::from_value(serde_json::json!({
            "protocol": ROOT_PROTOCOL, "control_protocol": SOURCE_CONTROL_PROTOCOL,
            "completion_protocol": "completion-continuation-v2", "domain_id": "domain",
            "supervisor_authority_id": "supervisor", "root_id": "root", "capability": "secret",
            "root_identity": identity, "guardian_identity": identity
        }))
        .unwrap();
        control_route(&grant.control_protocol).unwrap();
        assert!(control_route("unknown-control").is_err());
        let meta = Meta::new(
            "work".into(),
            1,
            2,
            vec![],
            PathBuf::from("/"),
            "tree",
            state::DeliveryMode::Async,
            None,
            vec![],
            None,
        );
        let intent = WorkIntent {
            protocol: PROTOCOL.into(),
            work_id: "work".into(),
            root_id: grant.root_id.clone(),
            domain_id: grant.domain_id.clone(),
            control_protocol: grant.control_protocol.clone(),
            root_identity: Some(grant.root_identity.clone()),
            root_endpoint: b"/guardian".to_vec(),
            supervisor_authority_id: grant.supervisor_authority_id.clone(),
            guardian_identity: grant.guardian_identity.clone(),
            cancel_capability: "independent-cancel".into(),
            handle: "work".into(),
            state_root: PathBuf::from("/tmp"),
            meta,
            argv: vec![],
            completion_scope: "tree".into(),
            ready_sentinel: None,
            registration_authority: None,
            environment: vec![],
            cancel_owner: None,
        };
        let saved: WorkIntent =
            serde_json::from_slice(&serde_json::to_vec(&intent).unwrap()).unwrap();
        assert_eq!(saved.domain_id, "domain");
        assert_eq!(saved.control_protocol, SOURCE_CONTROL_PROTOCOL);
        assert_eq!(saved.root_identity, Some(identity));
        assert_eq!(saved.cancel_capability, "independent-cancel");
        let mut old = serde_json::to_value(&grant).unwrap();
        old.as_object_mut().unwrap().remove("control_protocol");
        let old: RootAuthorityGrant = serde_json::from_value(old).unwrap();
        assert_eq!(old.control_protocol, LEGACY_CONTROL_PROTOCOL);
    }

    #[test]
    fn cancel_scope_uses_observed_namespace_and_real_parent() {
        let root = Path::new("pid:[root]");
        let host = Path::new("pid:[host]");
        let work = Path::new("pid:[work]");
        let kind = |scope: SourceScope<'_>| serde_json::to_value(scope).unwrap();
        assert_eq!(
            kind(scope_for_namespaces(
                host,
                host,
                Some("false-parent"),
                "target"
            )),
            serde_json::json!({"kind":"cancel_outside","work_id":"target"})
        );
        assert_eq!(
            kind(scope_for_namespaces(root, host, None, "target")),
            serde_json::json!({"kind":"root"})
        );
        assert_eq!(
            kind(scope_for_namespaces(work, host, Some("parent"), "target")),
            serde_json::json!({"kind":"nested","parent_work_id":"parent"})
        );
        // Without a causal parent, the broker will validate the root
        // candidate; a nested caller cannot acquire root scope by omission.
        assert_eq!(
            kind(scope_for_namespaces(work, host, None, "target")),
            serde_json::json!({"kind":"root"})
        );
        assert_eq!(
            kind(scope_for_namespaces(work, host, Some(""), "target")),
            serde_json::json!({"kind":"root"})
        );
    }

    #[test]
    fn explicit_root_and_nested_registration_do_not_overlap() {
        let root = serde_json::to_string(&WorkRegistration::Root).unwrap();
        let nested = serde_json::to_string(&WorkRegistration::Nested {
            parent_work_id: "parent".into(),
            parent_capability: "secret".into(),
        })
        .unwrap();
        assert_eq!(root, r#"{"kind":"root"}"#);
        assert!(nested.contains("parent_work_id"));
        assert!(nested.contains("parent_capability"));
        assert!(
            serde_json::from_str::<WorkRegistration>(
                r#"{"kind":"nested","parent_work_id":"parent"}"#
            )
            .is_err()
        );
    }

    #[test]
    fn post_send_response_conflict_and_unknown_status_are_never_retry_safe() {
        let identity = ProcessIdentity {
            pid: 10,
            boot_id: "00000000-0000-4000-8000-000000000001".into(),
            starttime_ticks: 20,
        };
        let submission = WorkSubmission {
            protocol: PROTOCOL.into(),
            root_authority: RootAuthorityGrant {
                protocol: ROOT_PROTOCOL.into(),
                control_protocol: LEGACY_CONTROL_PROTOCOL.into(),
                completion_protocol: "completion-continuation-v2".into(),
                domain_id: "domain".into(),
                supervisor_authority_id: "supervisor".into(),
                root_id: "root".into(),
                capability: "secret".into(),
                root_identity: identity.clone(),
                guardian_identity: identity.clone(),
            },
            work_id: "work".into(),
            request_sha256: "digest".into(),
            registration: WorkRegistration::Root,
            cancel_capability: "cancel".into(),
        };
        let response = |status: &str, root_id: &str| WorkResponse {
            protocol: PROTOCOL.into(),
            work_id: "work".into(),
            status: status.into(),
            root_id: root_id.into(),
            supervisor_authority_id: "supervisor".into(),
            worker_identity: Some(identity.clone()),
            detail: None,
        };

        assert_eq!(
            submit_response_disposition(&response("accepted", "wrong-root"), &submission),
            SubmitResponseDisposition::EffectsPossibleNoReplay
        );
        assert_eq!(
            submit_response_disposition(&response("future-status", "root"), &submission),
            SubmitResponseDisposition::EffectsPossibleNoReplay
        );
        assert_eq!(
            submit_response_disposition(&response("rejected_preaccept", "root"), &submission),
            SubmitResponseDisposition::RejectedPreaccept
        );
    }

    #[test]
    fn paired_session_ring_requires_exact_identity_and_canonical_uuid() {
        let uid = unsafe { libc::geteuid() };
        let valid = format!(
            "keyring;{uid};{uid};3f030000;{PAIRED_RING_PREFIX}12345678-1234-4abc-8abc-123456789abc"
        );
        assert_eq!(
            parse_session_ring_description(valid.as_bytes(), uid).unwrap(),
            true
        );
        for ring in [
            "_ses",
            "_uid_ses.1000",
            "unrelated-work:12345678-1234-4abc-8abc-123456789abc",
        ] {
            let description = format!("keyring;{uid};{uid};3f030000;{ring}");
            assert_eq!(
                parse_session_ring_description(description.as_bytes(), uid).unwrap(),
                false
            );
        }
        for invalid in [
            valid
                .replace(&format!(";{uid};"), ";999999999;")
                .into_bytes(),
            valid.replace("keyring;", "user;").into_bytes(),
            valid.replace("3f030000", "garbage!").into_bytes(),
            format!("{valid};second-name").into_bytes(),
            valid
                .replace("12345678-1234-4abc", "12345678-1234-7abc")
                .into_bytes(),
            valid
                .replace("8abc-123456789abc", "0abc-123456789abc")
                .into_bytes(),
            format!("keyring;{uid};{uid};3f030000;{PAIRED_RING_PREFIX}broken").into_bytes(),
            [valid.as_bytes(), &[0, b'x']].concat(),
        ] {
            assert!(
                parse_session_ring_description(&invalid, uid).is_err(),
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn protocol_has_no_arbitrary_liveness_deadline() {
        let source = include_str!("root_work.rs");
        assert!(!source.contains(&["from_secs", "(5)"].concat()));
        assert!(!source.contains(&["set_read_", "timeout"].concat()));
        assert!(!source.contains(&["set_write_", "timeout"].concat()));
    }

    #[test]
    fn every_submission_transport_gap_has_handle_local_evidence() {
        let source = include_str!("root_work.rs");
        for phase in [
            "intent_persist_failed_preaccept",
            "initiated",
            "transport_failed_preaccept",
            "peer_identity_rejected_preaccept",
            "descriptor_pin_failed_preaccept",
            "acceptance_outcome_unknown",
            "response_identity_conflict",
            "preaccept_failed",
        ] {
            assert!(source.contains(phase), "missing diagnostic phase {phase}");
        }
    }

    #[test]
    fn protocol_artifacts_are_owned_by_the_existing_handle_directory() {
        for artifact in [
            INTENT_FILE,
            ACCEPTED_FILE,
            DIAGNOSTIC_FILE,
            DIAGNOSTIC_ROTATED_FILE,
            DIAGNOSTIC_LOCK_FILE,
        ] {
            assert_eq!(std::path::Path::new(artifact).components().count(), 1);
        }
    }

    #[test]
    fn diagnostic_history_rotates_under_a_handle_local_lock() {
        let temp = tempfile::tempdir().unwrap();
        let paths = StatePaths::new(temp.path().to_path_buf(), "handle".into());
        std::fs::create_dir(&paths.state_dir).unwrap();
        std::fs::write(
            paths.state_dir.join(DIAGNOSTIC_FILE),
            vec![b'x'; MAX_DIAGNOSTIC_BYTES as usize - 1],
        )
        .unwrap();
        append_diagnostic(
            &paths,
            &Diagnostic {
                protocol: PROTOCOL,
                work_id: "handle",
                phase: "test",
                initiator_pid: std::process::id(),
                root_id: Some("root"),
                supervisor_authority_id: Some("authority"),
                worker_pid: None,
                worker_starttime_ticks: None,
                detail: None,
            },
        )
        .unwrap();

        assert!(paths.state_dir.join(DIAGNOSTIC_LOCK_FILE).exists());
        assert!(paths.state_dir.join(DIAGNOSTIC_ROTATED_FILE).exists());
        assert!(
            std::fs::metadata(paths.state_dir.join(DIAGNOSTIC_FILE))
                .unwrap()
                .len()
                < MAX_DIAGNOSTIC_BYTES
        );
    }
}
