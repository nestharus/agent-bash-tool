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
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

pub(crate) const PROTOCOL: &str = "original-work-v1";
const ROOT_PROTOCOL: &str = "root-authority-v1";
pub(crate) const EXECUTOR_ARG: &str = "__root-original-work-v1";
pub(crate) const ROOT_AUTHORITY_ENV: &str = "OULIPOLY_ROOT_AUTHORITY_V1";
pub(crate) const ROOT_WORK_ID_ENV: &str = "OULIPOLY_ROOT_WORK_ID";
pub(crate) const ROOT_PARENT_CAPABILITY_ENV: &str = "OULIPOLY_ROOT_PARENT_CAPABILITY_V1";
const ENDPOINT_ENV: &str = "OULIPOLY_COMPLETION_ENDPOINT";
const REQUIRED_ENV: &str = "OULIPOLY_ORIGINAL_WORK_REQUIRED_V1";
const INTENT_FILE: &str = "root-work-intent-v1.json";
pub(crate) const ACCEPTED_FILE: &str = "root-work-accepted-v1.json";
const DIAGNOSTIC_FILE: &str = "root-work-diagnostic-v1.jsonl";
const DIAGNOSTIC_LOCK_FILE: &str = "root-work-diagnostic-v1.lock";
const DIAGNOSTIC_ROTATED_FILE: &str = "root-work-diagnostic-v1.jsonl.1";
const MAX_DIAGNOSTIC_BYTES: u64 = 1024 * 1024;
const MAX_DIAGNOSTIC_RECORD_BYTES: usize = 128 * 1024;
const FD_COUNT: usize = 4;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
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
    completion_protocol: String,
    domain_id: String,
    supervisor_authority_id: String,
    root_id: String,
    capability: String,
    root_identity: ProcessIdentity,
    guardian_identity: ProcessIdentity,
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
    let mut pid = unsafe { libc::getppid() };
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
    authenticate_peer(&socket, &grant.guardian_identity).map_err(|error| {
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
    let mut frame = b"work!\n".to_vec();
    frame.extend(
        serde_json::to_vec(&submission)
            .map_err(io::Error::other)
            .map_err(|error| preaccept_failure(paths, meta, error))?,
    );
    frame.push(b'\n');
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
    let endpoint = OsString::from_vec(intent.root_endpoint.clone());
    let submission = CancelSubmission {
        protocol: PROTOCOL.into(),
        root_id: intent.root_id.clone(),
        supervisor_authority_id: intent.supervisor_authority_id.clone(),
        work_id: intent.work_id,
        cancel_capability: intent.cancel_capability,
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
    let response_result = (|| {
        authenticate_peer(&socket, &intent.guardian_identity)?;
        socket.write_all(b"cancel\n")?;
        serde_json::to_writer(&mut socket, &submission)?;
        socket.write_all(b"\n")?;
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
