use std::env;
use std::ffi::{CString, OsStr, OsString};
use std::fmt;
use std::fs::{self, File, Metadata};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use std::os::unix::process::ExitStatusExt;

use serde::{Deserialize, Serialize};

use crate::state::{
    self, CallerChainEntry, DeliveryHelperProvenance, DeliveryMeta, DeliveryMode, Meta, StatePaths,
};

const CONSUMER_GRACE_MS_ENV: &str = "AGENT_BASH_CONSUMER_GRACE_MS";
const MAX_CONSUMER_GRACE_MS: u64 = 10_000;
const CONSUMER_GRACE_POLL_MS: u64 = 25;
const OWNER_LOOKUP_TIMEOUT: Duration = Duration::from_secs(60);
const OWNER_LOOKUP_POLL: Duration = Duration::from_millis(10);
const DELIVERY_HELPER_SCHEMA_VERSION: u8 = 1;
const DELIVERY_HELPER_UNAVAILABLE: &str = "delivery_helper_unavailable";
const DELIVERY_HELPER_INVALID: &str = "delivery_helper_provenance_invalid";
const DELIVERY_HELPER_CHANGED: &str = "delivery_helper_changed";

#[derive(Debug)]
struct DeliveryHelper {
    provenance: DeliveryHelperProvenance,
    executable: File,
}

pub(crate) struct DeliveryRegistration {
    helper: DeliveryHelper,
}

impl DeliveryRegistration {
    pub(crate) fn provenance(&self) -> DeliveryHelperProvenance {
        self.helper.provenance.clone()
    }
}

#[derive(Debug)]
struct DeliveryHelperError {
    code: &'static str,
    detail: String,
}

impl DeliveryHelperError {
    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_UNAVAILABLE,
            detail: detail.into(),
        }
    }

    fn invalid(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_INVALID,
            detail: detail.into(),
        }
    }

    fn changed(detail: impl Into<String>) -> Self {
        Self {
            code: DELIVERY_HELPER_CHANGED,
            detail: detail.into(),
        }
    }
}

impl fmt::Display for DeliveryHelperError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for DeliveryHelperError {}

impl DeliveryHelper {
    fn from_environment() -> Result<Self, DeliveryHelperError> {
        let configured =
            env::var_os("AGENT_BASH_AGENT_RUNNER_BIN").unwrap_or_else(|| OsString::from("agents"));
        if configured.is_empty() {
            return Err(DeliveryHelperError::invalid(
                "AGENT_BASH_AGENT_RUNNER_BIN is empty",
            ));
        }
        if configured.as_os_str().as_bytes().contains(&b'/') {
            return Self::from_configured_path(Path::new(&configured));
        }
        Self::from_search_path(&configured)
    }

    fn from_configured_path(path: &Path) -> Result<Self, DeliveryHelperError> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            env::current_dir()
                .map_err(|err| {
                    DeliveryHelperError::unavailable(format!(
                        "cannot resolve configured delivery helper {}: {err}",
                        path.display()
                    ))
                })?
                .join(path)
        };
        let canonical = fs::canonicalize(&absolute).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot resolve configured delivery helper {}: {err}",
                absolute.display()
            ))
        })?;
        Self::from_resolved_path(&canonical)
    }

    fn from_search_path(name: &OsStr) -> Result<Self, DeliveryHelperError> {
        let Some(search_path) = env::var_os("PATH") else {
            return Err(DeliveryHelperError::unavailable(format!(
                "cannot find delivery helper {:?}: PATH is not set",
                name
            )));
        };
        for directory in env::split_paths(&search_path) {
            let candidate = directory.join(name);
            let Ok(canonical) = fs::canonicalize(&candidate) else {
                continue;
            };
            if let Ok(helper) = Self::from_resolved_path(&canonical) {
                return Ok(helper);
            }
        }
        Err(DeliveryHelperError::unavailable(format!(
            "cannot find executable delivery helper {:?} in PATH",
            name
        )))
    }

    fn from_resolved_path(path: &Path) -> Result<Self, DeliveryHelperError> {
        if !path.is_absolute() {
            return Err(DeliveryHelperError::invalid(
                "resolved delivery helper path is not absolute",
            ));
        }
        let path_text = path.to_str().ok_or_else(|| {
            DeliveryHelperError::invalid("delivery helper path is not valid UTF-8")
        })?;
        let executable = open_delivery_helper(path).map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot open delivery helper {}: {err}",
                path.display()
            ))
        })?;
        let metadata = executable.metadata().map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot inspect delivery helper {}: {err}",
                path.display()
            ))
        })?;
        validate_delivery_helper_metadata(path, &metadata).map_err(DeliveryHelperError::invalid)?;
        Ok(Self {
            provenance: provenance_from_metadata(path_text.to_string(), &metadata),
            executable,
        })
    }

    fn from_provenance(
        provenance: Option<&DeliveryHelperProvenance>,
        handle: &str,
    ) -> Result<Self, DeliveryHelperError> {
        let provenance = provenance.ok_or_else(|| {
            DeliveryHelperError::unavailable(format!(
                "registered delivery helper provenance is missing for {handle}"
            ))
        })?;
        if provenance.schema_version != DELIVERY_HELPER_SCHEMA_VERSION {
            return Err(DeliveryHelperError::invalid(format!(
                "registered delivery helper for {} has unsupported schema version {}",
                handle, provenance.schema_version
            )));
        }
        let path = PathBuf::from(&provenance.path);
        if !path.is_absolute() {
            return Err(DeliveryHelperError::invalid(format!(
                "registered delivery helper path for {} is not absolute",
                handle
            )));
        }
        let executable = open_delivery_helper(&path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                DeliveryHelperError::unavailable(format!(
                    "registered delivery helper {} for {} is unavailable: {err}",
                    path.display(),
                    handle
                ))
            } else {
                DeliveryHelperError::changed(format!(
                    "registered delivery helper {} for {} cannot be opened safely: {err}",
                    path.display(),
                    handle
                ))
            }
        })?;
        let metadata = executable.metadata().map_err(|err| {
            DeliveryHelperError::unavailable(format!(
                "cannot inspect registered delivery helper {} for {}: {err}",
                path.display(),
                handle
            ))
        })?;
        validate_delivery_helper_metadata(&path, &metadata)
            .map_err(|detail| DeliveryHelperError::changed(format!("{detail} for {handle}")))?;
        if !provenance_matches(provenance, &metadata) {
            return Err(DeliveryHelperError::changed(format!(
                "registered delivery helper identity changed for {} at {}",
                handle,
                path.display()
            )));
        }
        Ok(Self {
            provenance: provenance.clone(),
            executable,
        })
    }

    fn command(&self) -> Command {
        let fd = self.executable.as_raw_fd();
        let mut command = Command::new(format!("/proc/self/fd/{fd}"));
        unsafe {
            command.pre_exec(move || {
                let flags = libc::fcntl(fd, libc::F_GETFD);
                if flags < 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        command
    }
}

fn open_delivery_helper(path: &Path) -> io::Result<File> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "helper path contains NUL"))?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn validate_delivery_helper_metadata(path: &Path, metadata: &Metadata) -> Result<(), String> {
    if !metadata.is_file() {
        return Err(format!(
            "delivery helper {} is not a regular file",
            path.display()
        ));
    }
    if metadata.mode() & 0o111 == 0 {
        return Err(format!(
            "delivery helper {} is not executable",
            path.display()
        ));
    }
    Ok(())
}

fn provenance_from_metadata(path: String, metadata: &Metadata) -> DeliveryHelperProvenance {
    DeliveryHelperProvenance {
        schema_version: DELIVERY_HELPER_SCHEMA_VERSION,
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        mode: metadata.mode(),
    }
}

fn provenance_matches(provenance: &DeliveryHelperProvenance, metadata: &Metadata) -> bool {
    provenance.device == metadata.dev()
        && provenance.inode == metadata.ino()
        && provenance.size == metadata.size()
        && provenance.modified_seconds == metadata.mtime()
        && provenance.modified_nanoseconds == metadata.mtime_nsec()
        && provenance.mode == metadata.mode()
}

#[derive(Debug, Serialize)]
pub(crate) struct DetachOutcome {
    handle: String,
    delivery_mode: DeliveryMode,
    state: String,
    transitioned: bool,
    notification_attempted: bool,
}

#[derive(Debug, Deserialize)]
struct PidSessionResponse {
    found: bool,
    invocation_uuid: Option<String>,
    session_id: Option<String>,
}

pub(crate) fn resolve_owner_binding(
    caller_chain: &[CallerChainEntry],
    expected_invocation_uuid: &str,
) -> io::Result<Option<(String, String)>> {
    for entry in caller_chain
        .iter()
        .filter(|entry| state::process_identity_is_live(entry))
    {
        if let Some(owner) = resolve_owner_for_pid(entry.pid, expected_invocation_uuid)? {
            return Ok(Some(owner));
        }
    }
    Ok(None)
}

fn resolve_owner_for_pid(
    pid: libc::pid_t,
    expected_invocation_uuid: &str,
) -> io::Result<Option<(String, String)>> {
    let helper = DeliveryHelper::from_environment().map_err(io::Error::other)?;
    let mut command = helper.command();
    let mut child = command
        .args(["session", "of-pid", &pid.to_string(), "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let deadline = Instant::now() + OWNER_LOOKUP_TIMEOUT;
    loop {
        if child.try_wait()?.is_some() {
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("agents session of-pid {pid} timed out"),
            ));
        }
        thread::sleep(OWNER_LOOKUP_POLL);
    }
    let output = child.wait_with_output()?;
    if !output.status.success() {
        if output.status.code() == Some(1)
            && serde_json::from_slice::<PidSessionResponse>(&output.stdout)
                .is_ok_and(|response| !response.found)
        {
            return Ok(None);
        }
        let detail = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let fallback = String::from_utf8_lossy(&output.stdout).trim().to_string();
        return Err(io::Error::other(format!(
            "agents session of-pid {pid} exited with {}{}",
            output.status,
            if !detail.is_empty() {
                format!(": {detail}")
            } else if !fallback.is_empty() {
                format!(": {fallback}")
            } else {
                String::new()
            }
        )));
    }
    let response: PidSessionResponse = serde_json::from_slice(&output.stdout).map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("agents session of-pid {pid} returned invalid JSON: {err}"),
        )
    })?;
    if !response.found || response.invocation_uuid.as_deref() != Some(expected_invocation_uuid) {
        return Ok(None);
    }
    let Some(session_id) = response.session_id.filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let Some(invocation_uuid) = response.invocation_uuid else {
        return Ok(None);
    };
    Ok(Some((session_id, invocation_uuid)))
}

pub(crate) fn prepare_registration() -> io::Result<DeliveryRegistration> {
    let helper = DeliveryHelper::from_environment().map_err(io::Error::other)?;
    Ok(DeliveryRegistration { helper })
}

pub(crate) fn register(
    paths: &StatePaths,
    meta: &Meta,
    registration: DeliveryRegistration,
) -> std::io::Result<()> {
    run_required_runner_command(&register_request(meta, paths, registration.helper))
}

pub(crate) fn complete(paths: &StatePaths, meta: &mut Meta) -> std::io::Result<()> {
    let _lock = state::lock_delivery(paths)?;
    let persisted = state::read_meta(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    meta.delivery_mode = mode;
    meta.delivery = completion_delivery(mode, &persisted.delivery, meta, paths);
    meta.touch();
    state::write_meta_atomic(paths, meta)
}

pub(crate) fn detach(paths: &StatePaths) -> std::io::Result<DetachOutcome> {
    let delivery_lock = state::lock_delivery(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    let mut meta = state::read_meta(paths)?;
    if mode == DeliveryMode::Async {
        meta.delivery_mode = mode;
        return Ok(detach_outcome(&meta, false, false));
    }

    let request = activate_request(&meta, &meta.handle).map_err(io::Error::other)?;
    run_required_runner_command(&request)?;
    state::write_delivery_mode_atomic(paths, DeliveryMode::Async)?;
    drop(delivery_lock);

    let _completion_lock = state::lock_completion(paths)?;
    let mut meta = state::read_meta(paths)?;
    meta.delivery_mode = DeliveryMode::Async;
    state::write_meta_atomic(paths, &meta)?;

    Ok(detach_outcome(&meta, true, state::terminal(&meta)))
}

fn completion_delivery(
    mode: DeliveryMode,
    persisted: &DeliveryMeta,
    meta: &Meta,
    paths: &StatePaths,
) -> DeliveryMeta {
    if persisted.attempted && persisted.exit_code == Some(0) {
        return persisted.clone();
    }
    trigger(
        meta.caller_ppid,
        &meta.handle,
        paths,
        consumed_before_delivery(paths),
        mode,
        meta.delivery_helper.as_ref(),
    )
}

fn detach_outcome(meta: &Meta, transitioned: bool, notification_attempted: bool) -> DetachOutcome {
    DetachOutcome {
        handle: meta.handle.clone(),
        delivery_mode: meta.delivery_mode,
        state: meta.state.clone(),
        transitioned,
        notification_attempted,
    }
}

fn trigger(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
    _mode: DeliveryMode,
    provenance: Option<&DeliveryHelperProvenance>,
) -> DeliveryMeta {
    let request = match trigger_request(caller_ppid, handle, paths, consumed, provenance) {
        Ok(request) => request,
        Err(err) => return delivery_meta_from_helper_error(err),
    };
    match run_notify_command(&request) {
        Ok(status) => delivery_meta_from_status(status),
        Err(err) => delivery_meta_from_error(err),
    }
}

fn consumed_before_delivery(paths: &StatePaths) -> bool {
    if paths.consumed.exists() {
        return true;
    }
    let grace = consumer_grace();
    if grace.is_zero() {
        return false;
    }
    wait_for_consumed_marker(paths, grace)
}

fn consumer_grace() -> Duration {
    let millis = std::env::var(CONSUMER_GRACE_MS_ENV)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .unwrap_or(0)
        .min(MAX_CONSUMER_GRACE_MS);
    Duration::from_millis(millis)
}

fn wait_for_consumed_marker(paths: &StatePaths, grace: Duration) -> bool {
    let deadline = Instant::now() + grace;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(CONSUMER_GRACE_POLL_MS));
        if paths.consumed.exists() {
            return true;
        }
    }
    false
}

struct NotifyRequest {
    helper: DeliveryHelper,
    args: Vec<OsString>,
}

fn register_request(meta: &Meta, paths: &StatePaths, helper: DeliveryHelper) -> NotifyRequest {
    NotifyRequest {
        helper,
        args: register_args(meta, paths),
    }
}

fn activate_request(meta: &Meta, handle: &str) -> Result<NotifyRequest, DeliveryHelperError> {
    Ok(NotifyRequest {
        helper: DeliveryHelper::from_provenance(meta.delivery_helper.as_ref(), &meta.handle)?,
        args: activate_args(handle),
    })
}

fn trigger_request(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
    provenance: Option<&DeliveryHelperProvenance>,
) -> Result<NotifyRequest, DeliveryHelperError> {
    Ok(NotifyRequest {
        helper: DeliveryHelper::from_provenance(provenance, handle)?,
        args: trigger_args(caller_ppid, handle, paths, consumed),
    })
}

fn register_args(meta: &Meta, paths: &StatePaths) -> Vec<OsString> {
    vec![
        OsString::from("notify"),
        OsString::from("agent-bash-register"),
        OsString::from("--handle"),
        OsString::from(&meta.handle),
        OsString::from("--delivery-mode"),
        OsString::from(meta.delivery_mode.as_str()),
        OsString::from("--state-dir"),
        path_arg(&paths.state_dir),
        OsString::from("--meta"),
        path_arg(&paths.meta),
        OsString::from("--log"),
        path_arg(&paths.log),
        OsString::from("--rc"),
        path_arg(&paths.rc),
    ]
}

fn activate_args(handle: &str) -> Vec<OsString> {
    vec![
        OsString::from("notify"),
        OsString::from("agent-bash-activate"),
        OsString::from("--handle"),
        OsString::from(handle),
    ]
}

fn trigger_args(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
) -> Vec<OsString> {
    let mut args = vec![
        OsString::from("notify"),
        OsString::from("agent-bash-complete"),
        OsString::from("--caller-ppid"),
        OsString::from(caller_ppid.to_string()),
        OsString::from("--handle"),
        OsString::from(handle),
        OsString::from("--state-dir"),
        path_arg(&paths.state_dir),
        OsString::from("--meta"),
        path_arg(&paths.meta),
        OsString::from("--log"),
        path_arg(&paths.log),
        OsString::from("--rc"),
        path_arg(&paths.rc),
    ];
    if consumed {
        args.push(OsString::from("--consumed"));
    }
    args
}

fn path_arg(path: &Path) -> OsString {
    path.as_os_str().to_os_string()
}

fn run_notify_command(request: &NotifyRequest) -> std::io::Result<ExitStatus> {
    request
        .helper
        .command()
        .args(&request.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn run_required_runner_command(request: &NotifyRequest) -> std::io::Result<()> {
    let output = request
        .helper
        .command()
        .args(&request.args)
        .stdin(Stdio::null())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let detail = command_failure_detail(&output.stderr, &output.stdout);
    Err(std::io::Error::other(format!(
        "runner exited with {}{}",
        output
            .status
            .code()
            .map_or_else(|| "no exit code".to_string(), |code| code.to_string()),
        detail
            .as_deref()
            .map_or_else(String::new, |detail| format!(": {detail}"))
    )))
}

fn command_failure_detail(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    [stderr, stdout].into_iter().find_map(|bytes| {
        let detail = String::from_utf8_lossy(bytes).trim().to_string();
        (!detail.is_empty()).then_some(detail)
    })
}

fn delivery_meta_from_status(status: ExitStatus) -> DeliveryMeta {
    let mut meta = attempted_delivery_meta();
    if let Some(code) = status.code() {
        meta.exit_code = Some(code);
        return meta;
    }
    meta.error = Some(delivery_signal_error(status));
    meta
}

fn delivery_meta_from_error(err: std::io::Error) -> DeliveryMeta {
    let mut meta = attempted_delivery_meta();
    meta.error = Some(err.to_string());
    meta
}

fn delivery_meta_from_helper_error(err: DeliveryHelperError) -> DeliveryMeta {
    DeliveryMeta {
        attempted: false,
        exit_code: None,
        error: Some(err.to_string()),
        error_code: Some(err.code.to_string()),
        retryable: Some(true),
        skipped: None,
    }
}

fn attempted_delivery_meta() -> DeliveryMeta {
    DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: None,
        error_code: None,
        retryable: None,
        skipped: None,
    }
}

pub(crate) fn delivery_needs_retry(meta: &Meta) -> bool {
    state::terminal(meta) && meta.delivery.retryable == Some(true)
}

fn delivery_signal_error(status: ExitStatus) -> String {
    if let Some(signal) = status.signal() {
        return format!("terminated by signal {signal}");
    }
    "terminated without exit status".to_string()
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn changed_registered_helper_is_rejected_before_execution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let helper_path = temp.path().join("helper");
        fs::write(&helper_path, "#!/bin/sh\nexit 0\n").expect("write helper");
        let mut permissions = fs::metadata(&helper_path)
            .expect("helper metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("make helper executable");
        let helper = DeliveryHelper::from_configured_path(&helper_path).expect("resolve helper");
        let provenance = helper.provenance;

        let retained = temp.path().join("retained-helper");
        fs::rename(&helper_path, &retained).expect("retain original helper");
        fs::write(&helper_path, "#!/bin/sh\nexit 99\n").expect("write replacement helper");
        let mut permissions = fs::metadata(&helper_path)
            .expect("replacement metadata")
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&helper_path, permissions).expect("make replacement executable");

        let err = DeliveryHelper::from_provenance(Some(&provenance), "ab_helper_change")
            .expect_err("replacement must fail closed");
        assert_eq!(err.code, DELIVERY_HELPER_CHANGED);
    }
}
