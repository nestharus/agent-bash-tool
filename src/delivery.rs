use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

use std::os::unix::process::ExitStatusExt;

use serde::{Deserialize, Serialize};

use crate::state::{self, CallerChainEntry, DeliveryMeta, DeliveryMode, Meta, StatePaths};

const CONSUMER_GRACE_MS_ENV: &str = "AGENT_BASH_CONSUMER_GRACE_MS";
const MAX_CONSUMER_GRACE_MS: u64 = 10_000;
const CONSUMER_GRACE_POLL_MS: u64 = 25;

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
) -> Option<(String, String)> {
    caller_chain
        .iter()
        .filter(|entry| state::process_identity_is_live(entry))
        .find_map(|entry| resolve_owner_for_pid(entry.pid, expected_invocation_uuid))
}

fn resolve_owner_for_pid(
    pid: libc::pid_t,
    expected_invocation_uuid: &str,
) -> Option<(String, String)> {
    let output = Command::new(delivery_binary())
        .args(["session", "of-pid", &pid.to_string(), "--json"])
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let response: PidSessionResponse = serde_json::from_slice(&output.stdout).ok()?;
    if !response.found || response.invocation_uuid.as_deref() != Some(expected_invocation_uuid) {
        return None;
    }
    let session_id = response.session_id.filter(|value| !value.is_empty())?;
    let invocation_uuid = response.invocation_uuid?;
    Some((session_id, invocation_uuid))
}

pub(crate) fn register(paths: &StatePaths, meta: &Meta) -> std::io::Result<()> {
    run_required_runner_command(&register_request(meta, paths))
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
    let _lock = state::lock_delivery(paths)?;
    let mode = state::read_delivery_mode(paths)?;
    let mut meta = state::read_meta(paths)?;
    if mode == DeliveryMode::Async {
        return Ok(detach_outcome(&meta, false, false));
    }

    run_required_runner_command(&activate_request(&meta.handle))?;
    state::write_delivery_mode_atomic(paths, DeliveryMode::Async)?;
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
) -> DeliveryMeta {
    let request = trigger_request(caller_ppid, handle, paths, consumed);
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
    binary: OsString,
    args: Vec<OsString>,
}

fn register_request(meta: &Meta, paths: &StatePaths) -> NotifyRequest {
    NotifyRequest {
        binary: delivery_binary(),
        args: register_args(meta, paths),
    }
}

fn activate_request(handle: &str) -> NotifyRequest {
    NotifyRequest {
        binary: delivery_binary(),
        args: activate_args(handle),
    }
}

fn trigger_request(
    caller_ppid: libc::pid_t,
    handle: &str,
    paths: &StatePaths,
    consumed: bool,
) -> NotifyRequest {
    NotifyRequest {
        binary: delivery_binary(),
        args: trigger_args(caller_ppid, handle, paths, consumed),
    }
}

fn delivery_binary() -> OsString {
    std::env::var_os("AGENT_BASH_AGENT_RUNNER_BIN").unwrap_or_else(|| OsString::from("agents"))
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
    Command::new(&request.binary)
        .args(&request.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
}

fn run_required_runner_command(request: &NotifyRequest) -> std::io::Result<()> {
    let output = Command::new(&request.binary)
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

fn attempted_delivery_meta() -> DeliveryMeta {
    DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: None,
        skipped: None,
    }
}

fn delivery_signal_error(status: ExitStatus) -> String {
    if let Some(signal) = status.signal() {
        return format!("terminated by signal {signal}");
    }
    "terminated without exit status".to_string()
}
