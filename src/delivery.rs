use std::ffi::OsString;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};

use std::os::unix::process::ExitStatusExt;

use crate::state::{DeliveryMeta, StatePaths};

pub(crate) fn notify(caller_ppid: libc::pid_t, handle: &str, paths: &StatePaths) -> DeliveryMeta {
    let request = notify_request(caller_ppid, handle, paths);
    match run_notify_command(&request) {
        Ok(status) => delivery_meta_from_status(status),
        Err(err) => delivery_meta_from_error(err),
    }
}

struct NotifyRequest {
    binary: OsString,
    args: Vec<OsString>,
}

fn notify_request(caller_ppid: libc::pid_t, handle: &str, paths: &StatePaths) -> NotifyRequest {
    NotifyRequest {
        binary: delivery_binary(),
        args: notify_args(caller_ppid, handle, paths),
    }
}

fn delivery_binary() -> OsString {
    std::env::var_os("AGENT_BASH_AGENT_RUNNER_BIN").unwrap_or_else(|| OsString::from("agents"))
}

fn notify_args(caller_ppid: libc::pid_t, handle: &str, paths: &StatePaths) -> Vec<OsString> {
    vec![
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
    ]
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
    }
}

fn delivery_signal_error(status: ExitStatus) -> String {
    if let Some(signal) = status.signal() {
        return format!("terminated by signal {signal}");
    }
    "terminated without exit status".to_string()
}
