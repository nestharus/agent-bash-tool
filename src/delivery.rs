use std::process::{Command, Stdio};

use std::os::unix::process::ExitStatusExt;

use crate::state::{DeliveryMeta, StatePaths};

pub(crate) fn notify(caller_ppid: libc::pid_t, handle: &str, paths: &StatePaths) -> DeliveryMeta {
    let mut result = DeliveryMeta {
        attempted: true,
        exit_code: None,
        error: None,
    };
    let binary = std::env::var_os("AGENT_BASH_AGENT_RUNNER_BIN")
        .unwrap_or_else(|| std::ffi::OsString::from("agents"));
    match Command::new(binary)
        .arg("notify")
        .arg("agent-bash-complete")
        .arg("--caller-ppid")
        .arg(caller_ppid.to_string())
        .arg("--handle")
        .arg(handle)
        .arg("--state-dir")
        .arg(&paths.state_dir)
        .arg("--meta")
        .arg(&paths.meta)
        .arg("--log")
        .arg(&paths.log)
        .arg("--rc")
        .arg(&paths.rc)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) => {
            if let Some(code) = status.code() {
                result.exit_code = Some(code);
            } else if let Some(signal) = status.signal() {
                result.error = Some(format!("terminated by signal {signal}"));
            } else {
                result.error = Some("terminated without exit status".to_string());
            }
        }
        Err(err) => {
            result.error = Some(err.to_string());
        }
    }
    result
}
