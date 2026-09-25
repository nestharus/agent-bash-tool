//! Private user-namespace exercise of the real Bash binary and v30 child
//! registration and closed ordinary command route.
use crate::state::DeliveryMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OrdinaryCommand {
    version: u32,
    original_cli_argv: Vec<String>,
    argv: Vec<String>,
    resolved_program: std::path::PathBuf,
    cwd: std::path::PathBuf,
    environment: Vec<(String, String)>,
    completion_scope: String,
    ready_sentinel: Option<String>,
    cancel_on_owner_exit: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Session {
    lane_id: String,
    source_generation: String,
    session_id: String,
    request_id: String,
    allocation_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Actor {
    host_pid: i32,
    boot_id: String,
    starttime_ticks: u64,
    pidns_dev: u64,
    pidns_ino: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Child {
    request_id: String,
    d_key: String,
    invocation_uuid: String,
    handle: String,
    root_handoff_id: String,
    root_id: String,
    parent_invocation_uuid: String,
    parent_work_grant_id: String,
    parent_work_id: String,
    actor: Actor,
    registration_authority: String,
    #[serde(default, skip_serializing_if = "ListenerPolicy::is_response_only")]
    listener_policy: ListenerPolicy,
    session: Session,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ListenerPolicy {
    ResponseOnly,
    Notify,
}

impl Default for ListenerPolicy {
    fn default() -> Self {
        Self::ResponseOnly
    }
}

impl ListenerPolicy {
    fn from_delivery(mode: DeliveryMode) -> Self {
        match mode {
            DeliveryMode::Sync => Self::ResponseOnly,
            DeliveryMode::Async => Self::Notify,
        }
    }

    fn wire_byte(self) -> u8 {
        match self {
            Self::ResponseOnly => 0,
            Self::Notify => 1,
        }
    }

    fn is_response_only(&self) -> bool {
        *self == Self::ResponseOnly
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ResultReceipt {
    request_id: String,
    grant_id: String,
    exit_code: i32,
    stdout_sha256: String,
    stdout_len: u64,
    stderr_sha256: String,
    stderr_len: u64,
}

fn private_user_namespace() -> bool {
    (unsafe { libc::geteuid() }) == 0
        && std::fs::read_to_string("/proc/self/uid_map")
            .ok()
            .is_some_and(|map| map.split_ascii_whitespace().nth(2) == Some("1"))
}

/// Called only for a resolved v30 owner in the private feature build. The
/// broker authenticates the connected process and consumed parent work; an
/// ambient owner marker or local handle never authorizes C. An ordinary
/// command is admitted only through the broker-selected private X/^ route;
/// async returns a consumed-K receipt while Q/W/F settle independently.
pub(crate) fn register_ordinary_run(
    mode: DeliveryMode,
    argv: &[String],
    cwd: &Path,
    completion_scope: crate::supervisor::CompletionScope,
    ready_sentinel: Option<&str>,
    cancel_on_owner_exit: bool,
) -> Result<Option<PrivateRunResult>, String> {
    if !private_user_namespace() {
        return Ok(None);
    }
    let Ok(control) = std::env::var("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1") else {
        return Ok(None);
    };
    let socket = Path::new(&control).with_file_name("v30.sock");
    let request_id = match std::env::var("AGE319_PRIVATE_ORDINARY_COPIED_REQUEST_ID_V1") {
        Ok(copied) => copied,
        Err(_) => random_uuid()?,
    };
    let request = uuid_bytes(&request_id)?;
    let policy = ListenerPolicy::from_delivery(mode);
    if completion_scope != crate::supervisor::CompletionScope::Tree
        || ready_sentinel.is_some()
        || cancel_on_owner_exit
    {
        return Err("ordinary fresh root/ready/owner-cancel mode unavailable before K".into());
    }
    // The pinned Bash image is the source at the original parsed CLI entry.
    // Legacy exec_workload removes both keys before execvp. This private
    // source runs before legacy helper preparation, so scrub them explicitly.
    let original_cli_argv = std::env::args_os()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "non-UTF-8 original Bash CLI argv unavailable".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment = workload_environment()?;
    let mut command = OrdinaryCommand {
        version: 1,
        original_cli_argv,
        argv: argv.to_vec(),
        resolved_program: resolve_execvp_program(&argv[0], cwd)?,
        cwd: cwd.to_path_buf(),
        environment,
        completion_scope: "tree".into(),
        ready_sentinel: None,
        cancel_on_owner_exit: false,
    };
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_MUTATE_ARGV_BEFORE_C_V1").is_some() {
        command.argv.push("changed-before-c".into());
    }
    let child = register_child(
        &socket,
        &request_id,
        &request,
        policy,
        true,
        std::env::var_os("AGE319_PRIVATE_ORDINARY_DROP_C_REPLY_V1").is_some(),
        Some(&command),
    )
    .map_err(|error| {
        format!("fresh C outcome refused or unknown; request_id={request_id}: {error}")
    })?;
    if let Some(gate) = std::env::var_os("AGE319_PRIVATE_ORDINARY_PAUSE_AFTER_C_DIR_V1") {
        let gate = std::path::PathBuf::from(gate);
        std::fs::write(gate.join("ordinary-paused"), &request_id)
            .map_err(|error| error.to_string())?;
        while !gate.join("ordinary-release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_MUTATE_ENV_AFTER_C_V1").is_some() {
        unsafe { std::env::set_var("AGE319_ORDINARY_EFFECTIVE_ENV", "changed-after-c") };
    }
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_MUTATE_CWD_AFTER_C_V1").is_some() {
        std::env::set_current_dir("/").map_err(|error| error.to_string())?;
    }
    // This digest is only a veto for post-C drift in the pinned Bash image.
    // The broker executes its original C selection; no later Bash assertion
    // can replace argv, cwd, environment, or executable after selection.
    let mut at_k = command.clone();
    at_k.original_cli_argv = std::env::args_os()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "non-UTF-8 Bash CLI argv unavailable before K".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    at_k.cwd = std::env::current_dir().map_err(|error| error.to_string())?;
    at_k.environment = workload_environment()?;
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_MUTATE_ARGV_AFTER_C_V1").is_some() {
        at_k.argv.push("changed-after-c".into());
    }
    at_k.resolved_program = resolve_execvp_program(&argv[0], &at_k.cwd)?;
    let digest = Sha256::digest(serde_json::to_vec(&at_k).map_err(|error| error.to_string())?);
    let mut k_request = request.to_vec();
    k_request.extend_from_slice(&digest);
    let command_file = sealed_command_file(&command)?;
    // `^` is the versioned ordinary one-use K. Fixed private `8` remains
    // its own recipe route. A lost ^ reply can only be read through 9.
    let k_result = if std::env::var_os("AGE319_PRIVATE_ORDINARY_DROP_K_REPLY_V1").is_some() {
        request_frame_with_command(&socket, b'^', &k_request, Some(&command_file), false)
            .and_then(|_| Err("ordinary K reply deliberately lost after durable receipt".into()))
    } else {
        request_frame_with_command(&socket, b'^', &k_request, Some(&command_file), true)
    };
    let physical = match k_result {
        Ok(reply) => reply,
        Err(k_error) => request_frame(&socket, b'9', &request, true)
            .map_err(|read_error| {
                if k_error.contains("ordinary Bash argv/cwd/environment changed after C before K")
                    && read_error.contains("fresh Bash physical K absent")
                {
                    format!("ordinary Bash command drift unavailable before K; request_id={request_id} handle={}; {k_error}", child.handle)
                } else {
                    format!("ordinary Bash K outcome unknown; request_id={request_id} handle={}; K={k_error}; Q readback={read_error}", child.handle)
                }
            })?,
    };
    let grant_id = physical
        .strip_prefix("fresh-bash-physical-k ")
        .or_else(|| physical.strip_prefix("fresh-bash-physical-pending "))
        .or_else(|| physical.strip_prefix("fresh-bash-physical-exited "))
        .or_else(|| physical.strip_prefix("fresh-bash-physical-drained "))
        .and_then(|rest| rest.split_ascii_whitespace().next())
        .ok_or_else(|| format!("ordinary Bash physical K readback unknown; request_id={request_id} handle={}: {physical}", child.handle))?
        .to_owned();
    uuid_bytes(&grant_id)?;
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_CANCEL_AFTER_K_V1").is_some() {
        let cancelled = request_frame(&socket, b'!', &request, true)
            .map_err(|error| format!("ordinary Bash physical cancel unknown; request_id={request_id} grant={grant_id}: {error}"))?;
        if !cancelled.starts_with(&format!("fresh-bash-physical-cancel {grant_id}")) {
            return Err(format!(
                "ordinary Bash physical cancel changed; request_id={request_id} grant={grant_id}: {cancelled}"
            ));
        }
    }
    let raw_dir = socket
        .parent()
        .ok_or("fresh Bash socket directory absent")?
        .join("fresh-provider");
    let base = serde_json::json!({
        "schema_version": 30,
        "request_id": request_id,
        "handle": child.handle,
        "delivery_mode": if mode == DeliveryMode::Sync { "sync" } else { "async" },
        "completion_policy": "tree",
        "physical_grant_id": grant_id,
        "stdout_path": raw_dir.join(format!("{grant_id}.stdout")),
        "stderr_path": raw_dir.join(format!("{grant_id}.stderr")),
        "effects_possible": true,
    });
    if mode == DeliveryMode::Async {
        if std::env::var_os("AGE319_PRIVATE_ASYNC_PROBE_SYNC_REFUSAL_V1").is_some() {
            let refused = request_frame(&socket, b'v', &request, true)
                .err()
                .ok_or("async C unexpectedly acquired direct sync result")?;
            if !refused.contains("response-only") {
                return Err(format!("async sync-result refusal changed: {refused}"));
            }
        }
        let mut result = base;
        result["dispatch_state"] = "broker-k-consumed".into();
        return Ok(Some(PrivateRunResult::Dispatch(result)));
    }
    if std::env::var_os("AGE319_PRIVATE_ORDINARY_DROP_Q_REPLY_V1").is_some() {
        request_frame(&socket, b'9', &request, false)?;
    }
    let physical_q = loop {
        let state = request_frame(&socket, b'9', &request, true)
            .map_err(|error| format!("ordinary Bash physical Q unknown; request_id={request_id} grant={grant_id}: {error}"))?;
        if state.starts_with(&format!("fresh-bash-physical-drained {grant_id} ")) {
            break state;
        }
        if state.starts_with("fresh-bash-physical-unknown ") {
            return Err(format!(
                "ordinary Bash physical Q unknown; request_id={request_id} grant={grant_id}: {state}"
            ));
        }
        if !state.starts_with(&format!("fresh-bash-physical-pending {grant_id}"))
            && !state.starts_with(&format!("fresh-bash-physical-exited {grant_id} "))
        {
            return Err(format!(
                "ordinary Bash physical Q changed; request_id={request_id} grant={grant_id}: {state}"
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let first_w = if std::env::var_os("AGE319_PRIVATE_ORDINARY_DROP_W_REPLY_V1").is_some() {
        request_frame(&socket, b'%', &request, false)
            .and_then(|_| Err("ordinary W reply deliberately lost after durable receipt".into()))
    } else {
        request_frame(&socket, b'%', &request, true)
    };
    let accepted = first_w.or_else(|first_error| {
        request_frame(&socket, b'%', &request, true).map_err(|read_error| format!(
            "ordinary Bash W unknown; request_id={request_id} grant={grant_id}; first={first_error}; readback={read_error}"
        ))
    })?;
    let source: serde_json::Value = serde_json::from_str(
        accepted.strip_prefix("fresh-bash-source-accepted ")
            .ok_or_else(|| format!("ordinary Bash W readback unknown; request_id={request_id} grant={grant_id}: {accepted}"))?
            .trim_end(),
    ).map_err(|error| error.to_string())?;
    if source["request_id"] != request_id
        || source["source_id"] != child.handle
        || source["physical_grant_id"] != grant_id
        || source["parent_work_grant_id"] != child.parent_work_grant_id
        || source["parent_work_id"] != child.parent_work_id
        || source["tree_drained"] != true
        || source["output_closed"] != true
    {
        return Err(format!(
            "ordinary Bash W identity mismatch; request_id={request_id} grant={grant_id}"
        ));
    }
    if let Some(gate) = std::env::var_os("AGE319_PRIVATE_SYNC_PAUSE_AFTER_W_DIR_V1") {
        let gate = std::path::PathBuf::from(gate);
        std::fs::write(gate.join("sync-paused"), &request_id).map_err(|e| e.to_string())?;
        while !gate.join("sync-release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    let _ = (base, physical_q);
    let begun = if std::env::var_os("AGE319_PRIVATE_SYNC_DROP_BEGIN_REPLY_V1").is_some() {
        request_frame(&socket, b'v', &request, false)
            .and_then(|_| Err("sync begin reply deliberately lost".into()))
    } else {
        request_sync_begin(&socket, &request)
    };
    let (reply, files) = match begun {
        Ok(value) => value,
        Err(_) => {
            let readback = request_frame(&socket, b'u', &request, true).map_err(|error| {
                format!("sync publication unknown; request_id={request_id}: {error}")
            })?;
            (readback, None)
        }
    };
    let (first, json) = if let Some(json) = reply.strip_prefix("fresh-bash-sync-begin ") {
        (true, json)
    } else if let Some(json) = reply.strip_prefix("fresh-bash-sync-unknown ") {
        (false, json)
    } else {
        return Err(format!(
            "sync publication reply unknown; request_id={request_id}"
        ));
    };
    let publication: serde_json::Value =
        serde_json::from_str(json.trim_end()).map_err(|error| error.to_string())?;
    if publication["version"] != 1
        || publication["phase"] != "unknown"
        || publication["child"]["request_id"] != request_id
        || publication["child"]["d_key"] != child.d_key
        || publication["child"]["actor"]
            != serde_json::to_value(&child.actor).map_err(|e| e.to_string())?
        || publication["event"] != source
    {
        return Err(format!(
            "sync publication identity mismatch; request_id={request_id}"
        ));
    }
    if !first {
        if files.is_some() {
            return Err("sync readback unexpectedly carried streams".into());
        }
        return Ok(Some(PrivateRunResult::Dispatch(serde_json::json!({
            "schema_version": 31,
            "dispatch_state": "sync-publication-unknown",
            "publication": publication,
        }))));
    }
    if std::env::var_os("AGE319_PRIVATE_SYNC_REPEAT_BEGIN_V1").is_some() {
        let (repeat, repeat_files) = request_sync_begin(&socket, &request)?;
        if !repeat.starts_with("fresh-bash-sync-unknown ") || repeat_files.is_some() {
            return Err("same-key sync begin unexpectedly reissued streams".into());
        }
    }
    let [mut stdout, mut stderr] =
        files.ok_or("sync begin descriptors absent; publication unknown")?;
    if let Some(gate) = std::env::var_os("AGE319_PRIVATE_SYNC_PAUSE_AFTER_BEGIN_DIR_V1") {
        let gate = std::path::PathBuf::from(gate);
        std::fs::write(gate.join("sync-begin-paused"), &request_id).map_err(|e| e.to_string())?;
        while !gate.join("sync-begin-release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    verify_sync_file(
        &mut stdout,
        publication["event"]["stdout_len"]
            .as_u64()
            .ok_or("stdout length absent")?,
        publication["event"]["stdout_sha256"]
            .as_str()
            .ok_or("stdout hash absent")?,
    )?;
    verify_sync_file(
        &mut stderr,
        publication["event"]["stderr_len"]
            .as_u64()
            .ok_or("stderr length absent")?,
        publication["event"]["stderr_sha256"]
            .as_str()
            .ok_or("stderr hash absent")?,
    )?;
    if let Some(gate) = std::env::var_os("AGE319_PRIVATE_SYNC_PAUSE_AFTER_VERIFY_DIR_V1") {
        let gate = std::path::PathBuf::from(gate);
        std::fs::write(gate.join("sync-verify-paused"), &request_id).map_err(|e| e.to_string())?;
        while !gate.join("sync-verify-release").exists() {
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    Ok(Some(PrivateRunResult::Sync {
        publication,
        stdout,
        stderr,
    }))
}

pub(crate) enum PrivateRunResult {
    Dispatch(serde_json::Value),
    Sync {
        publication: serde_json::Value,
        stdout: File,
        stderr: File,
    },
}

pub(crate) fn write_private_result(result: PrivateRunResult) -> std::io::Result<()> {
    let mut caller = std::io::stdout().lock();
    match result {
        PrivateRunResult::Dispatch(value) => serde_json::to_writer(&mut caller, &value)?,
        PrivateRunResult::Sync {
            publication,
            mut stdout,
            mut stderr,
        } => {
            let stdout_hash = publication["event"]["stdout_sha256"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("sync stdout digest absent"))?;
            let stderr_hash = publication["event"]["stderr_sha256"]
                .as_str()
                .ok_or_else(|| std::io::Error::other("sync stderr digest absent"))?;
            if std::env::var_os("AGE319_PRIVATE_SYNC_PARTIAL_CALLER_WRITE_V1").is_some() {
                caller.write_all(
                    b"{\"schema_version\":31,\"dispatch_state\":\"sync-child-result\"",
                )?;
                caller.flush()?;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "private partial caller write",
                ));
            }
            caller.write_all(
                b"{\"schema_version\":31,\"dispatch_state\":\"sync-child-result\",\"publication\":",
            )?;
            serde_json::to_writer(&mut caller, &publication)?;
            caller.write_all(b",\"stdout_encoding\":\"base64\",\"stdout_base64\":\"")?;
            write_base64(&mut stdout, &mut caller, stdout_hash)?;
            caller.write_all(b"\",\"stderr_encoding\":\"base64\",\"stderr_base64\":\"")?;
            write_base64(&mut stderr, &mut caller, stderr_hash)?;
            caller.write_all(b"\"}")?;
        }
    }
    caller.write_all(b"\n")?;
    caller.flush()
}

fn write_base64(
    input: &mut File,
    output: &mut impl Write,
    expected_hash: &str,
) -> std::io::Result<()> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut input_bytes = [0u8; 48 * 1024];
    let mut encoded = [0u8; 64 * 1024];
    let mut remaining = input.metadata()?.len();
    let mut digest = Sha256::new();
    while remaining > 0 {
        let n = remaining.min(input_bytes.len() as u64) as usize;
        input.read_exact(&mut input_bytes[..n])?;
        digest.update(&input_bytes[..n]);
        remaining -= n as u64;
        let mut used = 0;
        for chunk in input_bytes[..n].chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            encoded[used] = TABLE[(a >> 2) as usize];
            encoded[used + 1] = TABLE[(((a & 3) << 4) | (b >> 4)) as usize];
            encoded[used + 2] = if chunk.len() > 1 {
                TABLE[(((b & 15) << 2) | (c >> 6)) as usize]
            } else {
                b'='
            };
            encoded[used + 3] = if chunk.len() > 2 {
                TABLE[(c & 63) as usize]
            } else {
                b'='
            };
            used += 4;
        }
        output.write_all(&encoded[..used])?;
    }
    if format!("{:x}", digest.finalize()) != expected_hash {
        return Err(std::io::Error::other(
            "sync stream changed during caller encoding",
        ));
    }
    Ok(())
}

fn verify_sync_file(file: &mut File, expected_len: u64, expected_hash: &str) -> Result<(), String> {
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file() || meta.len() != expected_len {
        return Err("sync stream descriptor length changed".into());
    }
    let mut hash = Sha256::new();
    let mut count = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        count = count.checked_add(n as u64).ok_or("sync stream overflow")?;
        hash.update(&buffer[..n]);
    }
    if count != expected_len
        || format!("{:x}", hash.finalize()) != expected_hash
        || file.metadata().map_err(|e| e.to_string())?.len() != expected_len
    {
        return Err("sync stream descriptor hash changed".into());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    Ok(())
}

fn workload_environment() -> Result<Vec<(String, String)>, String> {
    let mut environment = std::env::vars_os()
        .filter(|(key, _)| {
            key != "AGENT_BASH_AGENT_RUNNER_BIN"
                && key != "OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY"
        })
        .map(|(key, value)| {
            Ok((
                key.into_string()
                    .map_err(|_| "non-UTF-8 Bash environment key unavailable")?,
                value
                    .into_string()
                    .map_err(|_| "non-UTF-8 Bash environment value unavailable")?,
            ))
        })
        .collect::<Result<Vec<_>, &str>>()
        .map_err(str::to_owned)?;
    environment.sort();
    Ok(environment)
}

fn resolve_execvp_program(first: &str, cwd: &Path) -> Result<std::path::PathBuf, String> {
    use std::os::unix::ffi::OsStrExt;
    if unsafe { libc::getuid() != libc::geteuid() || libc::getgid() != libc::getegid() } {
        return Err("ordinary Bash changed effective credentials unavailable before K".into());
    }
    let candidates: Vec<_> = if first.contains('/') {
        vec![cwd.join(first)]
    } else {
        std::env::var_os("PATH")
            .unwrap_or_else(|| "/bin:/usr/bin".into())
            .to_str()
            .ok_or("non-UTF-8 Bash PATH unavailable before K")?
            .split(':')
            .map(|entry| cwd.join(entry).join(first))
            .collect()
    };
    for candidate in candidates {
        let Ok(path) = std::ffi::CString::new(candidate.as_os_str().as_bytes()) else {
            return Err("ordinary Bash command path contains NUL unavailable before K".into());
        };
        if candidate.metadata().is_ok_and(|meta| meta.is_file())
            && unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0
        {
            return Ok(candidate);
        }
    }
    Err("ordinary Bash command not executable in original PATH before K".into())
}

fn register_child(
    socket: &Path,
    request_id: &str,
    request: &[u8; 16],
    policy: ListenerPolicy,
    explicit_policy: bool,
    drop_first_reply: bool,
    ordinary_command: Option<&OrdinaryCommand>,
) -> Result<Child, String> {
    let mut registration = request.to_vec();
    if explicit_policy {
        registration.push(policy.wire_byte());
    }
    let command_file = ordinary_command.map(sealed_command_file).transpose()?;
    let admitted = if drop_first_reply {
        request_frame_with_command(
            socket,
            if ordinary_command.is_some() {
                b'X'
            } else {
                b'C'
            },
            &registration,
            command_file.as_ref(),
            false,
        )?;
        request_frame(socket, b'c', request, true)?
    } else {
        let opcode = if ordinary_command.is_some() {
            b'X'
        } else {
            b'C'
        };
        match request_frame_with_command(socket, opcode, &registration, command_file.as_ref(), true)
        {
            Ok(reply) => reply,
            Err(first_error) => {
                // A lost reply may follow a durable C. Read only the same
                // request; never submit C again or infer acceptance from EOF.
                request_frame(socket, b'c', request, true).map_err(|read_error| {
                    format!("C reply uncertain: {first_error}; c readback: {read_error}")
                })?
            }
        }
    };
    let child: Child = serde_json::from_str(
        admitted
            .strip_prefix("fresh-bash-child ")
            .ok_or("Bash child registration refused")?
            .trim_end(),
    )
    .map_err(|e| e.to_string())?;
    let read = request_frame(socket, b'c', request, true)?;
    if read != admitted
        || child.request_id != request_id
        || child.session.request_id != child.d_key
        || !child.handle.starts_with("ab30_")
        || child.invocation_uuid == child.parent_invocation_uuid
        || child.d_key == child.session.session_id
        || child.parent_work_grant_id.is_empty()
        || child.parent_work_id.is_empty()
        || child.listener_policy != policy
    {
        return Err("Bash child durable readback or listener policy mismatch".into());
    }
    Ok(child)
}

fn sealed_command_file(command: &OrdinaryCommand) -> Result<File, String> {
    let bytes = serde_json::to_vec(command).map_err(|error| error.to_string())?;
    if bytes.len() > 64 * 1024 {
        return Err(
            "ordinary Bash command admission descriptor too large unavailable before K".into(),
        );
    }
    let fd = unsafe {
        libc::memfd_create(
            c"ordinary-bash-command".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(&bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    let seals = libc::F_SEAL_SEAL | libc::F_SEAL_SHRINK | libc::F_SEAL_GROW | libc::F_SEAL_WRITE;
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    Ok(file)
}

pub(crate) fn internal_main() -> Option<i32> {
    if std::env::args().nth(1).as_deref() == Some("__age319-private-probe-sibling-read-v1") {
        let result = (|| -> Result<(), String> {
            if !private_user_namespace() {
                return Err("private sibling probe requires user namespace".into());
            }
            let args: Vec<_> = std::env::args().collect();
            if args.len() != 4 {
                return Err("private sibling probe arguments invalid".into());
            }
            let request = uuid_bytes(&args[3])?;
            match request_frame(Path::new(&args[2]), b'c', &request, true) {
                Err(error) if error.contains("actor") => {}
                outcome => return Err(format!("sibling read was not actor-refused: {outcome:?}")),
            }
            match request_frame(Path::new(&args[2]), b'u', &request, true) {
                Err(error) if error.contains("actor") => Ok(()),
                outcome => Err(format!(
                    "sibling sync publication read was not actor-refused: {outcome:?}"
                )),
            }
        })();
        return Some(match result {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("AGE319_PRIVATE_SIBLING={error}");
                70
            }
        });
    }
    if std::env::args().nth(1).as_deref() != Some("__age319-private-admit-child-v1") {
        return None;
    }
    let result = (|| -> Result<(), String> {
        if !private_user_namespace() {
            return Err("private Bash child probe requires user namespace".into());
        }
        // Arguments are fixture routing data only. The broker never trusts
        // their contents without its challenged peer and consumed work K.
        let args: Vec<_> = std::env::args().collect();
        let explicit = args.len() >= 5;
        if explicit
            && args[5..]
                .iter()
                .any(|arg| arg != "no-cancel" && arg != "notify")
        {
            return Err("invalid private Bash child option".into());
        }
        let no_cancel = explicit && args[5..].iter().any(|arg| arg == "no-cancel");
        let policy = if explicit && args[5..].iter().any(|arg| arg == "notify") {
            ListenerPolicy::Notify
        } else {
            ListenerPolicy::ResponseOnly
        };
        let (socket, request_id, marker) = if explicit {
            std::thread::sleep(std::time::Duration::from_millis(250));
            (
                Path::new(&args[2]).to_path_buf(),
                args[3].clone(),
                args[4].clone(),
            )
        } else {
            let control = std::env::var("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1")
                .map_err(|_| "private broker socket absent")?;
            (
                Path::new(&control).with_file_name("v30.sock"),
                std::env::var("AGE319_PRIVATE_BASH_REQUEST_KEY").unwrap_or(random_uuid()?),
                std::env::var("AGE319_PRIVATE_BASH_EFFECT_MARKER")
                    .map_err(|_| "private effect marker absent")?,
            )
        };
        let request = uuid_bytes(&request_id)?;
        let status_before_c =
            std::fs::read_to_string("/proc/self/status").map_err(|error| error.to_string())?;
        let parent_pid_before_c: u32 = status_before_c
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .ok_or("Bash parent PID absent before C")?
            .trim()
            .parse()
            .map_err(|error: std::num::ParseIntError| error.to_string())?;
        let child = register_child(
            &socket,
            &request_id,
            &request,
            policy,
            policy == ListenerPolicy::Notify,
            true,
            None,
        )?;
        if Path::new(&marker).exists() {
            return Err("private effect marker exists before grant".into());
        }
        let grant = request_frame(&socket, b'E', &request, true)?;
        let grant_id = grant
            .strip_prefix("fresh-bash-work ")
            .ok_or("private Bash work not admitted")?
            .trim_end()
            .to_owned();
        uuid_bytes(&grant_id)?;
        if Path::new(&marker).exists() {
            return Err("private effect happened before grant reply".into());
        }
        // One direct child and no Bash supervisor. Production `run` remains
        // closed; this fixed command is a private positive effect witness.
        let output = Command::new("/bin/sh")
            .args([
                "-c",
                "printf 'v30-child-output\\n'; printf 'ran\\n' > \"$1\"",
                "sh",
                &marker,
            ])
            .output()
            .map_err(|e| e.to_string())?;
        // This describes Bash's local observation only. O stores the report;
        // it does not certify a broker fork, complete physical output, Q, W,
        // recipient transport, or ACK.
        let result = ResultReceipt {
            request_id,
            grant_id,
            exit_code: output.status.code().ok_or("private work signal exit")?,
            stdout_sha256: format!("{:x}", Sha256::digest(&output.stdout)),
            stdout_len: output.stdout.len() as u64,
            stderr_sha256: format!("{:x}", Sha256::digest(&output.stderr)),
            stderr_len: output.stderr.len() as u64,
        };
        let result_bytes = serde_json::to_vec(&result).map_err(|e| e.to_string())?;
        // Result receipt retry is idempotent. It never repeats the command.
        request_frame(&socket, b'O', &result_bytes, false)?;
        let reported = request_frame(&socket, b'O', &result_bytes, true)?;
        let readback: ResultReceipt = serde_json::from_str(
            reported
                .strip_prefix("fresh-bash-result ")
                .ok_or("private Bash result not committed")?
                .trim_end(),
        )
        .map_err(|e| e.to_string())?;
        if readback != result {
            return Err("private Bash result readback mismatch".into());
        }
        if request_frame(&socket, b'E', &request, true)
            .is_ok_and(|reply| reply.starts_with("fresh-bash-work "))
        {
            return Err("private Bash work grant replayed".into());
        }
        // The fixed private physical K belongs to the broker. Drop its
        // response deliberately; only observation of the same consumed K may
        // recover it. The earlier O record is still just Bash's own report.
        request_frame(&socket, b'8', &request, false)?;
        if request_frame(&socket, b'8', &request, true)
            .is_ok_and(|reply| reply.starts_with("fresh-bash-physical-k "))
        {
            return Err("broker child K replayed after lost reply".into());
        }
        let grant = loop {
            let state = request_frame(&socket, b'9', &request, true)?;
            if let Some(rest) = state.strip_prefix("fresh-bash-physical-drained ") {
                let id = rest
                    .split_ascii_whitespace()
                    .next()
                    .ok_or("physical Q id absent")?;
                uuid_bytes(id)?;
                break id.to_owned();
            }
            if let Some(rest) = state.strip_prefix("fresh-bash-physical-exited ") {
                if no_cancel {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                let id = rest
                    .split_ascii_whitespace()
                    .next()
                    .ok_or("physical K id absent")?;
                uuid_bytes(id)?;
                break id.to_owned();
            }
            if !state.starts_with("fresh-bash-physical-pending ") {
                return Err(format!(
                    "broker child did not reach separate provider exit: {state}"
                ));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        if !no_cancel {
            request_frame(&socket, b'!', &request, true)?;
        }
        let physical = loop {
            let state = request_frame(&socket, b'9', &request, true)?;
            if let Some(rest) = state.strip_prefix("fresh-bash-physical-drained ") {
                let fields: Vec<_> = rest.split_ascii_whitespace().collect();
                let expected_stdout = b"broker-child-output\n";
                if fields.len() != 7
                    || fields[0] != grant
                    || fields[1] != "0"
                    || fields[2] != expected_stdout.len().to_string()
                    || fields[3] != "0"
                    || fields[4] != if no_cancel { "false" } else { "true" }
                    || fields[5] != format!("{:x}", Sha256::digest(expected_stdout))
                    || fields[6] != format!("{:x}", Sha256::digest([]))
                {
                    return Err(format!("broker child physical Q mismatch: {state}"));
                }
                break state.trim_end().to_owned();
            }
            if !(state.starts_with("fresh-bash-physical-exited ")
                || state.starts_with("fresh-bash-physical-pending "))
            {
                return Err(format!("broker child physical Q absent: {state}"));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let unrelated = uuid_bytes(&random_uuid()?)?;
        if request_frame(&socket, b'9', &unrelated, true)
            .is_ok_and(|reply| reply.starts_with("fresh-bash-physical-"))
        {
            return Err("unrelated child key observed broker physical Q".into());
        }
        // `%` is the private W transition. Drop its response and read the
        // same captured event back. No Bash O field is submitted as source
        // authority; the broker binds its own K/output/Q to C/D and parent K.
        request_frame(&socket, b'%', &request, false)?;
        let accepted = request_frame(&socket, b'%', &request, true)?;
        let source: serde_json::Value = serde_json::from_str(
            accepted
                .strip_prefix("fresh-bash-source-accepted ")
                .ok_or("fresh source W not accepted")?
                .trim_end(),
        )
        .map_err(|e| e.to_string())?;
        if source["request_id"] != child.request_id
            || source["source_id"] != child.handle
            || source["attempt_id"] != child.invocation_uuid
            || source["physical_grant_id"] != grant
            || source["parent_work_grant_id"] != child.parent_work_grant_id
            || source["parent_work_id"] != child.parent_work_id
            || source["completion_policy"] != "tree"
            || source["selected_kind"]
                != if no_cancel {
                    "tree_drained"
                } else {
                    "cancelled"
                }
            || source["tree_drained"] != true
            || source["output_closed"] != true
        {
            return Err("fresh source W exact readback mismatch".into());
        }
        let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
        let status_value = |field: &str| -> Result<u32, String> {
            status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| format!("missing process status {field}"))
        };
        println!(
            "{}",
            serde_json::json!({
                "child": child,
                "bash_reported_result": result,
                "result_provenance": "bash-self-report-only",
                "broker_physical_q": physical,
                "fresh_source_w": source,
                "stdout": String::from_utf8_lossy(&output.stdout),
                "stderr": String::from_utf8_lossy(&output.stderr),
                "parent_pid_before_c": parent_pid_before_c,
                "no_new_privs": status_value("NoNewPrivs:")?,
                "seccomp": status_value("Seccomp:")?,
            })
        );
        Ok(())
    })();
    Some(match result {
        Ok(()) => {
            write_terminal_witness(0);
            0
        }
        Err(error) => {
            eprintln!("AGE319_PRIVATE_BASH_CHILD={error}");
            write_terminal_witness(70);
            70
        }
    })
}

fn write_terminal_witness(code: i32) {
    if let Some(marker) = std::env::args().nth(4) {
        if let Some(parent) = Path::new(&marker).parent() {
            let _ = std::fs::write(parent.join("bash-causal-terminal-status"), code.to_string());
        }
    }
}

fn request_frame(socket: &Path, opcode: u8, payload: &[u8], read: bool) -> Result<String, String> {
    request_frame_with_command(socket, opcode, payload, None, read)
}

fn request_sync_begin(
    socket: &Path,
    request: &[u8; 16],
) -> Result<(String, Option<[File; 2]>), String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut challenge = [0u8; 16];
    stream
        .read_exact(&mut challenge)
        .map_err(|e| e.to_string())?;
    let mut frame = Vec::with_capacity(33);
    frame.push(b'v');
    frame.extend_from_slice(&challenge);
    frame.extend_from_slice(request);
    stream.write_all(&frame).map_err(|e| e.to_string())?;
    let mut response = [0u8; 8193];
    #[repr(align(8))]
    struct Aligned([u8; 64]);
    let mut control = Aligned([0; 64]);
    let mut iov = libc::iovec {
        iov_base: response.as_mut_ptr().cast(),
        iov_len: response.len(),
    };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.0.as_mut_ptr().cast();
    msg.msg_controllen = control.0.len();
    let first = unsafe { libc::recvmsg(stream.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) };
    if first <= 0 {
        return Err(format!(
            "sync begin descriptor reply absent: {}",
            std::io::Error::last_os_error()
        ));
    }
    if msg.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
        return Err("sync begin descriptor reply truncated".into());
    }
    let mut files = Vec::new();
    let mut cmsg = unsafe { libc::CMSG_FIRSTHDR(&msg) };
    while !cmsg.is_null() {
        let header = unsafe { &*cmsg };
        if header.cmsg_level != libc::SOL_SOCKET || header.cmsg_type != libc::SCM_RIGHTS {
            return Err("sync begin unexpected ancillary data".into());
        }
        let base = unsafe { libc::CMSG_LEN(0) } as usize;
        let bytes = (header.cmsg_len as usize)
            .checked_sub(base)
            .ok_or("sync begin bad descriptor header")?;
        if bytes % std::mem::size_of::<i32>() != 0 {
            return Err("sync begin bad descriptor count".into());
        }
        for index in 0..bytes / std::mem::size_of::<i32>() {
            let fd = unsafe { *(libc::CMSG_DATA(cmsg) as *const i32).add(index) };
            files.push(unsafe { File::from_raw_fd(fd) });
        }
        cmsg = unsafe { libc::CMSG_NXTHDR(&msg, cmsg) };
    }
    let mut bytes = response[..first as usize].to_vec();
    if bytes.len() <= 8192 {
        stream
            .take((8193 - bytes.len()) as u64)
            .read_to_end(&mut bytes)
            .map_err(|e| e.to_string())?;
    }
    if bytes.len() > 8192 || !bytes.ends_with(b"\n") {
        return Err("sync begin metadata incomplete".into());
    }
    if bytes.starts_with(b"error ") {
        return Err(String::from_utf8_lossy(&bytes).trim_end().into());
    }
    let reply = String::from_utf8(bytes).map_err(|e| e.to_string())?;
    let files = match files.len() {
        0 => None,
        2 => Some(
            files
                .try_into()
                .map_err(|_| "sync begin descriptor count changed")?,
        ),
        _ => return Err("sync begin descriptor count invalid".into()),
    };
    Ok((reply, files))
}

fn request_frame_with_command(
    socket: &Path,
    opcode: u8,
    payload: &[u8],
    command_file: Option<&File>,
    read: bool,
) -> Result<String, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    let mut challenge = [0u8; 16];
    stream
        .read_exact(&mut challenge)
        .map_err(|e| e.to_string())?;
    let mut frame = Vec::with_capacity(17 + payload.len());
    frame.push(opcode);
    frame.extend_from_slice(&challenge);
    frame.extend_from_slice(payload);
    if let Some(command_file) = command_file {
        #[repr(align(8))]
        struct Aligned([u8; 64]);
        let mut control = Aligned([0; 64]);
        let mut iov = libc::iovec {
            iov_base: frame.as_mut_ptr().cast(),
            iov_len: frame.len(),
        };
        let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.0.as_mut_ptr().cast();
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as _) as usize };
        let cmsg = unsafe { libc::CMSG_FIRSTHDR(&message) };
        if cmsg.is_null() {
            return Err("ordinary Bash command descriptor frame unavailable".into());
        }
        unsafe {
            (*cmsg).cmsg_level = libc::SOL_SOCKET;
            (*cmsg).cmsg_type = libc::SCM_RIGHTS;
            (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<i32>() as _) as usize;
            *(libc::CMSG_DATA(cmsg) as *mut i32) = command_file.as_raw_fd();
        }
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent != frame.len() as isize {
            return Err(format!(
                "ordinary Bash C descriptor frame incomplete: {}",
                std::io::Error::last_os_error()
            ));
        }
    } else {
        stream.write_all(&frame).map_err(|e| e.to_string())?;
    }
    if !read {
        let mut first = [0u8; 1];
        stream.read_exact(&mut first).map_err(|e| e.to_string())?;
        if first != [b'f'] {
            let mut rest = Vec::new();
            stream
                .take(8192)
                .read_to_end(&mut rest)
                .map_err(|e| e.to_string())?;
            let mut response = first.to_vec();
            response.extend_from_slice(&rest);
            return Err(format!(
                "private lost-reply request refused: {}",
                String::from_utf8_lossy(&response).trim_end()
            ));
        }
        return Ok(String::new());
    }
    let mut bytes = Vec::new();
    stream
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 8192 || !bytes.ends_with(b"\n") {
        return Err("incomplete broker reply".into());
    }
    if bytes.starts_with(b"error ") {
        return Err(String::from_utf8_lossy(&bytes).trim_end().to_owned());
    }
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn random_uuid() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .map_err(|e| e.to_string())?
        .read_exact(&mut bytes)
        .map_err(|e| e.to_string())?;
    bytes[6] = bytes[6] & 0x0f | 0x40;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}

fn uuid_bytes(value: &str) -> Result<[u8; 16], String> {
    let hex = value.replace('-', "");
    if value.len() != 36
        || hex.len() != 32
        || value.as_bytes()[8] != b'-'
        || value.as_bytes()[13] != b'-'
        || value.as_bytes()[18] != b'-'
        || value.as_bytes()[23] != b'-'
    {
        return Err("invalid UUID".into());
    }
    let mut bytes = [0u8; 16];
    for (index, part) in hex.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] =
            u8::from_str_radix(std::str::from_utf8(part).map_err(|e| e.to_string())?, 16)
                .map_err(|e| e.to_string())?;
    }
    if bytes == [0; 16] {
        return Err("nil UUID".into());
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    fn sample_child(request_id: &str, policy: ListenerPolicy) -> Child {
        let d_key = "22222222-2222-4222-8222-222222222222".to_owned();
        Child {
            request_id: request_id.into(),
            d_key: d_key.clone(),
            invocation_uuid: "33333333-3333-4333-8333-333333333333".into(),
            handle: "ab30_44444444444444444444444444444444".into(),
            root_handoff_id: "55555555-5555-4555-8555-555555555555".into(),
            root_id: "66666666-6666-4666-8666-666666666666".into(),
            parent_invocation_uuid: "77777777-7777-4777-8777-777777777777".into(),
            parent_work_grant_id: "88888888-8888-4888-8888-888888888888".into(),
            parent_work_id: "99999999-9999-4999-8999-999999999999".into(),
            actor: Actor {
                host_pid: 42,
                boot_id: "boot".into(),
                starttime_ticks: 1,
                pidns_dev: 1,
                pidns_ino: 1,
            },
            registration_authority: "authority".into(),
            listener_policy: policy,
            session: Session {
                lane_id: "lane".into(),
                source_generation: "generation".into(),
                session_id: "session".into(),
                request_id: d_key,
                allocation_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa".into(),
            },
        }
    }

    #[test]
    fn ordinary_delivery_selects_an_immutable_c_policy() {
        assert_eq!(
            ListenerPolicy::from_delivery(DeliveryMode::Sync).wire_byte(),
            0
        );
        assert_eq!(
            ListenerPolicy::from_delivery(DeliveryMode::Async).wire_byte(),
            1
        );
        assert_eq!(
            serde_json::from_str::<ListenerPolicy>("\"response_only\"").unwrap(),
            ListenerPolicy::ResponseOnly
        );
        assert_eq!(
            serde_json::from_str::<ListenerPolicy>("\"notify\"").unwrap(),
            ListenerPolicy::Notify
        );
        assert!(serde_json::from_str::<ListenerPolicy>("\"unknown\"").is_err());
    }

    #[test]
    fn c_lost_reply_reads_back_exact_original_listener_policy() {
        for (requested, admitted, expected_success, drop_first_reply) in [
            (
                ListenerPolicy::ResponseOnly,
                ListenerPolicy::ResponseOnly,
                true,
                false,
            ),
            (ListenerPolicy::Notify, ListenerPolicy::Notify, true, false),
            (ListenerPolicy::Notify, ListenerPolicy::Notify, true, true),
            (
                ListenerPolicy::Notify,
                ListenerPolicy::ResponseOnly,
                false,
                true,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let socket = directory.path().join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            let request_id = "11111111-1111-4111-8111-111111111111";
            let request = uuid_bytes(request_id).unwrap();
            let child = sample_child(request_id, admitted);
            let reply = format!(
                "fresh-bash-child {}\n",
                serde_json::to_string(&child).unwrap()
            );
            let server = std::thread::spawn(move || {
                for index in 0..if drop_first_reply { 3 } else { 2 } {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream.write_all(&[1; 16]).unwrap();
                    let mut frame = vec![0; if index == 0 { 34 } else { 33 }];
                    stream.read_exact(&mut frame).unwrap();
                    assert_eq!(&frame[1..17], &[1; 16]);
                    assert_eq!(&frame[17..33], &request);
                    if index == 0 {
                        assert_eq!(frame[0], b'C');
                        assert_eq!(frame[33], requested.wire_byte());
                        stream
                            .write_all(if drop_first_reply {
                                b"f"
                            } else {
                                reply.as_bytes()
                            })
                            .unwrap();
                    } else {
                        assert_eq!(frame[0], b'c');
                        stream.write_all(reply.as_bytes()).unwrap();
                    }
                }
            });
            let result = register_child(
                &socket,
                request_id,
                &request,
                requested,
                true,
                drop_first_reply,
                None,
            );
            assert_eq!(result.is_ok(), expected_success, "{result:?}");
            server.join().unwrap();
        }
    }
}
