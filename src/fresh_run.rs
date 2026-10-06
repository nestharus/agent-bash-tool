//! Ordinary v30 Bash source. The Broker selects the parent and the workload;
//! this process never allocates a local handle for a fresh source.
use crate::state::DeliveryMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;

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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Parent {
    root_id: String,
    root_invocation_uuid: String,
    root_session_id: String,
    parent_work_grant_id: String,
    parent_work_id: String,
}

pub(crate) fn private_probe_available() -> bool {
    (unsafe { libc::geteuid() }) == 0
        && std::fs::read_to_string("/proc/self/uid_map")
            .ok()
            .is_some_and(|map| map.split_ascii_whitespace().nth(2) == Some("1"))
        && std::env::var_os("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1").is_some()
}

fn broker_socket() -> Option<std::path::PathBuf> {
    if private_probe_available() {
        return std::env::var_os("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1")
            .map(|control| Path::new(&control).with_file_name("v30.sock"));
    }
    let installed = Path::new("/run/oulipoly-kernel-broker/v30.sock");
    installed.exists().then(|| installed.to_path_buf())
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ListenerPolicy {
    #[default]
    ResponseOnly,
    Notify,
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

pub(crate) fn register_ordinary_run(
    mode: DeliveryMode,
    argv: &[String],
    cwd: &Path,
    completion_scope: crate::supervisor::CompletionScope,
    ready_sentinel: Option<&str>,
    cancel_on_owner_exit: bool,
) -> Result<Option<FreshRunResult>, String> {
    let Some(socket) = broker_socket() else {
        return Ok(None);
    };
    // The fixture socket variable is only an address in a user namespace.
    // A challenged Broker probe must resolve this exact connected process
    // before Bash can select the fresh route or submit C.
    let probe = match request_frame(&socket, 0x90, &[]) {
        Ok(reply) => reply,
        Err(error) if error == "error Bash child is outside a released root" => {
            return Ok(None);
        }
        Err(error) => return Err(format!("fresh Bash parent probe refused: {error}")),
    };
    // Parse the challenged connected peer's causal parent before C can have
    // any effect. The Broker rechecks this parent on every later operation.
    let parent: Parent = serde_json::from_str(
        probe
            .strip_prefix("fresh-bash-parent ")
            .ok_or("fresh Bash parent probe changed")?
            .trim_end(),
    )
    .map_err(|error| format!("fresh Bash parent probe invalid: {error}"))?;
    uuid_bytes(&parent.root_id)?;
    uuid_bytes(&parent.root_invocation_uuid)?;
    uuid_bytes(&parent.parent_work_grant_id)?;
    if !parent.root_session_id.starts_with("v30:") || parent.parent_work_id.is_empty() {
        return Err("fresh Bash causal parent probe invalid".into());
    }
    let policy = ListenerPolicy::from_delivery(mode);
    if completion_scope != crate::supervisor::CompletionScope::Tree
        || ready_sentinel.is_some()
        || cancel_on_owner_exit
    {
        return Err("ordinary fresh root/ready/owner-cancel mode unavailable before K".into());
    }
    let request_id = random_uuid()?;
    let request = uuid_bytes(&request_id)?;
    // The pinned Bash image is the source at the original parsed CLI entry.
    // Legacy exec_workload removes both keys before execvp. This source
    // runs before legacy helper preparation, so scrub them explicitly.
    let original_cli_argv = std::env::args_os()
        .map(|arg| {
            arg.into_string()
                .map_err(|_| "non-UTF-8 original Bash CLI argv unavailable".to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let environment = workload_environment()?;
    let command = OrdinaryCommand {
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

    let child =
        register_child(&socket, &request_id, &request, policy, &command).map_err(|error| {
            format!("fresh C outcome refused or unknown; request_id={request_id}: {error}")
        })?;
    if parent.root_id != child.root_id
        || parent.root_invocation_uuid != child.parent_invocation_uuid
        || parent.parent_work_grant_id != child.parent_work_grant_id
        || parent.parent_work_id != child.parent_work_id
    {
        return Err("fresh Bash parent changed between probe and C".into());
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

    // The C-selected pathname remains the command to execute. Re-resolving
    // PATH here would turn a normal replacement/removal into a pre-K refusal
    // or silently select a different PATH entry.
    let digest = Sha256::digest(serde_json::to_vec(&at_k).map_err(|error| error.to_string())?);
    let mut k_request = request.to_vec();
    k_request.extend_from_slice(&digest);
    let command_file = sealed_command_file(&command)?;
    // A lost K reply can only be read through physical Q.
    let k_result = request_frame_with_command(&socket, b'^', &k_request, Some(&command_file));
    let physical = match k_result {
        Ok(reply) => reply,
        Err(k_error) => request_frame(&socket, b'9', &request)
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
    let base = serde_json::json!({
        "schema_version": 30,
        "request_id": request_id,
        "handle": child.handle,
        "delivery_mode": if mode == DeliveryMode::Sync { "sync" } else { "async" },
        "completion_policy": "tree",
        "physical_grant_id": grant_id,
        "effects_possible": true,
    });
    if mode == DeliveryMode::Async {
        let mut result = base;
        result["dispatch_state"] = "broker-k-consumed".into();
        return Ok(Some(FreshRunResult::Dispatch(result)));
    }

    let physical_q = loop {
        let state = request_frame(&socket, b'9', &request)
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
    let first_w = request_frame(&socket, b'%', &request);
    let accepted = first_w.or_else(|first_error| {
        request_frame(&socket, b'%', &request).map_err(|read_error| format!(
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
        || source["attempt_id"] != child.invocation_uuid
        || source["lane_id"] != child.session.lane_id
        || source["source_generation"] != child.session.source_generation
        || source["session_id"] != child.session.session_id
        || source["root_id"] != child.root_id
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
    let _ = (base, physical_q);
    let begun = request_sync_begin(&socket, &request);
    let (reply, files) = match begun {
        Ok(value) => value,
        Err(_) => {
            let readback = request_frame(&socket, b'u', &request).map_err(|error| {
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
        return Ok(Some(FreshRunResult::Dispatch(serde_json::json!({
            "schema_version": 31,
            "dispatch_state": "sync-publication-unknown",
            "publication": publication,
        }))));
    }
    let [mut stdout, mut stderr] =
        files.ok_or("sync begin descriptors absent; publication unknown")?;
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
    Ok(Some(FreshRunResult::Sync {
        publication,
        stdout,
        stderr,
    }))
}

pub(crate) enum FreshRunResult {
    Dispatch(serde_json::Value),
    Sync {
        publication: serde_json::Value,
        stdout: File,
        stderr: File,
    },
}

pub(crate) fn write_result(result: FreshRunResult) -> std::io::Result<()> {
    let mut caller = std::io::stdout().lock();
    match result {
        FreshRunResult::Dispatch(value) => serde_json::to_writer(&mut caller, &value)?,
        FreshRunResult::Sync {
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
    let mut non_executable = None;
    for candidate in candidates {
        let Ok(path) = std::ffi::CString::new(candidate.as_os_str().as_bytes()) else {
            return Err("ordinary Bash command path contains NUL unavailable before K".into());
        };
        if candidate.metadata().is_ok_and(|meta| meta.is_file()) {
            if unsafe { libc::access(path.as_ptr(), libc::X_OK) } == 0 {
                return Ok(candidate);
            }
            non_executable.get_or_insert(candidate);
        }
    }
    // A present ordinary command may be refused by the OS at exec. Keep its
    // selected path so that refusal produces physical Q after the one-use K.
    if let Some(candidate) = non_executable {
        return Ok(candidate);
    }
    Err("ordinary Bash command not executable in original PATH before K".into())
}

fn register_child(
    socket: &Path,
    request_id: &str,
    request: &[u8; 16],
    policy: ListenerPolicy,
    ordinary_command: &OrdinaryCommand,
) -> Result<Child, String> {
    let mut registration = request.to_vec();
    registration.push(policy.wire_byte());
    let command_file = sealed_command_file(ordinary_command)?;
    let admitted =
        match request_frame_with_command(socket, b'X', &registration, Some(&command_file)) {
            Ok(reply) => reply,
            Err(first_error) => {
                // A lost reply may follow a durable C. Read only the same
                // request; never submit C again or infer acceptance from EOF.
                request_frame(socket, b'c', request).map_err(|read_error| {
                    format!("C reply uncertain: {first_error}; c readback: {read_error}")
                })?
            }
        };
    let child: Child = serde_json::from_str(
        admitted
            .strip_prefix("fresh-bash-child ")
            .ok_or("Bash child registration refused")?
            .trim_end(),
    )
    .map_err(|e| e.to_string())?;
    let read = request_frame(socket, b'c', request)?;
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

fn request_frame(socket: &Path, opcode: u8, payload: &[u8]) -> Result<String, String> {
    request_frame_with_command(socket, opcode, payload, None)
}

fn request_sync_begin(
    socket: &Path,
    request: &[u8; 16],
) -> Result<(String, Option<[File; 2]>), String> {
    let mut stream = connect_broker(socket)?;
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
) -> Result<String, String> {
    let mut stream = connect_broker(socket)?;
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

fn connect_broker(socket: &Path) -> Result<UnixStream, String> {
    let stream = UnixStream::connect(socket).map_err(|error| error.to_string())?;
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
        || len as usize != std::mem::size_of::<libc::ucred>()
        || peer.uid != 0
    {
        return Err("fresh Bash Broker peer is not root".into());
    }
    Ok(stream)
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

pub(crate) fn uuid_bytes(value: &str) -> Result<[u8; 16], String> {
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
    for (index, part) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        bytes[index] =
            u8::from_str_radix(std::str::from_utf8(part).map_err(|e| e.to_string())?, 16)
                .map_err(|e| e.to_string())?;
    }
    if bytes == [0; 16] {
        return Err("nil UUID".into());
    }
    Ok(bytes)
}
