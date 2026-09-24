//! Private user-namespace exercise of the real Bash binary and v30 child
//! registration. The ordinary `run` entry may register its listener here,
//! but cannot launch work until a broker-owned command/handle route exists.
use crate::state::DeliveryMode;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::Command;

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
/// ambient owner marker or local handle never authorizes C. Returning this
/// receipt does not grant a command K, source W, or recipient F.
pub(crate) fn register_ordinary_run(
    mode: DeliveryMode,
) -> Result<Option<(String, String)>, String> {
    if !private_user_namespace() {
        return Ok(None);
    }
    let Ok(control) = std::env::var("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1") else {
        return Ok(None);
    };
    let socket = Path::new(&control).with_file_name("v30.sock");
    let request_id = random_uuid()?;
    let request = uuid_bytes(&request_id)?;
    let policy = ListenerPolicy::from_delivery(mode);
    let child =
        register_child(&socket, &request_id, &request, policy, true, false).map_err(|error| {
            format!("fresh C outcome refused or unknown; request_id={request_id}: {error}")
        })?;
    Ok(Some((request_id, child.handle)))
}

fn register_child(
    socket: &Path,
    request_id: &str,
    request: &[u8; 16],
    policy: ListenerPolicy,
    explicit_policy: bool,
    drop_first_reply: bool,
) -> Result<Child, String> {
    let mut registration = request.to_vec();
    if explicit_policy {
        registration.push(policy.wire_byte());
    }
    let admitted = if drop_first_reply {
        request_frame(socket, b'C', &registration, false)?;
        request_frame(socket, b'c', request, true)?
    } else {
        match request_frame(socket, b'C', &registration, true) {
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

pub(crate) fn internal_main() -> Option<i32> {
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
        Ok(()) => 0,
        Err(error) => {
            eprintln!("AGE319_PRIVATE_BASH_CHILD={error}");
            70
        }
    })
}

fn request_frame(socket: &Path, opcode: u8, payload: &[u8], read: bool) -> Result<String, String> {
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
    stream.write_all(&frame).map_err(|e| e.to_string())?;
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
            );
            assert_eq!(result.is_ok(), expected_success, "{result:?}");
            server.join().unwrap();
        }
    }
}
