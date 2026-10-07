//! Synchronous `run` through a new-lineage root's own Bash ingress (root v1).
//!
//! When `OULIPOLY_ROOT_BASH_V1` is present, this process is inside a harness
//! of a root that owns its Bash work. `run` then sends the command to that
//! root's ingress and nowhere else: no Broker, guardian, supervisor, probe,
//! state directory or local execution is used, and nothing is retried.
//!
//! Delivery must be explicit on this path. `--delivery sync` reads the run
//! to its end. `--delivery async` returns once the owner has durably
//! accepted and created the work child (`outcome` `running` unless exec failed); the root owner later
//! delivers its end to the requesting harness as an ACP v2 input naming
//! the run's retained output. That later input is not this process's
//! result and is not a local acceptance. An omitted `--delivery` (the CLI's
//! legacy async default) and the legacy lease/scope/sentinel options are
//! refused before anything is sent; they are never converted.
//!
//! The result is one JSON object on stdout (`result_surface`
//! `agent-bash-root-v1`). It reports what the root's stage lines showed and
//! no more: the command's wait status is only in `wait`, never in this
//! process's exit status. Exit 0 means the object was written, whatever the
//! outcome; any other exit means the result is unresolved.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;

use serde_json::{Value, json};

/// Environment variable naming the root's Bash ingress socket.
pub(crate) const ROOT_BASH_ENV: &str = "OULIPOLY_ROOT_BASH_V1";
const PROTOCOL: u64 = 1;
pub(crate) const RESULT_SURFACE: &str = "agent-bash-root-v1";
// Keep a useful orientation prefix, not an unbounded model-facing body.
const OUTPUT_PREFIX_BYTES: usize = 64 * 1024;

/// The root path applies when its environment names an ingress, even an
/// empty or unusable one: a marked context never falls back.
pub(crate) fn selected() -> Option<std::ffi::OsString> {
    std::env::var_os(ROOT_BASH_ENV)
}

/// The completion delivery a root v1 run asked for. Only an explicit
/// choice is honoured: the CLI's legacy async default never silently
/// backgrounds a root v1 command.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Delivery {
    Sync,
    /// The owner answers once the run has started; its end later reaches
    /// the requesting harness as an owner input (ACP v2), not this process.
    Async,
    Unspecified,
}

/// What the caller asked `run` for, as far as the root path cares.
pub(crate) struct Request<'a> {
    pub(crate) delivery: Delivery,
    /// Legacy options this path cannot honour, by flag name.
    pub(crate) unsupported: Vec<&'static str>,
    pub(crate) argv: &'a [String],
}

/// Runs one request and returns the result object.
pub(crate) fn run(ingress: &std::ffi::OsStr, request: &Request<'_>) -> Value {
    if request.delivery == Delivery::Unspecified {
        return refused(
            "agent-bash",
            "delivery-required-under-root-v1",
            "root v1 needs an explicit --delivery sync or --delivery async",
        );
    }
    if let Some(flag) = request.unsupported.first() {
        return refused(
            "agent-bash",
            "option-unavailable-under-root-v1",
            &format!("{flag} has no root v1 equivalent"),
        );
    }
    if ingress.is_empty() {
        return refused(
            "agent-bash",
            "no-ingress",
            &format!("{ROOT_BASH_ENV} is empty"),
        );
    }
    let cwd = match std::env::current_dir() {
        Ok(cwd) => match cwd.to_str() {
            Some(cwd) => cwd.to_owned(),
            None => return refused("agent-bash", "no-cwd", "current directory is not UTF-8"),
        },
        Err(error) => return refused("agent-bash", "no-cwd", &error.to_string()),
    };
    let mut stream = match UnixStream::connect(ingress) {
        Ok(stream) => stream,
        Err(error) => return refused("agent-bash", "owner-unreachable", &error.to_string()),
    };
    let background = request.delivery == Delivery::Async;
    let mut line = json!({ "v": PROTOCOL, "op": "run", "argv": request.argv, "cwd": cwd });
    if background {
        line["delivery"] = json!("async");
    }
    // The owner may refuse and close before reading; its refusal is still
    // there to read, so a failed write is not the answer.
    let sent = writeln!(stream, "{line}")
        .and_then(|()| stream.flush())
        .is_ok();
    if background {
        decode_async(BufReader::new(stream), sent)
    } else {
        decode(BufReader::new(stream), sent)
    }
}

/// Reads a background run's stage lines: `accepted` (durable), `started`,
/// then `detached`. Its result is `running`: the command's end, wait and
/// output are not known here; they are owed to the requesting harness as
/// a later owner input naming `reference`. Anything else is a refusal,
/// a proven no-start, or unknown with possible effects.
pub(crate) fn decode_async(reader: impl BufRead, sent: bool) -> Value {
    let mut stages: Vec<Value> = Vec::new();
    let mut faults: Vec<String> = Vec::new();
    let mut detached = false;
    let mut exec_error: Option<String> = None;
    let mut terminal: Option<Value> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                faults.push(format!("read-failed: {error}"));
                break;
            }
        };
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            faults.push("protocol-violation: unparseable stage line".to_owned());
            break;
        };
        let name = event["event"].as_str().unwrap_or_default().to_owned();
        stages.push(event.clone());
        match (name.as_str(), stages.len()) {
            ("refused", 1) => {
                let mut result = refused("root-owner", "", "");
                result["delivery_mode"] = json!("async");
                result["refusal"]["reason"] = event["reason"].clone();
                result["refusal"]["detail"] = Value::Null;
                result["stages"] = json!(stages);
                return result;
            }
            ("accepted", 1) if event["delivery"] == "async" => {}
            ("started", 2) => match started_exec_error(&event, &stages[0]) {
                Ok(error) => exec_error = error,
                Err(fault) => {
                    faults.push(fault.into());
                    break;
                }
            },
            ("detached", 3)
                if event["work"] == stages[0]["work"]
                    && (exec_error.is_none()
                        || event["completion"] == "owed-to-requesting-harness") =>
            {
                detached = true;
                break;
            }
            ("launch-failed" | "launch-unknown", 2) => {
                terminal = Some(event);
                break;
            }
            _ => {
                faults.push(format!("unexpected-stage: {name}"));
                break;
            }
        }
    }
    let reference = stages.first().and_then(|accepted| {
        let root = accepted["root_id"].as_str()?;
        let work = accepted["work"].as_i64()?;
        let reference = format!("rv1w:{root}:{work}");
        parse_reference(&reference).map(|_| reference)
    });
    let base = |outcome: &str, meaning: &str, effects: bool| {
        json!({
            "result_surface": RESULT_SURFACE,
            "version": 1,
            "delivery_mode": "async",
            "outcome": outcome,
            "meaning": meaning,
            "effects_possible": effects,
            "retry_safe": !effects,
            "refusal": null,
            "wait": null,
            "output": { "delivery": "none", "bytes": 0, "base64": "", "reference": reference },
            "faults": faults,
            "stages": stages,
            "request_sent": sent,
            "exec_error": exec_error,
        })
    };
    if detached && faults.is_empty() {
        let mut result = base(
            if exec_error.is_some() {
                "unknown"
            } else {
                "running"
            },
            if exec_error.is_some() {
                "requested-program-exec-failed; work end, wait and output owed to the requesting harness as a later input"
            } else {
                "accepted-and-started; end, wait and output owed to the requesting harness as a later input"
            },
            true,
        );
        result["completion"] = json!({
            "delivery": "owed-to-requesting-harness",
            "work": stages[0]["work"],
            "root_id": stages[0]["root_id"],
        });
        return result;
    }
    match terminal {
        Some(end) if end["event"] == "launch-failed" && end["not_started"] == true => {
            base("not-started", "launch-refused-before-start", false)
        }
        Some(_) => base("unknown", "possible-effect-unknown", true),
        None if stages.first().is_some_and(|s| s["event"] == "accepted") => {
            let mut faults = faults.clone();
            if !detached {
                faults.push("no-detached-stage".to_owned());
            }
            let mut result = base("unknown", "accepted-completion-delivery-unknown", true);
            result["faults"] = json!(faults);
            result
        }
        None => {
            let mut result = base("unknown", "possible-effect-unknown", true);
            if faults.is_empty() {
                result["faults"] = json!(["no-final-stage"]);
            }
            result
        }
    }
}

/// Missing/null is not a positive failure. Other malformed values establish
/// neither successful exec nor failed exec and must keep the result uncertain.
fn started_exec_error(event: &Value, accepted: &Value) -> Result<Option<String>, &'static str> {
    match event.get("exec_error") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(error)) if !error.is_empty() => {
            if accepted["durable"] != true
                || !accepted["root_id"].as_str().is_some_and(|s| !s.is_empty())
                || !accepted["work"].as_i64().is_some_and(|w| w > 0)
            {
                return Err("exec-error-without-usable-acceptance");
            }
            Ok(Some(error.clone()))
        }
        _ => Err("started-exec-error-invalid"),
    }
}

fn refused(by: &str, reason: &str, detail: &str) -> Value {
    json!({
        "result_surface": RESULT_SURFACE,
        "version": 1,
        "delivery_mode": "sync",
        "outcome": "refused",
        "effects_possible": false,
        "retry_safe": true,
        "refusal": { "by": by, "reason": reason, "detail": detail },
        "wait": null,
        "output": { "delivery": "none", "bytes": 0, "base64": "" },
        "faults": [],
        "stages": [],
    })
}

/// Reads the root's stage lines and says what they establish. Order is
/// checked here rather than trusted: a stage out of order makes the outcome
/// unknown, and output is complete only when its count, closure and the
/// end's own output state all agree.
pub(crate) fn decode(reader: impl BufRead, sent: bool) -> Value {
    let mut stages: Vec<Value> = Vec::new();
    let mut faults: Vec<String> = Vec::new();
    let mut output = Vec::new();
    let mut bytes = 0u64;
    let mut output_stage: Option<usize> = None;
    let mut chunks = 0u64;
    let mut stream_hash = sha2::Sha256::new();
    use sha2::Digest;
    let mut accepted = false;
    let mut started = false;
    let mut exec_error: Option<String> = None;
    let mut closed = false;
    let mut output_fault = false;
    let mut order_fault = false;
    let mut terminal: Option<Value> = None;
    for line in reader.lines() {
        let line = match line {
            Ok(line) => line,
            Err(error) => {
                faults.push(format!("read-failed: {error}"));
                break;
            }
        };
        let Ok(event) = serde_json::from_str::<Value>(&line) else {
            faults.push("protocol-violation: unparseable stage line".to_owned());
            order_fault = true;
            break;
        };
        let name = event["event"].as_str().unwrap_or_default().to_owned();
        if name == "output" {
            // Output chunks are counted, not retained as an ever-growing
            // stage list. Continue draining even after the prefix is full.
            chunks += 1;
            let index = *output_stage.get_or_insert_with(|| {
                stages.push(json!({ "event": "output" }));
                stages.len() - 1
            });
            let chunk = event["b64"].as_str().and_then(unbase64);
            match chunk {
                _ if !started => {
                    faults.push("output-before-started".to_owned());
                    order_fault = true;
                }
                None => {
                    faults.push("output-invalid-or-missing-base64".to_owned());
                    output_fault = true;
                }
                Some(_) if closed => {
                    faults.push("output-after-closure".to_owned());
                    output_fault = true;
                }
                Some(chunk) => {
                    stream_hash.update(&chunk);
                    bytes += chunk.len() as u64;
                    let keep = chunk.len().min(OUTPUT_PREFIX_BYTES - output.len());
                    output.extend_from_slice(&chunk[..keep]);
                }
            }
            stages[index] = json!({ "event": "output", "chunks": chunks, "bytes": bytes });
            continue;
        }
        stages.push(event.clone());
        match name.as_str() {
            "refused" if stages.len() == 1 => {
                return json!({
                    "result_surface": RESULT_SURFACE,
                    "version": 1,
                    "delivery_mode": "sync",
                    "outcome": "refused",
                    "effects_possible": false,
                    "retry_safe": true,
                    "refusal": { "by": "root-owner", "reason": event["reason"], "detail": null },
                    "wait": null,
                    "output": { "delivery": "none", "bytes": 0, "base64": "" },
                    "faults": [],
                    "stages": stages,
                });
            }
            "accepted" if stages.len() == 1 => accepted = true,
            "started" if accepted && !started => {
                started = true;
                match started_exec_error(&event, &stages[0]) {
                    Ok(error) => exec_error = error,
                    Err(fault) => {
                        faults.push(fault.into());
                        order_fault = true;
                    }
                }
            }
            "output-closed" if started && !closed => {
                closed = true;
                if event["bytes"].as_u64() != Some(bytes) {
                    faults.push("output-byte-count-mismatch".to_owned());
                    output_fault = true;
                }
            }
            "output-failed" if started => {
                faults.push("owner-output-failed".to_owned());
                output_fault = true;
            }
            "end" if started => {
                terminal = Some(event);
                break;
            }
            "launch-failed" | "launch-unknown" if accepted && !started => {
                terminal = Some(event);
                break;
            }
            "end-unknown" | "left-to-successor" if accepted => {
                terminal = Some(event);
                break;
            }
            _ => {
                faults.push(format!("unexpected-stage: {name}"));
                order_fault = true;
                // A terminal-looking stage out of order still ends the reply.
                if matches!(
                    name.as_str(),
                    "refused"
                        | "end"
                        | "end-unknown"
                        | "launch-failed"
                        | "launch-unknown"
                        | "left-to-successor"
                ) {
                    break;
                }
            }
        }
    }
    // A valid UTF-8 prefix can end inside one character. In a truncated
    // result, omit that incomplete character as well; never replace bytes.
    if bytes > output.len() as u64
        && let Err(error) = std::str::from_utf8(&output)
        && error.error_len().is_none()
    {
        output.truncate(error.valid_up_to());
    }
    let mut retained = terminal
        .as_ref()
        .map(|end| end["retained"].clone())
        .unwrap_or(Value::Null);
    if !retained.is_null() && retained["state"] != "unsealed" {
        let valid = valid_record(&retained)
            && stages.first().is_some_and(|s| {
                s["work"] == retained["work"] && s["root_id"] == retained["root_id"]
            });
        let complete_matches = retained["state"] != "complete"
            || (retained["received"].as_u64() == Some(bytes)
                && retained["bytes"].as_u64() == Some(bytes)
                && retained["sha256"] == format!("{:x}", stream_hash.finalize()));
        if !valid || !complete_matches {
            faults.push("retained-identity-or-stream-mismatch".into());
            retained =
                json!({ "state": "unknown", "reason": "retained-identity-or-stream-mismatch" });
        }
    }
    let reference = stages.first().and_then(|accepted| {
        let root = accepted["root_id"].as_str()?;
        let work = accepted["work"].as_i64()?;
        let reference = format!("rv1w:{root}:{work}");
        parse_reference(&reference).map(|_| reference)
    });
    let presented_bytes = output.len();
    let omitted_bytes = bytes - presented_bytes as u64;
    let base64 = base64(&output);
    let presentation = |delivery: &str| {
        json!({
            "delivery": delivery,
            "bytes": bytes,
            "presented_bytes": presented_bytes,
            "omitted_bytes": omitted_bytes,
            "remainder": if omitted_bytes > 0 {
                if retained["state"] == "complete" { "retained-by-owner" } else if retained["state"] == "partial" { "partial-owner-retention" } else { "discarded" }
            } else { "none" },
            "retained": retained,
            "reference": reference,
            "base64": base64,
        })
    };
    let unknown = |meaning: &str, faults: Vec<String>, delivery: &str| {
        json!({
            "result_surface": RESULT_SURFACE,
            "version": 1,
            "delivery_mode": "sync",
            "outcome": "unknown",
            "meaning": meaning,
            "exec_error": exec_error,
            "effects_possible": true,
            "retry_safe": false,
            "refusal": null,
            "wait": null,
            "output": presentation(delivery),
            "faults": faults,
            "stages": stages,
            "request_sent": sent,
        })
    };
    let Some(end) = terminal.filter(|_| !order_fault) else {
        let mut faults = faults;
        if !order_fault {
            faults.push("no-final-stage".to_owned());
        }
        let meaning = if accepted {
            "accepted-end-unknown"
        } else {
            "possible-effect-unknown"
        };
        return unknown(meaning, faults, "unproven");
    };
    match end["event"].as_str().unwrap_or_default() {
        "end" => {
            let status = end["status"].as_str().unwrap_or_default();
            let wait = wait_status(status);
            let observer = end["observer"].as_str().unwrap_or_default();
            if wait.is_none() || observer != "work-pid1-wait" {
                let mut faults = faults;
                faults.push("end-without-usable-wait-status".to_owned());
                return unknown("ended-status-unknown", faults, "unproven");
            }
            let mut faults = faults;
            if !closed {
                faults.push("output-not-closed".to_owned());
            }
            if end["output"]["state"] != "closed" || end["output"]["bytes"].as_u64() != Some(bytes)
            {
                faults.push("end-output-state-not-closed-with-count".to_owned());
            }
            let complete = !output_fault && faults.is_empty();
            json!({
                "result_surface": RESULT_SURFACE,
                "version": 1,
                "delivery_mode": "sync",
                "outcome": if complete { "ended" } else { "ended-output-unproven" },
                "meaning": if exec_error.is_some() { "requested-program-exec-failed" } else { "work-ended" },
                "exec_error": exec_error,
                "effects_possible": true,
                "retry_safe": false,
                "refusal": null,
                "wait": { "status": status, "observer": observer, "exit": wait },
                "output": presentation(if !complete { "unproven" }
                    else if omitted_bytes > 0 { "partial" } else { "complete" }),
                "faults": faults,
                "stages": stages,
            })
        }
        "launch-failed" if end["not_started"] == true => json!({
            "result_surface": RESULT_SURFACE,
            "version": 1,
            "delivery_mode": "sync",
            "outcome": "not-started",
            "effects_possible": false,
            "retry_safe": true,
            "refusal": null,
            "wait": null,
            "output": { "delivery": "none", "bytes": 0, "base64": "" },
            "faults": faults,
            "stages": stages,
        }),
        other => {
            let meaning = match other {
                "launch-failed" | "launch-unknown" => "possible-effect-unknown",
                "left-to-successor" => "left-to-successor",
                _ => "accepted-end-unknown",
            };
            unknown(meaning, faults, "unproven")
        }
    }
}

/// Parse the opaque identity without turning it into a path or authority.
fn parse_identity(identity: &str) -> Option<(String, i64, u64, String)> {
    let parts: Vec<_> = identity.split(':').collect();
    if parts.len() != 5
        || parts[0] != "rv1o"
        || parts[1].is_empty()
        || parts[1].len() > 64
        || !parts[1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || parts[4].len() != 64
        || !parts[4]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let work = parts[2].parse::<i64>().ok()?;
    let bytes = parts[3].parse::<u64>().ok()?;
    if work <= 0 || bytes > 64 * 1024 * 1024 {
        return None;
    }
    let parsed = (parts[1].to_owned(), work, bytes, parts[4].to_owned());
    (format!("rv1o:{}:{}:{}:{}", parsed.0, parsed.1, parsed.2, parsed.3) == identity)
        .then_some(parsed)
}

fn parse_reference(reference: &str) -> Option<(String, i64)> {
    let parts: Vec<_> = reference.split(':').collect();
    if parts.len() != 3 || parts[0] != "rv1w" {
        return None;
    }
    let exact = format!("rv1o:{}:{}:0:{}", parts[1], parts[2], "0".repeat(64));
    let (root, work, _, _) = parse_identity(&exact)?;
    Some((root, work))
}

fn valid_record(record: &Value) -> bool {
    let Some((root, work, bytes, hash)) = record["identity"].as_str().and_then(parse_identity)
    else {
        return false;
    };
    record["root_id"] == root
        && record["work"] == work
        && record["bytes"] == bytes
        && record["sha256"] == hash
        && matches!(record["state"].as_str(), Some("complete" | "partial"))
        && record["losses"].is_array()
}

/// Explicit read or local acceptance through the same attributed ingress.
/// A missing reply to accept is unknown, never a fabricated receipt or retry.
pub(crate) fn retained(
    ingress: &std::ffi::OsStr,
    identity: &str,
    accept: bool,
    offset: u64,
    length: u64,
) -> Value {
    let surface = "agent-bash-root-v1-output";
    let refuse = |reason: &str| json!({ "result_surface": surface, "version": 1, "outcome": "refused", "reason": reason });
    let exact = parse_identity(identity);
    let target = exact
        .as_ref()
        .map(|(root, work, _, _)| (root.clone(), *work))
        .or_else(|| (!accept).then(|| parse_reference(identity)).flatten());
    let Some((root, work)) = target else {
        return refuse("bad-identity");
    };
    if !accept
        && (length == 0
            || length > 256 * 1024
            || offset > exact.as_ref().map_or(64 * 1024 * 1024, |i| i.2))
    {
        return refuse("bad-range");
    }
    let mut stream = match UnixStream::connect(ingress) {
        Ok(stream) => stream,
        Err(_) => return refuse("owner-unreachable"),
    };
    let mut request = json!({ "v": 1, "op": if accept { "accept" } else { "output" },
        "root_id": root, "work": work, "offset": offset, "length": length });
    if let Some((_, _, bytes, hash)) = &exact {
        request["bytes"] = json!(bytes);
        request["sha256"] = json!(hash);
    }
    let sent = writeln!(stream, "{request}")
        .and_then(|()| stream.flush())
        .is_ok();
    let mut line = Vec::new();
    let reader = BufReader::new(stream);
    use std::io::Read;
    let read = reader.take(400_000).read_until(b'\n', &mut line);
    let unknown = || {
        json!({ "result_surface": surface, "version": 1, "outcome": "unknown",
        "reason": "reply-missing-or-invalid", "request_sent": sent, "acceptance": "unconfirmed" })
    };
    if read.is_err() || !line.ends_with(b"\n") {
        return unknown();
    }
    let Ok(reply) = serde_json::from_slice::<Value>(&line) else {
        return unknown();
    };
    if reply["event"] == "refused" {
        return refuse(reply["reason"].as_str().unwrap_or("owner-refused"));
    }
    if !valid_record(&reply["retained"])
        || reply["retained"]["root_id"] != root
        || reply["retained"]["work"] != work
        || (exact.is_some() && reply["retained"]["identity"] != identity)
    {
        return unknown();
    }
    let bytes = reply["retained"]["bytes"]
        .as_u64()
        .expect("validated record");
    let hash = reply["retained"]["sha256"]
        .as_str()
        .expect("validated record");
    if accept {
        if reply["event"] != "output-accepted"
            || reply["durable"] != true
            || !reply["repeat"].is_boolean()
            || reply["receipt"]["root_id"] != root
            || reply["receipt"]["work"] != work
            || reply["receipt"]["bytes"] != bytes
            || reply["receipt"]["sha256"] != hash
        {
            return unknown();
        }
    } else {
        let Some(data) = reply["b64"].as_str().and_then(unbase64) else {
            return unknown();
        };
        if offset > bytes {
            return unknown();
        }
        let take = length.min(bytes - offset);
        if reply["event"] != "output-range"
            || reply["offset"] != offset
            || reply["length"] != take
            || data.len() as u64 != take
            || reply["next_offset"] != offset + take
            || reply["eof"] != (offset + take == bytes)
        {
            return unknown();
        }
    }
    json!({ "result_surface": surface, "version": 1,
        "outcome": if accept { "accepted" } else { "read" }, "reply": reply })
}

/// `code:N` or `signal:N` as written by the root's work PID 1 wait.
fn wait_status(status: &str) -> Option<Value> {
    if let Some(code) = status.strip_prefix("code:") {
        return code.parse::<i32>().ok().map(|code| json!({ "code": code }));
    }
    let signal = status.strip_prefix("signal:")?.parse::<i32>().ok()?;
    Some(json!({ "signal": signal }))
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded base64.
pub(crate) fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let triple = chunk.iter().enumerate().fold(0u32, |acc, (i, &byte)| {
            acc | u32::from(byte) << (16 - 8 * i)
        });
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[(triple >> (18 - 6 * i)) as usize & 63]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Canonical standard base64 only: anything that does not re-encode to
/// itself is rejected.
fn unbase64(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for quad in text.as_bytes().chunks(4) {
        let pad = quad.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 {
            return None;
        }
        let mut triple = 0u32;
        for (i, &c) in quad.iter().enumerate() {
            let value = if i >= 4 - pad {
                0
            } else {
                ALPHABET.iter().position(|&a| a == c)? as u32
            };
            triple |= value << (18 - 6 * i);
        }
        out.extend_from_slice(&triple.to_be_bytes()[1..4 - pad]);
    }
    (base64(&out) == text).then_some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn transcript(events: &[Value]) -> Cursor<Vec<u8>> {
        Cursor::new(
            events
                .iter()
                .map(|event| format!("{event}\n"))
                .collect::<String>()
                .into_bytes(),
        )
    }

    fn accepted() -> Value {
        json!({ "event": "accepted", "root_id": "fixture", "work": 7, "durable": true })
    }
    fn started() -> Value {
        json!({ "event": "started", "work": 7 })
    }
    fn output() -> Value {
        json!({ "event": "output", "b64": "aGkK" })
    }
    fn closed(bytes: u64) -> Value {
        json!({ "event": "output-closed", "bytes": bytes })
    }
    fn end(status: &str, bytes: u64) -> Value {
        json!({ "event": "end", "status": status, "observer": "work-pid1-wait",
                "output": { "state": "closed", "bytes": bytes } })
    }

    #[test]
    fn a_waited_end_with_counted_closed_output_is_ended_and_keeps_the_command_status() {
        let result = decode(
            transcript(&[accepted(), started(), output(), closed(3), end("code:3", 3)]),
            true,
        );
        assert_eq!(result["outcome"], "ended", "{result}");
        assert_eq!(result["wait"]["exit"]["code"], 3);
        assert_eq!(result["output"]["delivery"], "complete");
        assert_eq!(result["output"]["base64"], "aGkK");
        assert_eq!(result["effects_possible"], true);
        assert_eq!(result["retry_safe"], false);
        let signal = decode(
            transcript(&[accepted(), started(), closed(0), end("signal:9", 0)]),
            true,
        );
        assert_eq!(signal["outcome"], "ended");
        assert_eq!(signal["wait"]["exit"]["signal"], 9);
    }

    #[test]
    fn output_faults_keep_the_wait_but_never_read_as_complete() {
        for events in [
            vec![accepted(), started(), output(), end("code:0", 3)],
            vec![accepted(), started(), output(), closed(2), end("code:0", 3)],
            vec![
                accepted(),
                started(),
                json!({ "event": "output", "b64": "aG==aGkK" }),
                closed(0),
                end("code:0", 0),
            ],
            vec![
                accepted(),
                started(),
                output(),
                closed(3),
                output(),
                end("code:0", 3),
            ],
            vec![
                accepted(),
                started(),
                json!({ "event": "output-failed", "reason": "x" }),
                json!({ "event": "end", "status": "code:0", "observer": "work-pid1-wait", "output": { "state": "failed" } }),
            ],
            vec![
                accepted(),
                started(),
                output(),
                closed(3),
                json!({ "event": "end", "status": "code:0", "observer": "work-pid1-wait" }),
            ],
        ] {
            let result = decode(transcript(&events), true);
            assert_eq!(result["outcome"], "ended-output-unproven", "{result}");
            assert_eq!(result["output"]["delivery"], "unproven");
            assert_eq!(result["wait"]["status"], "code:0");
            assert!(!result["faults"].as_array().unwrap().is_empty());
        }
    }

    #[test]
    fn stages_out_of_order_are_not_trusted() {
        for events in [
            vec![closed(0), end("code:0", 0)],
            vec![accepted(), closed(0), end("code:0", 0)],
            vec![
                accepted(),
                accepted(),
                started(),
                closed(0),
                end("code:0", 0),
            ],
            vec![
                accepted(),
                started(),
                closed(0),
                json!({ "event": "refused", "reason": "late" }),
            ],
            vec![
                accepted(),
                started(),
                closed(0),
                json!({ "event": "end", "status": "code:0", "observer": "receipt-guess",
                         "output": { "state": "closed", "bytes": 0 } }),
            ],
        ] {
            let result = decode(transcript(&events), true);
            assert_eq!(result["outcome"], "unknown", "{result}");
            assert_eq!(result["effects_possible"], true);
            assert_eq!(result["retry_safe"], false);
            assert!(result["wait"].is_null());
        }
    }

    #[test]
    fn missing_or_uncertain_ends_are_possible_effects_and_only_positive_no_start_is_not_run() {
        for sent in [false, true] {
            let result = decode(Cursor::new(b""), sent);
            assert_eq!(result["outcome"], "unknown");
            assert_eq!(result["meaning"], "possible-effect-unknown");
            assert_eq!(result["request_sent"], sent);
        }
        let lost = decode(transcript(&[accepted()]), true);
        assert_eq!(lost["meaning"], "accepted-end-unknown");
        for terminal in [
            json!({ "event": "launch-unknown", "reason": "x" }),
            json!({ "event": "launch-failed", "not_started": false }),
            json!({ "event": "launch-failed" }),
        ] {
            let result = decode(transcript(&[accepted(), terminal]), true);
            assert_eq!(result["outcome"], "unknown", "{result}");
            assert_eq!(result["meaning"], "possible-effect-unknown");
        }
        let gone = decode(
            transcript(&[
                accepted(),
                started(),
                json!({ "event": "left-to-successor" }),
            ]),
            true,
        );
        assert_eq!(gone["meaning"], "left-to-successor");
        let not_run = decode(
            transcript(&[
                accepted(),
                json!({ "event": "launch-failed", "not_started": true }),
            ]),
            true,
        );
        assert_eq!(not_run["outcome"], "not-started");
        assert_eq!(not_run["effects_possible"], false);
        let refused = decode(
            transcript(&[json!({ "event": "refused", "reason": "peer-unattributed: x" })]),
            true,
        );
        assert_eq!(refused["outcome"], "refused");
        assert_eq!(refused["refusal"]["by"], "root-owner");
        assert_eq!(refused["effects_possible"], false);
    }

    #[test]
    fn bounded_prefix_keeps_total_closure_wait_and_compacts_chunk_stages() {
        let chunk = vec![b'x'; 16 * 1024];
        let mut events = vec![accepted(), started()];
        for _ in 0..128 {
            events.push(json!({ "event": "output", "b64": base64(&chunk) }));
        }
        let total = 128 * chunk.len() as u64;
        events.extend([closed(total), end("code:2", total)]);
        let result = decode(transcript(&events), true);
        assert_eq!(result["outcome"], "ended");
        assert_eq!(result["wait"]["exit"]["code"], 2);
        assert_eq!(result["output"]["delivery"], "partial");
        assert_eq!(result["output"]["bytes"], total);
        assert_eq!(result["output"]["presented_bytes"], OUTPUT_PREFIX_BYTES);
        assert_eq!(
            result["output"]["omitted_bytes"],
            total - OUTPUT_PREFIX_BYTES as u64
        );
        assert_eq!(result["output"]["remainder"], "discarded");
        assert_eq!(
            unbase64(result["output"]["base64"].as_str().unwrap()).unwrap(),
            vec![b'x'; OUTPUT_PREFIX_BYTES]
        );
        assert_eq!(result["stages"].as_array().unwrap().len(), 5);
        assert_eq!(result["stages"][2]["chunks"], 128);
        // The discarded suffix is still validated: no early-stop green.
        events.insert(
            events.len() - 2,
            json!({ "event": "output", "b64": "!!!!" }),
        );
        let bad = decode(transcript(&events), true);
        assert_eq!(bad["outcome"], "ended-output-unproven");
        assert_eq!(bad["wait"]["exit"]["code"], 2);
        assert_eq!(bad["output"]["delivery"], "unproven");
        assert!(
            bad["faults"]
                .as_array()
                .unwrap()
                .contains(&json!("output-invalid-or-missing-base64"))
        );
        events.remove(events.len() - 3);
        let closure_index = events.len() - 2;
        events[closure_index] = closed(total - 1);
        let bad_count = decode(transcript(&events), true);
        assert_eq!(bad_count["outcome"], "ended-output-unproven");
        events.pop();
        let lost = decode(transcript(&events), true);
        assert_eq!(lost["outcome"], "unknown");
        assert!(lost["wait"].is_null());
        assert_eq!(lost["retry_safe"], false);
    }

    #[test]
    fn prefix_boundary_is_exact_and_does_not_split_valid_utf8_or_rewrite_binary() {
        for (payload, shown) in [
            (vec![b'x'; OUTPUT_PREFIX_BYTES], OUTPUT_PREFIX_BYTES),
            (vec![b'x'; OUTPUT_PREFIX_BYTES + 1], OUTPUT_PREFIX_BYTES),
            (
                "€".repeat(OUTPUT_PREFIX_BYTES / 3 + 1).into_bytes(),
                OUTPUT_PREFIX_BYTES - 1,
            ),
            (vec![0xff; OUTPUT_PREFIX_BYTES + 1], OUTPUT_PREFIX_BYTES),
        ] {
            let total = payload.len() as u64;
            let result = decode(
                transcript(&[
                    accepted(),
                    started(),
                    json!({ "event": "output", "b64": base64(&payload) }),
                    closed(total),
                    end("code:0", total),
                ]),
                true,
            );
            assert_eq!(result["outcome"], "ended");
            assert_eq!(result["output"]["presented_bytes"], shown);
            assert_eq!(result["output"]["bytes"], total);
            let prefix = unbase64(result["output"]["base64"].as_str().unwrap()).unwrap();
            assert_eq!(prefix, payload[..shown]);
        }
    }

    #[test]
    fn retained_identity_is_joined_to_work_and_actual_full_stream_without_replacing_wait() {
        use sha2::Digest;
        let payload = vec![b'x'; 100_000];
        let hash = format!("{:x}", sha2::Sha256::digest(&payload));
        let record = json!({ "state": "complete", "root_id": "fixture", "work": 7,
            "bytes": payload.len(), "sha256": hash, "received": payload.len(), "losses": [],
            "identity": format!("rv1o:fixture:7:100000:{hash}") });
        let mut final_stage = end("code:7", 100000);
        final_stage["retained"] = record.clone();
        let make = |end| {
            transcript(&[
                accepted(),
                started(),
                json!({ "event": "output", "b64": base64(&payload) }),
                closed(100000),
                end,
            ])
        };
        let full = decode(make(final_stage.clone()), true);
        assert_eq!(full["outcome"], "ended");
        assert_eq!(full["wait"]["status"], "code:7");
        assert_eq!(full["output"]["remainder"], "retained-by-owner");
        assert_eq!(full["output"]["retained"], record);
        final_stage["retained"]["sha256"] = json!("0".repeat(64));
        final_stage["retained"]["identity"] =
            json!(format!("rv1o:fixture:7:100000:{}", "0".repeat(64)));
        let mismatch = decode(make(final_stage), true);
        assert_eq!(mismatch["wait"]["status"], "code:7");
        assert_eq!(mismatch["outcome"], "ended-output-unproven");
        assert!(mismatch["output"]["retained"]["identity"].is_null());
        assert_eq!(mismatch["output"]["retained"]["state"], "unknown");
    }

    #[test]
    fn accepted_work_reference_survives_an_unknown_end_without_inventing_wait_or_seal() {
        let result = decode(
            transcript(&[
                json!({ "event": "accepted", "root_id": "fixture", "work": 7, "durable": true }),
                started(),
            ]),
            true,
        );
        assert_eq!(result["outcome"], "unknown");
        assert!(result["wait"].is_null());
        assert_eq!(result["output"]["reference"], "rv1w:fixture:7");
        assert!(result["output"]["retained"].is_null());
        assert_eq!(
            parse_reference("rv1w:fixture:7"),
            Some(("fixture".into(), 7))
        );
        assert!(parse_reference("rv1w:fixture:07").is_none());
    }

    #[test]
    fn async_and_legacy_options_are_refused_before_anything_is_sent() {
        let argv = vec!["true".to_owned()];
        // A path that would fail to connect proves no connection is attempted
        // only together with the process test; here the reason is checked.
        let ingress = std::ffi::OsStr::new("/nonexistent/agent-bash-root-v1.sock");
        let result = run(
            ingress,
            &Request {
                delivery: Delivery::Unspecified,
                unsupported: vec![],
                argv: &argv,
            },
        );
        assert_eq!(result["outcome"], "refused");
        assert_eq!(
            result["refusal"]["reason"],
            "delivery-required-under-root-v1"
        );
        let result = run(
            ingress,
            &Request {
                delivery: Delivery::Sync,
                unsupported: vec!["--cancel-on-owner-exit"],
                argv: &argv,
            },
        );
        assert_eq!(
            result["refusal"]["reason"],
            "option-unavailable-under-root-v1"
        );
        for delivery in [Delivery::Sync, Delivery::Async] {
            let result = run(
                ingress,
                &Request {
                    delivery,
                    unsupported: vec![],
                    argv: &argv,
                },
            );
            assert_eq!(result["refusal"]["reason"], "owner-unreachable");
        }
    }

    #[test]
    fn positive_exec_error_preserves_wait_custody_and_async_completion() {
        let mut failed = started();
        failed["exec_error"] = json!("No such file or directory (os error 2)");
        let sync = decode(
            transcript(&[accepted(), failed.clone(), closed(0), end("code:127", 0)]),
            true,
        );
        assert_eq!(sync["outcome"], "ended");
        assert_eq!(sync["meaning"], "requested-program-exec-failed");
        assert_eq!(sync["exec_error"], failed["exec_error"]);
        assert_eq!(sync["wait"]["exit"]["code"], 127);
        assert_eq!(sync["output"]["delivery"], "complete");
        assert_eq!(sync["effects_possible"], true);
        assert_eq!(sync["retry_safe"], false);
        let ordinary = decode(
            transcript(&[
                accepted(),
                started(),
                output(),
                closed(3),
                end("code:127", 3),
            ]),
            true,
        );
        assert_eq!(ordinary["outcome"], "ended");
        assert_eq!(ordinary["exec_error"], Value::Null);
        assert_eq!(ordinary["output"]["base64"], "aGkK");
        let mut accepted = accepted();
        accepted["delivery"] = json!("async");
        let detached =
            json!({"event":"detached", "work":7, "completion":"owed-to-requesting-harness"});
        let async_result = decode_async(
            transcript(&[accepted.clone(), failed.clone(), detached]),
            true,
        );
        assert_eq!(async_result["outcome"], "unknown");
        assert!(
            async_result["meaning"]
                .as_str()
                .unwrap()
                .starts_with("requested-program-exec-failed")
        );
        assert_eq!(async_result["exec_error"], failed["exec_error"]);
        assert_eq!(
            async_result["completion"]["delivery"],
            "owed-to-requesting-harness"
        );
        assert_eq!(async_result["wait"], Value::Null);
        assert_eq!(async_result["effects_possible"], true);
        assert_eq!(async_result["retry_safe"], false);
        let incomplete_detach = decode_async(
            transcript(&[
                accepted.clone(),
                failed.clone(),
                json!({"event":"detached", "work":7}),
            ]),
            true,
        );
        assert_eq!(incomplete_detach["outcome"], "unknown");
        assert_eq!(incomplete_detach["completion"], Value::Null);
        let missing_detach = decode_async(transcript(&[accepted, failed.clone()]), true);
        assert_eq!(missing_detach["outcome"], "unknown");
        assert_eq!(missing_detach["completion"], Value::Null);
        assert_eq!(missing_detach["exec_error"], failed["exec_error"]);
        let unfinished = decode(transcript(&[accepted_sync(), failed]), true);
        assert_eq!(unfinished["outcome"], "unknown");
        assert_eq!(unfinished["wait"], Value::Null);
        assert_eq!(unfinished["output"]["delivery"], "unproven");
    }

    #[test]
    fn malformed_exec_diagnostic_never_proves_running_or_no_start() {
        for error in [
            json!(true),
            json!(127),
            json!(""),
            json!({"error":"ENOENT"}),
        ] {
            let mut malformed = started();
            malformed["exec_error"] = error;
            let sync = decode(
                transcript(&[accepted(), malformed.clone(), closed(0), end("code:127", 0)]),
                true,
            );
            assert_eq!(sync["outcome"], "unknown");
            assert_eq!(sync["wait"], Value::Null);
            let mut accepted = accepted();
            accepted["delivery"] = json!("async");
            let result = decode_async(
                transcript(&[accepted, malformed, json!({"event":"detached", "work":7})]),
                true,
            );
            assert_eq!(result["outcome"], "unknown");
            assert_eq!(result["completion"], Value::Null);
            assert_eq!(result["retry_safe"], false);
        }
    }

    #[test]
    fn async_run_is_running_only_after_durable_accept_start_and_detach() {
        let accepted = json!({ "event": "accepted", "root_id": "fixture", "work": 7, "durable": true, "delivery": "async" });
        let detached =
            json!({ "event": "detached", "work": 7, "completion": "owed-to-requesting-harness" });
        let result = decode_async(
            transcript(&[accepted.clone(), started(), detached.clone()]),
            true,
        );
        assert_eq!(result["outcome"], "running");
        assert_eq!(result["delivery_mode"], "async");
        assert_eq!(result["wait"], Value::Null);
        assert_eq!(result["effects_possible"], true);
        assert_eq!(result["output"]["reference"], "rv1w:fixture:7");
        assert_eq!(result["completion"]["work"], 7);
        // No detach: accepted work whose completion delivery is unknown.
        let lost = decode_async(transcript(&[accepted.clone(), started()]), true);
        assert_eq!(lost["outcome"], "unknown");
        assert_eq!(lost["meaning"], "accepted-completion-delivery-unknown");
        // A sync-shaped acceptance is never read as a background run.
        let sync_shaped = decode_async(
            transcript(&[accepted_sync(), started(), detached.clone()]),
            true,
        );
        assert_eq!(sync_shaped["outcome"], "unknown");
        // Detach naming other work is not this run's detach.
        let other = json!({ "event": "detached", "work": 8 });
        assert_eq!(
            decode_async(transcript(&[accepted.clone(), started(), other]), true)["outcome"],
            "unknown"
        );
        let not_started = decode_async(
            transcript(&[
                accepted.clone(),
                json!({ "event": "launch-failed", "not_started": true }),
            ]),
            true,
        );
        assert_eq!(not_started["outcome"], "not-started");
        assert_eq!(not_started["effects_possible"], false);
        let refused = decode_async(
            transcript(&[
                json!({ "event": "refused", "reason": "async-unavailable: registered child" }),
            ]),
            true,
        );
        assert_eq!(refused["outcome"], "refused");
        assert_eq!(
            refused["refusal"]["reason"],
            "async-unavailable: registered child"
        );
        assert_eq!(refused["delivery_mode"], "async");
    }

    fn accepted_sync() -> Value {
        accepted()
    }

    #[test]
    fn base64_is_canonical_both_ways() {
        for bytes in [&b""[..], b"h", b"hi", b"hi\n", b"\x00\xff\x10\x80"] {
            assert_eq!(unbase64(&base64(bytes)).as_deref(), Some(bytes));
        }
        for bad in ["a", "aGk", "aG==aGkK", "aGl=", "!!!!", "a==="] {
            assert_eq!(unbase64(bad), None, "{bad}");
        }
    }
}
