//! Synchronous `run` through a new-lineage root's own Bash ingress (root v1).
//!
//! When `OULIPOLY_ROOT_BASH_V1` is present, this process is inside a harness
//! of a root that owns its Bash work. `run` then sends the command to that
//! root's ingress and nowhere else: no Broker, guardian, supervisor, probe,
//! state directory or local execution is used, and nothing is retried.
//!
//! Only synchronous delivery exists on this path. Asynchronous delivery
//! (the CLI default) and the legacy lease/scope/sentinel options are refused
//! before anything is sent; they are never converted.
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

/// The root path applies when its environment names an ingress, even an
/// empty or unusable one: a marked context never falls back.
pub(crate) fn selected() -> Option<std::ffi::OsString> {
    std::env::var_os(ROOT_BASH_ENV)
}

/// What the caller asked `run` for, as far as the root path cares.
pub(crate) struct Request<'a> {
    pub(crate) sync: bool,
    /// Legacy options this path cannot honour, by flag name.
    pub(crate) unsupported: Vec<&'static str>,
    pub(crate) argv: &'a [String],
}

/// Runs one request and returns the result object.
pub(crate) fn run(ingress: &std::ffi::OsStr, request: &Request<'_>) -> Value {
    if !request.sync {
        return refused(
            "agent-bash",
            "async-delivery-unavailable-under-root-v1",
            "root v1 serves synchronous commands only",
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
    let line = json!({ "v": PROTOCOL, "op": "run", "argv": request.argv, "cwd": cwd });
    // The owner may refuse and close before reading; its refusal is still
    // there to read, so a failed write is not the answer.
    let sent = writeln!(stream, "{line}")
        .and_then(|()| stream.flush())
        .is_ok();
    decode(BufReader::new(stream), sent)
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
    let mut accepted = false;
    let mut started = false;
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
            stages.push(json!({ "event": "output", "chunk": stages.len() }));
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
                Some(chunk) => output.extend_from_slice(&chunk),
            }
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
            "started" if accepted && !started => started = true,
            "output-closed" if started && !closed => {
                closed = true;
                if event["bytes"].as_u64() != Some(output.len() as u64) {
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
    let bytes = output.len();
    let base64 = base64(&output);
    let unknown = |meaning: &str, faults: Vec<String>, delivery: &str| {
        json!({
            "result_surface": RESULT_SURFACE,
            "version": 1,
            "delivery_mode": "sync",
            "outcome": "unknown",
            "meaning": meaning,
            "effects_possible": true,
            "retry_safe": false,
            "refusal": null,
            "wait": null,
            "output": { "delivery": delivery, "bytes": bytes, "base64": base64 },
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
            if end["output"]["state"] != "closed"
                || end["output"]["bytes"].as_u64() != Some(bytes as u64)
            {
                faults.push("end-output-state-not-closed-with-count".to_owned());
            }
            let complete = !output_fault && faults.is_empty();
            json!({
                "result_surface": RESULT_SURFACE,
                "version": 1,
                "delivery_mode": "sync",
                "outcome": if complete { "ended" } else { "ended-output-unproven" },
                "effects_possible": true,
                "retry_safe": false,
                "refusal": null,
                "wait": { "status": status, "observer": observer, "exit": wait },
                "output": {
                    "delivery": if complete { "complete" } else { "unproven" },
                    "bytes": bytes,
                    "base64": base64,
                },
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
        json!({ "event": "accepted", "work": 7, "durable": true })
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
    fn async_and_legacy_options_are_refused_before_anything_is_sent() {
        let argv = vec!["true".to_owned()];
        // A path that would fail to connect proves no connection is attempted
        // only together with the process test; here the reason is checked.
        let ingress = std::ffi::OsStr::new("/nonexistent/agent-bash-root-v1.sock");
        let result = run(
            ingress,
            &Request {
                sync: false,
                unsupported: vec![],
                argv: &argv,
            },
        );
        assert_eq!(result["outcome"], "refused");
        assert_eq!(
            result["refusal"]["reason"],
            "async-delivery-unavailable-under-root-v1"
        );
        let result = run(
            ingress,
            &Request {
                sync: true,
                unsupported: vec!["--cancel-on-owner-exit"],
                argv: &argv,
            },
        );
        assert_eq!(
            result["refusal"]["reason"],
            "option-unavailable-under-root-v1"
        );
        let result = run(
            ingress,
            &Request {
                sync: true,
                unsupported: vec![],
                argv: &argv,
            },
        );
        assert_eq!(result["refusal"]["reason"], "owner-unreachable");
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
