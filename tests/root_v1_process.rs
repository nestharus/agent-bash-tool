//! `run` inside a root-v1 context, against a configured owner socket that
//! stands in for the root's Bash ingress. These show what agent-bash sends,
//! how it reports the stage lines it gets back, and that it contacts nothing
//! else. They are not a witness of an actual root owner or root PID 1.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const ROOT_ENV: &str = "OULIPOLY_ROOT_BASH_V1";

/// A configured owner: counts connections, keeps each request line and
/// answers the first with `reply`, then closes.
struct Owner {
    connections: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<Value>>>,
}

impl Owner {
    fn start(socket: &Path, reply: Vec<Value>) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let connections = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (count, seen) = (Arc::clone(&connections), Arc::clone(&requests));
        thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(20);
            while Instant::now() < deadline {
                let Ok((stream, _)) = listener.accept() else {
                    thread::sleep(Duration::from_millis(5));
                    continue;
                };
                stream.set_nonblocking(false).unwrap();
                count.fetch_add(1, Ordering::SeqCst);
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                seen.lock()
                    .unwrap()
                    .push(serde_json::from_str(&line).unwrap_or(Value::Null));
                let mut stream = &stream;
                for event in &reply {
                    writeln!(stream, "{event}").unwrap();
                }
            }
        });
        Self {
            connections,
            requests,
        }
    }

    /// Connections seen, after giving any (wrong) late retry time to arrive.
    fn connections(&self) -> usize {
        thread::sleep(Duration::from_millis(200));
        self.connections.load(Ordering::SeqCst)
    }
}

fn agent_bash(dir: &Path, socket: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_agent-bash"))
        .args(args)
        .current_dir(dir)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", dir.join("home"))
        .env(ROOT_ENV, socket)
        .output()
        .unwrap()
}

fn result(output: &Output) -> Value {
    assert_eq!(
        output.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

fn stages() -> Vec<Value> {
    vec![
        json!({ "event": "accepted", "work": 4, "durable": true, "harness": "a" }),
        json!({ "event": "started", "work": 4, "pid": 2 }),
        json!({ "event": "output", "b64": "aGkKZXJyCg==" }),
        json!({ "event": "output-closed", "bytes": 7 }),
        json!({ "event": "end", "status": "code:3", "observer": "work-pid1-wait",
                "output": { "state": "closed", "bytes": 7 } }),
    ]
}

#[test]
fn sync_run_sends_one_request_and_reports_the_waited_end_and_output() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("bash.sock");
    let owner = Owner::start(&socket, stages());
    let output = agent_bash(
        dir.path(),
        &socket,
        &["run", "--delivery", "sync", "--", "sh", "-c", "exit 3"],
    );
    let value = result(&output);
    assert_eq!(value["result_surface"], "agent-bash-root-v1");
    assert_eq!(value["outcome"], "ended", "{value}");
    assert_eq!(value["wait"]["exit"]["code"], 3);
    assert_eq!(value["output"]["delivery"], "complete");
    assert_eq!(value["output"]["base64"], "aGkKZXJyCg==");
    assert_eq!(value["effects_possible"], true);
    assert_eq!(value["retry_safe"], false);
    assert_eq!(owner.connections(), 1);
    let request = owner.requests.lock().unwrap()[0].clone();
    assert_eq!(
        request,
        json!({ "v": 1, "op": "run", "argv": ["sh", "-c", "exit 3"],
                "cwd": dir.path().canonicalize().unwrap() })
    );
    assert!(
        !dir.path().join("home").exists(),
        "no legacy state is created"
    );
}

#[test]
fn a_lost_reply_after_acceptance_is_unknown_and_not_retried() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("bash.sock");
    let owner = Owner::start(&socket, stages()[..2].to_vec());
    let value = result(&agent_bash(
        dir.path(),
        &socket,
        &["run", "--delivery", "sync", "--", "true"],
    ));
    assert_eq!(value["outcome"], "unknown", "{value}");
    assert_eq!(value["meaning"], "accepted-end-unknown");
    assert_eq!(value["effects_possible"], true);
    assert!(value["wait"].is_null());
    assert_eq!(owner.connections(), 1, "no retry");
}

#[test]
fn async_default_and_legacy_options_are_refused_without_contacting_the_owner() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("bash.sock");
    let owner = Owner::start(&socket, stages());
    for (args, reason) in [
        (
            &["run", "--delivery", "async", "--", "true"][..],
            "async-delivery-unavailable-under-root-v1",
        ),
        (
            &["run", "--", "true"][..],
            "async-delivery-unavailable-under-root-v1",
        ),
        (
            &[
                "run",
                "--delivery",
                "sync",
                "--completion-scope",
                "root",
                "--",
                "true",
            ][..],
            "option-unavailable-under-root-v1",
        ),
        (
            &[
                "run",
                "--delivery",
                "sync",
                "--cancel-on-owner-exit",
                "--owner-pid",
                "1",
                "--",
                "true",
            ][..],
            "option-unavailable-under-root-v1",
        ),
    ] {
        let value = result(&agent_bash(dir.path(), &socket, args));
        assert_eq!(value["outcome"], "refused", "{value}");
        assert_eq!(value["refusal"]["by"], "agent-bash");
        assert_eq!(value["refusal"]["reason"], reason);
        assert_eq!(value["effects_possible"], false);
    }
    assert_eq!(owner.connections(), 0);
}

#[test]
fn root_legacy_controls_refuse_before_config_state_reconciliation_or_socket_contact() {
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("agent-bash");
    fs::copy(env!("CARGO_BIN_EXE_agent-bash"), &binary).unwrap();
    fs::write(dir.path().join("agent-bash.toml"), "state_root = [").unwrap();
    let state = dir.path().join("state");
    fs::create_dir(&state).unwrap();
    let retained = state.join("retained-fixture");
    fs::write(&retained, "retained evidence must stay untouched").unwrap();
    let root_socket = dir.path().join("bash.sock");
    let root = UnixListener::bind(&root_socket).unwrap();
    root.set_nonblocking(true).unwrap();
    let broker_socket = dir.path().join("control.sock");
    let broker = UnixListener::bind(&broker_socket).unwrap();
    broker.set_nonblocking(true).unwrap();
    for args in [
        vec!["list", "--all", "--json"],
        vec!["cancel", "retained-fixture"],
        vec!["detach", "retained-fixture"],
        vec!["status", "retained-fixture"],
        vec!["snapshot", "retained-fixture"],
        vec!["mode", "retained-fixture"],
        vec!["accept-output", "retained-fixture", "--snapshot", "fixture"],
        vec![
            "completion-reconcile-v2",
            "--registration-file",
            "missing-registration",
            "--confirmation",
            "missing-confirmation",
            "--json",
        ],
    ] {
        // Empty presence also selects root, never an alternate legacy route.
        for ingress in [root_socket.as_os_str(), std::ffi::OsStr::new("")] {
            let output = Command::new(&binary)
                .args(&args)
                .current_dir(dir.path())
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &state)
                .env("XDG_STATE_HOME", &state)
                .env("OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1", &broker_socket)
                .env(ROOT_ENV, ingress)
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(69), "{args:?}: {output:?}");
            assert!(
                String::from_utf8_lossy(&output.stderr).contains("root v1 refuses legacy controls")
            );
            assert!(output.stdout.is_empty());
            assert_eq!(
                fs::read_to_string(&retained).unwrap(),
                "retained evidence must stay untouched"
            );
            assert_eq!(fs::read_dir(&state).unwrap().count(), 1);
            assert!(!dir.path().join("missing-confirmation").exists());
        }
    }
    assert_eq!(
        root.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(
        broker.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(root);
    drop(broker);
    let fixture = dir.path().to_owned();
    dir.close().unwrap();
    assert!(!fixture.exists());
    println!("owned fixture removed: {}", fixture.display());
}

/// With the root context present but its owner unreachable, nothing else is
/// tried: not the private Broker probe (made available here by a user
/// namespace and its fixture socket), not the legacy configuration or state.
#[test]
fn unreachable_root_owner_is_refused_with_no_broker_probe_or_legacy_state() {
    const STAGE: &str = "AGENT_BASH_ROOT_V1_PRIVATE_STAGE";
    if std::env::var_os(STAGE).is_none() {
        let output = Command::new("unshare")
            .args(["-Ur", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unreachable_root_owner_is_refused_with_no_broker_probe_or_legacy_state",
                "--nocapture",
            ])
            .env(STAGE, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed"),
            "stdout={stdout} stderr={}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let binary = dir.path().join("agent-bash");
    fs::copy(env!("CARGO_BIN_EXE_agent-bash"), &binary).unwrap();
    fs::write(dir.path().join("agent-bash.toml"), "state_root = [").unwrap();
    let broker = Owner::start(&dir.path().join("v30.sock"), Vec::new());
    let state = dir.path().join("state");
    fs::create_dir(&state).unwrap();
    let output = Command::new(&binary)
        .args(["run", "--delivery", "sync", "--", "true"])
        .current_dir(dir.path())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &state)
        .env("XDG_STATE_HOME", &state)
        .env(
            "OULIPOLY_KERNEL_BROKER_FIXTURE_SOCKET_V1",
            dir.path().join("control.sock"),
        )
        .env(ROOT_ENV, dir.path().join("missing.sock"))
        .output()
        .unwrap();
    let value = result(&output);
    assert_eq!(value["outcome"], "refused", "{value}");
    assert_eq!(value["refusal"]["reason"], "owner-unreachable");
    assert_eq!(broker.connections(), 0, "no Broker probe");
    assert_eq!(fs::read_dir(&state).unwrap().count(), 0, "no legacy state");
}
