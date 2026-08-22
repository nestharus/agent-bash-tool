use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Output, Stdio};
use std::sync::{OnceLock, mpsc};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const FIXTURE_DEADLINE: Duration = Duration::from_secs(30);

#[derive(Debug, PartialEq, Eq)]
struct ProcIdentity {
    pid: libc::pid_t,
    starttime_ticks: u64,
}

fn agent_bash(temp: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("agent-bash").expect("agent-bash binary");
    cmd.env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env_remove("AGENT_BASH_CONSUMER_GRACE_MS")
        .env_remove("OULIPOLY_PARENT_INVOCATION")
        .env_remove("OULIPOLY_DATA_DIR");
    cmd
}

fn run_cmd(temp: &tempfile::TempDir, args: &[&str]) -> (Output, Duration) {
    let start = Instant::now();
    let output = agent_bash(temp).args(args).output().expect("run command");
    (output, start.elapsed())
}

fn parse_run_output(output: &Output) -> Value {
    assert_command_success(output);
    parse_stdout_json(output)
}

fn assert_command_success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        command_failure_message(output)
    );
}

fn command_failure_message(output: &Output) -> String {
    format!(
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn parse_stdout_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("run JSON")
}

fn status_text(temp: &tempfile::TempDir, handle: &str, full: bool) -> String {
    let output = status_output(temp, handle, full);
    assert_command_success(&output);
    stdout_utf8(output, "status utf8")
}

fn mode_text(temp: &tempfile::TempDir, handle: &str) -> String {
    let output = agent_bash(temp)
        .args(["mode", handle])
        .output()
        .expect("mode command");
    assert_command_success(&output);
    stdout_utf8(output, "mode utf8").trim().to_string()
}

fn status_output(temp: &tempfile::TempDir, handle: &str, full: bool) -> Output {
    let mut cmd = agent_bash(temp);
    cmd.args(status_args(handle, full))
        .output()
        .expect("status command")
}

fn status_args(handle: &str, full: bool) -> Vec<&str> {
    let mut args = vec!["status"];
    if full {
        args.push("--full");
    }
    args.push(handle);
    args
}

fn stdout_utf8(output: Output, context: &str) -> String {
    String::from_utf8(output.stdout).expect(context)
}

#[track_caller]
fn wait_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(value) = check() {
            return value;
        }
        assert_wait_pending(deadline, timeout);
        std::thread::sleep(Duration::from_millis(25));
    }
}

#[track_caller]
fn assert_wait_pending(deadline: Instant, timeout: Duration) {
    assert!(Instant::now() < deadline, "timed out after {timeout:?}");
}

fn build_detached_guard_helper(temp: &tempfile::TempDir) -> PathBuf {
    let source = detached_guard_source_path();
    let helper = detached_guard_helper_path(temp);
    let output = compile_detached_guard_helper(&source, &helper);
    assert_detached_guard_compiled(&output);
    helper
}

fn detached_guard_source_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/detached_guard_helper.c")
}

fn detached_guard_helper_path(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("detached_guard_helper")
}

fn compile_detached_guard_helper(source: &Path, helper: &Path) -> Output {
    let compiler = std::env::var_os("CC").unwrap_or_else(|| "cc".into());
    StdCommand::new(compiler)
        .arg("-O2")
        .arg("-Wall")
        .arg("-Wextra")
        .arg(source)
        .arg("-o")
        .arg(helper)
        .output()
        .expect("compile detached helper")
}

fn assert_detached_guard_compiled(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        detached_guard_compile_failure_message(output)
    );
}

fn detached_guard_compile_failure_message(output: &Output) -> String {
    format!(
        "detached helper compile failed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn wait_for_status_prefix(temp: &tempfile::TempDir, handle: &str, prefix: &str) -> String {
    wait_until(FIXTURE_DEADLINE, || {
        let text = status_text(temp, handle, true);
        if text.starts_with(prefix) {
            Some(text)
        } else {
            None
        }
    })
}

fn wait_for_terminal_status(temp: &tempfile::TempDir, handle: &str) -> String {
    wait_until(FIXTURE_DEADLINE, || {
        let text = status_text(temp, handle, true);
        (!text.starts_with("RUNNING ")).then_some(text)
    })
}

fn meta_path(run_json: &Value) -> PathBuf {
    PathBuf::from(run_json["meta"].as_str().expect("meta path"))
}

fn rc_path(run_json: &Value) -> PathBuf {
    PathBuf::from(run_json["rc"].as_str().expect("rc path"))
}

fn state_dir_path(run_json: &Value) -> PathBuf {
    PathBuf::from(run_json["state_dir"].as_str().expect("state dir"))
}

fn read_meta(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).expect("read meta")).expect("meta json")
}

fn unix_ms() -> u64 {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("unix time")
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

fn seed_done_state_dir(
    temp: &tempfile::TempDir,
    handle: &str,
    updated_at_unix_ms: u64,
    consumed: bool,
) -> PathBuf {
    let root = temp.path().join("agent-bash");
    let state_dir = root.join(handle);
    fs::create_dir_all(&state_dir).expect("state dir");
    let meta = done_state_meta(handle, updated_at_unix_ms);
    write_seeded_state_files(&state_dir, &meta);
    if consumed {
        write_consumed_marker(&state_dir);
    }
    state_dir
}

fn done_state_meta(handle: &str, updated_at_unix_ms: u64) -> Value {
    json!({
        "schema_version": 1,
        "handle": handle,
        "created_at_unix_ms": updated_at_unix_ms,
        "updated_at_unix_ms": updated_at_unix_ms,
        "state": "DONE",
        "completion_reason": "exit",
        "caller_ppid": unsafe { libc::getpid() },
        "caller_chain": [],
        "launcher_pid": unsafe { libc::getpid() },
        "supervisor_pid": null,
        "workload_pid": null,
        "workload_pgid": null,
        "workload_pidfd": false,
        "argv": ["bash", "-lc", "true"],
        "cwd": "/tmp",
        "mode": "exit",
        "ready_sentinel": null,
        "ready_at_unix_ms": null,
        "completed_at_unix_ms": updated_at_unix_ms,
        "rc": 0,
        "signal": null,
        "workload_rc": 0,
        "workload_signal": null,
        "delivery": {
            "attempted": false,
            "exit_code": null,
            "error": null
        },
        "cgroup": {
            "mode": "subreaper-only",
            "path": null,
            "delegated": false,
            "events_watch": false,
            "degraded_reason": null
        },
        "error": null
    })
}

fn format_seeded_meta(meta: &Value) -> Vec<u8> {
    serde_json::to_vec_pretty(&meta).expect("meta json")
}

fn write_seeded_state_files(state_dir: &Path, meta: &Value) {
    fs::write(state_dir.join("meta.json"), format_seeded_meta(meta)).expect("write meta");
    fs::write(state_dir.join("rc"), b"0\n").expect("write rc");
    fs::write(state_dir.join("log"), b"old\n").expect("write log");
}

fn active_state_meta(handle: &str, caller_ppid: libc::pid_t, caller_chain: Value) -> Value {
    json!({
        "schema_version": 1,
        "handle": handle,
        "created_at_unix_ms": unix_ms(),
        "updated_at_unix_ms": unix_ms(),
        "state": "RUNNING",
        "completion_reason": null,
        "caller_ppid": caller_ppid,
        "caller_chain": caller_chain,
        "launcher_pid": caller_ppid,
        "supervisor_pid": null,
        "workload_pid": null,
        "workload_pgid": null,
        "workload_pidfd": false,
        "argv": ["bash", "-lc", "sleep 1"],
        "cwd": "/tmp",
        "mode": "exit",
        "ready_sentinel": null,
        "ready_at_unix_ms": null,
        "completed_at_unix_ms": null,
        "rc": null,
        "signal": null,
        "workload_rc": null,
        "workload_signal": null,
        "delivery": {
            "attempted": false,
            "exit_code": null,
            "error": null
        },
        "cgroup": {
            "mode": "subreaper-only",
            "path": null,
            "delegated": false,
            "events_watch": false,
            "degraded_reason": null
        },
        "error": null
    })
}

fn seed_active_state_dir(temp: &tempfile::TempDir, handle: &str, meta: &Value) {
    let state_dir = temp.path().join("agent-bash").join(handle);
    fs::create_dir_all(&state_dir).expect("state dir");
    fs::write(state_dir.join("meta.json"), format_seeded_meta(meta)).expect("write meta");
    fs::write(state_dir.join("log"), b"").expect("write log");
}

fn state_dir_count(temp: &tempfile::TempDir) -> usize {
    let root = temp.path().join("agent-bash");
    match fs::read_dir(root) {
        Ok(entries) => entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                    && entry.file_name().to_string_lossy().starts_with("ab_")
            })
            .count(),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => 0,
        Err(err) => panic!("read isolated state root: {err}"),
    }
}

fn list_json(temp: &tempfile::TempDir, all: bool) -> Vec<Value> {
    let mut command = agent_bash(temp);
    command.arg("list");
    if all {
        command.arg("--all");
    }
    let output = command.arg("--json").output().expect("list command");
    assert_command_success(&output);
    serde_json::from_slice(&output.stdout).expect("list JSON")
}

fn write_consumed_marker(state_dir: &Path) {
    fs::write(state_dir.join("consumed"), b"").expect("write consumed");
}

fn write_delivery_helper_provenance(state_dir: &Path, helper: &Path) {
    let snapshot = state_dir.join("delivery-helper");
    fs::copy(helper, &snapshot).expect("copy helper snapshot");
    let mut permissions = fs::metadata(&snapshot)
        .expect("snapshot metadata")
        .permissions();
    permissions.set_mode(0o500);
    fs::set_permissions(&snapshot, permissions).expect("make snapshot executable");
    let snapshot = fs::canonicalize(snapshot).expect("canonical helper snapshot");
    let metadata = fs::metadata(&snapshot).expect("helper metadata");
    let sha256 = format!(
        "{:x}",
        Sha256::digest(fs::read(&snapshot).expect("read snapshot"))
    );
    let provenance = json!({
        "schema_version": 2,
        "path": snapshot.to_str().expect("UTF-8 helper path"),
        "device": metadata.dev(),
        "inode": metadata.ino(),
        "size": metadata.size(),
        "modified_seconds": metadata.mtime(),
        "modified_nanoseconds": metadata.mtime_nsec(),
        "mode": metadata.mode(),
        "sha256": sha256,
    });
    let meta_path = state_dir.join("meta.json");
    let mut meta = read_meta(&meta_path);
    meta["delivery_helper"] = provenance;
    fs::write(&meta_path, format_seeded_meta(&meta)).expect("write delivery helper provenance");
}

fn fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    named_fake_agents(temp, "fake-agents", "delivery.log")
}

fn named_fake_agents(
    temp: &tempfile::TempDir,
    helper_name: &str,
    log_name: &str,
) -> (PathBuf, PathBuf) {
    let fake = temp.path().join(helper_name);
    let delivery_log = temp.path().join(log_name);
    fs::write(&fake, fake_agents_script(&delivery_log)).expect("write fake");
    set_executable(&fake);
    (fake, delivery_log)
}

fn fake_agents_script(delivery_log: &Path) -> String {
    format!(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nexit 0\n",
        shell_quote(delivery_log)
    )
}

fn interpreter_backed_fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf) {
    let interpreter = temp.path().join("delivery-interpreter");
    let helper = temp.path().join("interpreter-backed-agents");
    let log = temp.path().join("interpreter-backed.log");
    fs::write(
        &interpreter,
        format!(
            "#!/bin/sh\nprintf '%s\\n' \"$@\" >> {}\nexit 0\n",
            shell_quote(&log)
        ),
    )
    .expect("write delivery interpreter");
    set_executable(&interpreter);
    fs::write(&helper, format!("#!{}\n", interpreter.display()))
        .expect("write interpreter-backed helper");
    set_executable(&helper);
    (helper, interpreter, log)
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_string_lossy().replace('\'', "'\"'\"'"))
}

#[derive(Clone)]
struct BlockingDeliveryFixture {
    helper: PathBuf,
    activation_started: PathBuf,
    activation_release: PathBuf,
    completion_started: PathBuf,
    completion_release: PathBuf,
    completion_finished: PathBuf,
    delivery_log: PathBuf,
}

fn blocking_delivery_fake_agents(temp: &tempfile::TempDir) -> BlockingDeliveryFixture {
    let fake = temp.path().join("blocking-activate-fake-agents");
    let activate_started = temp.path().join("activate-started");
    let activate_release = temp.path().join("activate-release");
    let complete_started = temp.path().join("complete-started");
    let complete_release = temp.path().join("complete-release");
    let complete_finished = temp.path().join("complete-finished");
    let delivery_log = temp.path().join("blocking-delivery.log");
    fs::write(
        &fake,
        r#"#!/bin/sh
if [ "${2:-}" = agent-bash-activate ]; then
    printf 'agent-bash-activate\n' >> "$AGENT_BASH_FAKE_DELIVERY_LOG"
    : > "$AGENT_BASH_FAKE_ACTIVATE_STARTED"
    while [ ! -e "$AGENT_BASH_FAKE_ACTIVATE_RELEASE" ]; do sleep 0.01; done
elif [ "${2:-}" = agent-bash-complete ]; then
    printf 'agent-bash-complete\n' >> "$AGENT_BASH_FAKE_DELIVERY_LOG"
    : > "$AGENT_BASH_FAKE_COMPLETE_STARTED"
    attempts=0
    while [ ! -e "$AGENT_BASH_FAKE_COMPLETE_RELEASE" ] && [ "$attempts" -lt 800 ]; do
        attempts=$((attempts + 1))
        sleep 0.01
    done
    [ -e "$AGENT_BASH_FAKE_COMPLETE_RELEASE" ] || exit 1
    : > "$AGENT_BASH_FAKE_COMPLETE_FINISHED"
fi
exit 0
"#,
    )
    .expect("write blocking activation fake");
    set_executable(&fake);
    BlockingDeliveryFixture {
        helper: fake,
        activation_started: activate_started,
        activation_release: activate_release,
        completion_started: complete_started,
        completion_release: complete_release,
        completion_finished: complete_finished,
        delivery_log,
    }
}

fn parent_killing_fake_agents(
    temp: &tempfile::TempDir,
    killed_operation: &str,
) -> (PathBuf, PathBuf) {
    let fake = temp.path().join(format!("kill-parent-{killed_operation}"));
    let log = temp
        .path()
        .join(format!("kill-parent-{killed_operation}.log"));
    fs::write(
        &fake,
        format!(
            "#!/bin/sh\noperation=${{2:-}}\nif [ \"$operation\" = {} ]; then\n  printf '%s\\n' \"$operation\" >> \"$AGENT_BASH_FAKE_DELIVERY_LOG\"\n  caller_pid=$(ps -o ppid= -p \"$PPID\")\n  kill -KILL \"$caller_pid\"\nfi\nexit 0\n",
            shell_quote(Path::new(killed_operation))
        ),
    )
    .expect("write parent-killing fake");
    set_executable(&fake);
    (fake, log)
}

fn nonzero_completion_fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let fake = temp.path().join("nonzero-completion-fake-agents");
    let log = temp.path().join("nonzero-completion.log");
    fs::write(
        &fake,
        r#"#!/bin/sh
if [ "${2:-}" = agent-bash-complete ]; then
    printf 'agent-bash-complete\n' >> "$AGENT_BASH_FAKE_DELIVERY_LOG"
    exit 17
fi
exit 0
"#,
    )
    .expect("write nonzero completion fake");
    set_executable(&fake);
    (fake, log)
}

fn owner_resolving_fake_agents(temp: &tempfile::TempDir) -> PathBuf {
    let fake = temp.path().join("owner-resolving-fake-agents");
    fs::write(
        &fake,
        r#"#!/bin/sh
if [ "${1:-}" = session ] && [ "${2:-}" = of-pid ]; then
    if [ -n "${AGENT_BASH_FAKE_RESOLVER_DELAY:-}" ]; then
        sleep "$AGENT_BASH_FAKE_RESOLVER_DELAY"
    fi
    if [ -n "${AGENT_BASH_FAKE_FIRST_MISS_MARKER:-}" ] && [ ! -e "$AGENT_BASH_FAKE_FIRST_MISS_MARKER" ]; then
        : > "$AGENT_BASH_FAKE_FIRST_MISS_MARKER"
        printf '{"found":false,"invocation_uuid":null,"session_id":null}\n'
        exit 1
    fi
    printf '{"found":true,"invocation_uuid":"11111111-1111-4111-8111-111111111111","session_id":"%s"}\n' "${AGENT_BASH_FAKE_RESOLVED_SESSION:-ses_resolved}"
fi
exit 0
"#,
    )
    .expect("write owner-resolving fake");
    set_executable(&fake);
    fake
}

fn registration_rejecting_fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let fake = temp.path().join("registration-rejecting-fake-agents");
    let resolver_log = temp.path().join("resolver-called");
    fs::write(
        &fake,
        r#"#!/bin/sh
if [ "${1:-}" = session ] && [ "${2:-}" = of-pid ]; then
    printf 'called\n' > "$AGENT_BASH_FAKE_RESOLVER_LOG"
    printf '%s\n' '{"found":true,"invocation_uuid":"11111111-1111-4111-8111-111111111111","session_id":"ses_resolved"}'
    exit 0
fi
printf '%s\n' '{"status":"notification_event_error","message":"meta.json owner_session_id and owner_invocation_uuid are both required"}'
exit 74
"#,
    )
    .expect("write registration-rejecting fake");
    set_executable(&fake);
    (fake, resolver_log)
}

fn delivery_attempt_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "agent-bash-complete")
        .count()
}

fn operation_count(path: &Path, operation: &str) -> usize {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == operation)
        .count()
}

fn detach_with_fake(
    temp: &tempfile::TempDir,
    handle: &str,
    fake: &Path,
    delivery_log: &Path,
) -> Output {
    agent_bash(temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", delivery_log)
        .args(["detach", handle])
        .output()
        .expect("detach command")
}

fn observing_fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let fake = temp.path().join("observing-fake-agents");
    let delivery_log = temp.path().join("observed-delivery.log");
    let meta_snapshot = temp.path().join("delivery-meta-snapshot.json");
    let rc_snapshot = temp.path().join("delivery-rc-snapshot");
    fs::write(&fake, observing_fake_agents_script()).expect("write observing fake");
    set_executable(&fake);
    (fake, delivery_log, meta_snapshot, rc_snapshot)
}

fn observing_fake_agents_script() -> &'static str {
    r#"#!/bin/sh
operation=${2:-}
if [ "$operation" != "agent-bash-complete" ]; then
    exit 0
fi
meta=
rc=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --meta) shift; meta=$1 ;;
        --rc) shift; rc=$1 ;;
    esac
    shift
done
cp "$meta" "$AGENT_BASH_FAKE_META_SNAPSHOT"
cp "$rc" "$AGENT_BASH_FAKE_RC_SNAPSHOT"
printf 'delivery\n' >> "$AGENT_BASH_FAKE_DELIVERY_LOG"
exit 0
"#
}

fn set_executable(path: &Path) {
    let mut perms = fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms).expect("chmod fake");
}

fn write_adapter_driver(temp: &tempfile::TempDir) -> PathBuf {
    let path = adapter_driver_path(temp);
    fs::write(&path, adapter_driver_source()).expect("write adapter driver");
    path
}

fn adapter_driver_path(temp: &tempfile::TempDir) -> PathBuf {
    temp.path().join("opencode-adapter-driver.ts")
}

fn adapter_driver_source() -> &'static str {
    r#"import { mock } from "bun:test"

const optional = () => ({})
const describe = () => ({ optional })
const string = () => ({ describe })
const tool = Object.assign((definition) => definition, { schema: { string } })

mock.module("@opencode-ai/plugin", () => ({ tool }))

const mode = process.argv[2]
const adapterPath = process.argv[3]
const value = process.argv[4]
const mod = await import(adapterPath)
const controller = new AbortController()
const context = {
  sessionID: "ses_adapter",
  messageID: "msg_adapter",
  agent: "test",
  directory: process.cwd(),
  worktree: process.cwd(),
  abort: controller.signal,
  metadata: () => {},
  ask: async () => {},
}

if (mode === "joint") {
  const launched = await mod.default.execute(
    { command: "sleep 1; printf 'adapter joint done\\n'", delivery: "async" },
    context,
  )
  const launchedResult = typeof launched === "string" ? launched : String(launched)
  const launchedHandle = launchedResult.match(/handle=([^\s)]+)/)?.[1]
  if (!launchedHandle) throw new Error(`joint launch did not return a handle: ${launchedResult}`)

  const listed = await mod.default.execute(
    { command: `${process.env.AGENT_BASH_BIN} list --json` },
    context,
  )
  const listResult = typeof listed === "string" ? listed : String(listed)
  console.log(JSON.stringify({ launchedResult, launchedHandle, listResult }))
  process.exit(0)
}

if (mode === "parallel-live") {
  const results = await Promise.all([
    mod.default.execute({ command: "printf 'first live command\\n'" }, context),
    mod.default.execute({ command: "printf 'second live command\\n'" }, context),
  ])
  console.log(JSON.stringify({ result: results.map(String).join("\n") }))
  process.exit(0)
}

if (mode === "move-helper") {
  const execution = mod.default.execute(
    { command: `sleep 0.1; mv "$AGENT_BASH_BIN" "$AGENT_BASH_BIN.moved"; sleep 0.2` },
    context,
  ).then(
    (result) => ({ kind: "result", result: typeof result === "string" ? result : String(result) }),
    (error) => ({ kind: "error", result: String(error) }),
  )
  const outcome = await Promise.race([
    execution,
    Bun.sleep(30000).then(() => ({ kind: "timeout", result: "polling did not terminate" })),
  ])
  console.log(JSON.stringify(outcome))
  process.exit(outcome.kind === "error" ? 0 : 1)
}

const args = mode === "poll"
  ? { handle: value }
  : mode === "async"
    ? {
        command: `printf started > "$ADAPTER_ASYNC_STARTED"; attempts=0; while [ "$attempts" -lt 800 ]; do if [ -e "$ADAPTER_ASYNC_RELEASE" ]; then printf 'adapter async\\n'; exit 0; fi; attempts=$((attempts + 1)); sleep 0.01; done; exit 1`,
        delivery: "async",
      }
    : mode === "sleep"
      ? { command: "sleep 0.05" }
    : mode === "abort"
      ? { command: "sleep 60; printf 'adapter abort failed\\n'" }
      : mode === "detachable"
        ? { command: `printf started > "$ADAPTER_DETACHABLE_STARTED"; attempts=0; while [ "$attempts" -lt 800 ]; do if [ -e "$ADAPTER_DETACHABLE_RELEASE" ]; then printf 'adapter detached\\n'; exit 0; fi; attempts=$((attempts + 1)); sleep 0.01; done; exit 1` }
      : mode === "wrapper"
        ? { command: `${process.env.AGENT_BASH_BIN} run -- agents --version` }
      : mode === "wrapper-env"
        ? { command: `XDG_STATE_HOME=${process.env.XDG_STATE_HOME} ${process.env.AGENT_BASH_BIN} run -- agents --version` }
      : mode === "binding-env"
        ? { command: "printf '%s|%s\\n' \"${OULIPOLY_LIVE_SESSION_BIND_SOCKET-unset}\" \"${OULIPOLY_LIVE_SESSION_BIND_TOKEN-unset}\"" }
      : mode === "inherited-env"
        ? { command: "printf '%s|%s|%s\\n' \"$INHERITED_ENV_SENTINEL\" \"$OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY\" \"$OULIPOLY_PARENT_INVOCATION\"" }
      : mode === "agent-sync"
        ? { command: "agents --version", delivery: "sync" }
        : mode === "agent"
          ? { command: "agents --version" }
          : mode === "control"
            ? { command: value }
            : { command: "printf 'adapter inline\\n'" }
if (mode === "abort") setTimeout(() => controller.abort(), 100)
const result = await mod.default.execute(args, context)
const text = typeof result === "string" ? result : String(result)
const matched = text.match(/handle=([^\s)]+)/)

console.log(JSON.stringify({ result: text, handle: matched?.[1] ?? null }))
if (mode === "detachable") await Bun.sleep(3000)
"#
}

fn run_adapter_driver(
    temp: &tempfile::TempDir,
    driver: &Path,
    mode: &str,
    handle: Option<&str>,
) -> Value {
    let mut command = adapter_driver_command(temp, driver, mode, handle);
    let output = command.output().expect("adapter driver");
    assert_command_success(&output);
    parse_stdout_json(&output)
}

fn adapter_driver_command(
    temp: &tempfile::TempDir,
    driver: &Path,
    mode: &str,
    handle: Option<&str>,
) -> StdCommand {
    let mut command = StdCommand::new(bun_bin_path());
    let adapter_agent_bash = temp.path().join("adapter-agent-bash");
    if !adapter_agent_bash.exists() {
        fs::copy(
            assert_cmd::cargo::cargo_bin("agent-bash"),
            &adapter_agent_bash,
        )
        .expect("copy adapter agent-bash");
        set_executable(&adapter_agent_bash);
    }
    command
        .arg(driver)
        .arg(mode)
        .arg(adapter_module_path())
        .env("AGENT_BASH_BIN", adapter_agent_bash)
        .env(
            "AGENT_BASH_AGENT_RUNNER_BIN",
            owner_resolving_fake_agents(temp),
        )
        .env("AGENT_BASH_FAKE_RESOLVED_SESSION", "ses_adapter")
        .env("AGENT_BASH_TOOL_POLL_MS", "25")
        .env(
            "ADAPTER_ASYNC_STARTED",
            temp.path().join("adapter-async-started"),
        )
        .env(
            "ADAPTER_ASYNC_RELEASE",
            temp.path().join("adapter-async-release"),
        )
        .env(
            "ADAPTER_DETACHABLE_STARTED",
            temp.path().join("adapter-detachable-started"),
        )
        .env(
            "ADAPTER_DETACHABLE_RELEASE",
            temp.path().join("adapter-detachable-release"),
        )
        .env("XDG_STATE_HOME", temp.path())
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            r#"{"source":"opencode","id":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .env_remove("OULIPOLY_LIVE_SESSION_BIND_SOCKET")
        .env_remove("OULIPOLY_LIVE_SESSION_BIND_TOKEN")
        .env_remove("OULIPOLY_DATA_DIR");
    if let Some(handle) = handle {
        command.arg(handle);
    }
    command
}

fn run_adapter_driver_with_live_binding(
    temp: &tempfile::TempDir,
    driver: &Path,
    mode: &str,
) -> (Value, Value) {
    let socket_path = temp.path().join("live-session.sock");
    let state_root = temp.path().join("agent-bash");
    let listener = UnixListener::bind(&socket_path).expect("bind live-session socket");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept live-session report");
        let mut line = String::new();
        BufReader::new(stream.try_clone().expect("clone live-session stream"))
            .read_line(&mut line)
            .expect("read live-session report");
        let report: Value =
            serde_json::from_str(line.trim_end()).expect("live-session report JSON");
        assert!(
            !state_root.exists()
                || fs::read_dir(&state_root)
                    .expect("read pre-binding state root")
                    .next()
                    .is_none(),
            "agent-bash dispatched before live-session acknowledgement"
        );
        writeln!(
            stream,
            "{}",
            json!({ "ok": true, "session_id": "ses_adapter", "error": null })
        )
        .expect("write live-session response");
        report
    });
    let mut command = adapter_driver_command(temp, driver, mode, None);
    let output = command
        .env("OULIPOLY_LIVE_SESSION_BIND_SOCKET", &socket_path)
        .env("OULIPOLY_LIVE_SESSION_BIND_TOKEN", "fixture-token")
        .output()
        .expect("live-session adapter driver");
    assert_command_success(&output);
    (
        parse_stdout_json(&output),
        server.join().expect("join live-session server"),
    )
}

fn run_adapter_driver_with_stale_live_binding(
    temp: &tempfile::TempDir,
    driver: &Path,
    mode: &str,
) -> Value {
    let mut command = adapter_driver_command(temp, driver, mode, None);
    let output = command
        .env(
            "OULIPOLY_LIVE_SESSION_BIND_SOCKET",
            temp.path().join("removed-live-session.sock"),
        )
        .env("OULIPOLY_LIVE_SESSION_BIND_TOKEN", "stale-fixture-token")
        .output()
        .expect("stale live-session adapter driver");
    assert_command_success(&output);
    parse_stdout_json(&output)
}

fn bun_bin_path() -> PathBuf {
    env::var_os("BUN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("bun"))
}

fn assert_bun_available() {
    let path = bun_bin_path();
    let output = StdCommand::new(&path)
        .arg("--version")
        .output()
        .unwrap_or_else(|err| {
            panic!(
                "required bun binary is missing at {}: {err}",
                path.display()
            )
        });
    assert_command_success(&output);
}

fn adapter_module_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("integrations/opencode/tools/bash.ts")
}

fn adapter_result_text(result: &Value) -> &str {
    result["result"].as_str().expect("adapter result")
}

fn adapter_result_handle(result: &Value) -> &str {
    result["handle"].as_str().expect("adapter handle")
}

fn assert_adapter_result_contains(result: &Value, expected: &str) {
    let text = adapter_result_text(result);
    assert!(text.contains(expected), "{text}");
}

fn state_handles(temp: &tempfile::TempDir) -> Vec<String> {
    let Ok(entries) = fs::read_dir(temp.path().join("agent-bash")) else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("ab_"))
        .collect()
}

fn initialized_state_handle(temp: &tempfile::TempDir) -> Option<String> {
    state_handles(temp).into_iter().find(|handle| {
        let state_dir = temp.path().join("agent-bash").join(handle);
        state_dir.join("meta.json").exists() && state_dir.join("delivery-mode").exists()
    })
}

fn read_boot_id() -> String {
    fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .expect("boot id")
        .trim()
        .to_string()
}

fn proc_ancestry(start_pid: libc::pid_t) -> Vec<ProcIdentity> {
    let mut chain = Vec::new();
    let mut pid = start_pid;
    for _ in 0..128 {
        if pid <= 0 {
            break;
        }
        let Some((identity, ppid)) = proc_identity(pid) else {
            break;
        };
        chain.push(identity);
        if pid == 1 {
            break;
        }
        pid = ppid;
    }
    chain
}

fn proc_identity(pid: libc::pid_t) -> Option<(ProcIdentity, libc::pid_t)> {
    let contents = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let end_comm = contents.rfind(") ")?;
    let fields: Vec<_> = contents[end_comm + 2..].split_whitespace().collect();
    let ppid = fields.get(1)?.parse::<libc::pid_t>().ok()?;
    let starttime_ticks = fields.get(19)?.parse::<u64>().ok()?;
    Some((
        ProcIdentity {
            pid,
            starttime_ticks,
        },
        ppid,
    ))
}

fn exact_identity(identity: &ProcIdentity) -> Value {
    json!({
        "pid": identity.pid,
        "starttime_ticks": identity.starttime_ticks,
        "boot_id": read_boot_id()
    })
}

fn terminated_process_identity() -> ProcIdentity {
    let mut child = StdCommand::new("sleep")
        .arg("60")
        .spawn()
        .expect("spawn identity process");
    let pid = child.id() as libc::pid_t;
    let (identity, _) = proc_identity(pid).expect("read live process identity");
    child.kill().expect("kill identity process");
    child.wait().expect("reap identity process");
    assert!(
        proc_identity(pid).is_none(),
        "identity process must be gone"
    );
    identity
}

fn seed_running_state_dir(
    temp: &tempfile::TempDir,
    handle: &str,
    mode: &str,
    supervisor_identity: Option<Value>,
    workload_identity: Option<Value>,
    consumed: bool,
) -> Value {
    let state_dir = temp.path().join("agent-bash").join(handle);
    fs::create_dir_all(&state_dir).expect("state dir");
    let meta = json!({
        "schema_version": 1,
        "handle": handle,
        "created_at_unix_ms": unix_ms(),
        "updated_at_unix_ms": unix_ms(),
        "state": "RUNNING",
        "completion_reason": null,
        "caller_ppid": unsafe { libc::getpid() },
        "caller_chain": [],
        "launcher_pid": unsafe { libc::getpid() },
        "supervisor_pid": supervisor_identity.as_ref().and_then(|value| value["pid"].as_i64()),
        "supervisor_pid_starttime_ticks": supervisor_identity
            .as_ref()
            .and_then(|value| value["starttime_ticks"].as_u64()),
        "workload_pid": workload_identity.as_ref().and_then(|value| value["pid"].as_i64()),
        "workload_pid_starttime_ticks": workload_identity
            .as_ref()
            .and_then(|value| value["starttime_ticks"].as_u64()),
        "process_boot_id": supervisor_identity
            .as_ref()
            .and_then(|value| value["boot_id"].as_str()),
        "workload_pgid": null,
        "workload_pidfd": false,
        "argv": ["bash", "-lc", "printf retained"],
        "cwd": "/tmp",
        "mode": mode,
        "ready_sentinel": if mode == "sentinel" { Value::String("READY".to_string()) } else { Value::Null },
        "ready_at_unix_ms": null,
        "completed_at_unix_ms": null,
        "rc": null,
        "signal": null,
        "workload_rc": null,
        "workload_signal": null,
        "delivery": {
            "attempted": false,
            "exit_code": null,
            "error": null
        },
        "cgroup": {
            "mode": "subreaper-only",
            "path": null,
            "delegated": false,
            "events_watch": false,
            "degraded_reason": null
        },
        "error": null
    });
    fs::write(state_dir.join("meta.json"), format_seeded_meta(&meta)).expect("write meta");
    fs::write(state_dir.join("log"), b"retained log\n").expect("write log");
    if consumed {
        write_consumed_marker(&state_dir);
    }
    meta
}

fn status_with_observing_delivery(
    temp: &tempfile::TempDir,
    handle: &str,
    fake: &Path,
    delivery_log: &Path,
    meta_snapshot: &Path,
    rc_snapshot: &Path,
) -> Output {
    let state_dir = temp.path().join("agent-bash").join(handle);
    if read_meta(&state_dir.join("meta.json"))["delivery_helper"].is_null() {
        write_delivery_helper_provenance(&state_dir, fake);
    }
    let mut cmd = agent_bash(temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", delivery_log)
        .env("AGENT_BASH_FAKE_META_SNAPSHOT", meta_snapshot)
        .env("AGENT_BASH_FAKE_RC_SNAPSHOT", rc_snapshot)
        .args(["status", "--full", handle])
        .output()
        .expect("status command")
}

fn assert_running_without_delivery(
    temp: &tempfile::TempDir,
    handle: &str,
    fake: &Path,
    delivery_log: &Path,
    meta_snapshot: &Path,
    rc_snapshot: &Path,
) {
    let output = status_with_observing_delivery(
        temp,
        handle,
        fake,
        delivery_log,
        meta_snapshot,
        rc_snapshot,
    );
    assert_command_success(&output);
    let text = stdout_utf8(output, "status utf8");
    assert!(
        text.starts_with(&format!("RUNNING handle={handle}")),
        "{text}"
    );
}

fn assert_process_alive(pid: libc::pid_t) {
    let rc = unsafe { libc::kill(pid, 0) };
    assert_eq!(rc, 0, "expected live process pid {pid}");
}

fn wait_for_process_gone(pid: libc::pid_t) {
    wait_until(FIXTURE_DEADLINE, || {
        proc_identity(pid).is_none().then_some(())
    });
}

struct ReleaseMarker(Option<PathBuf>);

impl ReleaseMarker {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn release(mut self) {
        fs::write(self.0.take().expect("release marker path"), b"").expect("write release marker");
    }
}

impl Drop for ReleaseMarker {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::write(path, b"");
        }
    }
}

struct OwnerScenario {
    child: Option<Child>,
    run_json: PathBuf,
    ready: PathBuf,
    list_now: PathBuf,
    owner_list: PathBuf,
    list_caller_pid: PathBuf,
    workload_release: PathBuf,
}

impl OwnerScenario {
    fn child_pid(&self) -> libc::pid_t {
        self.child.as_ref().expect("owner child").id() as libc::pid_t
    }

    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.take().expect("owner child").wait()
    }
}

impl Drop for OwnerScenario {
    fn drop(&mut self) {
        let Some(mut child) = self.child.take() else {
            return;
        };
        let _ = child.kill();
        let deadline = Instant::now() + FIXTURE_DEADLINE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(None) | Err(_) => {
                    hand_off_child_reaping(child);
                    return;
                }
            }
        }
    }
}

fn hand_off_child_reaping(child: Child) {
    let _ = owner_scenario_reaper().send(child);
}

fn owner_scenario_reaper() -> &'static mpsc::Sender<Child> {
    static REAPER: OnceLock<mpsc::Sender<Child>> = OnceLock::new();
    REAPER.get_or_init(|| {
        let (sender, receiver) = mpsc::channel::<Child>();
        std::thread::Builder::new()
            .name("owner-scenario-reaper".to_string())
            .spawn(move || {
                for mut child in receiver {
                    let _ = child.wait();
                }
            })
            .expect("start owner scenario reaper");
        sender
    })
}

fn spawn_owner_scenario(temp: &tempfile::TempDir, workload_seconds: &str) -> OwnerScenario {
    spawn_owner_scenario_with_release(temp, workload_seconds, false)
}

fn spawn_releasable_owner_scenario(temp: &tempfile::TempDir) -> OwnerScenario {
    spawn_owner_scenario_with_release(temp, "0", true)
}

fn spawn_owner_scenario_with_release(
    temp: &tempfile::TempDir,
    workload_seconds: &str,
    releasable: bool,
) -> OwnerScenario {
    let _ = owner_scenario_reaper();
    let run_json = temp.path().join("owner-run.json");
    let ready = temp.path().join("owner-ready");
    let list_now = temp.path().join("owner-list-now");
    let owner_list = temp.path().join("owner-list.json");
    let list_caller_pid = temp.path().join("owner-list-caller-pid");
    let workload_release = temp.path().join("owner-workload-release");
    let script = r#"
set -eu
test -z "${AGENT_BASH_OWNER_SESSION_ID+x}"
test -z "${AGENT_BASH_OWNER_INVOCATION_UUID+x}"
if [ "$OWNER_WORKLOAD_RELEASABLE" = 1 ]; then
    "$AGENT_BASH_BIN" run -- bash -lc 'for _ in {1..800}; do [ -e "$OWNER_WORKLOAD_RELEASE" ] && exit 0; sleep 0.01; done; exit 1' > "$RUN_JSON"
else
    "$AGENT_BASH_BIN" run -- sleep "$OWNER_WORKLOAD_SECONDS" > "$RUN_JSON"
fi
while [ ! -e "$LIST_NOW" ]; do : > "$READY"; sleep 0.01; done
bash -c 'printf "%s\n" "$$" > "$LIST_CALLER_PID"; "$AGENT_BASH_BIN" list --json > "$OWNER_LIST"; rc=$?; exit "$rc"'
rc=$?
:
exit "$rc"
"#;
    let child = StdCommand::new("bash")
        .arg("-c")
        .arg(script)
        .env("AGENT_BASH_BIN", assert_cmd::cargo::cargo_bin("agent-bash"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("XDG_STATE_HOME", temp.path())
        .env_remove("AGENT_BASH_OWNER_SESSION_ID")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .env_remove("OULIPOLY_PARENT_INVOCATION")
        .env_remove("OULIPOLY_DATA_DIR")
        .env("RUN_JSON", &run_json)
        .env("READY", &ready)
        .env("LIST_NOW", &list_now)
        .env("OWNER_LIST", &owner_list)
        .env("LIST_CALLER_PID", &list_caller_pid)
        .env("OWNER_WORKLOAD_SECONDS", workload_seconds)
        .env(
            "OWNER_WORKLOAD_RELEASABLE",
            if releasable { "1" } else { "0" },
        )
        .env("OWNER_WORKLOAD_RELEASE", &workload_release)
        .spawn()
        .expect("spawn owner scenario");
    OwnerScenario {
        child: Some(child),
        run_json,
        ready,
        list_now,
        owner_list,
        list_caller_pid,
        workload_release,
    }
}

fn shell_list_json(temp: &tempfile::TempDir, all: bool) -> Vec<Value> {
    let all_arg = if all { " --all" } else { "" };
    let script = format!(
        "test -z \"${{AGENT_BASH_OWNER_SESSION_ID+x}}\" && \
         test -z \"${{AGENT_BASH_OWNER_INVOCATION_UUID+x}}\" && \
         \"$AGENT_BASH_BIN\" list{all_arg} --json"
    );
    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(script)
        .env("AGENT_BASH_BIN", assert_cmd::cargo::cargo_bin("agent-bash"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("XDG_STATE_HOME", temp.path())
        .env_remove("AGENT_BASH_OWNER_SESSION_ID")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .output()
        .expect("shell list command");
    assert_command_success(&output);
    serde_json::from_slice(&output.stdout).expect("shell list JSON")
}

#[derive(Debug, Default, PartialEq, Eq)]
struct ProcessCleanup {
    term_sent: usize,
    kill_sent: usize,
}

#[derive(Debug)]
struct OwnedProcess {
    pidfd: OwnedFd,
}

struct StoppedProcess<'a> {
    process: &'a OwnedProcess,
    resumed: bool,
}

impl<'a> StoppedProcess<'a> {
    fn stop(process: &'a OwnedProcess) -> Self {
        assert!(process.signal(libc::SIGSTOP), "stop owned process");
        Self {
            process,
            resumed: false,
        }
    }

    fn resume(&mut self) -> bool {
        self.resumed = self.process.signal(libc::SIGCONT);
        self.resumed
    }
}

impl Drop for StoppedProcess<'_> {
    fn drop(&mut self) {
        if !self.resumed {
            let _ = self.process.signal(libc::SIGCONT);
        }
    }
}

impl OwnedProcess {
    fn capture(
        identity: ProcIdentity,
        boot_id: &str,
        expected_parent: Option<libc::pid_t>,
    ) -> Option<Self> {
        if read_boot_id() != boot_id {
            return None;
        }
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, identity.pid, 0) };
        if fd < 0 {
            return None;
        }
        let pidfd = unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) };
        let (observed, parent) = proc_identity(identity.pid)?;
        if observed != identity || expected_parent.is_some_and(|expected| parent != expected) {
            return None;
        }
        Some(Self { pidfd })
    }

    fn capture_current(pid: libc::pid_t, expected_parent: Option<libc::pid_t>) -> Option<Self> {
        let (identity, parent) = proc_identity(pid)?;
        if expected_parent.is_some_and(|expected| parent != expected) {
            return None;
        }
        Self::capture(identity, &read_boot_id(), expected_parent)
    }

    fn capture_workload(meta: &Value) -> Option<Self> {
        Self::capture(
            ProcIdentity {
                pid: libc::pid_t::try_from(meta["workload_pid"].as_i64()?).ok()?,
                starttime_ticks: meta["workload_pid_starttime_ticks"].as_u64()?,
            },
            meta["process_boot_id"].as_str()?,
            None,
        )
    }

    fn capture_supervisor(meta: &Value) -> Option<Self> {
        Self::capture(
            ProcIdentity {
                pid: libc::pid_t::try_from(meta["supervisor_pid"].as_i64()?).ok()?,
                starttime_ticks: meta["supervisor_pid_starttime_ticks"].as_u64()?,
            },
            meta["process_boot_id"].as_str()?,
            None,
        )
    }

    fn signal(&self, signal: libc::c_int) -> bool {
        if self.exited() {
            return false;
        }
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            ) == 0
        }
    }

    fn exited(&self) -> bool {
        let mut pollfd = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut pollfd, 1, 0) };
        ready == 1 && pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0
    }
}

fn terminate_owned_processes(processes: &[OwnedProcess]) -> ProcessCleanup {
    let term_sent = processes
        .iter()
        .filter(|process| process.signal(libc::SIGTERM))
        .count();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && processes.iter().any(|process| !process.exited()) {
        std::thread::sleep(Duration::from_millis(10));
    }

    let kill_sent = processes
        .iter()
        .filter(|process| process.signal(libc::SIGKILL))
        .count();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline && processes.iter().any(|process| !process.exited()) {
        std::thread::sleep(Duration::from_millis(10));
    }
    ProcessCleanup {
        term_sent,
        kill_sent,
    }
}

fn terminate_workload_from_meta(meta: &Value) -> ProcessCleanup {
    let Some(workload) = OwnedProcess::capture_workload(meta) else {
        return ProcessCleanup::default();
    };
    terminate_owned_processes(&[workload])
}

fn workload_meta(identity: &ProcIdentity) -> Value {
    json!({
        "workload_pid": identity.pid,
        "workload_pid_starttime_ticks": identity.starttime_ticks,
        "process_boot_id": read_boot_id(),
    })
}

#[test]
fn process_cleanup_rejects_mismatched_workload_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ready = temp.path().join("mismatch-ready");
    let check = temp.path().join("mismatch-check");
    let acknowledged = temp.path().join("mismatch-acknowledged");
    let signaled = temp.path().join("mismatch-signaled");
    let mut workload = StdCommand::new("bash")
        .args([
            "-c",
            "trap ': > \"$SIGNALED\"' TERM; : > \"$READY\"; for _ in {1..200}; do [ -e \"$CHECK\" ] && { : > \"$ACKNOWLEDGED\"; sleep 2; exit 0; }; sleep 0.01; done; exit 1",
        ])
        .env("READY", &ready)
        .env("CHECK", &check)
        .env("ACKNOWLEDGED", &acknowledged)
        .env("SIGNALED", &signaled)
        .spawn()
        .expect("spawn workload");
    wait_until(FIXTURE_DEADLINE, || ready.exists().then_some(()));
    let pid = workload.id() as libc::pid_t;
    let (mut mismatched, _) = proc_identity(pid).expect("workload identity");
    mismatched.starttime_ticks += 1;

    let cleanup = terminate_workload_from_meta(&workload_meta(&mismatched));
    fs::write(&check, b"").expect("release mismatch observation");
    wait_until(FIXTURE_DEADLINE, || acknowledged.exists().then_some(()));
    let signal_observed = signaled.exists();
    workload.kill().expect("kill workload");
    workload.wait().expect("reap workload");

    assert_eq!(cleanup, ProcessCleanup::default());
    assert!(!signal_observed, "mismatched identity was signaled");
}

#[test]
fn process_cleanup_skips_escalation_after_termination() {
    let mut workload = StdCommand::new("sleep")
        .arg("2")
        .spawn()
        .expect("spawn workload");
    let process = OwnedProcess::capture_current(workload.id() as libc::pid_t, None)
        .expect("capture workload");

    let cleanup = terminate_owned_processes(&[process]);
    workload.wait().expect("reap workload");

    assert_eq!(
        cleanup,
        ProcessCleanup {
            term_sent: 1,
            kill_sent: 0,
        }
    );
}

#[test]
fn process_cleanup_escalates_for_owned_group_members_and_reaps_descendant() {
    let temp = tempfile::tempdir().expect("tempdir");
    let child_pid_path = temp.path().join("cleanup-child.pid");
    let ready_path = temp.path().join("cleanup-ready");
    let script = format!(
        "trap '' TERM; sleep 5 & echo $! > {}; : > {}; wait",
        child_pid_path.display(),
        ready_path.display()
    );
    let mut workload = StdCommand::new("setsid")
        .args(["bash", "-c", &script])
        .spawn()
        .expect("spawn workload tree");
    let pid = workload.id() as libc::pid_t;
    let child_pid = wait_until(FIXTURE_DEADLINE, || {
        ready_path.exists().then(|| {
            fs::read_to_string(&child_pid_path)
                .expect("child pid")
                .trim()
                .parse::<libc::pid_t>()
                .expect("numeric child pid")
        })
    });
    let root = OwnedProcess::capture_current(pid, None).expect("capture workload root");
    let child = OwnedProcess::capture_current(child_pid, Some(pid)).expect("capture child");
    let root_group = unsafe { libc::getpgid(pid) };
    let child_group = unsafe { libc::getpgid(child_pid) };

    let cleanup = terminate_owned_processes(&[root, child]);
    workload.wait().expect("reap workload root");
    wait_for_process_gone(child_pid);

    assert_eq!(
        cleanup,
        ProcessCleanup {
            term_sent: 2,
            kill_sent: 2,
        }
    );
    assert_eq!(root_group, pid, "workload root did not lead its group");
    assert_eq!(child_group, pid, "descendant was not in the workload group");
}

#[test]
fn list_attached_empty_state_is_json_array() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = agent_bash(&temp)
        .args(["list", "--json"])
        .output()
        .expect("list");
    assert!(output.status.success());
    assert_eq!(String::from_utf8(output.stdout).expect("utf8"), "[]\n");
}

#[test]
fn attached_guard_rejects_detached_invocation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let out = temp.path().join("out");
    let err = temp.path().join("err");
    let rc = temp.path().join("rc");
    let ppid_trace = temp.path().join("ppid-trace");
    let bin = assert_cmd::cargo::cargo_bin("agent-bash");
    let helper = build_detached_guard_helper(&temp);
    let status = StdCommand::new(&helper)
        .arg(&bin)
        .arg(temp.path())
        .arg(&out)
        .arg(&err)
        .arg(&rc)
        .arg(&ppid_trace)
        .status()
        .expect("detached helper launcher");
    assert!(status.success(), "detached helper launcher failed");
    let child_rc = wait_until(FIXTURE_DEADLINE, || fs::read_to_string(&rc).ok());
    assert_eq!(child_rc.trim(), "64", "detached child rc");
    let observed_ppids = fs::read_to_string(&ppid_trace).expect("ppid trace");
    let ppids: Vec<_> = observed_ppids.lines().collect();
    assert_eq!(ppids.len(), 2, "expected startup and reparented PPIDs");
    assert_ne!(ppids[0], ppids[1], "agent-bash parent did not change");
    assert_eq!(fs::read(&out).expect("detached stdout"), b"");
    let stderr = fs::read_to_string(&err).expect("detached stderr");
    assert_eq!(
        stderr,
        "agent-bash: must be called as an attached subprocess\n"
    );
}

#[test]
fn run_returns_immediately_and_later_completes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let started = temp.path().join("run-immediate-started");
    let release = temp.path().join("run-immediate-release");
    let release_marker = ReleaseMarker::new(release.clone());
    let script = format!(
        "printf started > {}; attempts=0; while [ \"$attempts\" -lt 400 ]; do if [ -e {} ]; then echo late; exit 0; fi; attempts=$((attempts + 1)); sleep 0.01; done; exit 1",
        started.display(),
        release.display()
    );
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", &script]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    wait_until(FIXTURE_DEADLINE, || started.exists().then_some(()));
    let immediate = status_text(&temp, handle, false);
    assert!(immediate.starts_with("RUNNING handle="), "{immediate}");
    release_marker.release();
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("late\n"), "{final_status}");
}

#[test]
fn cancel_terminates_the_entire_adopted_process_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let child_pid_path = temp.path().join("child.pid");
    let script = format!(
        "trap 'exit 0' TERM; sleep 60 & echo $! > {}; wait",
        child_pid_path.display()
    );
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", &script]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let workload_pid = wait_until(fixture_deadline, || {
        read_meta(&meta_path)["workload_pid"]
            .as_i64()
            .map(|pid| pid as libc::pid_t)
    });
    let child_pid = wait_until(fixture_deadline, || {
        fs::read_to_string(&child_pid_path)
            .ok()?
            .trim()
            .parse::<libc::pid_t>()
            .ok()
    });
    assert_process_alive(workload_pid);
    assert_process_alive(child_pid);

    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    let status = wait_for_terminal_status(&temp, handle);
    assert!(
        status.starts_with(&format!(
            "DONE rc=143 handle={handle} reason=cancel-request"
        )),
        "{status}"
    );
    let meta = read_meta(&meta_path);
    assert_eq!(meta["rc"], 143);
    assert_eq!(meta["signal"], libc::SIGTERM);
    assert_eq!(meta["workload_rc"], 0);
    assert!(meta["workload_signal"].is_null());
    wait_for_process_gone(workload_pid);
    wait_for_process_gone(child_pid);
}

#[test]
fn cancel_immediately_after_run_is_not_lost_during_supervisor_startup() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(&temp, &["run", "--", "sleep", "60"]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");

    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    let status = wait_for_terminal_status(&temp, handle);
    assert!(status.contains("reason=cancel-request"), "{status}");
}

#[test]
fn supervisor_finishes_durable_cancel_without_wakeup_signal() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(&temp, &["run", "--", "sleep", "60"]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let state_dir = state_dir_path(&json);
    wait_until(FIXTURE_DEADLINE, || {
        read_meta(&meta_path(&json))["supervisor_pid"]
            .is_number()
            .then_some(())
    });
    let marker = state_dir.join("cancel-requested");
    let file = fs::File::create(&marker).expect("create accepted cancel marker");
    file.sync_all().expect("sync accepted cancel marker");
    fs::File::open(&state_dir)
        .expect("open state dir")
        .sync_all()
        .expect("sync state dir");

    let status = wait_for_terminal_status(&temp, handle);
    assert!(status.contains("reason=cancel-request"), "{status}");
}

#[test]
fn cancel_without_a_live_exact_supervisor_is_an_idempotent_noop() {
    let temp = tempfile::tempdir().expect("tempdir");
    let handle = "ab_cancel_missing_supervisor";
    let meta = active_state_meta(handle, unsafe { libc::getpid() }, json!([]));
    seed_active_state_dir(&temp, handle, &meta);

    for _ in 0..2 {
        let output = agent_bash(&temp)
            .args(["cancel", handle])
            .output()
            .expect("cancel missing supervisor");
        assert_command_success(&output);
        assert_eq!(parse_stdout_json(&output)["requested"], false);
    }

    let state_dir = temp.path().join("agent-bash").join(handle);
    assert_eq!(read_meta(&state_dir.join("meta.json"))["state"], "RUNNING");
    assert!(!state_dir.join("cancel-requested").exists());
}

#[test]
fn cancel_rejects_a_live_pid_with_stale_supervisor_identity() {
    let temp = tempfile::tempdir().expect("tempdir");
    let ready = temp.path().join("stale-supervisor-ready");
    let signaled = temp.path().join("stale-supervisor-signaled");
    let mut process = StdCommand::new("bash")
        .args([
            "-c",
            "trap ': > \"$SIGNALED\"' USR1; : > \"$READY\"; sleep 60",
        ])
        .env("READY", &ready)
        .env("SIGNALED", &signaled)
        .spawn()
        .expect("spawn stale-identity process");
    wait_until(FIXTURE_DEADLINE, || ready.exists().then_some(()));
    let pid = process.id() as libc::pid_t;
    let (identity, _) = proc_identity(pid).expect("live process identity");
    let handle = "ab_cancel_stale_supervisor";
    let mut meta = active_state_meta(handle, unsafe { libc::getpid() }, json!([]));
    meta["supervisor_pid"] = json!(pid);
    meta["supervisor_pid_starttime_ticks"] = json!(identity.starttime_ticks + 1);
    meta["process_boot_id"] = json!(read_boot_id());
    seed_active_state_dir(&temp, handle, &meta);

    let output = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel stale supervisor");

    assert_command_success(&output);
    assert_eq!(parse_stdout_json(&output)["requested"], false);
    assert!(!signaled.exists(), "stale supervisor identity was signaled");
    assert!(
        !temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("cancel-requested")
            .exists()
    );
    process.kill().expect("kill stale-identity process");
    process.wait().expect("reap stale-identity process");
}

#[test]
fn accepted_cancel_is_owned_by_guardian_after_supervisor_loss() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let (fake, delivery_log) = fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "sleep", "60"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let running = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    let workload = OwnedProcess::capture_workload(&running).expect("capture workload");
    let supervisor = OwnedProcess::capture_supervisor(&running).expect("capture supervisor");
    let stopped = StoppedProcess::stop(&supervisor);

    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    assert!(supervisor.signal(libc::SIGKILL), "kill exact supervisor");
    drop(stopped);

    let terminal = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        (meta["completion_reason"] == "cancel-request" && meta["delivery"]["exit_code"] == 0)
            .then_some(meta)
    });
    assert_eq!(terminal["state"], "DONE");
    assert_eq!(terminal["rc"], 143);
    assert_eq!(terminal["signal"], libc::SIGTERM);
    assert!(workload.exited(), "guardian did not terminate workload");
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
}

#[test]
fn accepted_cancel_precedes_already_pending_workload_completion() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let release = temp.path().join("cancel-completion-release");
    let output = agent_bash(&temp)
        .env("RELEASE", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let running = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    let supervisor = OwnedProcess::capture_supervisor(&running).expect("capture supervisor");
    let workload = OwnedProcess::capture_workload(&running).expect("capture workload");
    let mut stopped = StoppedProcess::stop(&supervisor);

    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    fs::write(&release, b"").expect("release workload");
    wait_until(fixture_deadline, || workload.exited().then_some(()));
    assert!(stopped.resume(), "resume supervisor");

    let status = wait_for_terminal_status(&temp, handle);
    assert!(
        status.starts_with(&format!(
            "DONE rc=143 handle={handle} reason=cancel-request"
        )),
        "{status}"
    );
    assert_eq!(read_meta(&meta_path)["workload_rc"], 0);
}

#[test]
fn guardian_escalates_accepted_cancel_for_term_resistant_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let child_pid_path = temp.path().join("term-resistant-child.pid");
    let script = format!(
        "trap '' TERM; sleep 60 & echo $! > {}; wait",
        child_pid_path.display()
    );
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", &script]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let running = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    let workload = OwnedProcess::capture_workload(&running).expect("capture workload");
    let supervisor = OwnedProcess::capture_supervisor(&running).expect("capture supervisor");
    let child_pid = wait_until(fixture_deadline, || {
        fs::read_to_string(&child_pid_path)
            .ok()?
            .trim()
            .parse::<libc::pid_t>()
            .ok()
    });
    let stopped = StoppedProcess::stop(&supervisor);
    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    assert!(supervisor.signal(libc::SIGKILL), "kill exact supervisor");
    drop(stopped);

    let started = Instant::now();
    let status = wait_for_terminal_status(&temp, handle);
    assert!(status.contains("reason=cancel-request"), "{status}");
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "guardian did not observe cancellation grace"
    );
    wait_until(fixture_deadline, || workload.exited().then_some(()));
    wait_for_process_gone(child_pid);
}

#[test]
fn owner_exit_cancels_opted_in_workload_and_descendants() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let child_pid_path = temp.path().join("owner-child.pid");
    let workload_script = format!(
        "trap 'exit 0' TERM; sleep 60 & echo $! > {}; wait",
        child_pid_path.display()
    );
    let binary = assert_cmd::cargo::cargo_bin("agent-bash");
    let launcher_script = format!(
        "\"{}\" run --cancel-on-owner-exit --owner-pid \"$BASHPID\" -- bash -lc \"$WORKLOAD_SCRIPT\"; rc=$?; for _ in {{1..250}}; do [ -s \"$CHILD_PID_PATH\" ] && break; sleep 0.02; done; exit $rc",
        binary.display()
    );
    let output = StdCommand::new("bash")
        .args(["-c", &launcher_script])
        .env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("WORKLOAD_SCRIPT", workload_script)
        .env("CHILD_PID_PATH", &child_pid_path)
        .env_remove("OULIPOLY_PARENT_INVOCATION")
        .env_remove("OULIPOLY_DATA_DIR")
        .output()
        .expect("owner launcher");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let meta = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    assert_eq!(meta["cancel_owner"]["pid"], meta["caller_ppid"]);
    let workload_pid = meta["workload_pid"].as_i64().expect("workload pid") as libc::pid_t;
    let child_pid = wait_until(fixture_deadline, || {
        fs::read_to_string(&child_pid_path)
            .ok()?
            .trim()
            .parse::<libc::pid_t>()
            .ok()
    });

    let status = wait_for_terminal_status(&temp, handle);
    assert!(
        status.starts_with(&format!("DONE rc=143 handle={handle} reason=owner-exit")),
        "{status}"
    );
    let meta = read_meta(&meta_path);
    assert_eq!(meta["rc"], 143);
    assert_eq!(meta["signal"], libc::SIGTERM);
    assert_eq!(meta["workload_rc"], 0);
    assert!(meta["workload_signal"].is_null());
    wait_for_process_gone(workload_pid);
    wait_for_process_gone(child_pid);
}

#[test]
fn explicit_cancel_wins_when_owner_exit_is_already_pollable() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_json_path = temp.path().join("owner-race-run.json");
    let owner_ready = temp.path().join("owner-race-ready");
    let fixture_deadline = FIXTURE_DEADLINE;
    let binary = assert_cmd::cargo::cargo_bin("agent-bash");
    let launcher_script = format!(
        "\"{}\" run --cancel-on-owner-exit --owner-pid \"$BASHPID\" -- sleep 60 > \"$RUN_JSON\"; : > \"$OWNER_READY\"; read -r _",
        binary.display()
    );
    let mut owner = StdCommand::new("bash")
        .args(["-c", &launcher_script])
        .stdin(Stdio::piped())
        .env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("RUN_JSON", &run_json_path)
        .env("OWNER_READY", &owner_ready)
        .env_remove("OULIPOLY_PARENT_INVOCATION")
        .env_remove("OULIPOLY_DATA_DIR")
        .spawn()
        .expect("owner launcher");
    wait_until(fixture_deadline, || owner_ready.exists().then_some(()));
    let run_json: Value = serde_json::from_slice(&fs::read(&run_json_path).expect("run JSON"))
        .expect("parse run JSON");
    let handle = run_json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&run_json);
    let supervisor_pid = wait_until(fixture_deadline, || {
        read_meta(&meta_path)["supervisor_pid"]
            .as_i64()
            .map(|pid| pid as libc::pid_t)
    });

    let supervisor =
        OwnedProcess::capture_current(supervisor_pid, None).expect("capture supervisor process");
    let mut stopped_supervisor = StoppedProcess::stop(&supervisor);
    let cancel = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("cancel command");
    owner
        .stdin
        .take()
        .expect("owner stdin")
        .write_all(b"release\n")
        .expect("release owner");
    let owner_status = owner.wait().expect("reap owner");
    let continued = stopped_supervisor.resume();

    assert!(continued, "continue supervisor");
    assert!(owner_status.success(), "owner status: {owner_status:?}");
    assert_command_success(&cancel);
    assert_eq!(parse_stdout_json(&cancel)["requested"], true);
    let status = wait_for_terminal_status(&temp, handle);
    assert!(
        status.starts_with(&format!(
            "DONE rc=143 handle={handle} reason=cancel-request"
        )),
        "{status}"
    );

    let repeated = agent_bash(&temp)
        .args(["cancel", handle])
        .output()
        .expect("repeated cancel command");
    assert_command_success(&repeated);
    assert_eq!(parse_stdout_json(&repeated)["requested"], false);
}

#[test]
fn run_startup_reaps_old_consumed_state_dir_without_stdout_pollution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old = seed_done_state_dir(&temp, "ab_old_consumed", unix_ms() - 2_000, true);

    let output = agent_bash(&temp)
        .env("AGENT_BASH_STATE_TTL_SECS", "1")
        .env("AGENT_BASH_STATE_REAP_MAX_DIRS", "1")
        .env("AGENT_BASH_STATE_REAP_SHARDS", "1")
        .args(["run", "--", "bash", "-lc", "true"])
        .output()
        .expect("run");

    let json = parse_run_output(&output);
    assert!(json["handle"].as_str().expect("handle").starts_with("ab_"));
    assert!(!old.exists(), "old state dir should be reaped");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("state reaper"), "{stderr}");
    assert!(stderr.contains("reaped=1"), "{stderr}");
}

#[test]
fn exit_mode_completion_rc_and_captured_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(
        &temp,
        &["run", "--", "bash", "-lc", "echo out; echo err >&2; exit 7"],
    );
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=7 handle={handle}"));
    assert!(final_status.contains("out\n"), "{final_status}");
    assert!(final_status.contains("err\n"), "{final_status}");
    assert_eq!(fs::read_to_string(rc_path(&json)).expect("rc"), "7\n");
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["state"], "DONE");
    assert_eq!(meta["completion_reason"], "exit");
    assert_eq!(meta["rc"], 7);
    let caller_chain = meta["caller_chain"].as_array().expect("caller chain");
    let expected_boot_id = read_boot_id();
    assert!(meta["supervisor_pid_starttime_ticks"].is_number());
    assert!(meta["workload_pid_starttime_ticks"].is_number());
    assert_eq!(meta["process_boot_id"], expected_boot_id);
    let expected_chain = proc_ancestry(unsafe { libc::getpid() });
    assert!(
        expected_chain.len() > 1,
        "expected current process to have ancestry beyond itself"
    );
    assert_eq!(
        caller_chain.len(),
        expected_chain.len(),
        "full caller chain"
    );
    assert_eq!(caller_chain[0]["pid"], json["caller_ppid"]);
    for (entry, expected) in caller_chain.iter().zip(expected_chain) {
        assert_eq!(entry["pid"], expected.pid);
        assert_eq!(entry["starttime_ticks"], expected.starttime_ticks);
        assert!(expected.pid > 0, "caller-chain pid must be positive");
        assert!(
            expected.starttime_ticks > 0,
            "caller-chain starttime_ticks must be positive"
        );
        assert_eq!(entry["boot_id"], expected_boot_id);
        assert!(!expected_boot_id.is_empty(), "boot_id must be non-empty");
    }
}

#[test]
fn captured_log_is_bounded_and_retains_newest_output() {
    let temp = tempfile::tempdir().expect("tempdir");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_LOG_MAX_BYTES", "65536")
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "head -c 200000 /dev/zero | tr '\\0' x; printf 'tail-marker\\n'",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));

    let log = fs::read(json["log"].as_str().expect("log path")).expect("read log");
    assert!(log.len() <= 65_536, "retained {} bytes", log.len());
    assert!(
        log.windows(b"[agent-bash log truncated".len())
            .any(|window| window == b"[agent-bash log truncated")
    );
    assert!(log.ends_with(b"tail-marker\n"));
}

#[test]
fn ready_sentinel_reports_done_without_killing_workload() {
    let temp = tempfile::tempdir().expect("tempdir");
    let child_pid_path = temp.path().join("sentinel-child.pid");
    let workload_release = temp.path().join("sentinel-workload-release");
    let release_marker = ReleaseMarker::new(workload_release.clone());
    let mut command = agent_bash(&temp);
    command
        .env("SENTINEL_CHILD_PID_PATH", &child_pid_path)
        .env("SENTINEL_WORKLOAD_RELEASE", &workload_release)
        .args([
            "run",
            "--ready-sentinel",
            "READY:[0-9]+",
            "--",
            "bash",
            "-lc",
            "echo boot; echo READY:123; bash -lc 'attempts=0; while [ \"$attempts\" -lt 2000 ]; do [ -e \"$SENTINEL_WORKLOAD_RELEASE\" ] && exit 0; attempts=$((attempts + 1)); sleep 0.01; done; exit 1' & echo $! > \"$SENTINEL_CHILD_PID_PATH\"; wait",
        ]);
    let output = command.output().expect("run sentinel workload");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(
        &temp,
        handle,
        &format!("DONE rc=0 handle={handle} reason=ready-sentinel workload=running"),
    );
    let meta = read_meta(&meta_path(&json));
    let workload_pid = meta["workload_pid"].as_i64().expect("workload pid") as libc::pid_t;
    let child_pid = wait_until(FIXTURE_DEADLINE, || {
        fs::read_to_string(&child_pid_path)
            .ok()?
            .trim()
            .parse::<libc::pid_t>()
            .ok()
    });
    let workload_alive = unsafe { libc::kill(workload_pid, 0) == 0 };
    let child_alive = unsafe { libc::kill(child_pid, 0) == 0 };

    assert_eq!(json["mode"], "sentinel");
    assert!(final_status.contains("boot\n"), "{final_status}");
    assert!(final_status.contains("READY:123\n"), "{final_status}");
    assert_eq!(meta["completion_reason"], "ready-sentinel");
    assert_eq!(meta["rc"], 0);
    assert!(meta["ready_at_unix_ms"].is_number());
    assert!(meta["workload_rc"].is_null());
    assert!(workload_alive, "sentinel workload was not running");
    assert!(child_alive, "sentinel child was not running");

    release_marker.release();
    wait_for_process_gone(workload_pid);
    wait_for_process_gone(child_pid);
}

#[test]
fn tree_capture_waits_for_setsid_detached_grandchild_via_subreaper() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("grandchild-marker");
    let script =
        "(setsid sh -c 'sleep 2; printf grandchild > \"$MARKER\"' >/dev/null 2>&1 &) ; exit 0";
    let mut cmd = agent_bash(&temp);
    cmd.env("MARKER", &marker)
        .args(["run", "--", "bash", "-lc", script]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);

    wait_until(Duration::from_millis(1500), || {
        let meta = read_meta(&meta_path);
        if meta["workload_rc"].as_i64() == Some(0) {
            Some(())
        } else {
            None
        }
    });
    assert!(
        !marker.exists(),
        "grandchild marker appeared before root-only window"
    );
    let running = status_text(&temp, handle, false);
    assert!(running.starts_with("RUNNING handle="), "{running}");

    wait_until(FIXTURE_DEADLINE, || marker.exists().then_some(()));
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.starts_with(&format!("DONE rc=0 handle={handle}")));
    let meta = read_meta(&meta_path);
    assert!(matches!(
        meta["cgroup"]["mode"].as_str(),
        Some("subreaper-only" | "v2")
    ));
}

#[test]
fn root_completion_does_not_wait_for_setsid_detached_grandchild() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join("root-completion-grandchild-marker");
    let ready = temp.path().join("root-completion-grandchild-ready");
    let release = temp.path().join("root-completion-grandchild-release");
    let release_marker = ReleaseMarker::new(release.clone());
    let script = r#"(setsid bash -lc '
        printf ready > "$GRANDCHILD_READY"
        for _ in {1..800}; do
            if [ -e "$GRANDCHILD_RELEASE" ]; then
                printf grandchild > "$MARKER"
                exit 0
            fi
            sleep 0.01
        done
        exit 1
    ' >/dev/null 2>&1 &) ; exit 0"#;
    let mut cmd = agent_bash(&temp);
    cmd.env("MARKER", &marker)
        .env("GRANDCHILD_READY", &ready)
        .env("GRANDCHILD_RELEASE", &release)
        .args([
            "run",
            "--completion-scope",
            "root",
            "--",
            "bash",
            "-lc",
            script,
        ]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");

    wait_until(FIXTURE_DEADLINE, || ready.exists().then_some(()));
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.starts_with(&format!("DONE rc=0 handle={handle}")));
    assert!(
        !marker.exists(),
        "root completion waited for the detached grandchild"
    );

    release_marker.release();
    wait_until(FIXTURE_DEADLINE, || marker.exists().then_some(()));
}

#[test]
fn cgroup_v2_live_set_path_runs_when_delegated_and_skips_otherwise() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", "sleep 1.5"]);
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    if meta["cgroup"]["mode"] == "subreaper-only" {
        return;
    }
    assert_eq!(meta["cgroup"]["mode"], "v2");
    assert_eq!(meta["cgroup"]["delegated"], true);
    assert_eq!(meta["cgroup"]["events_watch"], true);
    let cgroup_path = PathBuf::from(meta["cgroup"]["path"].as_str().expect("cgroup path"));
    let procs = fs::read_to_string(cgroup_path.join("cgroup.procs")).expect("cgroup.procs");
    let workload_pid = meta["workload_pid"]
        .as_i64()
        .expect("workload pid")
        .to_string();
    assert!(procs.lines().any(|line| line == workload_pid));
}

#[test]
fn cgroup_disable_uses_subreaper_only_without_degradation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_DISABLE_CGROUP", "1")
        .args(["run", "--", "bash", "-lc", "echo ok"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("ok\n"));
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["cgroup"]["mode"], "subreaper-only");
    assert!(meta["cgroup"]["degraded_reason"].is_null());
}

#[test]
fn opencode_adapter_poll_marks_terminal_result_consumed_without_mutating_delivery_mode() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(
        &temp,
        &["run", "--", "bash", "-lc", "printf 'adapter poll\\n'"],
    );
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("adapter poll\n"), "{final_status}");

    let driver = write_adapter_driver(&temp);
    let result = run_adapter_driver(&temp, &driver, "poll", Some(handle));

    assert_adapter_result_contains(&result, "adapter poll");
    assert_eq!(mode_text(&temp, handle), "async");
    assert!(state_dir_path(&json).join("consumed").exists());
}

#[test]
fn opencode_adapter_binds_exact_live_session_once_before_parallel_dispatch() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let (result, report) = run_adapter_driver_with_live_binding(&temp, &driver, "parallel-live");

    assert_adapter_result_contains(&result, "first live command");
    assert_adapter_result_contains(&result, "second live command");
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["token"], "fixture-token");
    assert_eq!(
        report["invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(report["provider_session_id"], "ses_adapter");
}

#[test]
fn opencode_adapter_does_not_propagate_consumed_live_binding_to_workloads() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let (result, report) = run_adapter_driver_with_live_binding(&temp, &driver, "binding-env");

    assert_adapter_result_contains(&result, "unset|unset");
    assert_eq!(report["provider_session_id"], "ses_adapter");
}

#[test]
fn opencode_adapter_recovers_from_inherited_removed_live_binding() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver_with_stale_live_binding(&temp, &driver, "binding-env");

    assert_adapter_result_contains(&result, "unset|unset");
}

#[test]
fn opencode_adapter_ordinary_command_completes_in_band_in_sync_mode() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "run", None);

    assert_adapter_result_contains(&result, "adapter inline");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "sync");
    let meta_path = temp
        .path()
        .join("agent-bash")
        .join(handle)
        .join("meta.json");
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["attempted"] == true
            && meta["delivery"]["error_code"] != "delivery_attempt_in_progress")
            .then_some(meta)
    });
    assert_eq!(meta["delivery_mode"], "sync");
    assert!(meta["cancel_owner"]["pid"].is_number());
    assert_eq!(meta["owner_session_id"], "ses_adapter");
    assert_eq!(
        meta["owner_invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
    let owner = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("owner.json"),
    );
    assert_eq!(owner["owner_session_id"], "ses_adapter");
    assert_eq!(
        owner["owner_invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
}

#[test]
fn opencode_adapter_initial_dispatch_uses_verified_parent_session() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let mut command = adapter_driver_command(&temp, &driver, "run", None);
    let output = command
        .env("AGENT_BASH_FAKE_RESOLVED_SESSION", "ses_parent")
        .env("AGENT_BASH_FAKE_RESOLVER_DELAY", "2.2")
        .env(
            "AGENT_BASH_FAKE_FIRST_MISS_MARKER",
            temp.path().join("first-owner-lookup-missed"),
        )
        .output()
        .expect("adapter driver");
    assert_command_success(&output);
    let result = parse_stdout_json(&output);
    let handle = adapter_result_handle(&result);
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );

    assert_eq!(meta["owner_session_id"], "ses_parent");
    assert_eq!(
        meta["owner_invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
}

#[test]
fn opencode_adapter_initial_dispatch_preserves_inherited_environment() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let mut command = adapter_driver_command(&temp, &driver, "inherited-env", None);
    let output = command
        .env("INHERITED_ENV_SENTINEL", "fixture-env")
        .env(
            "OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY",
            "fixture-authority",
        )
        .output()
        .expect("adapter driver");
    assert_command_success(&output);
    let result = parse_stdout_json(&output);

    assert_adapter_result_contains(
        &result,
        "fixture-env|fixture-authority|{\"source\":\"opencode\",\"id\":\"11111111-1111-4111-8111-111111111111\"}",
    );
}

#[test]
fn opencode_adapter_polling_stops_when_helper_path_disappears() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "move-helper", None);

    assert_eq!(result["kind"], "error");
    assert!(
        result["result"]
            .as_str()
            .is_some_and(|message| message.contains("ENOENT")),
        "{result}"
    );
}

#[test]
fn opencode_adapter_standalone_sleep_does_not_create_spool_state() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "sleep", None);

    assert_eq!(adapter_result_text(&result), "DONE rc=0\n--- output ---");
    assert!(
        !temp.path().join("agent-bash").exists(),
        "standalone sleep must not create agent-bash state"
    );
}

#[test]
fn list_adopts_handle_owned_by_resumed_session_after_caller_pid_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let state_dir = seed_done_state_dir(&temp, "ab_resumed_owner", unix_ms(), false);
    let meta_path = state_dir.join("meta.json");
    let mut meta = read_meta(&meta_path);
    meta["caller_ppid"] = json!(i32::MAX);
    fs::write(&meta_path, format_seeded_meta(&meta)).expect("write resumed owner meta");
    fs::write(
        state_dir.join("owner.json"),
        r#"{"owner_session_id":"ses_resumed","owner_invocation_uuid":"11111111-1111-4111-8111-111111111111"}"#,
    )
    .expect("write durable owner");

    let matching = agent_bash(&temp)
        .env("AGENT_BASH_OWNER_SESSION_ID", "ses_resumed")
        .args(["list", "--json"])
        .output()
        .expect("matching list");
    assert_command_success(&matching);
    let matching = parse_stdout_json(&matching);
    assert_eq!(matching.as_array().expect("list").len(), 1);
    assert_eq!(matching[0]["handle"], "ab_resumed_owner");

    let other = agent_bash(&temp)
        .env("AGENT_BASH_OWNER_SESSION_ID", "ses_other")
        .args(["list", "--json"])
        .output()
        .expect("other list");
    assert_command_success(&other);
    assert_eq!(parse_stdout_json(&other), json!([]));
}

#[test]
fn opencode_adapter_explicit_async_returns_handle_immediately() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let started = temp.path().join("adapter-async-started");
    let release = temp.path().join("adapter-async-release");
    let release_marker = ReleaseMarker::new(release);

    let result = run_adapter_driver(&temp, &driver, "async", None);

    wait_until(FIXTURE_DEADLINE, || started.exists().then_some(()));
    assert_adapter_result_contains(&result, "Running asynchronously");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "async");
    release_marker.release();
    let status = wait_for_terminal_status(&temp, handle);
    assert!(
        status.starts_with(&format!("DONE rc=0 handle={handle}")),
        "{status}"
    );
    assert!(status.contains("adapter async\n"), "{status}");
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert!(meta["cancel_owner"].is_null());
}

#[test]
fn opencode_adapter_abort_signal_cancels_sync_workload() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "abort", None);

    assert_adapter_result_contains(&result, "Cancellation requested");
    let handle = adapter_result_handle(&result);
    let state_dir = temp.path().join("agent-bash").join(handle);
    let meta = read_meta(&state_dir.join("meta.json"));
    assert!(
        adapter_result_text(&result).contains(r#""requested":true"#),
        "{}\nmeta={meta}\naccepted_cancel={}",
        adapter_result_text(&result),
        state_dir.join("cancel-requested").exists()
    );
    let status = wait_for_terminal_status(&temp, handle);
    assert!(status.contains("reason=cancel-request"), "{status}");
}

#[test]
fn opencode_adapter_agent_dispatch_defaults_to_async() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "agent", None);

    assert_adapter_result_contains(&result, "Running asynchronously");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "async");
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert!(
        meta["argv"].as_array().expect("argv").iter().any(|arg| arg
            .as_str()
            .is_some_and(|arg| arg.contains("owner-resolving-fake-agents"))),
        "configured agent-runner binary was not pinned: {}",
        meta["argv"]
    );
}

#[test]
fn opencode_adapter_explicit_agent_bash_run_is_not_nested() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "wrapper", None);

    assert_adapter_result_contains(&result, "Running asynchronously");
    assert_eq!(state_handles(&temp), vec![adapter_result_handle(&result)]);
}

#[test]
fn opencode_adapter_environment_prefixed_agent_bash_run_is_not_nested() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "wrapper-env", None);

    assert_adapter_result_contains(&result, "Running asynchronously");
    let handle = adapter_result_handle(&result);
    assert_eq!(state_handles(&temp), vec![handle]);
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert!(meta["cancel_owner"].is_null());
}

#[test]
fn opencode_adapter_headless_agent_dispatch_forces_async_delivery() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "agent-sync", None);

    assert_adapter_result_contains(&result, "Running asynchronously");
    assert_adapter_result_contains(&result, "End this headless turn now");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "async");
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert!(meta["cancel_owner"].is_null());
}

#[test]
fn opencode_adapter_sync_wait_returns_when_handle_is_detached() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let started = temp.path().join("adapter-detachable-started");
    let release = temp.path().join("adapter-detachable-release");
    let release_marker = ReleaseMarker::new(release);
    let mut adapter = adapter_driver_command(&temp, &driver, "detachable", None)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adapter driver");
    let handle = wait_until(FIXTURE_DEADLINE, || initialized_state_handle(&temp));
    wait_until(FIXTURE_DEADLINE, || started.exists().then_some(()));
    assert_eq!(mode_text(&temp, &handle), "sync");

    let detach = agent_bash(&temp)
        .args(["detach", &handle])
        .output()
        .expect("detach command");
    assert_command_success(&detach);
    assert_eq!(parse_stdout_json(&detach)["transitioned"], true);
    let stdout = adapter.stdout.take().expect("adapter stdout");
    let line = BufReader::new(stdout)
        .lines()
        .next()
        .expect("adapter result line")
        .expect("adapter result");
    let result: Value = serde_json::from_str(&line).expect("adapter result json");

    assert_adapter_result_contains(&result, "Running asynchronously");
    assert_eq!(adapter_result_handle(&result), handle);
    release_marker.release();
    let final_status = wait_for_terminal_status(&temp, &handle);
    assert!(
        final_status.starts_with(&format!("DONE rc=0 handle={handle}")),
        "{final_status}"
    );
    assert!(
        final_status.contains("adapter detached\n"),
        "{final_status}"
    );
    assert!(adapter.wait().expect("adapter exit").success());
}

#[test]
fn rca_agent_bash_visibility_opencode_list_control_does_not_spool() {
    // Verifies that OpenCode executes agent-bash list as a control command without creating a workload.
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let command = format!(
        "{} list --all --json",
        temp.path().join("adapter-agent-bash").display()
    );

    let configured_result = run_adapter_driver(&temp, &driver, "control", Some(&command));
    let bare_result = run_adapter_driver(
        &temp,
        &driver,
        "control",
        Some("agent-bash list --json --all"),
    );

    assert_eq!(
        state_dir_count(&temp),
        0,
        "OpenCode list control created nested spool state; configured result={}; bare result={}",
        adapter_result_text(&configured_result),
        adapter_result_text(&bare_result)
    );
    for result in [&configured_result, &bare_result] {
        let listed: Vec<Value> =
            serde_json::from_str(adapter_result_text(result)).expect("direct list JSON result");
        assert!(listed.is_empty(), "isolated state should list empty");
    }
}

#[test]
fn rca_agent_bash_visibility_persistent_adapter_lists_owned_active_workload() {
    // Verifies launch and direct default-list ownership through one persistent adapter process.
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "joint", None);
    let handle = result["launchedHandle"]
        .as_str()
        .expect("joint launched handle");
    let launched = result["launchedResult"]
        .as_str()
        .expect("joint launched result");
    let listed: Vec<Value> =
        serde_json::from_str(result["listResult"].as_str().expect("joint list result"))
            .expect("joint list JSON");

    assert!(launched.contains("Running asynchronously"), "{launched}");
    assert!(
        listed
            .iter()
            .any(|entry| entry["handle"] == handle && entry["state"] == "RUNNING"),
        "persistent adapter did not list its active workload {handle}: {listed:?}"
    );
    assert_eq!(
        state_dir_count(&temp),
        1,
        "direct list created a second workload state directory"
    );

    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(
        final_status.contains("adapter joint done\n"),
        "{final_status}"
    );
}

#[test]
fn rca_agent_bash_visibility_non_list_only_commands_still_spool() {
    // Verifies that shell operators and incidental list text cannot enter the control path.
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);
    let compound = format!(
        "{} list --json; printf 'compound marker\\n'",
        assert_cmd::cargo::cargo_bin("agent-bash").display()
    );

    let compound_result = run_adapter_driver(&temp, &driver, "control", Some(&compound));
    assert_adapter_result_contains(&compound_result, "compound marker");
    assert_eq!(
        state_dir_count(&temp),
        1,
        "compound command was not spooled"
    );
    assert!(
        adapter_result_text(&compound_result).starts_with("DONE rc=0"),
        "compound workload did not complete through the adapter"
    );

    let incidental_result = run_adapter_driver(
        &temp,
        &driver,
        "control",
        Some("printf '%s\\n' 'agent-bash list --json'"),
    );
    assert_adapter_result_contains(&incidental_result, "agent-bash list --json");
    assert_eq!(
        state_dir_count(&temp),
        2,
        "incidental list text was not spooled"
    );
    assert!(
        adapter_result_text(&incidental_result).starts_with("DONE rc=0"),
        "incidental-text workload did not complete through the adapter"
    );
}

#[test]
fn rca_agent_bash_visibility_process_tree_owner_isolated_unless_all() {
    // Verifies owner-tree visibility and unrelated-caller isolation at the real CLI/process seam.
    let temp = tempfile::tempdir().expect("tempdir");
    let mut owner = spawn_releasable_owner_scenario(&temp);
    wait_until(FIXTURE_DEADLINE, || owner.ready.exists().then_some(()));
    let run_json: Value =
        serde_json::from_slice(&fs::read(&owner.run_json).expect("owner run JSON"))
            .expect("owner run JSON value");
    let handle = run_json["handle"].as_str().expect("handle").to_string();
    let meta = read_meta(&meta_path(&run_json));
    let owner_meta: Value = serde_json::from_slice(
        &fs::read(Path::new(run_json["state_dir"].as_str().expect("state dir")).join("owner.json"))
            .expect("owner metadata"),
    )
    .expect("owner metadata JSON");
    assert!(meta["owner_session_id"].is_null(), "{meta}");
    assert!(meta["owner_invocation_uuid"].is_null(), "{meta}");
    assert!(owner_meta["owner_session_id"].is_null(), "{owner_meta}");
    assert!(
        owner_meta["owner_invocation_uuid"].is_null(),
        "{owner_meta}"
    );
    let active_status = status_text(&temp, &handle, false);
    let unrelated = shell_list_json(&temp, false);
    let all_access = shell_list_json(&temp, true);

    fs::write(&owner.list_now, b"").expect("release owner list");
    let owner_status = owner.wait().expect("owner scenario");
    let owner_list: Vec<Value> =
        serde_json::from_slice(&fs::read(&owner.owner_list).expect("owner list"))
            .expect("owner list JSON");
    let owner_pid = run_json["caller_ppid"].as_i64().expect("owner pid");
    let list_caller_pid: i64 = fs::read_to_string(&owner.list_caller_pid)
        .expect("list caller pid")
        .trim()
        .parse()
        .expect("numeric list caller pid");
    fs::write(&owner.workload_release, b"").expect("release owner workload");
    let final_status =
        wait_for_status_prefix(&temp, &handle, &format!("DONE rc=0 handle={handle}"));

    eprintln!(
        "owner scenario handle={handle} owner_pid={owner_pid} list_caller_pid={list_caller_pid} active_status={active_status:?} owner_list={owner_list:?} unrelated_list={unrelated:?} all_list={all_access:?}"
    );
    assert!(owner_status.success(), "owner scenario failed");
    assert!(
        active_status.starts_with(&format!("RUNNING handle={handle}")),
        "owned workload was not active: {active_status}"
    );
    assert_ne!(
        owner_pid, list_caller_pid,
        "owner listing must execute from a descendant, not the original caller PID"
    );
    assert!(
        owner_list.iter().any(|entry| entry["handle"] == handle),
        "owning process tree could not see active workload {handle}: {owner_list:?}"
    );
    assert!(
        unrelated.iter().all(|entry| entry["handle"] != handle),
        "unrelated caller saw owned workload without --all: {unrelated:?}"
    );
    assert!(
        all_access.iter().any(|entry| entry["handle"] == handle),
        "explicit --all did not expose workload {handle}: {all_access:?}"
    );
    assert!(final_status.contains("--- output ---"));
}

#[test]
fn owner_scenario_drop_terminates_and_reaps_polling_shell() {
    let temp = tempfile::tempdir().expect("tempdir");
    let owner = spawn_owner_scenario(&temp, "1");
    wait_until(FIXTURE_DEADLINE, || owner.ready.exists().then_some(()));
    let run_json: Value =
        serde_json::from_slice(&fs::read(&owner.run_json).expect("owner run JSON"))
            .expect("owner run JSON value");
    let owner_pid = owner.child_pid();

    drop(owner);

    assert!(
        proc_identity(owner_pid).is_none(),
        "owner polling shell was not reaped"
    );
    let handle = run_json["handle"].as_str().expect("handle");
    let _ = wait_for_terminal_status(&temp, handle);
}

#[test]
fn rca_agent_bash_visibility_rejects_reused_pid_identity() {
    // Verifies that stale, absent, or invalid nearest ownership identities fail closed.
    let temp = tempfile::tempdir().expect("tempdir");
    let pid = unsafe { libc::getpid() };
    let (identity, _) = proc_identity(pid).expect("current process identity");
    let boot_id = read_boot_id();
    let stale_start_handle = "ab_rca_stale_start";
    let stale_boot_handle = "ab_rca_stale_boot";
    let empty_chain_handle = "ab_rca_empty_chain";
    let invalid_pid_handle = "ab_rca_invalid_pid";
    let invalid_start_handle = "ab_rca_invalid_start";
    let invalid_boot_handle = "ab_rca_invalid_boot";
    let missing_live_handle = "ab_rca_missing_live";
    let stale_start = active_state_meta(
        stale_start_handle,
        pid,
        json!([{
            "pid": pid,
            "starttime_ticks": identity.starttime_ticks.saturating_add(1),
            "boot_id": boot_id.clone()
        }]),
    );
    let stale_boot = active_state_meta(
        stale_boot_handle,
        pid,
        json!([{
            "pid": pid,
            "starttime_ticks": identity.starttime_ticks,
            "boot_id": "different-boot-id"
        }]),
    );
    let empty_chain = active_state_meta(empty_chain_handle, pid, json!([]));
    let invalid_pid = active_state_meta(
        invalid_pid_handle,
        pid,
        json!([
            {
                "pid": 1,
                "starttime_ticks": 1,
                "boot_id": boot_id.clone()
            },
            {
                "pid": pid,
                "starttime_ticks": identity.starttime_ticks,
                "boot_id": boot_id.clone()
            }
        ]),
    );
    let invalid_start = active_state_meta(
        invalid_start_handle,
        pid,
        json!([{
            "pid": pid,
            "starttime_ticks": 0,
            "boot_id": boot_id.clone()
        }]),
    );
    let invalid_boot = active_state_meta(
        invalid_boot_handle,
        pid,
        json!([{
            "pid": pid,
            "starttime_ticks": identity.starttime_ticks,
            "boot_id": ""
        }]),
    );
    let missing_live = active_state_meta(
        missing_live_handle,
        pid,
        json!([{
            "pid": 999_999,
            "starttime_ticks": 1,
            "boot_id": boot_id
        }]),
    );
    seed_active_state_dir(&temp, stale_start_handle, &stale_start);
    seed_active_state_dir(&temp, stale_boot_handle, &stale_boot);
    seed_active_state_dir(&temp, empty_chain_handle, &empty_chain);
    seed_active_state_dir(&temp, invalid_pid_handle, &invalid_pid);
    seed_active_state_dir(&temp, invalid_start_handle, &invalid_start);
    seed_active_state_dir(&temp, invalid_boot_handle, &invalid_boot);
    seed_active_state_dir(&temp, missing_live_handle, &missing_live);

    let owned = list_json(&temp, false);
    let all_access = list_json(&temp, true);

    assert!(
        owned.is_empty(),
        "unverifiable identities were treated as owned: {owned:?}"
    );
    assert_eq!(all_access.len(), 7, "--all should bypass ownership only");
}

#[test]
fn rca_agent_bash_visibility_many_synthetic_entries_is_bounded() {
    // Verifies that listing thousands of isolated state entries completes within a practical bound.
    const ENTRY_COUNT: usize = 4096;
    const LIST_BOUND: Duration = Duration::from_secs(5);
    let temp = tempfile::tempdir().expect("tempdir");
    for index in 0..ENTRY_COUNT {
        let handle = format!("ab_rca_scale_{index:05}");
        let meta = active_state_meta(&handle, 999_999, json!([]));
        seed_active_state_dir(&temp, &handle, &meta);
    }

    let start = Instant::now();
    let listed = list_json(&temp, true);
    let elapsed = start.elapsed();

    assert_eq!(listed.len(), ENTRY_COUNT);
    assert!(
        elapsed < LIST_BOUND,
        "listing {ENTRY_COUNT} synthetic entries took {elapsed:?}, bound is {LIST_BOUND:?}"
    );
    eprintln!("listed {ENTRY_COUNT} synthetic entries in {elapsed:?}");
}

#[test]
fn concurrent_registrations_share_warm_cache_within_declared_bound() {
    const CONCURRENCY: usize = 8;
    const ADMISSION_BOUND: Duration = Duration::from_secs(8);

    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let helper_size = fs::metadata(&fake).expect("helper metadata").len();
    let warmup = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "true"])
        .output()
        .expect("warm helper cache");
    let _ = parse_run_output(&warmup);

    let started = Instant::now();
    let mut registrations = Vec::new();
    for _ in 0..CONCURRENCY {
        let binary = assert_cmd::cargo::cargo_bin("agent-bash");
        let root = temp.path().to_path_buf();
        let fake = fake.clone();
        let delivery_log = delivery_log.clone();
        registrations.push(std::thread::spawn(move || {
            StdCommand::new(binary)
                .env("XDG_STATE_HOME", root)
                .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
                .env("AGENT_BASH_FAKE_DELIVERY_LOG", delivery_log)
                .env_remove("OULIPOLY_PARENT_INVOCATION")
                .env_remove("OULIPOLY_DATA_DIR")
                .args(["run", "--", "true"])
                .output()
                .expect("parallel registration")
        }));
    }
    for output in registrations
        .into_iter()
        .map(|registration| registration.join().expect("registration thread"))
    {
        let _ = parse_run_output(&output);
    }
    let elapsed = started.elapsed();
    assert!(
        elapsed < ADMISSION_BOUND,
        "{CONCURRENCY} warm-cache registrations of a {helper_size}-byte helper took {elapsed:?}, bound is {ADMISSION_BOUND:?}"
    );
    eprintln!(
        "{CONCURRENCY} warm-cache registrations of a {helper_size}-byte helper completed in {elapsed:?}"
    );
}

#[test]
fn missing_explicit_owner_resolves_verified_parent_invocation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fake = owner_resolving_fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
        .env_remove("AGENT_BASH_OWNER_SESSION_ID")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            r#"{"source":"opencode","id":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .args(["run", "--", "bash", "-lc", "printf 'resolved owner\\n'"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let meta = read_meta(&meta_path(&json));

    assert_eq!(meta["owner_session_id"], "ses_resolved");
    assert_eq!(
        meta["owner_invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
}

#[test]
fn partial_explicit_owner_fails_closed_with_runner_detail() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, resolver_log) = registration_rejecting_fake_agents(&temp);
    let workload_marker = temp.path().join("workload-started");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
        .env("AGENT_BASH_FAKE_RESOLVER_LOG", &resolver_log)
        .env("AGENT_BASH_OWNER_SESSION_ID", "ses_partial")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            r#"{"source":"opencode","id":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            &format!("touch {}", workload_marker.display()),
        ])
        .output()
        .expect("run");

    assert_eq!(output.status.code(), Some(74));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("runner exited with 74: {\"status\":\"notification_event_error\"")
            && stderr.contains("owner_session_id and owner_invocation_uuid are both required"),
        "{stderr}"
    );
    assert!(
        !resolver_log.exists(),
        "partial owner must not use fallback resolution"
    );
    assert!(
        !workload_marker.exists(),
        "workload launched after rejected registration"
    );
    assert_eq!(
        state_dir_count(&temp),
        0,
        "rejected registration leaked state"
    );
}

#[test]
fn resolved_owner_must_match_parent_invocation_marker() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, resolver_log) = registration_rejecting_fake_agents(&temp);
    let workload_marker = temp.path().join("workload-started");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
        .env("AGENT_BASH_FAKE_RESOLVER_LOG", &resolver_log)
        .env_remove("AGENT_BASH_OWNER_SESSION_ID")
        .env_remove("AGENT_BASH_OWNER_INVOCATION_UUID")
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            r#"{"source":"opencode","id":"22222222-2222-4222-8222-222222222222"}"#,
        )
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            &format!("touch {}", workload_marker.display()),
        ])
        .output()
        .expect("run");

    assert_eq!(output.status.code(), Some(74));
    assert!(
        resolver_log.exists(),
        "verified PID lookup was not attempted"
    );
    assert!(
        !workload_marker.exists(),
        "workload launched with mismatched resolved owner"
    );
    assert_eq!(
        state_dir_count(&temp),
        0,
        "rejected registration leaked state"
    );
}

#[test]
fn delivery_seam_records_invocation_outcome() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "bash", "-lc", "echo delivered"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    assert_eq!(json["delivery_mode"], "async");
    assert_eq!(mode_text(&temp, handle), "async");
    let deadline = Instant::now() + FIXTURE_DEADLINE;
    while delivery_attempt_count(&delivery_log) != 1 && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    assert_eq!(
        delivery_attempt_count(&delivery_log),
        1,
        "meta={} log={}",
        read_meta(&meta_path),
        fs::read_to_string(&delivery_log).unwrap_or_default()
    );
    wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["exit_code"] == 0).then_some(())
    });
    let status = status_text(&temp, handle, true);
    assert!(
        status.starts_with(&format!("DONE rc=0 handle={handle}")),
        "{status}"
    );
    let delivered = fs::read_to_string(&delivery_log).expect("delivery log");
    let lines: Vec<_> = delivered.lines().map(str::to_string).collect();
    assert_eq!(
        lines,
        vec![
            "notify".to_string(),
            "agent-bash-register".to_string(),
            "--handle".to_string(),
            handle.to_string(),
            "--delivery-mode".to_string(),
            "async".to_string(),
            "--state-dir".to_string(),
            json["state_dir"].as_str().expect("state dir").to_string(),
            "--meta".to_string(),
            json["meta"].as_str().expect("meta").to_string(),
            "--log".to_string(),
            json["log"].as_str().expect("log").to_string(),
            "--rc".to_string(),
            json["rc"].as_str().expect("rc").to_string(),
            "notify".to_string(),
            "agent-bash-complete".to_string(),
            "--caller-ppid".to_string(),
            json["caller_ppid"]
                .as_i64()
                .expect("caller ppid")
                .to_string(),
            "--handle".to_string(),
            handle.to_string(),
            "--state-dir".to_string(),
            json["state_dir"].as_str().expect("state dir").to_string(),
            "--meta".to_string(),
            json["meta"].as_str().expect("meta").to_string(),
            "--log".to_string(),
            json["log"].as_str().expect("log").to_string(),
            "--rc".to_string(),
            json["rc"].as_str().expect("rc").to_string(),
        ]
    );
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
}

#[test]
fn caller_death_after_completion_handoff_does_not_repeat_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let (fake, delivery_log) = parent_killing_fake_agents(&temp, "agent-bash-complete");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "bash", "-lc", "printf complete"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);

    wait_until(fixture_deadline, || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    let delivered = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["exit_code"] == 0).then_some(meta)
    });
    assert_eq!(delivered["delivery"]["attempted"], true);
    assert!(delivered["delivery"]["retryable"].is_null());
    assert!(delivered["delivery"]["error"].is_null());

    for _ in 0..4 {
        let status = status_text(&temp, handle, true);
        assert!(status.starts_with("DONE rc=0"), "{status}");
    }
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
}

#[test]
fn delivery_owner_finishes_after_supervisor_dies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let fixture = blocking_delivery_fake_agents(&temp);
    let release = temp.path().join("owner-completion-workload-release");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fixture.helper)
        .env(
            "AGENT_BASH_FAKE_COMPLETE_STARTED",
            &fixture.completion_started,
        )
        .env(
            "AGENT_BASH_FAKE_COMPLETE_RELEASE",
            &fixture.completion_release,
        )
        .env(
            "AGENT_BASH_FAKE_COMPLETE_FINISHED",
            &fixture.completion_finished,
        )
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &fixture.delivery_log)
        .env("RELEASE", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let running = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["supervisor_pid"].is_number().then_some(meta)
    });
    let supervisor = OwnedProcess::capture_supervisor(&running).expect("capture supervisor");
    fs::write(&release, b"").expect("release workload");
    wait_until(fixture_deadline, || {
        fixture.completion_started.exists().then_some(())
    });
    assert!(supervisor.signal(libc::SIGKILL), "kill supervisor");
    fs::write(&fixture.completion_release, b"").expect("release completion helper");

    let delivered = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["exit_code"] == 0).then_some(meta)
    });
    assert_eq!(delivered["delivery"]["attempted"], true);
    assert!(fixture.completion_finished.exists());
    assert_eq!(
        operation_count(&fixture.delivery_log, "agent-bash-complete"),
        1
    );
    let status = status_text(&temp, handle, true);
    assert!(status.starts_with("DONE rc=0"), "{status}");
}

#[test]
fn delivery_owner_finishes_after_detach_caller_dies() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let fixture = blocking_delivery_fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fixture.helper)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &fixture.delivery_log)
        .args(["run", "--delivery", "sync", "--", "sleep", "60"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let binary = assert_cmd::cargo::cargo_bin("agent-bash");
    let mut detach = StdCommand::new(binary)
        .env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fixture.helper)
        .env(
            "AGENT_BASH_FAKE_ACTIVATE_STARTED",
            &fixture.activation_started,
        )
        .env(
            "AGENT_BASH_FAKE_ACTIVATE_RELEASE",
            &fixture.activation_release,
        )
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &fixture.delivery_log)
        .args(["detach", handle])
        .spawn()
        .expect("spawn detach");
    wait_until(fixture_deadline, || {
        fixture.activation_started.exists().then_some(())
    });
    detach.kill().expect("kill detach caller");
    detach.wait().expect("reap detach caller");
    fs::write(&fixture.activation_release, b"").expect("release activation helper");

    let repeated = agent_bash(&temp)
        .args(["detach", handle])
        .output()
        .expect("repeated detach");
    assert_command_success(&repeated);
    let repeated = parse_stdout_json(&repeated);
    assert_eq!(repeated["transitioned"], false);
    assert_eq!(repeated["notification_attempted"], false);
    assert_eq!(
        operation_count(&fixture.delivery_log, "agent-bash-activate"),
        1
    );
    let _ = agent_bash(&temp).args(["cancel", handle]).output();
}

#[test]
fn concurrent_status_after_nonzero_helper_exit_does_not_repeat_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = nonzero_completion_fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "true"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle").to_string();
    let meta_path = meta_path(&json);
    wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["exit_code"] == 17).then_some(())
    });

    let mut observers = Vec::new();
    for _ in 0..8 {
        let binary = assert_cmd::cargo::cargo_bin("agent-bash");
        let state_root = temp.path().to_path_buf();
        let handle = handle.clone();
        observers.push(std::thread::spawn(move || {
            StdCommand::new(binary)
                .env("XDG_STATE_HOME", state_root)
                .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/false")
                .args(["status", "--full", &handle])
                .output()
                .expect("status observer")
        }));
    }
    for observer in observers {
        assert_command_success(&observer.join().expect("join observer"));
    }
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert_eq!(read_meta(&meta_path)["delivery"]["exit_code"], 17);
}

#[test]
fn legacy_helperless_handles_fail_closed_without_retry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let handle = "ab_legacy_helperless";
    let state_dir = seed_done_state_dir(&temp, handle, unix_ms(), false);
    fs::write(state_dir.join("delivery-mode"), b"async").expect("write delivery mode");
    let meta_path = state_dir.join("meta.json");
    let mut meta = read_meta(&meta_path);
    meta["delivery"]["retryable"] = json!(true);
    fs::write(&meta_path, format_seeded_meta(&meta)).expect("write retry admission");

    let status = status_text(&temp, handle, true);
    assert!(status.starts_with("DONE rc=0"), "{status}");
    let meta = read_meta(&meta_path);
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(
        meta["delivery"]["error_code"],
        "delivery_helper_legacy_unsupported"
    );
    assert_eq!(meta["delivery"]["retryable"], false);

    let detach_handle = "ab_legacy_helperless_detach";
    let detach_dir = seed_done_state_dir(&temp, detach_handle, unix_ms(), false);
    fs::write(detach_dir.join("delivery-mode"), b"sync").expect("write sync mode");
    let detach = agent_bash(&temp)
        .args(["detach", detach_handle])
        .output()
        .expect("detach legacy handle");
    assert!(!detach.status.success());
    assert!(
        String::from_utf8_lossy(&detach.stderr).contains("delivery_helper_legacy_unsupported"),
        "{}",
        String::from_utf8_lossy(&detach.stderr)
    );
    assert_eq!(
        fs::read_to_string(detach_dir.join("delivery-mode")).unwrap(),
        "sync"
    );
    assert!(!detach_dir.join("activation-attempted").exists());
}

#[test]
fn caller_death_after_activation_handoff_does_not_repeat_or_split_detach() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let (fake, delivery_log) = parent_killing_fake_agents(&temp, "agent-bash-activate");
    let release = temp.path().join("detach-crash-release");
    let release_marker = ReleaseMarker::new(release.clone());
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("RELEASE", &release)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");

    let interrupted = agent_bash(&temp)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["detach", handle])
        .output()
        .expect("interrupted detach");
    assert!(!interrupted.status.success());
    wait_until(fixture_deadline, || {
        (operation_count(&delivery_log, "agent-bash-activate") == 1).then_some(())
    });
    wait_until(fixture_deadline, || {
        (mode_text(&temp, handle) == "async"
            && read_meta(&meta_path(&json))["delivery_mode"] == "async")
            .then_some(())
    });

    let repeated = agent_bash(&temp)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["detach", handle])
        .output()
        .expect("repeated detach");
    assert_command_success(&repeated);
    let repeated = parse_stdout_json(&repeated);
    assert_eq!(repeated["transitioned"], false);
    assert_eq!(repeated["notification_attempted"], false);
    assert_eq!(operation_count(&delivery_log, "agent-bash-activate"), 1);
    assert_eq!(mode_text(&temp, handle), "async");
    assert_eq!(read_meta(&meta_path(&json))["delivery_mode"], "async");
    release_marker.release();
    let status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(status.starts_with(&format!("DONE rc=0 handle={handle}")));
    assert_eq!(operation_count(&delivery_log, "agent-bash-activate"), 1);
}

#[test]
fn observer_cannot_substitute_registered_delivery_helper() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (helper_a, log_a) = named_fake_agents(&temp, "helper-a", "helper-a.log");
    let (helper_b, log_b) = named_fake_agents(&temp, "helper-b", "helper-b.log");
    let release = temp.path().join("release-workload");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &helper_a)
        .env("RELEASE_WORKLOAD", &release)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "for _ in {1..800}; do [ -e \"$RELEASE_WORKLOAD\" ] && exit 0; sleep 0.01; done; exit 1",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");

    let detach = detach_with_fake(&temp, handle, &helper_b, &log_b);
    assert_command_success(&detach);
    fs::write(&release, b"").expect("release workload");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    wait_until(FIXTURE_DEADLINE, || {
        (delivery_attempt_count(&log_a) == 1).then_some(())
    });

    let helper_a_operations = fs::read_to_string(&log_a).expect("helper A log");
    assert!(
        helper_a_operations
            .lines()
            .any(|line| line == "agent-bash-activate"),
        "registered helper did not receive detach activation: {helper_a_operations}"
    );
    assert_eq!(delivery_attempt_count(&log_a), 1);
    assert!(
        !log_b.exists(),
        "observer helper received registered-handle operations: {}",
        fs::read_to_string(&log_b).unwrap_or_default()
    );
}

#[test]
fn registered_helper_snapshot_survives_source_replacement_without_polling() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let (helper, delivery_log) = fake_agents(&temp);
    let retained_helper = temp.path().join("retained-fake-agents");
    let replacement_log = temp.path().join("replacement-delivery.log");
    let workload_started = temp.path().join("workload-started");
    let release = temp.path().join("release-workload");
    let release_marker = ReleaseMarker::new(release.clone());
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &helper)
        .env("WORKLOAD_STARTED", &workload_started)
        .env("RELEASE_WORKLOAD", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "printf started > \"$WORKLOAD_STARTED\"; for _ in {1..800}; do [ -e \"$RELEASE_WORKLOAD\" ] && exit 0; sleep 0.01; done; exit 1",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);

    wait_until(fixture_deadline, || workload_started.exists().then_some(()));
    fs::rename(&helper, &retained_helper).expect("retain registered source helper");
    fs::write(&helper, fake_agents_script(&replacement_log)).expect("write replacement helper");
    set_executable(&helper);
    release_marker.release();
    let delivered = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["exit_code"] == 0).then_some(meta)
    });
    assert_eq!(delivered["delivery"]["attempted"], true);
    assert!(delivered["delivery"]["error"].is_null());
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert!(
        !replacement_log.exists(),
        "replacement helper executed: {}",
        fs::read_to_string(&replacement_log).unwrap_or_default()
    );
    assert_eq!(
        delivered["delivery_helper"]["path"],
        state_dir_path(&json)
            .join("delivery-helper")
            .to_string_lossy()
            .as_ref()
    );
    let status = status_text(&temp, handle, true);
    assert!(
        status.starts_with(&format!("DONE rc=0 handle={handle}")),
        "{status}"
    );
}

#[test]
fn unavailable_pinned_helper_allows_one_bounded_pre_execution_retry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let (observer, observer_log) =
        named_fake_agents(&temp, "observer-agents", "observer-delivery.log");
    let release = temp.path().join("bounded-retry-release");
    let release_marker = ReleaseMarker::new(release.clone());
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("RELEASE", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let snapshot = state_dir_path(&json).join("delivery-helper");
    let retained_snapshot = state_dir_path(&json).join("retained-delivery-helper");
    fs::rename(&snapshot, &retained_snapshot).expect("make pinned helper unavailable");
    release_marker.release();

    let initial = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["error_code"] == "delivery_helper_unavailable").then_some(meta)
    });
    assert_eq!(initial["delivery"]["attempted"], false);
    assert_eq!(initial["delivery"]["retryable"], true);
    assert_eq!(initial["delivery"]["retry_count"].as_u64().unwrap_or(0), 0);

    let first_retry = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &observer)
        .args(["status", "--full", handle])
        .output()
        .expect("first status retry");
    assert_command_success(&first_retry);
    let first_retry = stdout_utf8(first_retry, "status utf8");
    assert!(first_retry.starts_with("DONE rc=0"), "{first_retry}");
    let closed = read_meta(&meta_path);
    assert_eq!(closed["delivery"]["attempted"], false);
    assert_eq!(closed["delivery"]["retryable"], false);
    assert_eq!(closed["delivery"]["retry_count"], 1);

    fs::rename(&retained_snapshot, &snapshot).expect("restore pinned helper");
    let repeated = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &observer)
        .args(["status", "--full", handle])
        .output()
        .expect("repeated status");
    assert_command_success(&repeated);
    let repeated = stdout_utf8(repeated, "status utf8");
    assert!(repeated.starts_with("DONE rc=0"), "{repeated}");
    assert_eq!(delivery_attempt_count(&delivery_log), 0);
    assert!(
        !observer_log.exists(),
        "observer-local helper executed: {}",
        fs::read_to_string(&observer_log).unwrap_or_default()
    );
    assert_eq!(read_meta(&meta_path)["delivery"]["retry_count"], 1);
}

#[test]
fn completion_launch_failure_is_retryable_and_never_claimed_as_admitted() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (helper, interpreter, _) = interpreter_backed_fake_agents(&temp);
    let retained_interpreter = temp.path().join("retained-delivery-interpreter");
    let release = temp.path().join("launch-failure-release");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &helper)
        .env("RELEASE", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    fs::rename(&interpreter, &retained_interpreter).expect("remove helper interpreter");
    fs::write(&release, b"").expect("release workload");

    let initial = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["error_code"] == "delivery_helper_launch_failed").then_some(meta)
    });
    assert_eq!(initial["delivery"]["attempted"], false);
    assert_eq!(initial["delivery"]["retryable"], true);
    assert_eq!(initial["delivery"]["retry_count"].as_u64().unwrap_or(0), 0);

    let status = status_text(&temp, handle, true);
    assert!(status.starts_with("DONE rc=0"), "{status}");
    let closed = read_meta(&meta_path);
    assert_eq!(closed["delivery"]["attempted"], false);
    assert_eq!(closed["delivery"]["retryable"], false);
    assert_eq!(closed["delivery"]["retry_count"], 1);
}

#[test]
fn detach_launch_failure_restores_sync_mode_and_allows_retry() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (helper, interpreter, _) = interpreter_backed_fake_agents(&temp);
    let retained_interpreter = temp.path().join("retained-delivery-interpreter");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &helper)
        .args(["run", "--delivery", "sync", "--", "sleep", "60"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let state_dir = state_dir_path(&json);
    fs::rename(&interpreter, &retained_interpreter).expect("remove helper interpreter");

    let failed = agent_bash(&temp)
        .args(["detach", handle])
        .output()
        .expect("failed detach");
    assert!(!failed.status.success(), "detach unexpectedly succeeded");
    assert_eq!(mode_text(&temp, handle), "sync");
    assert!(!state_dir.join("activation-attempted").exists());

    fs::rename(&retained_interpreter, &interpreter).expect("restore helper interpreter");
    let retried = agent_bash(&temp)
        .args(["detach", handle])
        .output()
        .expect("retried detach");
    assert_command_success(&retried);
    assert_eq!(mode_text(&temp, handle), "async");
    let _ = agent_bash(&temp).args(["cancel", handle]).output();
}

#[test]
fn changed_handle_helper_fails_closed_through_completion_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let release = temp.path().join("changed-helper-release");
    let executed = temp.path().join("changed-helper-executed");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("RELEASE", &release)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let snapshot = state_dir_path(&json).join("delivery-helper");
    fs::remove_file(&snapshot).expect("remove registered helper link");
    fs::write(
        &snapshot,
        format!("#!/bin/sh\n: > {}\n", shell_quote(&executed)),
    )
    .expect("write changed helper");
    set_executable(&snapshot);
    fs::write(&release, b"").expect("release workload");

    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["error_code"] == "delivery_helper_changed").then_some(meta)
    });
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(meta["delivery"]["retryable"], true);
    assert_eq!(meta["delivery"]["retry_count"].as_u64().unwrap_or(0), 0);
    assert!(!executed.exists(), "changed helper executed");
    assert_eq!(delivery_attempt_count(&delivery_log), 0);
}

#[test]
fn product_state_and_helper_cache_are_account_private() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "true"])
        .output()
        .expect("run");
    let _ = parse_run_output(&output);
    let root = temp.path().join("agent-bash");
    let cache = root.join(".delivery-helpers");
    assert_eq!(
        fs::metadata(&root).expect("root metadata").mode() & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(&cache).expect("cache metadata").mode() & 0o777,
        0o700
    );
}

#[test]
fn sync_completion_triggers_its_inactive_completion_event() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "echo sync",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");

    let status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));

    assert!(status.contains("sync\n"), "{status}");
    assert_eq!(json["delivery_mode"], "sync");
    assert_eq!(mode_text(&temp, handle), "sync");
    wait_until(FIXTURE_DEADLINE, || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path(&json));
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(meta["delivery_mode"], "sync");
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
}

#[test]
fn detach_after_sync_completion_notifies_once() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "echo complete",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));

    let first = detach_with_fake(&temp, handle, &fake, &delivery_log);
    let second = detach_with_fake(&temp, handle, &fake, &delivery_log);

    let first = parse_stdout_json(&first);
    let second = parse_stdout_json(&second);
    assert_eq!(first["transitioned"], true);
    assert_eq!(first["notification_attempted"], true);
    assert_eq!(second["transitioned"], false);
    assert_eq!(second["notification_attempted"], false);
    assert_eq!(mode_text(&temp, handle), "async");
    wait_until(FIXTURE_DEADLINE, || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path(&json));
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(meta["delivery_mode"], "async");
    assert_eq!(meta["delivery"]["attempted"], true);
}

#[test]
fn concurrent_detach_and_completion_produce_one_notification() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "sleep 0.1; echo race",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle").to_string();
    std::thread::sleep(Duration::from_millis(75));

    let mut detach_threads = Vec::new();
    for _ in 0..8 {
        let binary = assert_cmd::cargo::cargo_bin("agent-bash");
        let state_root = temp.path().to_path_buf();
        let fake = fake.clone();
        let delivery_log = delivery_log.clone();
        let handle = handle.clone();
        detach_threads.push(std::thread::spawn(move || {
            StdCommand::new(binary)
                .env("XDG_STATE_HOME", state_root)
                .env("AGENT_BASH_AGENT_RUNNER_BIN", fake)
                .env("AGENT_BASH_FAKE_DELIVERY_LOG", delivery_log)
                .args(["detach", &handle])
                .output()
                .expect("concurrent detach")
        }));
    }
    let outcomes: Vec<Value> = detach_threads
        .into_iter()
        .map(|thread| thread.join().expect("detach thread"))
        .map(|output| {
            assert_command_success(&output);
            parse_stdout_json(&output)
        })
        .collect();

    let status = wait_for_status_prefix(&temp, &handle, &format!("DONE rc=0 handle={handle}"));
    assert!(status.contains("race\n"), "{status}");
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| outcome["transitioned"] == true)
            .count(),
        1
    );
    wait_until(FIXTURE_DEADLINE, || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert_eq!(mode_text(&temp, &handle), "async");
}

#[test]
fn detach_does_not_rewrite_terminal_metadata_after_activation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let fixture_deadline = FIXTURE_DEADLINE;
    let fixture = blocking_delivery_fake_agents(&temp);
    let workload_release = temp.path().join("workload-release");
    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fixture.helper)
        .env(
            "AGENT_BASH_FAKE_ACTIVATE_STARTED",
            &fixture.activation_started,
        )
        .env(
            "AGENT_BASH_FAKE_ACTIVATE_RELEASE",
            &fixture.activation_release,
        )
        .env(
            "AGENT_BASH_FAKE_COMPLETE_STARTED",
            &fixture.completion_started,
        )
        .env(
            "AGENT_BASH_FAKE_COMPLETE_RELEASE",
            &fixture.completion_release,
        )
        .env(
            "AGENT_BASH_FAKE_COMPLETE_FINISHED",
            &fixture.completion_finished,
        )
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &fixture.delivery_log)
        .env("WORKLOAD_RELEASE", &workload_release)
        .args([
            "run",
            "--delivery",
            "sync",
            "--",
            "bash",
            "-lc",
            "while [ ! -e \"$WORKLOAD_RELEASE\" ]; do sleep 0.01; done",
        ])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle").to_string();
    let workload = wait_until(fixture_deadline, || {
        OwnedProcess::capture_workload(&read_meta(&meta_path(&json)))
    });
    let binary = assert_cmd::cargo::cargo_bin("agent-bash");
    let state_root = temp.path().to_path_buf();
    let detach_fixture = fixture.clone();
    let detach_handle = handle.clone();
    let detach = std::thread::spawn(move || {
        StdCommand::new(binary)
            .env("XDG_STATE_HOME", state_root)
            .env("AGENT_BASH_AGENT_RUNNER_BIN", detach_fixture.helper)
            .env(
                "AGENT_BASH_FAKE_ACTIVATE_STARTED",
                detach_fixture.activation_started,
            )
            .env(
                "AGENT_BASH_FAKE_ACTIVATE_RELEASE",
                detach_fixture.activation_release,
            )
            .env(
                "AGENT_BASH_FAKE_COMPLETE_STARTED",
                detach_fixture.completion_started,
            )
            .env(
                "AGENT_BASH_FAKE_COMPLETE_RELEASE",
                detach_fixture.completion_release,
            )
            .env(
                "AGENT_BASH_FAKE_COMPLETE_FINISHED",
                detach_fixture.completion_finished,
            )
            .env("AGENT_BASH_FAKE_DELIVERY_LOG", detach_fixture.delivery_log)
            .args(["detach", &detach_handle])
            .output()
            .expect("detach")
    });
    wait_until(fixture_deadline, || {
        fixture.activation_started.exists().then_some(())
    });

    fs::write(&workload_release, b"").expect("release workload");
    wait_until(fixture_deadline, || workload.exited().then_some(()));
    wait_until(fixture_deadline, || {
        (read_meta(&meta_path(&json))["state"] == "DONE").then_some(())
    });
    fs::write(&fixture.activation_release, b"").expect("release activation");
    wait_until(fixture_deadline, || {
        fixture.completion_started.exists().then_some(())
    });
    let state_during_delivery = read_meta(&meta_path(&json))["state"]
        .as_str()
        .expect("state")
        .to_string();
    fs::write(&fixture.completion_release, b"").expect("release completion");
    wait_until(fixture_deadline, || {
        fixture.completion_finished.exists().then_some(())
    });
    let detach = detach.join().expect("detach thread");

    assert_eq!(state_during_delivery, "DONE");
    assert_command_success(&detach);
    let status = wait_for_terminal_status(&temp, &handle);
    assert!(status.starts_with("DONE rc=0"), "{status}");
    assert_eq!(read_meta(&meta_path(&json))["state"], "DONE");
    assert_eq!(delivery_attempt_count(&fixture.delivery_log), 1);
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
}

#[test]
fn consumed_marker_before_completion_suppresses_async_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "bash", "-lc", "sleep 1; echo consumed"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    fs::write(state_dir_path(&json).join("consumed"), b"").expect("write consumed marker");

    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("consumed\n"), "{final_status}");
    let meta_path = meta_path(&json);
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    let delivery = fs::read_to_string(&delivery_log).expect("event commands");
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert!(delivery.lines().any(|line| line == "--consumed"));
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
}

#[test]
fn consumed_marker_during_delivery_grace_suppresses_async_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);

    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("AGENT_BASH_CONSUMER_GRACE_MS", "8000")
        .args(["run", "--", "bash", "-lc", "echo consumed-after-rc"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    wait_until(FIXTURE_DEADLINE, || rc_path(&json).exists().then_some(()));
    fs::write(state_dir_path(&json).join("consumed"), b"").expect("write consumed marker");

    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(
        final_status.contains("consumed-after-rc\n"),
        "{final_status}"
    );
    wait_until(FIXTURE_DEADLINE, || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    let delivery = fs::read_to_string(&delivery_log).expect("event commands");
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert!(delivery.lines().any(|line| line == "--consumed"));
    let meta_path = meta_path(&json);
    let meta = wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
}

fn delivery_metadata_observed(meta: &Value) -> bool {
    (meta["delivery"]["attempted"] == true
        && meta["delivery"]["error_code"] != "delivery_attempt_in_progress")
        || meta["delivery"]["skipped"].is_string()
}

#[test]
fn consumed_marker_after_delivery_does_not_rewrite_delivery_meta() {
    let temp = tempfile::tempdir().expect("tempdir");
    let release_workload = temp.path().join("release-workload");
    let (fake, delivery_log) = fake_agents(&temp);

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("RELEASE_WORKLOAD", &release_workload)
        .args([
            "run",
            "--",
            "bash",
            "-lc",
            "for _ in {1..800}; do [ -e \"$RELEASE_WORKLOAD\" ] && { echo delivered; exit 0; }; sleep 0.01; done; exit 1",
        ]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);

    fs::write(&release_workload, b"").expect("release workload");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    wait_until(FIXTURE_DEADLINE, || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["attempted"] == true).then_some(())
    });

    let state_dir = state_dir_path(&json);
    let delivery_lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(state_dir.join("delivery.lock"))
        .expect("open delivery lock");
    wait_until(FIXTURE_DEADLINE, || {
        let result =
            unsafe { libc::flock(delivery_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result == 0 {
            return Some(());
        }
        let error = std::io::Error::last_os_error();
        assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK), "{error}");
        None
    });

    let before_meta = read_meta(&meta_path);
    assert_eq!(before_meta["state"], "DONE");
    assert_eq!(before_meta["rc"], 0);
    let before_delivery = before_meta["delivery"].clone();
    assert_eq!(before_delivery["attempted"], true);
    assert_eq!(before_delivery["exit_code"], 0);
    assert!(before_delivery["error"].is_null());
    assert!(before_delivery["skipped"].is_null());

    write_consumed_marker(&state_dir);
    let after_delivery = read_meta(&meta_path)["delivery"].clone();
    assert_eq!(after_delivery, before_delivery);
}

#[test]
fn status_reconciles_conclusively_lost_supervisor_once_and_fails_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log, meta_snapshot, rc_snapshot) = observing_fake_agents(&temp);
    let dead_supervisor = terminated_process_identity();
    let dead_workload = terminated_process_identity();
    let dead_supervisor = exact_identity(&dead_supervisor);
    let dead_workload = exact_identity(&dead_workload);

    let lost_handle = "ab_lost_supervisor";
    seed_running_state_dir(
        &temp,
        lost_handle,
        "exit",
        Some(dead_supervisor.clone()),
        Some(dead_workload.clone()),
        false,
    );

    let first = status_with_observing_delivery(
        &temp,
        lost_handle,
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );
    assert_command_success(&first);
    let first = stdout_utf8(first, "status utf8");
    assert!(
        first.starts_with(&format!("ERROR rc=70 handle={lost_handle}")),
        "{first}"
    );
    assert!(first.contains("retained log\n"), "{first}");
    assert_eq!(
        fs::read_to_string(&rc_snapshot).expect("delivery rc"),
        "70\n"
    );
    let delivered_meta = read_meta(&meta_snapshot);
    assert_eq!(delivered_meta["state"], "ERROR");
    assert_eq!(delivered_meta["completion_reason"], "supervisor-lost");
    assert_eq!(delivered_meta["rc"], 70);

    let terminal_meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(lost_handle)
            .join("meta.json"),
    );
    assert_eq!(terminal_meta["state"], "ERROR");
    assert_eq!(terminal_meta["delivery"]["attempted"], true);
    assert_eq!(terminal_meta["delivery"]["exit_code"], 0);
    assert_eq!(
        fs::read_to_string(temp.path().join("agent-bash").join(lost_handle).join("rc"))
            .expect("terminal rc"),
        "70\n"
    );

    let replay = status_with_observing_delivery(
        &temp,
        lost_handle,
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );
    assert_command_success(&replay);
    assert_eq!(
        fs::read_to_string(&delivery_log).expect("delivery log"),
        "delivery\n",
        "terminal replay must not deliver twice"
    );

    let (live_identity, _) = proc_identity(unsafe { libc::getpid() }).expect("live identity");
    let live_identity = exact_identity(&live_identity);
    seed_running_state_dir(
        &temp,
        "ab_live_exact",
        "exit",
        Some(live_identity.clone()),
        Some(live_identity.clone()),
        false,
    );
    assert_running_without_delivery(
        &temp,
        "ab_live_exact",
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );

    let mut mismatched_identity = live_identity;
    mismatched_identity["starttime_ticks"] = json!(
        mismatched_identity["starttime_ticks"]
            .as_u64()
            .expect("start time")
            + 1
    );
    seed_running_state_dir(
        &temp,
        "ab_pid_reused",
        "exit",
        Some(mismatched_identity.clone()),
        Some(mismatched_identity),
        false,
    );
    assert_running_without_delivery(
        &temp,
        "ab_pid_reused",
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );

    let mut boot_mismatch = exact_identity(
        &proc_identity(unsafe { libc::getpid() })
            .expect("live identity")
            .0,
    );
    boot_mismatch["boot_id"] = json!("different-boot-id");
    seed_running_state_dir(
        &temp,
        "ab_boot_mismatch",
        "exit",
        Some(boot_mismatch.clone()),
        Some(boot_mismatch),
        false,
    );
    assert_running_without_delivery(
        &temp,
        "ab_boot_mismatch",
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );

    let missing_identity = json!({
        "pid": dead_supervisor["pid"],
        "starttime_ticks": null,
        "boot_id": null
    });
    seed_running_state_dir(
        &temp,
        "ab_missing_identity",
        "exit",
        Some(missing_identity.clone()),
        Some(missing_identity),
        false,
    );
    assert_running_without_delivery(
        &temp,
        "ab_missing_identity",
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );

    seed_running_state_dir(
        &temp,
        "ab_ready_sentinel",
        "sentinel",
        Some(dead_supervisor.clone()),
        Some(dead_workload.clone()),
        false,
    );
    assert_running_without_delivery(
        &temp,
        "ab_ready_sentinel",
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );

    let consumed_handle = "ab_lost_consumed";
    seed_running_state_dir(
        &temp,
        consumed_handle,
        "exit",
        Some(dead_supervisor),
        Some(dead_workload),
        true,
    );
    let consumed = status_with_observing_delivery(
        &temp,
        consumed_handle,
        &fake,
        &delivery_log,
        &meta_snapshot,
        &rc_snapshot,
    );
    assert_command_success(&consumed);
    let consumed = stdout_utf8(consumed, "status utf8");
    assert!(
        consumed.starts_with(&format!("ERROR rc=70 handle={consumed_handle}")),
        "{consumed}"
    );
    assert_eq!(
        fs::read_to_string(&delivery_log).expect("delivery log"),
        "delivery\ndelivery\n",
        "each completion must trigger its own durable event"
    );
    let consumed_meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(consumed_handle)
            .join("meta.json"),
    );
    assert_eq!(consumed_meta["delivery"]["attempted"], true);
    assert_eq!(consumed_meta["delivery"]["exit_code"], 0);
    assert!(consumed_meta["delivery"]["skipped"].is_null());
}

#[test]
fn supervisor_sigkill_reconciles_and_delivers_without_status_polling() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let retained_helper = temp.path().join("retained-guardian-helper");
    let replacement_log = temp.path().join("guardian-replacement.log");
    let child_pid_path = temp.path().join("retained-child-pid");
    let allow_root_exit = temp.path().join("allow-root-exit");
    let root_release_marker = ReleaseMarker::new(allow_root_exit.clone());
    let fixture_deadline = FIXTURE_DEADLINE;

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("CHILD_PID_PATH", &child_pid_path)
        .env("ALLOW_ROOT_EXIT", &allow_root_exit)
        .args([
            "run",
            "--delivery",
            "async",
            "--",
            "bash",
            "-lc",
            "sleep 10 >/dev/null 2>&1 & child=$!; printf '%s\\n' \"$child\" > \"$CHILD_PID_PATH\"; for _ in {1..800}; do [ -e \"$ALLOW_ROOT_EXIT\" ] && exit 0; sleep 0.01; done; exit 1",
        ]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let initial_meta = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    let workload_pid = initial_meta["workload_pid"].as_i64().expect("workload pid") as libc::pid_t;
    let child_pid = wait_until(fixture_deadline, || {
        fs::read_to_string(&child_pid_path)
            .ok()?
            .trim()
            .parse::<libc::pid_t>()
            .ok()
    });
    let retained_child =
        OwnedProcess::capture_current(child_pid, Some(workload_pid)).expect("capture child");
    root_release_marker.release();
    let running_meta = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        (meta["workload_rc"] == 0).then_some(meta)
    });
    let supervisor =
        OwnedProcess::capture_supervisor(&running_meta).expect("capture exact supervisor");
    fs::rename(&fake, &retained_helper).expect("retain guardian helper source");
    fs::write(&fake, fake_agents_script(&replacement_log)).expect("replace guardian helper");
    set_executable(&fake);

    let supervisor_signaled = supervisor.signal(libc::SIGKILL);
    let deadline = Instant::now() + fixture_deadline;
    while !delivery_log.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    let cleanup = terminate_owned_processes(&[retained_child]);
    wait_for_process_gone(child_pid);

    assert!(supervisor_signaled, "exact supervisor signal failed");
    assert_eq!(cleanup.term_sent, 1);
    assert!(
        delivery_log.exists(),
        "supervisor loss must deliver without a status poll"
    );
    let terminal_meta = wait_until(fixture_deadline, || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(terminal_meta["state"], "ERROR");
    assert_eq!(terminal_meta["completion_reason"], "supervisor-lost");
    assert_eq!(terminal_meta["rc"], 70);
    assert_eq!(terminal_meta["workload_rc"], 0);
    assert_eq!(terminal_meta["delivery"]["exit_code"], 0);
    let notifications = fs::read_to_string(&delivery_log)
        .expect("delivery log")
        .lines()
        .filter(|line| *line == "agent-bash-complete")
        .count();
    assert_eq!(
        notifications, 1,
        "supervisor loss must deliver exactly once"
    );
    assert!(
        !replacement_log.exists(),
        "guardian executed replacement helper: {}",
        fs::read_to_string(&replacement_log).unwrap_or_default()
    );
}

#[test]
fn list_all_reconciles_lost_supervisors_without_async_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (observer, observer_log) =
        named_fake_agents(&temp, "list-observer-agents", "list-observer.log");
    let dead_supervisor = exact_identity(&terminated_process_identity());
    let dead_workload = exact_identity(&terminated_process_identity());
    let handle = "ab_list_lost_supervisor";
    seed_running_state_dir(
        &temp,
        handle,
        "exit",
        Some(dead_supervisor),
        Some(dead_workload),
        false,
    );

    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &observer)
        .args(["list", "--all", "--json"])
        .output()
        .expect("list all");
    assert_command_success(&output);
    let summaries = parse_stdout_json(&output);
    assert_eq!(summaries[0]["handle"], handle);
    assert_eq!(summaries[0]["state"], "ERROR");
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert_eq!(meta["completion_reason"], "supervisor-lost");
    assert_eq!(meta["delivery"]["attempted"], false);
    assert!(
        !observer_log.exists(),
        "list executed observer-local helper: {}",
        fs::read_to_string(&observer_log).unwrap_or_default()
    );
}
