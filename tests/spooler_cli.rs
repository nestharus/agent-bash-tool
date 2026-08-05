use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command as StdCommand, Output, Stdio};
use std::time::{Duration, Instant};

use assert_cmd::Command;
use serde_json::{Value, json};

#[derive(Debug, PartialEq, Eq)]
struct ProcIdentity {
    pid: libc::pid_t,
    starttime_ticks: u64,
}

fn agent_bash(temp: &tempfile::TempDir) -> Command {
    let mut cmd = Command::cargo_bin("agent-bash").expect("agent-bash binary");
    cmd.env("XDG_STATE_HOME", temp.path())
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
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
    wait_until(Duration::from_secs(6), || {
        let text = status_text(temp, handle, true);
        if text.starts_with(prefix) {
            Some(text)
        } else {
            None
        }
    })
}

fn wait_for_terminal_status(temp: &tempfile::TempDir, handle: &str) -> String {
    wait_until(Duration::from_secs(6), || {
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
            .filter(|entry| entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false))
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

fn fake_agents(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    let (fake, delivery_log) = fake_agents_paths(temp);
    fs::write(&fake, fake_agents_script()).expect("write fake");
    set_executable(&fake);
    (fake, delivery_log)
}

fn fake_agents_paths(temp: &tempfile::TempDir) -> (PathBuf, PathBuf) {
    (
        temp.path().join("fake-agents"),
        temp.path().join("delivery.log"),
    )
}

fn fake_agents_script() -> &'static str {
    "#!/bin/sh\nprintf '%s\\n' \"$@\" >> \"$AGENT_BASH_FAKE_DELIVERY_LOG\"\nexit 0\n"
}

fn delivery_attempt_count(path: &Path) -> usize {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|line| *line == "notify")
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

const args = mode === "poll"
  ? { handle: value }
  : mode === "async"
    ? { command: "sleep 1; printf 'adapter async\\n'", delivery: "async" }
    : mode === "sleep"
      ? { command: "sleep 0.05" }
    : mode === "abort"
      ? { command: "sleep 60; printf 'adapter abort failed\\n'" }
      : mode === "detachable"
        ? { command: "sleep 2; printf 'adapter detached\\n'" }
      : mode === "wrapper"
        ? { command: `${process.env.AGENT_BASH_BIN} run -- agents --version` }
      : mode === "wrapper-env"
        ? { command: `XDG_STATE_HOME=${process.env.XDG_STATE_HOME} ${process.env.AGENT_BASH_BIN} run -- agents --version` }
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
    command
        .arg(driver)
        .arg(mode)
        .arg(adapter_module_path())
        .env("AGENT_BASH_BIN", assert_cmd::cargo::cargo_bin("agent-bash"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("AGENT_BASH_TOOL_POLL_MS", "25")
        .env("XDG_STATE_HOME", temp.path())
        .env(
            "OULIPOLY_PARENT_INVOCATION",
            r#"{"source":"opencode","id":"11111111-1111-4111-8111-111111111111"}"#,
        )
        .env_remove("OULIPOLY_DATA_DIR");
    if let Some(handle) = handle {
        command.arg(handle);
    }
    command
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
    wait_until(Duration::from_secs(6), || {
        proc_identity(pid).is_none().then_some(())
    });
}

struct OwnerScenario {
    child: Child,
    run_json: PathBuf,
    ready: PathBuf,
    list_now: PathBuf,
    owner_list: PathBuf,
    list_caller_pid: PathBuf,
}

fn spawn_owner_scenario(temp: &tempfile::TempDir) -> OwnerScenario {
    let run_json = temp.path().join("owner-run.json");
    let ready = temp.path().join("owner-ready");
    let list_now = temp.path().join("owner-list-now");
    let owner_list = temp.path().join("owner-list.json");
    let list_caller_pid = temp.path().join("owner-list-caller-pid");
    let script = r#"
set -eu
"$AGENT_BASH_BIN" run -- bash -lc 'sleep 5' > "$RUN_JSON"
: > "$READY"
while [ ! -e "$LIST_NOW" ]; do sleep 0.01; done
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
        .env("RUN_JSON", &run_json)
        .env("READY", &ready)
        .env("LIST_NOW", &list_now)
        .env("OWNER_LIST", &owner_list)
        .env("LIST_CALLER_PID", &list_caller_pid)
        .spawn()
        .expect("spawn owner scenario");
    OwnerScenario {
        child,
        run_json,
        ready,
        list_now,
        owner_list,
        list_caller_pid,
    }
}

fn shell_list_json(temp: &tempfile::TempDir, all: bool) -> Vec<Value> {
    let all_arg = if all { " --all" } else { "" };
    let script = format!("\"$AGENT_BASH_BIN\" list{all_arg} --json; rc=$?; exit \"$rc\"");
    let output = StdCommand::new("bash")
        .arg("-c")
        .arg(script)
        .env("AGENT_BASH_BIN", assert_cmd::cargo::cargo_bin("agent-bash"))
        .env("AGENT_BASH_AGENT_RUNNER_BIN", "/bin/true")
        .env("XDG_STATE_HOME", temp.path())
        .output()
        .expect("shell list command");
    assert_command_success(&output);
    serde_json::from_slice(&output.stdout).expect("shell list JSON")
}

fn kill_process_group(meta: &Value) {
    if let Some(pgid) = meta["workload_pgid"].as_i64() {
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(100));
        unsafe {
            libc::kill(-(pgid as libc::pid_t), libc::SIGKILL);
        }
    }
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
    let child_rc = wait_until(Duration::from_secs(3), || fs::read_to_string(&rc).ok());
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
    let (output, elapsed) = run_cmd(&temp, &["run", "--", "bash", "-lc", "sleep 2; echo late"]);
    assert!(elapsed < Duration::from_secs(1), "run took {elapsed:?}");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let immediate = status_text(&temp, handle, false);
    assert!(immediate.starts_with("RUNNING handle="), "{immediate}");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.contains("late\n"), "{final_status}");
}

#[test]
fn cancel_terminates_the_entire_adopted_process_tree() {
    let temp = tempfile::tempdir().expect("tempdir");
    let child_pid_path = temp.path().join("child.pid");
    let script = format!("sleep 60 & echo $! > {}; wait", child_pid_path.display());
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", &script]);
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let workload_pid = wait_until(Duration::from_secs(2), || {
        read_meta(&meta_path)["workload_pid"]
            .as_i64()
            .map(|pid| pid as libc::pid_t)
    });
    let child_pid = wait_until(Duration::from_secs(2), || {
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
fn owner_exit_cancels_opted_in_workload_and_descendants() {
    let temp = tempfile::tempdir().expect("tempdir");
    let child_pid_path = temp.path().join("owner-child.pid");
    let workload_script = format!("sleep 60 & echo $! > {}; wait", child_pid_path.display());
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
        .env_remove("OULIPOLY_DATA_DIR")
        .output()
        .expect("owner launcher");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let meta_path = meta_path(&json);
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        meta["workload_pid"].is_number().then_some(meta)
    });
    assert_eq!(meta["cancel_owner"]["pid"], meta["caller_ppid"]);
    let workload_pid = meta["workload_pid"].as_i64().expect("workload pid") as libc::pid_t;
    let child_pid = wait_until(Duration::from_secs(2), || {
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
    wait_for_process_gone(workload_pid);
    wait_for_process_gone(child_pid);
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
    let (output, _) = run_cmd(
        &temp,
        &[
            "run",
            "--ready-sentinel",
            "READY:[0-9]+",
            "--",
            "bash",
            "-lc",
            "echo boot; echo READY:123; while true; do sleep 1; done",
        ],
    );
    let json = parse_run_output(&output);
    assert_eq!(json["mode"], "sentinel");
    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(
        &temp,
        handle,
        &format!("DONE rc=0 handle={handle} reason=ready-sentinel workload=running"),
    );
    assert!(final_status.contains("boot\n"), "{final_status}");
    assert!(final_status.contains("READY:123\n"), "{final_status}");
    let meta = read_meta(&meta_path(&json));
    assert_eq!(meta["completion_reason"], "ready-sentinel");
    assert_eq!(meta["rc"], 0);
    assert!(meta["ready_at_unix_ms"].is_number());
    assert!(meta["workload_rc"].is_null());
    let workload_pid = meta["workload_pid"].as_i64().expect("workload pid");
    assert_process_alive(workload_pid as libc::pid_t);
    kill_process_group(&meta);
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

    wait_until(Duration::from_secs(5), || marker.exists().then_some(()));
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
    let script =
        "(setsid sh -c 'sleep 2; printf grandchild > \"$MARKER\"' >/dev/null 2>&1 &) ; exit 0";
    let mut cmd = agent_bash(&temp);
    cmd.env("MARKER", &marker).args([
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

    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(final_status.starts_with(&format!("DONE rc=0 handle={handle}")));
    assert!(
        !marker.exists(),
        "root completion waited for the detached grandchild"
    );

    wait_until(Duration::from_secs(5), || marker.exists().then_some(()));
}

#[test]
fn cgroup_v2_live_set_path_runs_when_delegated_and_skips_otherwise() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (output, _) = run_cmd(&temp, &["run", "--", "bash", "-lc", "sleep 1.5"]);
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let meta = wait_until(Duration::from_secs(2), || {
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
fn opencode_adapter_ordinary_command_completes_in_band_in_sync_mode() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "run", None);

    assert_adapter_result_contains(&result, "adapter inline");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "sync");
    let meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(handle)
            .join("meta.json"),
    );
    assert_eq!(meta["delivery_mode"], "sync");
    assert!(meta["cancel_owner"]["pid"].is_number());
    assert_eq!(meta["owner_session_id"], "ses_adapter");
    assert_eq!(
        meta["owner_invocation_uuid"],
        "11111111-1111-4111-8111-111111111111"
    );
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(meta["delivery"]["skipped"], "sync_in_band");
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
    let start = Instant::now();

    let result = run_adapter_driver(&temp, &driver, "async", None);

    assert!(start.elapsed() < Duration::from_secs(1));
    assert_adapter_result_contains(&result, "Running asynchronously");
    let handle = adapter_result_handle(&result);
    assert_eq!(mode_text(&temp, handle), "async");
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
        meta["argv"]
            .as_array()
            .expect("argv")
            .iter()
            .any(|arg| arg.as_str().is_some_and(|arg| arg.contains("/bin/true"))),
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
    let mut adapter = adapter_driver_command(&temp, &driver, "detachable", None)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn adapter driver");
    let handle = wait_until(Duration::from_secs(2), || initialized_state_handle(&temp));
    assert_eq!(mode_text(&temp, &handle), "sync");

    let detach = agent_bash(&temp)
        .args(["detach", &handle])
        .output()
        .expect("detach command");
    assert_command_success(&detach);
    assert_eq!(parse_stdout_json(&detach)["transitioned"], true);
    let detached_at = Instant::now();
    let stdout = adapter.stdout.take().expect("adapter stdout");
    let line = BufReader::new(stdout)
        .lines()
        .next()
        .expect("adapter result line")
        .expect("adapter result");
    assert!(detached_at.elapsed() < Duration::from_secs(1));
    let result: Value = serde_json::from_str(&line).expect("adapter result json");

    assert_adapter_result_contains(&result, "Running asynchronously");
    assert_eq!(adapter_result_handle(&result), handle);
    let final_status =
        wait_for_status_prefix(&temp, &handle, &format!("DONE rc=0 handle={handle}"));
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
        assert_cmd::cargo::cargo_bin("agent-bash").display()
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
    let mut owner = spawn_owner_scenario(&temp);
    wait_until(Duration::from_secs(3), || {
        owner.ready.exists().then_some(())
    });
    let run_json: Value =
        serde_json::from_slice(&fs::read(&owner.run_json).expect("owner run JSON"))
            .expect("owner run JSON value");
    let handle = run_json["handle"].as_str().expect("handle").to_string();
    let active_status = status_text(&temp, &handle, false);
    let unrelated = shell_list_json(&temp, false);
    let all_access = shell_list_json(&temp, true);

    fs::write(&owner.list_now, b"").expect("release owner list");
    let owner_status = owner.child.wait().expect("owner scenario");
    let owner_list: Vec<Value> =
        serde_json::from_slice(&fs::read(&owner.owner_list).expect("owner list"))
            .expect("owner list JSON");
    let owner_pid = run_json["caller_ppid"].as_i64().expect("owner pid");
    let list_caller_pid: i64 = fs::read_to_string(&owner.list_caller_pid)
        .expect("list caller pid")
        .trim()
        .parse()
        .expect("numeric list caller pid");
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
    assert_eq!(json["delivery_mode"], "async");
    assert_eq!(mode_text(&temp, handle), "async");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    let delivered = wait_until(Duration::from_secs(2), || {
        fs::read_to_string(&delivery_log).ok()
    });
    let lines: Vec<_> = delivered.lines().map(str::to_string).collect();
    assert_eq!(
        lines,
        vec![
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
    let meta_path = meta_path(&json);
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["attempted"] == true).then_some(meta)
    });
    assert_eq!(meta["delivery"]["attempted"], true);
    assert_eq!(meta["delivery"]["exit_code"], 0);
    assert!(meta["delivery"]["skipped"].is_null());
}

#[test]
fn sync_completion_stays_in_band_without_notifying() {
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
    assert!(!delivery_log.exists());
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path(&json));
        (meta["delivery"]["skipped"] == "sync_in_band").then_some(meta)
    });
    assert_eq!(meta["delivery_mode"], "sync");
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(meta["delivery"]["skipped"], "sync_in_band");
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
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    let meta = read_meta(&meta_path(&json));
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
    wait_until(Duration::from_secs(2), || {
        (delivery_attempt_count(&delivery_log) == 1).then_some(())
    });
    assert_eq!(delivery_attempt_count(&delivery_log), 1);
    assert_eq!(mode_text(&temp, &handle), "async");
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
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert!(!delivery_log.exists());
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(meta["delivery"]["skipped"], "consumed_in_call");
}

#[test]
fn consumed_marker_during_delivery_grace_suppresses_async_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);

    let output = agent_bash(&temp)
        .env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("AGENT_BASH_CONSUMER_GRACE_MS", "2000")
        .args(["run", "--", "bash", "-lc", "echo consumed-after-rc"])
        .output()
        .expect("run");
    let json = parse_run_output(&output);
    wait_until(Duration::from_secs(2), || {
        rc_path(&json).exists().then_some(())
    });
    fs::write(state_dir_path(&json).join("consumed"), b"").expect("write consumed marker");

    let handle = json["handle"].as_str().expect("handle");
    let final_status = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    assert!(
        final_status.contains("consumed-after-rc\n"),
        "{final_status}"
    );
    assert!(!delivery_log.exists());
    let meta_path = meta_path(&json);
    let meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        delivery_metadata_observed(&meta).then_some(meta)
    });
    assert_eq!(meta["delivery"]["attempted"], false);
    assert_eq!(meta["delivery"]["skipped"], "consumed_in_call");
}

fn delivery_metadata_observed(meta: &Value) -> bool {
    meta["delivery"]["attempted"] == true || meta["delivery"]["skipped"].is_string()
}

#[test]
fn consumed_marker_after_delivery_does_not_rewrite_delivery_meta() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .args(["run", "--", "bash", "-lc", "echo delivered"]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let handle = json["handle"].as_str().expect("handle");
    let _ = wait_for_status_prefix(&temp, handle, &format!("DONE rc=0 handle={handle}"));
    let meta_path = meta_path(&json);
    let before = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["attempted"] == true).then_some(meta["delivery"].clone())
    });
    assert!(delivery_log.exists(), "delivery fixture should be invoked");

    fs::write(state_dir_path(&json).join("consumed"), b"").expect("write consumed marker");
    std::thread::sleep(Duration::from_millis(100));
    let after = read_meta(&meta_path)["delivery"].clone();
    assert_eq!(after, before);
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
        "delivery\n",
        "consumed markers must suppress duplicate async delivery"
    );
    let consumed_meta = read_meta(
        &temp
            .path()
            .join("agent-bash")
            .join(consumed_handle)
            .join("meta.json"),
    );
    assert_eq!(consumed_meta["delivery"]["attempted"], false);
    assert_eq!(consumed_meta["delivery"]["skipped"], "consumed_in_call");
}

#[test]
fn supervisor_sigkill_reconciles_and_delivers_without_status_polling() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (fake, delivery_log) = fake_agents(&temp);
    let child_pid_path = temp.path().join("retained-child-pid");

    let mut cmd = agent_bash(&temp);
    cmd.env("AGENT_BASH_AGENT_RUNNER_BIN", &fake)
        .env("AGENT_BASH_FAKE_DELIVERY_LOG", &delivery_log)
        .env("CHILD_PID_PATH", &child_pid_path)
        .args([
            "run",
            "--delivery",
            "async",
            "--",
            "bash",
            "-lc",
            "sleep 60 >/dev/null 2>&1 & printf '%s\\n' \"$!\" > \"$CHILD_PID_PATH\"",
        ]);
    let output = cmd.output().expect("run");
    let json = parse_run_output(&output);
    let meta_path = meta_path(&json);
    let running_meta = wait_until(Duration::from_secs(3), || {
        let meta = read_meta(&meta_path);
        (meta["workload_rc"] == 0 && child_pid_path.exists()).then_some(meta)
    });
    let supervisor_pid = running_meta["supervisor_pid"]
        .as_i64()
        .expect("supervisor pid") as libc::pid_t;

    assert_eq!(unsafe { libc::kill(supervisor_pid, libc::SIGKILL) }, 0);
    let deadline = Instant::now() + Duration::from_secs(3);
    while !delivery_log.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(25));
    }
    kill_process_group(&running_meta);

    assert!(
        delivery_log.exists(),
        "supervisor loss must deliver without a status poll"
    );
    let terminal_meta = wait_until(Duration::from_secs(2), || {
        let meta = read_meta(&meta_path);
        (meta["delivery"]["attempted"] == true).then_some(meta)
    });
    assert_eq!(terminal_meta["state"], "ERROR");
    assert_eq!(terminal_meta["completion_reason"], "supervisor-lost");
    assert_eq!(terminal_meta["rc"], 70);
    assert_eq!(terminal_meta["workload_rc"], 0);
    assert_eq!(terminal_meta["delivery"]["exit_code"], 0);
    let notifications = fs::read_to_string(&delivery_log)
        .expect("delivery log")
        .lines()
        .filter(|line| *line == "notify")
        .count();
    assert_eq!(
        notifications, 1,
        "supervisor loss must deliver exactly once"
    );
}

#[test]
fn list_all_reconciles_lost_supervisors_without_async_delivery() {
    let temp = tempfile::tempdir().expect("tempdir");
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
}
