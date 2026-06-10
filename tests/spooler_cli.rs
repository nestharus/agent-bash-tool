use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Output};
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
const handle = process.argv[4]
const mod = await import(adapterPath)
const args = mode === "poll" ? { handle } : { command: "printf 'adapter inline\\n'" }
const result = await mod.default.execute(args)
const text = typeof result === "string" ? result : String(result)
const matched = text.match(/handle=([^\s)]+)/)

console.log(JSON.stringify({ result: text, handle: matched?.[1] ?? null }))
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
        .env("AGENT_BASH_TOOL_WAIT_MS", "5000")
        .env("AGENT_BASH_TOOL_POLL_MS", "25")
        .env("XDG_STATE_HOME", temp.path())
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

fn consumed_marker_path_for_handle(temp: &tempfile::TempDir, handle: &str) -> PathBuf {
    temp.path().join("agent-bash").join(handle).join("consumed")
}

fn assert_consumed_marker_exists(path: &Path) {
    assert!(
        path.exists(),
        "consumed marker missing at {}",
        path.display()
    );
}

fn assert_adapter_result_contains(result: &Value, expected: &str) {
    let text = adapter_result_text(result);
    assert!(text.contains(expected), "{text}");
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

fn assert_process_alive(pid: libc::pid_t) {
    let rc = unsafe { libc::kill(pid, 0) };
    assert_eq!(rc, 0, "expected live process pid {pid}");
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
fn run_startup_reaps_old_consumed_state_dir_without_stdout_pollution() {
    let temp = tempfile::tempdir().expect("tempdir");
    let old = seed_done_state_dir(&temp, "ab_old_consumed", unix_ms() - 2_000, true);

    let output = agent_bash(&temp)
        .env("AGENT_BASH_STATE_TTL_SECS", "1")
        .env("AGENT_BASH_STATE_REAP_MAX_DIRS", "1")
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
fn opencode_adapter_poll_path_marks_consumed_after_done() {
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
    assert_consumed_marker_exists(&state_dir_path(&json).join("consumed"));
}

#[test]
fn opencode_adapter_in_call_fast_command_marks_consumed() {
    assert_bun_available();
    let temp = tempfile::tempdir().expect("tempdir");
    let driver = write_adapter_driver(&temp);

    let result = run_adapter_driver(&temp, &driver, "run", None);

    assert_adapter_result_contains(&result, "adapter inline");
    assert_consumed_marker_exists(&consumed_marker_path_for_handle(
        &temp,
        adapter_result_handle(&result),
    ));
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
fn consumed_marker_before_completion_skips_delivery_notify() {
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
    assert!(
        !delivery_log.exists(),
        "delivery fixture should not be invoked when consumed marker exists"
    );
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
