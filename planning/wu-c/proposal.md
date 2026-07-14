# WU-C Spooler Core Proposal

This proposal implements the WU-C behavior described in `docs/DESIGN.md` without adding agent-specific logic. `agent-bash` is a Linux-first, always-background spooler: it accepts an attached invocation from an agent harness, returns a handle immediately, supervises the workload out of band, captures output and process-tree state, and exposes non-blocking status. Delivery to agent-runner is specified as a CLI seam only; the spooler must not depend on agent-runner crates.

## Scope

Implement only the spooler core in this repository:

- CLI commands: `run`, `status`, `list`.
- Attached-required guard at process startup.
- Detached supervisor using double fork plus `setsid`.
- Workload stdout/stderr capture into a per-handle log.
- Completion detection by root-process exit or stdout ready sentinel.
- Linux process-tree capture using cgroup v2 when delegated.
- Degraded process-group behavior when cgroup v2/delegation is unavailable.
- Agent-runner notification seam as an external CLI call shape only.

Do not implement agent-runner session lookup, mailboxing, resume, PTY injection, or any dependency on agent-runner crates.

## CLI Surface

The binary remains `agent-bash`.

### `run`

Shape:

```text
agent-bash run [--ready-sentinel <regex>] -- <program> [arg ...]
```

Rules:

- `run` always backgrounds the workload. There is no foreground flag and no foreground path.
- `--` is recommended and should be shown in help. Clap may still accept the `last = true` argv shape used by the scaffold.
- `<program> [arg ...]` is required and is stored exactly as an argv vector; no shell joining or shell parsing is performed by `agent-bash`.
- `--ready-sentinel <regex>` compiles as a Rust `regex::bytes::Regex`. It matches stdout bytes only, not stderr and not the combined log.
- Invalid sentinel regex is a semantic usage error before forking.

`run` prints exactly one JSON object to stdout, followed by `\n`, then exits `0` after forking the supervisor. The JSON is intentionally limited to data known synchronously by the launcher; supervisor/workload PIDs are written later to `meta.json`.

```json
{
  "schema_version": 1,
  "handle": "ab_0198f4b58a75_12345_7f2c9a10d4e8b331",
  "state_dir": "/home/alice/.local/state/agent-bash/ab_0198f4b58a75_12345_7f2c9a10d4e8b331",
  "log": "/home/alice/.local/state/agent-bash/ab_0198f4b58a75_12345_7f2c9a10d4e8b331/log",
  "rc": "/home/alice/.local/state/agent-bash/ab_0198f4b58a75_12345_7f2c9a10d4e8b331/rc",
  "meta": "/home/alice/.local/state/agent-bash/ab_0198f4b58a75_12345_7f2c9a10d4e8b331/meta.json",
  "caller_ppid": 31415,
  "mode": "exit",
  "ready_sentinel": null
}
```

For sentinel mode, `mode` is `"sentinel"` and `ready_sentinel` is the original regex string.

Handle format:

```text
ab_<unix_ms_hex>_<launcher_pid_decimal>_<64bit_random_hex>
```

Generate the random suffix with `libc::getrandom` where available. If `getrandom` fails before any supervisor is forked, return a bootstrap error instead of falling back to a predictable handle.

### `status`

Shape:

```text
agent-bash status [--tail-bytes <n> | --full] <handle>
```

Defaults:

- `--tail-bytes` default is `65536`.
- `--full` prints the whole log and conflicts with `--tail-bytes`.

Output is non-blocking and human-readable:

```text
RUNNING handle=<handle>
--- output ---
<captured log tail or full log>
```

or:

```text
DONE rc=<n> handle=<handle>
--- output ---
<captured log tail or full log>
```

Sentinel mode reports `DONE rc=0` once the ready sentinel has matched, even if the workload is still alive. In that case status appends a single detail line before output:

```text
DONE rc=0 handle=<handle> reason=ready-sentinel workload=running
--- output ---
<captured log tail or full log>
```

If a sentinel-mode workload exits before the sentinel matches, completion is exit-based and status reports the real process rc with `reason=exit-before-ready`.

`status` returns exit `0` for both running and done handles. It does not return the workload rc as the process exit code; callers read the `DONE rc=<n>` line or the `rc` file.

### `list`

Shape:

```text
agent-bash list [--all] [--json]
```

Defaults:

- Without `--all`, capture the attached caller's live ancestry once and treat each workload's nearest recorded `caller_chain` entry as its ownership anchor. Include the workload only when that anchor has a PID greater than 1, a positive start-time tick value, and a non-empty boot ID, and the exact PID/start-time/boot-ID tuple occurs in the current caller ancestry. Matching is directional (workload anchor in current ancestry), so a shared higher ancestor does not confer ownership.
- An empty, invalid, or unmatched ownership anchor fails closed with no `caller_ppid` fallback.
- `--all` explicitly bypasses the ownership filter and lists all handles under the state root.
- Without `--json`, output is one line per handle:

```text
<handle> <RUNNING|DONE> rc=<n|-> mode=<exit|sentinel> created_at=<unix_ms> state_dir=<path>
```

- With `--json`, output is an array of summary objects:

```json
[
  {
    "handle": "ab_...",
    "state": "RUNNING",
    "rc": null,
    "mode": "exit",
    "created_at_unix_ms": 1710000000000,
    "state_dir": "/home/alice/.local/state/agent-bash/ab_..."
  }
]
```

`status` and `list` also run the attached-required guard. This preserves the invariant that `agent-bash` is called as an attached subprocess by an agent/harness, and it prevents detached polling from becoming a parallel control plane.

## State Layout

Use persistent XDG state, not XDG runtime:

```text
${XDG_STATE_HOME:-$HOME/.local/state}/agent-bash/<handle>/
```

Justification:

- The result location is passed to agent-runner after the supervisor has completed or observed readiness; it must remain readable after the supervisor exits.
- Completed logs and rc files are user state, not sockets or locks. They are useful for postmortem `status` and `list` after the original harness command has returned.
- `${XDG_RUNTIME_DIR:-/run/user/$UID}` is session-temporary and may be absent in non-systemd test or CI environments. Cgroups and PIDs are runtime concepts, but the output/result artifacts should be durable user state.

Create `${state_root}/agent-bash` and each handle directory with mode `0700`. Never follow symlinks when opening files under a handle directory. Use atomic `tempfile + fsync + rename` for metadata and rc updates.

Per-handle files:

```text
log        combined stdout/stderr bytes, appended by the supervisor
rc         single-line completion rc, written atomically when completion is observed
meta.json  structured metadata, updated atomically
```

`meta.json` schema:

```json
{
  "schema_version": 1,
  "handle": "ab_...",
  "created_at_unix_ms": 1710000000000,
  "updated_at_unix_ms": 1710000000123,
  "state": "RUNNING",
  "completion_reason": null,
  "caller_ppid": 31415,
  "launcher_pid": 27182,
  "supervisor_pid": null,
  "workload_pid": null,
  "workload_pgid": null,
  "workload_pidfd": false,
  "argv": ["bash", "-lc", "echo ok"],
  "cwd": "/home/alice/project",
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
    "mode": "v2",
    "path": null,
    "delegated": false,
    "events_watch": false,
    "degraded_reason": null
  },
  "error": null
}
```

Completion values:

- `state`: `RUNNING`, `DONE`, or `ERROR`.
- `completion_reason`: `exit`, `ready-sentinel`, `exit-before-ready`, or `supervisor-error`.
- `rc`: the spooler completion rc. In exit mode this is the workload rc. In sentinel mode this is `0` once ready is observed.
- `workload_rc`: the eventual root workload rc, which may remain null for long-lived sentinel-mode servers.

## Attached-Required Guard

At the start of every command, before doing state discovery or forking, capture:

```text
startup_ppid = getppid()
```

Validation rule:

- Reject immediately if `startup_ppid == 1`.
- Reject if a later validation point observes `getppid() != startup_ppid`. This catches reparenting to PID 1 or to a subreaper after process start.
- Accept only if `startup_ppid > 1` and `getppid() == startup_ppid` at validation.

Validation points:

- Immediately after clap parsing and before any command-specific side effects.
- Immediately before the `run` launcher forks the supervisor.

Exact stderr and exit code for guard failure:

```text
agent-bash: must be called as an attached subprocess
```

Exit code: `64` (`EX_USAGE`).

This mirrors the agent-runner pattern in `crates/oulipoly-runtime/src/executor/cli/supervision.rs::validate_child_parent_pid`: capture the expected parent PID, then reject if `getppid()` no longer equals that captured PID. In agent-runner the failed pre-exec returns `ESRCH`; here the top-level CLI converts the same condition into the explicit user-facing attached-required error above.

Limitation: if a process is already reparented to a non-PID-1 subreaper before `exec(agent-bash)` begins, Linux does not provide a reliable unprivileged API to prove that the current parent is a subreaper. The enforceable invariant is therefore the same as agent-runner's: the parent observed at startup must be live and unchanged until the supervisor has been forked, and PID 1 is always rejected.

## Always-Background Guarantee

`run` must never wait for workload completion and must never offer foreground execution.

Sequence:

1. Parse CLI and validate the attached guard.
2. Compile `--ready-sentinel`, if provided.
3. Create the handle directory and initial `meta.json` with `state=RUNNING`.
4. Create/open `log` for append and ensure `rc` does not exist yet.
5. Validate the attached guard again.
6. Fork a short-lived daemonization child.
7. Parent prints the handle JSON to stdout and exits `0` immediately. It does not `waitpid` the daemonization child, supervisor, or workload.
8. The daemonization child performs `setsid()`, forks the final supervisor, and exits.
9. The final supervisor owns all workload monitoring, logging, completion detection, metadata updates, cgroup cleanup, and delivery-seam invocation.

The launcher may not block on a readiness pipe from the supervisor, because that would create a foreground setup path. It is acceptable that `meta.json.supervisor_pid` and `meta.json.workload_pid` are populated asynchronously after the handle JSON has been returned.

## Supervisor Model

The final supervisor is detached from the launcher but still records the original `caller_ppid` from the launcher. It should:

- Set a restrictive umask for created files.
- Reopen stdin as `/dev/null`.
- Keep stdout/stderr closed or redirected to `/dev/null`; only workload output goes to the per-handle `log`.
- Spawn the workload as its direct child.
- Put the workload in a new process group for degraded teardown.
- Open a pidfd for the root workload process.
- Drive one event loop using `poll(2)` over workload stdout, workload stderr, pidfd or pidfd fallback, and cgroup inotify fd when available.
- Avoid busy loops. All waiting must be blocking/event-driven.

### Workload spawn

Use `std::process::Command` only if its Unix `pre_exec` path stays async-signal-safe. The safer implementation is a small manual Unix spawn helper around `pipe2`, `fork`, `dup2`, `setpgid`, cgroup enrollment, and `execvp` via `libc`, because cgroup enrollment must happen before exec and before the workload can fork descendants.

Child-side pre-exec steps:

1. `setpgid(0, 0)` so the root workload starts a new process group.
2. If cgroup v2 capture is active, write the child PID to the pre-opened cgroup `cgroup.procs` fd using `libc::write` with a stack buffer. This must happen before `execvp` to avoid a race where a fast workload forks a descendant before enrollment.
3. `dup2` stdout/stderr pipe write ends.
4. Redirect stdin from `/dev/null`.
5. Close unrelated fds.
6. `execvp(argv[0], argv)`.

Parent-side steps:

1. Close pipe write ends.
2. Persist `supervisor_pid`, `workload_pid`, and `workload_pgid` to `meta.json`.
3. Call `pidfd_open(workload_pid, 0)` through `libc::syscall(SYS_pidfd_open, ...)`.
4. If pidfd opens, include it in the poll set and set `workload_pidfd=true`.
5. If pidfd is unavailable (`ENOSYS`/`EINVAL`) but the workload is a direct child, degrade to a blocking `waitpid` helper thread that writes the exit status to an internal pipe polled by the supervisor. Record this as `workload_pidfd=false` in metadata. This fallback is event-driven and does not poll in a loop.

Linux kernel capability note: pidfd primary mode requires Linux >= 5.3. The waitpid-helper fallback preserves root-process exit detection because the supervisor is the direct parent, but pidfd remains the primary path required for modern Linux.

## Process-Tree Capture with cgroup v2

Primary tree capture uses cgroup v2 delegation.

Discovery:

1. Parse `/proc/self/mountinfo` and locate a `cgroup2` mount.
2. Parse `/proc/self/cgroup` for the `0::/<relative-path>` entry.
3. Compute the current cgroup directory as `<cgroup2_mount>/<relative-path>`.
4. Attempt to create `<current_cgroup>/agent-bash-<handle>`.
5. Open the child cgroup's `cgroup.procs` for write and `cgroup.events` for read.
6. Add an inotify watch on `cgroup.events` for `IN_MODIFY`.

Activation succeeds only if the child cgroup can be created and `cgroup.procs` is writable. No controller enablement is required for membership tracking; the core cgroup files are enough.

Enrollment:

- The workload child writes its own PID into the child cgroup's `cgroup.procs` before `execvp`.
- All descendants remain in that cgroup even if they daemonize, change process group, or call `setsid`, unless they explicitly move themselves to another cgroup. v1 does not try to prevent a malicious workload from moving cgroups.

Live set:

- `cgroup.procs` is the authoritative live process set for status/debugging while cgroup mode is active.
- The supervisor reads it when needed for teardown diagnostics, not as a polling loop.

Subtree-empty detection:

- The supervisor reads `cgroup.events` initially and after each inotify event.
- When `populated` transitions to `0`, the cgroup subtree is empty.
- In exit mode, final completion is recorded after the root workload rc is known and the cgroup is empty. This prevents declaring the tree done while a detached grandchild is still alive.
- In sentinel mode, readiness completion is recorded when the sentinel matches. The supervisor continues running after readiness to keep teeing output and to clean up when `populated=0` eventually occurs.

Teardown:

- Normal exit-mode completion removes the child cgroup after `populated=0`.
- Sentinel-mode readiness does not kill the workload and does not remove the cgroup while the server remains populated.
- If the supervisor needs to terminate a workload because of an internal spawn/setup failure after forking, send `SIGTERM` to the workload process group, wait briefly, then `SIGKILL` to the process group. If cgroup mode is active, also read `cgroup.procs` and send signals to remaining PIDs as a last-resort cleanup. Process-group `killpg` is the fallback, not the primary capture mechanism.

Degradation path:

- If there is no cgroup v2 mount, no `0::` entry, child cgroup creation fails, or `cgroup.procs` is not writable, record:

```json
{
  "cgroup": {
    "mode": "degraded-process-group",
    "path": null,
    "delegated": false,
    "events_watch": false,
    "degraded_reason": "no writable delegated cgroup v2"
  }
}
```

- In degraded mode, the workload still runs in a new process group and root-process exit is detected with pidfd/waitpid.
- Degraded mode cannot guarantee capture of a grandchild that calls `setsid` or moves process groups. This limitation must be visible in metadata and in tests. It is an accepted fallback only for environments without delegated cgroup v2.

## Completion Detection

There are two completion modes.

### Exit mode

Default when `--ready-sentinel` is absent.

Completion condition:

- Root workload exit is observed by pidfd readiness plus `waitpid`/status collection, or by the waitpid-helper fallback.
- If cgroup mode is active, the child cgroup also reaches `populated=0`.

Recorded result:

- `rc` is the workload exit code.
- If the workload died by signal, use shell-compatible rc `128 + signal` and record `signal=<n>` in metadata.
- `completion_reason="exit"`.
- Write `rc` atomically as `<n>\n`.
- Update `meta.json` to `state="DONE"`.
- Invoke the agent-runner delivery seam.

Nothing assumes the workload will exit. If it keeps running, status remains `RUNNING` indefinitely.

### Sentinel mode

Active when `--ready-sentinel <regex>` is present.

Completion condition:

- The compiled regex matches stdout bytes from the workload.
- Matching is incremental. Keep a bounded rolling stdout buffer large enough for matches spanning reads. The bound should be `max(1 MiB, regex_string.len() * 4)` to avoid unbounded memory growth; the full output still goes to the log.

Recorded readiness result:

- `rc` is `0`.
- `completion_reason="ready-sentinel"`.
- `ready_at_unix_ms` and `completed_at_unix_ms` are set to the match time.
- Write `rc` atomically as `0\n`.
- Update `meta.json` to `state="DONE"`.
- Invoke the agent-runner delivery seam once.

Supervisor behavior after readiness:

- The supervisor does not kill the workload.
- The supervisor continues to drain stdout/stderr into `log`.
- The supervisor continues to monitor pidfd and cgroup events for eventual workload exit and cgroup cleanup.
- If the workload later exits, record `workload_rc`/`workload_signal`, but do not change the already delivered `rc=0` and do not invoke delivery again.

If the root workload exits before the sentinel matches:

- Record the real rc.
- Set `completion_reason="exit-before-ready"`.
- Mark `state="DONE"`.
- Invoke delivery once with that failure/completion result.

## Output Capture

The workload's stdout and stderr are both piped to the supervisor.

Capture behavior:

- The supervisor polls both fds and appends bytes to the single per-handle `log` file.
- Bytes are written raw, without stream prefixes, so command output is not modified. Interleaving is best-effort based on readiness order from `poll`.
- The sentinel matcher sees stdout bytes only. Stderr never triggers readiness.
- The supervisor fsyncs `log` at completion before writing `rc` and final metadata, so delivery sees a stable result snapshot.

`status` behavior:

- Opens `meta.json`, `rc` if present, and `log` read-only.
- Does not attach to the supervisor and does not wait on any process.
- For running handles, prints `RUNNING` plus the current captured log tail/full output.
- For done handles, prints `DONE rc=<n>` plus the captured log tail/full output.
- If `meta.json` says `DONE` but `rc` is temporarily absent due to a crash between metadata and rc writes, status reports `ERROR` and exits `65` (`EX_DATAERR`). The implementation should write `rc` before final `DONE` metadata to make this rare.

## Agent-Runner Delivery Seam

WU-C defines only a CLI coupling. No agent-runner crate is added.

On first completion, the supervisor invokes this external command shape:

```text
agents notify agent-bash-complete \
  --caller-ppid <caller_ppid> \
  --handle <handle> \
  --state-dir <state_dir> \
  --meta <state_dir>/meta.json \
  --log <state_dir>/log \
  --rc <state_dir>/rc
```

Semantics:

- `caller_ppid` is the PPID captured by the original attached `agent-bash` launcher.
- `handle` is the spooler handle printed by `run`.
- `state-dir`, `meta`, `log`, and `rc` are absolute paths to the result artifacts.
- agent-runner is responsible for mapping `caller_ppid` to a session and delivering the result according to session mode.
- The spooler does not parse agent-runner state and does not know about sessions, providers, resumes, PTYs, or mailboxes.

Implementation detail for WU-C:

- Resolve the binary from `AGENT_BASH_AGENT_RUNNER_BIN` if set, otherwise `agents`.
- Delivery failure is non-fatal for the workload result. Record `delivery.attempted=true` and either `delivery.exit_code` or `delivery.error` in metadata.
- Tests can set `AGENT_BASH_AGENT_RUNNER_BIN` to a small fake executable if they need to assert the seam. The core WU-C tests do not require a real agent-runner installation.

WU-D may rename or refine the agent-runner subcommand, but it should preserve the data contract: caller PPID, handle, and result artifact paths.

## Error Taxonomy and Exit Codes

CLI process exit codes:

```text
0   success for run/status/list; run success means spooled, not workload success
2   clap parse error
64  semantic usage/precondition error: invalid regex, attached-required guard failure
65  data error: corrupt or inconsistent meta/rc state
66  no input: unknown handle for status
69  unavailable: required OS facility unavailable with no safe fallback
70  software/internal supervisor bootstrap error before handle return
73  cannot create state directory, log, rc, or metadata
74  I/O error reading or writing state after command start
```

Important user-facing errors:

```text
agent-bash: must be called as an attached subprocess
agent-bash: invalid --ready-sentinel regex: <regex error>
agent-bash: unknown handle: <handle>
agent-bash: state root unavailable: <path>: <io error>
agent-bash: failed to create handle state: <path>: <io error>
agent-bash: supervisor bootstrap failed: <io error>
```

Supervisor-recorded errors:

- Spawn failure: `completion_reason="supervisor-error"`, `state="ERROR"`, `rc=70`.
- pidfd unavailable with waitpid fallback: not an error; record `workload_pidfd=false`.
- cgroup unavailable/delegation missing: not an error; record degraded cgroup mode.
- Delivery command failure: not an error for `rc`; record in `delivery` metadata.

## Crate and Dependency Choices

Keep dependencies lean and Linux-focused.

Existing dependencies are appropriate:

- `clap` for CLI parsing.
- `libc` for `fork`, `setsid`, `setpgid`, `dup2`, `execvp`, `pipe2`, `poll`, `pidfd_open` via syscall, `inotify_*`, `getrandom`, signals, and wait fallback.
- `serde` and `serde_json` for handle JSON and `meta.json`.
- `thiserror` for internal error enums.

Add one runtime dependency:

- `regex = "1"` for `--ready-sentinel`. Use `regex::bytes::Regex` so sentinel matching is byte-oriented and does not require valid UTF-8 output.

Do not add these in WU-C:

- `nix`: convenient, but most needed syscalls are small and already available through `libc`; adding `nix` increases API surface and version churn.
- `daemonize`: double-fork/`setsid` is core behavior and should be explicit.
- `inotify`: use `libc` syscalls directly.
- `rand`/`uuid`: use `getrandom` and local formatting for handles.
- Any agent-runner crate.

Dev dependencies already present are enough:

- `assert_cmd`, `predicates`, `tempfile`.

## Implementation Structure

Keep the crate small but not monolithic:

```text
src/main.rs          clap entrypoint and top-level error-to-exit mapping
src/cli.rs           command structs if main.rs grows too large
src/state.rs         state root, handle generation, atomic meta/rc/log paths
src/guard.rs         attached-required guard
src/supervisor.rs    daemonization, workload spawn, event loop, completion
src/cgroup.rs        cgroup v2 discovery/enrollment/events and degraded mode
src/delivery.rs      external CLI seam only
```

This split is enough to keep tests targeted without over-engineering. If the follow-up agent prefers fewer files, `guard`, `state`, `cgroup`, `supervisor`, and `delivery` can be modules declared from `main.rs`.

## Proof plan

| Runtime claim | Proof method | Required runtime artifact | Evidence-class match |
|---|---|---|---|
| Attached-required guard rejects a detached/orphaned invocation with exit `64` and exact stderr `agent-bash: must be called as an attached subprocess`. | `tests/spooler_cli.rs::attached_guard_rejects_detached_invocation` | The compiled `agent-bash` binary is launched by a helper that traces its real `getppid()` syscalls, exits the original parent between the startup capture and validation call, records the real child wait status to an rc file, records both observed PPIDs, and captures stdout/stderr files. | This is not a unit proxy: the production binary executes the production guard and the test asserts the actual child rc `64`, empty stdout, exact stderr, and a changed parent PID trace. |
| `run` is always-background and returns immediately without waiting for workload completion. | `tests/spooler_cli.rs::run_returns_immediately_and_later_completes` | The compiled `agent-bash run -- bash -lc 'sleep 2; echo late'` process, elapsed launcher duration, returned handle JSON, later `status` output, and captured log. | The proof uses a real sleeping workload; launcher elapsed time is asserted below the threshold while the later status/log proves completion happens asynchronously. |
| The supervisor captures a `setsid`-detached grandchild through the subreaper/cgroup supervision path and completion waits for it. | `tests/spooler_cli.rs::tree_capture_waits_for_setsid_detached_grandchild_via_subreaper` | A real workload that exits after spawning a `setsid` grandchild, a marker file written only by that grandchild, intermediate metadata/status, and final status after marker creation. | The root shell exits before the marker appears, status remains `RUNNING` during that root-only window, and final `DONE rc=0` is observed only after the detached grandchild artifact exists. |
| Exit-mode completion records the real rc and captures stdout/stderr output. | `tests/spooler_cli.rs::exit_mode_completion_rc_and_captured_output` | The compiled binary runs `bash -lc 'echo out; echo err >&2; exit 7'`, then the test reads the rc file, full status/log output, and `meta.json`. | The proof uses production state files and log output: rc file contains `7\n`, status starts `DONE rc=7`, output contains both streams, and metadata records `state="DONE"`, `completion_reason="exit"`, and `rc=7`. |
| WU-C captures a correct, reuse-safe caller identity chain (`pid` + `starttime_ticks` + `boot_id` per ancestor) for the attached caller. Death-safe resolution across caller death or PID reuse is WU-D's claim, not WU-C's. | `tests/spooler_cli.rs::exit_mode_completion_rc_and_captured_output` | The compiled binary records `meta.json.caller_chain`; the test reads the real `/proc/<pid>/stat` ancestry for the attached caller process and `/proc/sys/kernel/random/boot_id`. | The proof compares the full captured chain against the real nearest-first `/proc` ancestry, requires more than the first PID, and checks every entry has a positive PID, positive start-time ticks, and non-empty matching boot ID. It proves WU-C capture correctness and reuse-safe identity fields only; WU-D proves later death-safe resolution. |
| Ready-sentinel mode reports readiness for a non-exiting server without killing the workload. | `tests/spooler_cli.rs::ready_sentinel_reports_done_without_killing_workload` | The compiled binary runs a workload that prints `READY:123` and then sleeps forever; the test reads status/log and `meta.json`, asserts `kill(workload_pid, 0)` succeeds after readiness, then kills the process group during cleanup. | The proof observes `DONE rc=0 ... reason=ready-sentinel workload=running`, sentinel bytes in the log, `ready_at_unix_ms`, `workload_rc=null`, and real OS liveness for the workload PID. |
| The delivery seam invokes the external CLI shape with caller PPID, handle, state-dir, meta, log, and rc paths, and records outcome metadata. | `tests/spooler_cli.rs::delivery_seam_records_invocation_outcome` | `AGENT_BASH_AGENT_RUNNER_BIN` points to a temp fake executable that records argv; after completion the test reads the fake delivery log and `meta.json.delivery`. | The production supervisor invokes the configured executable; the test asserts the full argv vector `notify agent-bash-complete --caller-ppid <pid> --handle <handle> --state-dir <dir> --meta <meta> --log <log> --rc <rc>` and persisted delivery success metadata. |

## Test Plan

All tests must keep `cargo fmt`, `cargo clippy -- -D warnings`, and `cargo test` green. Integration tests should set `XDG_STATE_HOME` to a `tempfile::TempDir` so they never touch a real user's state.

### Unit tests

State and handle tests:

- `state_root_uses_xdg_state_home`: with `XDG_STATE_HOME` set, state root is `$XDG_STATE_HOME/agent-bash`.
- `state_root_falls_back_to_home_local_state`: with `XDG_STATE_HOME` unset and `HOME` set, root is `$HOME/.local/state/agent-bash`.
- `handle_format_is_parseable_and_unique`: generated handles match `ab_<hex>_<pid>_<hex>` and multiple calls differ.
- `atomic_meta_round_trip`: write/read `meta.json` and verify schema fields.
- `rc_write_is_atomic_single_line`: write rc and verify `<n>\n`.

Guard tests:

- `attached_guard_accepts_stable_parent`: constructed guard with current `getppid()` accepts when unchanged.
- `attached_guard_rejects_pid_one`: pure helper rejects `1`.
- `attached_guard_rejects_changed_parent`: pure helper rejects when current PPID differs from captured expected PPID.

Cgroup tests:

- `parse_proc_self_cgroup_v2_entry`: parser handles `0::/user.slice/...`.
- `parse_mountinfo_cgroup2_mount`: parser finds a cgroup2 mountpoint.
- `parse_cgroup_events_populated`: parser reads `populated 0` and `populated 1`.
- `degraded_reason_when_no_mount_or_unwritable`: cgroup discovery reports degraded mode instead of panicking.

Completion/output tests:

- `sentinel_matches_stdout_only`: stdout bytes match, stderr bytes do not.
- `signal_to_shell_rc`: signal `15` maps to `143`.
- `status_formats_running_and_done`: status rendering matches exact first-line shapes.

### Integration tests with `assert_cmd`

Use the compiled `agent-bash` binary through `assert_cmd::Command::cargo_bin("agent-bash")`.

#### Attached guard rejects detached invocation

Goal: prove detached/orphaned invocation is rejected with the exact error and exit code.

Test shape:

```text
bash -lc 'setsid sh -c "exec agent-bash list" < /dev/null >out 2>err & wait $!'
```

The robust version should make the intermediate shell exit before `agent-bash` validates, for example by using a tiny helper shell that starts `agent-bash` after its parent exits. Expected:

- Exit code `64`.
- Stderr contains exactly `agent-bash: must be called as an attached subprocess`.

Also include a normal attached `agent-bash list --json` invocation that exits `0` with `[]` in a temp state root.

#### `run` returns immediately

Command:

```text
agent-bash run -- bash -lc 'sleep 2; echo late'
```

Assertions:

- Process exits `0` in under 250 ms on a normal CI machine. Use a generous 1 s hard threshold to avoid flakes.
- Stdout parses as handle JSON.
- `status <handle>` immediately after run is `RUNNING` or, on a very fast system if the command changed, never blocks. With `sleep 2`, it should be `RUNNING`.
- After waiting up to 5 s in test harness code, `status <handle>` reports `DONE rc=0` and output contains `late`.

This test proves the launcher did not wait for workload completion.

#### Exit-mode completion, rc, and captured output

Command:

```text
agent-bash run -- bash -lc 'echo out; echo err >&2; exit 7'
```

Assertions:

- `run` exits `0` and prints handle JSON.
- Eventually `rc` file contains `7\n`.
- `status <handle> --full` starts with `DONE rc=7 handle=<handle>`.
- Status output/log contains both `out` and `err`.
- `meta.json` has `state="DONE"`, `completion_reason="exit"`, and `rc=7`.

#### Ready sentinel for a non-exiting workload

Command:

```text
agent-bash run --ready-sentinel 'READY:[0-9]+' -- bash -lc 'echo boot; echo READY:123; while true; do sleep 1; done'
```

Assertions:

- `run` returns immediately with `mode="sentinel"`.
- Eventually `status <handle> --full` starts with `DONE rc=0 handle=<handle> reason=ready-sentinel workload=running`.
- Log contains `boot` and `READY:123`.
- `meta.json` has `completion_reason="ready-sentinel"`, `rc=0`, `ready_at_unix_ms` non-null, and `workload_rc=null` while the workload is still alive.
- Test cleanup reads `meta.json.workload_pgid` or cgroup procs and terminates the server to avoid leaking processes.

#### Tree capture of a grandchild that `setsid`-detaches

This is the key cgroup property and should run only when writable delegated cgroup v2 is available to the test process. If cgroup discovery reports degraded mode, mark the test skipped rather than failed; degraded mode explicitly cannot prove this property.

Command:

```text
agent-bash run -- bash -lc '(setsid sh -c "sleep 1; echo grandchild >> \"$MARKER\"" >/dev/null 2>&1 &) ; exit 0'
```

Use an environment variable `MARKER` pointing inside the tempdir.

Assertions in cgroup mode:

- Root shell exits quickly, but `status <handle>` remains `RUNNING` until the detached grandchild exits and the cgroup `populated` event reaches `0`.
- The marker file is created by the detached grandchild.
- Final `status <handle>` reports `DONE rc=0` only after the marker exists and the cgroup is empty.
- `meta.json.cgroup.mode="v2"`, `delegated=true`, and `events_watch=true`.

This test fails if implementation relies only on PPID walking or process groups, because the grandchild uses `setsid` and outlives the root shell.

#### Degraded cgroup path is explicit

Force degradation in a test-only way by setting an environment variable such as `AGENT_BASH_DISABLE_CGROUP=1`. This variable should be accepted only as a test/debug override and documented as not part of the stable CLI.

Command:

```text
AGENT_BASH_DISABLE_CGROUP=1 agent-bash run -- bash -lc 'echo ok'
```

Assertions:

- Command completes successfully.
- `meta.json.cgroup.mode="degraded-process-group"`.
- `meta.json.cgroup.degraded_reason` is non-null.

Do not assert setsid-grandchild capture in degraded mode.

#### Delivery seam records invocation outcome

Use a fake executable in a tempdir named by `AGENT_BASH_AGENT_RUNNER_BIN`. The fake executable appends argv to a file and exits `0`.

Command:

```text
agent-bash run -- bash -lc 'echo delivered'
```

Assertions:

- Fake executable receives subcommand/args matching:

```text
notify agent-bash-complete --caller-ppid <pid> --handle <handle> --state-dir <dir> --meta <meta> --log <log> --rc <rc>
```

- `meta.json.delivery.attempted=true` and `delivery.exit_code=0`.

This confirms the seam without requiring real agent-runner behavior.

## Open Risks and Follow-Up Decisions

- cgroup v2 delegation is environment-dependent. CI may not allow creating child cgroups, so the key tree-capture integration test must skip when delegation is unavailable, while unit tests still cover parser/degradation logic.
- A process already reparented to a non-PID-1 subreaper before `exec(agent-bash)` cannot be reliably identified from unprivileged Linux APIs. The proposal mirrors agent-runner's enforceable parent-stability rule and always rejects PID 1.
- Sentinel-mode supervisors may live as long as the server. This is intentional, but log growth is unbounded in v1. Log rotation or max-size policies should be a later work unit if needed.
- Workloads can intentionally move themselves to another cgroup if they have permission. v1 captures normal descendants, including `setsid` daemons, but does not sandbox malicious cgroup migration.
- The agent-runner CLI subcommand name is a seam. WU-D may adjust the spelling, but it should preserve the caller PPID, handle, and result-path contract.
