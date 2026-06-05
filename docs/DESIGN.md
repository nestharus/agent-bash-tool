# agent-bash-tool — Design Baseline

Status: **draft baseline** (owner-shaped; pre-implementation). This is the spec the
implementation pipeline builds against. Course-correct here before code.

## Problem

AI agent harnesses differ wildly in async support. Claude Code has `run_in_background`
+ a completion callback. opencode/gpt has **no background flag** and kills any foreground
bash command at a timeout. codex kills polled subagents. So a long-lived agent cannot
reliably "dispatch a long command, keep working, and be told when it finished" — which is
exactly what an orchestrator (or any agent running `agents` child dispatches) needs.

We fix this **below the harness**: agents call our tool instead of raw bash. Whether the
agent *thinks* it is calling foreground or background, our tool always runs the workload
detached and returns immediately. The result is delivered back to the agent out-of-band via
agent-runner.

## Two layers (strict separation)

1. **agent-bash-tool (this repo) — the spooler. General, provider-agnostic.**
   Knows nothing about agents, sessions, or providers. It detaches a command, captures its
   process tree, watches for completion, and reports. It is *always called by* an agent, so on
   completion it shells out to agent-runner to deliver the result — but it has no agent logic of
   its own. Loose coupling: it invokes the `agent-runner` / `agents` CLI, it does **not** depend
   on agent-runner crates.

2. **agent-runner — the agent layer. Specialized.** Owns PID↔session mapping, session
   liveness, the agent process tree, and delivery (resume for headless, PTY injection for
   interactive). This is where the **mailbox** lives; `--resume` is its delivery primitive.

> The chain: spooler watches a generic PID/tree → on completion hands agent-runner the result
> plus the caller ancestry captured at launch → agent-runner resolves the owning session from
> its own DB and wakes/forwards to that session. Some workloads are agents (launched via
> agent-runner), some are plain commands; they are distinguished by which spool/binary launched
> them.

## Spooler behavior (WU-C)

### Always background — foreground is not offered
There is no foreground mode. Every `run` detaches the workload and returns a handle
immediately. Even if an agent's harness *thinks* it is running us in the foreground, we return
right away (the harness sees a fast, clean exit), and the workload keeps going under our
supervisor. We never give agents the option to block on a workload.

### Attached-required — detached invocation bombs out
At startup the tool captures `getppid()`. The tool itself must be a real, attached subprocess
of its caller so it can walk up the tree to find the calling agent. If it was launched
detached (PPID is `1`/a reaper, i.e. already reparented), it **exits immediately with an error**:
`must be called as an attached subprocess`. This forces agents to call it attached so the
process tree is anchored. (agent-runner already uses this exact pattern —
`validate_child_parent_pid` in `executor/cli/supervision.rs`.)

### Process-tree capture — subreaper primary, cgroup v2 optional
The detached supervisor calls `prctl(PR_SET_CHILD_SUBREAPER, 1)` before it spawns the workload.
Every orphaned descendant — including `setsid` and double-forked grandchildren — reparents to
the supervisor instead of init. The supervisor blocks on `signalfd`/`poll`, reaps with
`waitpid(-1, ...)`, and considers the supervised subtree empty when `waitpid` reports
`ECHILD`. This is the primary completion guarantee and works on cgroup-v1 hosts.

If a delegated cgroup-v2 subtree is writable, the supervisor also enrolls the workload in a
dedicated child cgroup before `execvp`. In that optional mode, `cgroup.procs` is available as a
live set and `cgroup.events`/`populated` is watched for diagnostics and cleanup. If cgroup v2 is
unavailable or not delegated, the spooler records `cgroup.mode="subreaper-only"` and continues
without degradation because the subreaper remains authoritative. Process-group + `killpg`
(already used in agent-runner) is only a teardown fallback.

### Detached supervisor
`run` forks a supervisor that **survives the tool's return**. The supervisor owns the workload
(via subreaper reparenting plus a root `pidfd`, and optionally a cgroup-v2 live set), tees
stdout/stderr to a per-handle log, and records exit code. The `run` invocation itself returns
the handle and exits — it does not `wait`.

### Completion detection — two modes
- **exit mode (default):** wake on root process death with `pidfd_open` + `poll`, and finish
  only after the subreaper has reaped all descendants (`waitpid` → `ECHILD`). Optional cgroup-v2
  `populated` events may be recorded, but they are not required for correctness.
- **sentinel / server mode (`--ready-sentinel <regex>`):** for workloads that never exit (a
  server). "Done/ready" is a stdout marker match, because there is no exit to wait on.
  *We never assume a workload will exit.*

### Output / handle
`run` prints a handle (JSON) immediately. `status <handle>` is non-blocking: `RUNNING`, or
`DONE rc=<n>` + captured output. This generalizes the current `agents-bg{,-poll}` tmux helpers
into an event-driven, cgroup-tracked tool. The supervisor's poll of the PID is **harness-code
polling (cheap, no LLM tokens)** — not the LLM self-polling that is forbidden.

### Delivery resolution metadata
At launch, while the caller is still alive and `/proc` is readable, the spooler records
`caller_ppid` and a nearest-first `caller_chain` in `meta.json`. Each chain element contains
`pid`, `/proc/<pid>/stat` field 22 as `starttime_ticks`, and the host `boot_id` from
`/proc/sys/kernel/random/boot_id`. The delivery seam still passes `--caller-ppid` and
`--meta <path>`; agent-runner resolves the owning session from the recorded chain by pure DB
lookup. The spooler does not resolve sessions.

### Consumed marker duplicate suppression
A file named `consumed` inside a handle state directory means the caller already received the
terminal result in-call. Immediately before invoking `agents notify agent-bash-complete ...`, the
supervisor checks `<state>/<handle>/consumed`; when present, it skips the notify and records
`delivery: {"attempted": false, "skipped": "consumed_in_call"}` in `meta.json`.

The marker-write vs notify check is intentionally racy. If the opencode tool writes the marker
after the supervisor has already delivered, the worst case is a duplicate envelope for a result the
caller already saw. This preserves at-least-once delivery: the marker only suppresses notification
when it exists before the delivery seam runs, and if the in-call wait times out no marker exists so
normal completion notification still fires.

## agent-runner additions

### WU-A — session/PID query primitives
- Persist the child OS PID in the `invocations` row at spawn (if not already present).
- `session of-pid <pid>` → PID→invocation→session id.
- `session alive <pid>` → is this PID still an active session.
- subtree listing → PIDs of agents launched via agent-runner, full tree (builds on the existing
  `OULIPOLY_PARENT_INVOCATION` cross-invocation tracking + PID).
Reuse `session locate`, the process-group machinery, and `validate_child_parent_pid`.

### WU-B — notification mailbox + delivery
Accept a notification destined for a session (from the spooler), queue it (build on
`oulipoly-agent-messenger` + store/scratchpad), and deliver per session mode:

- **Headless → wait or queue, then `resume`.** Headless is the only mode with a real turn
  boundary (the process/turn ends). If the session is mid-turn, queue; deliver at turn end via
  the existing non-interactive `resume -m <model> --session-id <uuid> -f <payload>`, recording
  `resume_acceptance`. Multiple notifications queue and drain at successive turn boundaries —
  this is the "go between turns rather than wait for all work" behavior.
- **PTY → forward whenever.** A PTY session has **no finish signal** — it is server-like and
  always live. agent-runner does **not** wait for a turn end (there isn't one to detect); it
  injects the result over the PTY whenever it arrives. (Turn-boundary delivery for PTY would
  require the agent to emit its own sentinel — cf. `nestharus/claude-cli-proxy` hook-driven
  completion detection — out of scope for v1.)

agent-runner already knows a session's mode (PTY vs headless) because it launched it.

> `--resume` as the headless delivery primitive is the seed of a general per-agent **mailbox**.

## Dogfood / why this matters now
Once built, gpt/opencode orchestrators dispatch their `agents` children through `agent-bash`,
getting reliable detached background + out-of-band wake — which removes the broken-timeout
contamination that currently blocks trustworthy S9a/S9b gate runs.

## Non-goals (v1)
- No foreground mode (ever).
- No PTY turn-boundary detection (PTY = forward-whenever).
- No agent-runner crate dependency in the spooler (CLI coupling only).
- Linux-first (subreaper + pidfd; optional cgroup v2 live-set support). Other platforms degrade
  to process-group + poll later.
