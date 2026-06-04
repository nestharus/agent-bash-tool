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

> The chain: spooler watches a generic PID/tree → on completion asks agent-runner "whose
> session is PPID?" → hands agent-runner the result → agent-runner wakes/forwards to that
> session. Some workloads are agents (launched via agent-runner), some are plain commands;
> they are distinguished by which spool/binary launched them.

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

### Process-tree capture — cgroup v2
The workload is enrolled in a dedicated child cgroup at launch. Every descendant — **including
ones that detach / `setsid`** — stays in that cgroup, so PPID-walking (which breaks on detach)
is not relied upon. `cgroup.procs` is the live set; an inotify watch on `cgroup.events`
(`populated` 1→0) fires when the whole subtree has exited. No polling loop, no root required
(cgroup v2 delegation). Process-group + `killpg` (already used in agent-runner) is the fallback
for teardown.

### Detached supervisor
`run` forks a supervisor that **survives the tool's return**. The supervisor owns the workload
(via the cgroup + a `pidfd`), tees stdout/stderr to a per-handle log, and records exit
code. The `run` invocation itself returns the handle and exits — it does not `wait`.

### Completion detection — two modes
- **exit mode (default):** wake on process death — `pidfd_open` + `poll` (event-driven, even
  for non-children; Linux ≥5.3), backed by `cgroup.events` `populated`→0 for the full subtree.
- **sentinel / server mode (`--ready-sentinel <regex>`):** for workloads that never exit (a
  server). "Done/ready" is a stdout marker match, because there is no exit to wait on.
  *We never assume a workload will exit.*

### Output / handle
`run` prints a handle (JSON) immediately. `status <handle>` is non-blocking: `RUNNING`, or
`DONE rc=<n>` + captured output. This generalizes the current `agents-bg{,-poll}` tmux helpers
into an event-driven, cgroup-tracked tool. The supervisor's poll of the PID is **harness-code
polling (cheap, no LLM tokens)** — not the LLM self-polling that is forbidden.

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
- Linux-first (cgroup v2 + pidfd). Other platforms degrade to process-group + poll later.
