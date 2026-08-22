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

### Detached execution and explicit delivery
There is no foreground execution mode. Every `run` detaches the workload, returns a handle
immediately, and leaves the workload under the surviving supervisor. Execution lifetime and result
delivery are separate choices:

- `run --delivery sync` records completion for in-band consumption and does not invoke the
  agent-runner notification seam.
- `run --delivery async` invokes the notification seam at completion.
- The CLI defaults to `async` so handles created by older callers retain their behavior.
- The OpenCode adapter defaults ordinary shell commands to `sync` with root-process completion,
  defaults child-agent dispatches to `async` with full-tree completion, and accepts an explicit
  delivery override except for headless child-agent dispatches. Those remain asynchronous so the
  caller can end its turn and become resumable; an interactive PTY caller may explicitly select
  synchronous foreground delivery.
- A headless asynchronous handle has no process owner lease because normal completion of a
  headless turn destroys that OpenCode process. The detached workload survives and notifies the
  durable session. Synchronous handles and interactive PTY handles remain owner-leased.
- Leading shell environment assignments are ignored when classifying the command. An explicit
  `VAR=value agent-bash run -- agents ...` command is dispatched directly as one asynchronous
  spool instead of being captured by a synchronous outer spool.
- The adapter resolves a leading `agents` or `oulipoly-agent-runner` command to the configured
  `AGENT_BASH_AGENT_RUNNER_BIN`, avoiding PATH drift between interactive and detached execution.
- A standalone `sleep N` stays inside the adapter for up to five minutes by default, so passive
  waits do not create detached workloads or overlapping wake notifications.

A synchronous adapter call can block for its result without owning the workload process. Harness
timeout or caller death therefore does not terminate the detached workload.

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

Captured output is bounded by `AGENT_BASH_LOG_MAX_BYTES` (16 MiB by default, clamped between
64 KiB and 1 GiB). When the limit is crossed, the log records a truncation marker and retains the
newest output rather than allowing an unbounded state-directory file.

The intermediate daemon process remains as a guardian for the exact supervisor child. A clean
supervisor exit ends the guardian. After an abnormal exit, including `SIGKILL`, the guardian uses
the persisted PID/start-time/boot-ID identities and per-handle reconciliation lock to wait until
supervisor loss is conclusive, record `supervisor-lost`, and run any pending async delivery. A
persisted root exit code remains diagnostic evidence; supervisor loss is still `ERROR rc=70`
because full process-tree completion can no longer be proven.

The guardian becomes a subreaper before it forks the supervisor. If explicit cancellation was
accepted before abnormal supervisor exit, the synchronized `cancel-requested` marker is the
durable handoff and transfers that obligation to the guardian. `SIGUSR1` is only a low-latency
wake-up; the supervisor also observes the marker on its bounded poll, so requester death cannot
abandon an accepted request. The guardian adopts and terminates the remaining workload tree. Once
it has authoritatively observed an empty adopted tree, it can settle an accepted startup cancel
even when the supervisor died before publishing workload identity. The shared terminal-publication
operation then records `cancel-request`, status 143, instead of `supervisor-lost`. Recovery without
an accepted cancel continues to require both exact identities and fails closed when either is
missing. Every non-sentinel terminal producer uses that same precedence decision.

`cancel-requested` and `activation-attempted` use one state-layer durable create-once marker
primitive. It opens the state directory before marker creation, syncs the created file and directory,
and removes plus directory-syncs the marker if either publication sync fails. A failed publication
therefore does not become an accepted cancellation or consumed activation claim on a later call.
The activation lifecycle may also invoke the same durable rollback after a conclusive downstream
pre-admission failure.

Owner-authorized `status` and bulk `list` share the lost-supervisor terminal transition but not the
immediate notification role. A targeted owner `status` reconciliation owns pending completion
delivery in its current process. An owner-scoped bulk `list` may publish the same terminal state for
an accurate projection, but it never executes a helper as an incidental enumeration side effect; it
leaves delivery unattempted for the independent per-handle guardian. Cross-owner status and
`list --all` remain observational and do not reconcile state. The guardian re-enters reconciliation,
observes the terminal record, and claims pending delivery. A later targeted owner `status` may claim
it first. Both paths use the same `delivery.lock`, pinned helper, and write-ahead attempt record, so
this handoff changes the delivery owner without permitting a repeated attempt. Every valid run
creates the guardian before the supervisor; synthetic list fixtures without a guardian validate
only that list does not claim delivery, then exercise the targeted-status handoff separately.

### Completion detection — three modes
- **tree exit mode (default):** wake on root process death with `pidfd_open` + `poll`, and finish
  only after the subreaper has reaped all descendants (`waitpid` → `ECHILD`). Optional cgroup-v2
  `populated` events may be recorded, but they are not required for correctness.
- **root exit mode (`--completion-scope root`):** finish after the launched process exits and its
  captured output closes. Adopted descendants are reparented when the supervisor exits, so
  intentionally daemonized helpers do not keep an ordinary synchronous shell command running.
- **sentinel / server mode (`--ready-sentinel <regex>`):** for workloads that never exit (a
  server). "Done/ready" is a stdout marker match, because there is no exit to wait on.
  *We never assume a workload will exit.*

### Output / handle
`run` prints a handle (JSON) immediately. `status <handle>` is non-blocking: `RUNNING`, or
`DONE rc=<n>` + captured output. This generalizes the current `agents-bg{,-poll}` tmux helpers
into an event-driven, cgroup-tracked tool. The supervisor's poll of the PID is **harness-code
polling (cheap, no LLM tokens)** — not the LLM self-polling that is forbidden.

Handle observation and handle control are separate authorities. Default list visibility and
control use the same recorded owner-session or exact caller-chain predicate. `list --all` and a
cross-owner `status` may observe account-local handles, but they cannot publish recovery state,
claim delivery, cancel work, or change delivery mode. Cancel and detach fail with `EX_NOPERM` for
non-owners. Guardian recovery remains independent of any observing caller and is the automatic
cleanup/progress path after the originating process disappears. No unauthenticated cross-owner
operator override is exposed by this CLI.

### Delivery resolution metadata
At launch, while the caller is still alive and `/proc` is readable, the spooler records
`caller_ppid` and a nearest-first `caller_chain` in `meta.json`. Each chain element contains
`pid`, `/proc/<pid>/stat` field 22 as `starttime_ticks`, and the host `boot_id` from
`/proc/sys/kernel/random/boot_id`. The delivery seam still passes `--caller-ppid` and
`--meta <path>`; agent-runner resolves the owning session from the recorded chain by pure DB
lookup. The spooler does not resolve sessions.

The OpenCode adapter also supplies its provider session ID and parent invocation UUID. The spooler
records these as optional fields in `meta.json` and in a separate `owner.json`, allowing a resumed
session to rediscover its handles after the adapter process and caller PID change. Agent-runner may
use this pair as a delivery fallback only after confirming that the invocation belongs to the same
provider session. The recorded session ID also restores that session's control authority for
cancel, detach, and status reconciliation after its caller PID changes. Handles without session
metadata use the nearest exact PID/start-time/boot-ID caller-chain entry as their control anchor.

Registration resolves the configured helper once, reads it into a sealed executable image, and
stores its SHA-256 identity. The image is installed once per content digest under the account-private
state root and hard-linked as `delivery-helper` inside each dependent handle. Later activation,
completion, status recovery, and guardian recovery accept only that handle-local path, verify its
metadata and digest, copy it into a sealed in-memory image, and execute the sealed bytes. Replacing
or editing the configured source path after registration cannot change an in-flight handle.

The helper cache lock serializes cache installation, per-handle linking, and removal of cache entries
with no remaining handle links. Warm-cache content validation occurs before the lock; the critical
section rechecks the validated file identity before linking it. This keeps one physical snapshot per
live helper version rather than one full executable copy per handle without serializing full-image
hashing. The declared normal parallel admission point is eight same-account registrations sharing
one warm helper digest, bounded to eight seconds in the integration contract; the test records the
effective helper size and elapsed admission time.

The state root is a Unix-account trust boundary. Mode `0700` excludes other accounts, while
same-account workloads and observers are trusted not to rewrite another handle's state or helper
cache. The observer-isolation guarantee means a later process cannot substitute its environment or
configured helper path; it is not a sandbox between hostile processes sharing one Unix identity.
The owner check prevents accidental cross-session control within that account, but is not claimed
as authentication against a hostile same-UID process. A future cross-owner operator action requires
a separately authenticated broker or OS identity; `list --all` deliberately does not confer it.
The selected helper is an opaque trusted extension at this boundary. Its operation handlers may
maintain downstream state, but this repository claims only pinned byte identity, invocation
admission, and the observed helper-process outcome, not closure over arbitrary helper internals.

Helper provenance schema 2 is the activation boundary for this convention. A deployment owner must
drain handles created by older binaries before rollout. Draining includes explicitly terminating or
otherwise settling never-ending old-schema handles; rollout must not wait on them indefinitely.
Records with missing or older provenance are deliberately retired: later activation or completion fails closed with
`delivery_helper_legacy_unsupported` and does not fall back to the observer's helper.

### Durable delivery mode and atomic detach
Each handle stores its canonical delivery mode in `delivery-mode`; `meta.json.delivery_mode` mirrors
that value for observability. Missing mode files are interpreted as `async` for handles created by
older versions.

`detach <handle>` converts `sync` to `async`. Detach and terminal completion both hold
`delivery.lock` while deciding whether to invoke the external notification seam. Terminal state is
persisted before that decision so detach can safely observe a completion that won the race.

- If detach wins while the workload is running, it persists `async`; completion later notifies.
- If sync completion wins, it records `delivery.skipped="sync_in_band"`; a later detach transitions
  the terminal handle and notifies.
- If detach observes terminal state before completion's delivery step, detach notifies and records
  the attempt; completion reloads that record and does not notify again.
- Repeated detach calls observe `async` and are no-ops. If a caller died between the canonical mode
  write and the `meta.json` mirror, the retry repairs the mirror without repeating activation.

Detach and completion first fork a local delivery owner while retaining `delivery.lock`. That owner
persists `activation-attempted` plus canonical `async` mode, or `attempted=true` plus
`error_code="delivery_attempt_in_progress"`, immediately before it launches the helper. The owner
retains the lock and persists the observed outcome even if the initiating CLI or supervisor dies.
These are write-ahead transfer claims: once present, a successor never hands the same one-shot
obligation to the helper again, including after a nonzero exit or unknown admitted outcome.
Conclusive helper-resolution, fork, spawn, or pre-exec failures remain `attempted=false`; detach
restores sync mode, while completion records a typed result and permits one bounded retry because no
helper process received the operation. This chooses at-most-once invocation after admission without
discarding a provably pre-admission obligation.

The spooler's closed state machine ends at the admitted helper invocation and its observed process
exit. Agent-runner owns mailbox publication, transaction boundaries, and any downstream idempotency.
Accordingly, “at most once” in this repository means one admitted `agent-bash-activate` or
`agent-bash-complete` helper invocation; it does not claim an uninspected end-to-end mailbox theorem.

Before asynchronous notification, the supervisor checks the best-effort `consumed` marker. If
`AGENT_BASH_CONSUMER_GRACE_MS` is nonzero, it waits up to that bounded interval (clamped to ten
seconds) for an in-call consumer to create the marker. A marker suppresses the duplicate
notification and records `delivery.skipped="consumed_in_call"`; delivery locking still makes the
decision atomic with detach and completion.

Startup retention work is sharded by `AGENT_BASH_STATE_REAP_SHARDS` (16 by default) so large state
roots are scanned incrementally. In addition to settled terminal handles, the reaper may remove an
expired `ERROR` handle or `RUNNING` handle whose exact supervisor and workload identities are both
conclusively gone or reused. Missing or unreadable process identity evidence fails closed and keeps
the state directory.

All terminal handles use the configured state TTL. Retryable pre-invocation helper failures do not
receive a multiplied retention window, so failed delivery does not create a sevenfold retained-state
population. Each owner-authorized status observer may perform at most one helper-resolution retry
for the handle it observes; cross-owner status is read-only. `retry_count` bounds each handle to one
observer-triggered retry in total. The delivery lock serializes concurrently admitted owner
observers; the first persists either an attempt claim or a closed retry result, and later observers
cannot repeat it.

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
- No foreground execution mode; synchronous delivery still uses a detached workload.
- No PTY turn-boundary detection (PTY = forward-whenever).
- No agent-runner crate dependency in the spooler (CLI coupling only).
- Linux-first (subreaper + pidfd; optional cgroup v2 live-set support). Other platforms degrade
  to process-group + poll later.
