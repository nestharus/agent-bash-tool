# agent-bash-tool

General-purpose detached bash spooler for AI agents.

Agents call `agent-bash` instead of raw bash. Every command runs **detached**, regardless of
whether the agent's harness supports background execution. Callers independently choose whether
completion returns synchronously in-band or asynchronously through the agent mailbox.

- **Always detached.** There is no foreground execution mode. `run` returns a handle immediately
  and the workload continues under a surviving supervisor.
- **Explicit result delivery.** `run --delivery sync` keeps completion in-band;
  `run --delivery async` sends completion through agent-runner. The CLI defaults to `async` for
  existing callers, while the OpenCode adapter defaults ordinary shell commands to `sync` and
  child-agent dispatches to `async`. A headless OpenCode caller cannot override a child-agent
  dispatch to `sync`; it must end its turn so the mailbox can resume it when the child completes.
  Headless asynchronous work is not leased to the caller process, so it survives that normal turn
  exit. Interactive PTY callers retain the explicit foreground option and owner-exit cancellation.
- **Atomic detach.** `detach <handle>` converts a running synchronous call to asynchronous delivery.
  Completion and detach serialize on a per-handle lock and durably claim an external helper attempt
  before launching it, so successor processes do not repeat an uncertain completion or activation.
- **Attached-required.** The tool must be invoked as an attached subprocess (so it can anchor the
  process tree). A detached invocation is rejected immediately.
- **Explicit completion scope.** Tree scope remains the CLI default and waits for every orphaned
  descendant, including processes that `setsid`/detach. Root scope completes after the launched
  process exits and its captured output closes, allowing intentionally daemonized helpers to
  survive. The OpenCode adapter uses root scope for ordinary commands and tree scope for child
  agents. Delegated cgroup v2 remains an optional live-set enhancement.
- **Supervisor-loss recovery.** A detached guardian waits on the exact supervisor child. If the
  supervisor exits abnormally, the guardian reconciles durable process identity and terminal state
  and performs pending asynchronous delivery without requiring a caller to poll `status`. Bulk
  the default owner-scoped `list` may publish that terminal state for an accurate projection without
  executing a helper; it leaves delivery unclaimed in that reconciliation. `list --all` remains a
  read-only account-wide snapshot. The guardian normally claims the pending
  delivery, while targeted owner `status` may claim it first under the same delivery lock and wait
  for the helper outcome. The adapter records in-call consumption through a control-route-eligible
  spooler operation; cross-owner `status` is read-only. The guardian also adopts the workload
  tree and finishes any already-accepted explicit cancellation.
- **Owner-scoped cancellation.** Integrations can opt into an exact PID/start-time/boot-ID lease
  with `run --cancel-on-owner-exit --owner-pid <pid>`. `cancel <handle>`, an owner exit, or an
  OpenCode tool abort terminates the complete adopted workload process tree, escalating to `SIGKILL` after
  a bounded grace period. A direct cancel is accepted when its durable marker is synchronized;
  signaling only wakes the supervisor, which also observes the marker independently. Cancellation
  of nonterminal work captures and validates an exact supervisor pidfd, with no numeric-signal fallback; unavailable
  capture fails before acceptance. Cancel JSON `requested` reports durable acceptance by this attempt,
  not whether a prior accepted cancellation obligation remains pending (`false` does not mean none
  is pending). `wake`
  separately reports `not-requested`, `custody-polling`, `sent`, `supervisor-gone`, or `failed` (`wake_error` gives detail).
  Terminal work with same-boot physical custody accepts cancellation through the existing
  reapers' durable poll (`custody-polling`, no signal sent by the requester). Empty-tree
  discharge and this admission are serialized; drained work and duplicate terminal requests
  are no-ops. Completed root status/rc and notification/ACK custody remain unchanged.
  Admission does not wait on the completion helper's delivery lock. Founding completion
  uses a separate subreaper role custodian, preserving helpers and their descendants
  through worker loss and guardian takeover. Before signaling, a fresh post-ancestry
  userspace acknowledgement from that custodian proves role containment; pidfd
  nonreadiness alone is insufficient during kernel exit. Guardian-created completion
  also leaves its cancellation poll active. The custodian polls every 10ms, and each
  signal proof may wait 100ms for acknowledgement; these are not end-to-end bounds.
  Unexpected role-custodian loss retains
  uncertainty and may prevent cancellation progress; it never grants a stale PID exemption.
  Descendant PID scans are discovery hints only: each signal uses a pidfd after
  validating a live, pidfd-pinned parent chain to the adopting reaper. Unknown,
  exited or changed ancestry is skipped and retried, never numerically signaled;
  only an empty-tree reaping observation discharges cancellation custody.
  Descendant signal validation requires `/proc` to expose the same PID-namespace
  coordinates as the reaper's `pidfd_open` calls. A procfs mount from a different
  PID namespace is unsupported; the current boundary does not verify that mount
  condition. PIDfd identity checks are not a claim of universal namespace safety.
  Missing reapers or unavailable pidfds leave drain uncertain, not successful. A sent wake is not proof of completed cancellation or tree cessation. Direct CLI
  runs remain detached unless they explicitly request a lease. Direct cancel and detach require
  the handle's recorded session, attested from the live caller chain by the handle's pinned helper,
  falling back to exact caller-tree ownership only when no session was recorded; `list --all` is
    observation, not a supported control route. The Unix account is the security and decision
    principal; session checks are cooperative routing safeguards that prevent accidental
    cross-session CLI operations, not a distinct authority boundary or a sandbox against same-UID
    processes that directly rewrite spool state.
- **Versioned adapter boundary.** The bundled OpenCode adapter and binary form one supported release
  unit. Deployment owners stop new adapter calls, drain in-flight calls, replace all installed
  adapter copies and the binary while calls remain quiesced, and resume only after the matching pair
  is active. Mixed-version adapter/binary pairs are unsupported. Older adapters that write spool
  markers directly are retired rather than supported as a compatibility path.
- **Completion: root, tree, or sentinel.** Finite jobs use an explicit process boundary;
  never-exiting servers report ready on a stdout marker. Nothing is assumed to exit.
- **Delivery helper boundary.** Native v2 completion supplies immutable original-source evidence
  to the pinned runner, which owns continuation and exact listener ACK. Sync controls in-band
  presentation, not whether an unacknowledged event remains deliverable. `accept-output` receipts
  never acknowledge mailbox events; duplicate notification is an accepted cost. No producer
  `--consumed` flag is sent. See [the candidate protocol and pairing limits](docs/completion-continuation-v2.md).
  The spooler retains original/local process custody independently of mailbox closure.
- **Pinned delivery helper.** Registration snapshots the selected helper into a content-addressed,
  account-private cache and hard-links that exact version into the handle. It also records the exact
  initiating execution environment and clears later callers' ambient environment before every helper launch.
  Registration captures the complete UTF-8 initiating environment because the opaque helper alone
  knows which values it needs. Registration-only authority and the retired allowlist control are
  removed first. The environment is stored as mode-0600 handle-private state; only its SHA-256 digest
  appears in public handle provenance. A normal helper upgrade or later caller environment therefore
  cannot substitute or strand operations for handles already in flight.

The spooler is **general, provider-agnostic, and mailbox-agnostic**. It talks to agent-runner only
over its CLI, asks that helper to resolve an opaque origin-session binding, and compares the recorded
session ID when checking supported control routing. Agent-runner still owns PID-to-session mapping, session
semantics and liveness, and all mailbox behavior. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full
architecture and ownership boundary.

The spooler transfers each helper operation to a local delivery transfer worker before persisting its
write-ahead claim and guarantees at most one admitted helper invocation per handle operation.
Live supervisors acquire completion images and run the helper in that worker asynchronously, so
image recovery and child reaping continue during delivery. Pending delivery retains the supervisor
even for Root scope; ready-mode workload exit metadata is merged after the transfer lock releases.
Conclusive process-launch failures remain pre-admission. Automatic completion progression permits
one bounded status-triggered retry; activation instead restores sync mode and requires another
explicit control-route-eligible `detach` request before retrying. Agent-runner is the authority for
mailbox transactions and deduplication after accepting an invocation. The helper is an opaque,
trusted same-account extension; its internal mailbox effects are outside this repository's state
machine. State directories and the helper cache are protected between Unix accounts, not between
mutually untrusted processes running as the same account. Within that trust boundary, the CLI still
checks recorded origin-session routing before a caller may cancel, detach, or spend a
status-triggered delivery retry.

## Build

```bash
cargo build --release   # produces `agent-bash`
```

See [private parallel test execution](docs/testing.md) for test prerequisites and isolation.
Optional [local attempt diagnostics](docs/attempt-diagnostics.md) observe existing delivery-helper calls without delivery or custody authority.

## Installed configuration

An installed binary can use an adjacent `agent-bash.toml` with absolute paths:

```toml
state_root = "/home/example/.local/state/agent-bash"
agent_runner_bin = "/home/example/.config/oulipoly-agent-runner/runner/oulipoly-agent-runner"
```

The executable path is canonicalized before the file is located, so commands may enter through a
symlink in `~/.local/bin` while configuration remains beside the real binary. If `agent-bash.toml` is
absent, state-root selection falls back to `XDG_STATE_HOME`/`HOME` and helper selection falls back
to `AGENT_BASH_AGENT_RUNNER_BIN`/`PATH`. A present but invalid file is an error and never falls back.
When the configured runner has its own adjacent `config.toml`, its `data_dir` and `config_home` are
bound into the sealed delivery-helper environment. This preserves the runner's authoritative roots
when `agent-bash` executes its immutable snapshot from a Linux memfd.

## License

MIT

### Sealed delivery-helper image reuse

Managed trees share verified sealed helper images through a tree-owned, image-only
custodian. Independent roots may duplicate images; no host-wide memory bound is
claimed. Uncertain external helper transfers and lost founding custody retain handle
artifacts rather than treating logical settlement as physical cessation; no global
retention bound is claimed. See [ownership, budgets, tree lifetime and recovery behavior](docs/helper-image-custody.md).
