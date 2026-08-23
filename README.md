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
  for the helper outcome. Cross-owner `status` is read-only. The guardian also adopts the workload
  tree and finishes any already-accepted explicit cancellation.
- **Owner-scoped cancellation.** Integrations can opt into an exact PID/start-time/boot-ID lease
  with `run --cancel-on-owner-exit --owner-pid <pid>`. `cancel <handle>`, an owner exit, or an
  OpenCode tool abort terminates the complete adopted process tree, escalating to `SIGKILL` after
  a bounded grace period. A direct cancel is accepted when its durable marker is synchronized;
  signaling only wakes the supervisor, which also observes the marker independently. Direct CLI
  runs remain detached unless they explicitly request a lease. Direct cancel and detach require
  the handle's recorded session, attested from the live caller chain by the handle's pinned helper,
  falling back to exact caller-tree ownership only when no session was recorded; `list --all` is
  observation, not a grant of control authority.
- **Completion: root, tree, or sentinel.** Finite jobs use an explicit process boundary;
  never-exiting servers report ready on a stdout marker. Nothing is assumed to exit.
- **Delivery helper boundary.** Every completion invokes the handle's pinned helper operation.
  Agent-runner interprets the registered mode and event flags: asynchronous completion wakes
  (headless: `resume`) or forwards (PTY), while synchronous or already-consumed completion does not
  enter that mailbox. The spooler owns helper admission and process outcome, not mailbox closure.
- **Pinned delivery helper.** Registration snapshots the selected helper into a content-addressed,
  account-private cache and hard-links that exact version into the handle. It also records a small
  execution environment and clears later callers' ambient environment before every helper launch.
  Additional non-secret variables must be named at registration in
  `AGENT_BASH_DELIVERY_HELPER_ENV_ALLOWLIST`; their values become durable handle provenance. A normal
  helper upgrade or later caller environment therefore cannot substitute or strand operations for
  handles already in flight. Registration-only authority and helper-selection controls are removed
  before the workload starts.

The spooler is **general, provider-agnostic, and mailbox-agnostic**. It talks to agent-runner only
over its CLI, asks that helper to resolve an opaque owner-session binding, and compares the recorded
session ID when enforcing handle authority. Agent-runner still owns PID-to-session mapping, session
semantics and liveness, and all mailbox behavior. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full
architecture and ownership boundary.

The spooler transfers each helper operation to a local delivery owner before persisting its
write-ahead claim and guarantees at most one admitted helper invocation per handle operation.
Conclusive process-launch failures remain pre-admission and get one bounded retry. Agent-runner is
the authority for mailbox transactions and deduplication after accepting an invocation. The helper
is an opaque, trusted same-account extension; its internal mailbox effects are outside this
repository's state machine. State directories and the helper cache are protected between Unix
accounts, not between mutually untrusted processes running as the same account. Within that trust
boundary, the CLI still enforces recorded handle ownership before a caller may cancel, detach, or
spend a status-triggered delivery retry.

## Build

```bash
cargo build --release   # produces `agent-bash`
```

## License

MIT
