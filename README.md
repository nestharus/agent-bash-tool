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
  Completion and detach serialize on a per-handle lock, so either race ordering emits at most one
  mailbox notification.
- **Attached-required.** The tool must be invoked as an attached subprocess (so it can anchor the
  process tree). A detached invocation is rejected immediately.
- **Explicit completion scope.** Tree scope remains the CLI default and waits for every orphaned
  descendant, including processes that `setsid`/detach. Root scope completes after the launched
  process exits and its captured output closes, allowing intentionally daemonized helpers to
  survive. The OpenCode adapter uses root scope for ordinary commands and tree scope for child
  agents. Delegated cgroup v2 remains an optional live-set enhancement.
- **Supervisor-loss recovery.** A detached guardian waits on the exact supervisor child. If the
  supervisor exits abnormally, the guardian reconciles durable process identity and terminal state
  and performs pending asynchronous delivery without requiring a caller to poll `status`.
- **Owner-scoped cancellation.** Integrations can opt into an exact PID/start-time/boot-ID lease
  with `run --cancel-on-owner-exit --owner-pid <pid>`. `cancel <handle>`, an owner exit, or an
  OpenCode tool abort terminates the complete adopted process tree, escalating to `SIGKILL` after
  a bounded grace period. Direct CLI runs remain detached unless they explicitly request a lease.
- **Completion: root, tree, or sentinel.** Finite jobs use an explicit process boundary;
  never-exiting servers report ready on a stdout marker. Nothing is assumed to exit.
- **Async delivery via agent-runner.** For asynchronous completion the spooler asks agent-runner
  whose session the caller is and hands over the result; agent-runner wakes (headless: `resume`) or
  forwards (PTY). Synchronous completion never enters that mailbox.

The spooler is **general and provider-agnostic** — it knows nothing about agents or sessions and
talks to agent-runner only over its CLI. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full
architecture, layering, and the agent-runner-side mailbox.

## Build

```bash
cargo build --release   # produces `agent-bash`
```

## License

MIT
