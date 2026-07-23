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
  child-agent dispatches to `async`.
- **Atomic detach.** `detach <handle>` converts a running synchronous call to asynchronous delivery.
  Completion and detach serialize on a per-handle lock, so either race ordering emits at most one
  mailbox notification.
- **Attached-required.** The tool must be invoked as an attached subprocess (so it can anchor the
  process tree). A detached invocation is rejected immediately.
- **Process-tree capture via subreaper.** Every orphaned descendant — even ones that
  `setsid`/detach — reparents to the supervisor and is reaped event-driven. Delegated cgroup v2
  is used only when available as an optional live-set enhancement.
- **Completion: exit *or* sentinel.** Finite jobs wake on process exit (`pidfd`); never-exiting
  servers report ready on a stdout marker. Nothing is assumed to exit.
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
