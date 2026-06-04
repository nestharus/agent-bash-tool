# agent-bash-tool

General-purpose **always-background** bash spooler for AI agents.

Agents call `agent-bash` instead of raw bash. Every command runs **detached**, regardless of
whether the agent's harness supports background execution — so a long-lived agent can dispatch
a long command, keep working, and be notified when it finishes, on any harness.

- **Always background.** There is no foreground mode. `run` returns a handle immediately and the
  workload continues under a surviving supervisor.
- **Attached-required.** The tool must be invoked as an attached subprocess (so it can anchor the
  process tree). A detached invocation is rejected immediately.
- **Process-tree capture via subreaper.** Every orphaned descendant — even ones that
  `setsid`/detach — reparents to the supervisor and is reaped event-driven. Delegated cgroup v2
  is used only when available as an optional live-set enhancement.
- **Completion: exit *or* sentinel.** Finite jobs wake on process exit (`pidfd`); never-exiting
  servers report ready on a stdout marker. Nothing is assumed to exit.
- **Delivery via agent-runner.** On completion the spooler asks agent-runner whose session the
  caller is and hands over the result; agent-runner wakes (headless: `resume`) or forwards (PTY).

The spooler is **general and provider-agnostic** — it knows nothing about agents or sessions and
talks to agent-runner only over its CLI. See [`docs/DESIGN.md`](docs/DESIGN.md) for the full
architecture, layering, and the agent-runner-side mailbox.

## Status

Scaffold. Core implementation tracked as WU-C; agent-runner-side primitives as WU-A/WU-B.

## Build

```bash
cargo build --release   # produces `agent-bash`
```

## License

MIT
