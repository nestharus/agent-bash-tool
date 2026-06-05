import { tool } from "@opencode-ai/plugin"
import { join } from "node:path"

/**
 * opencode `bash` tool override — routes every shell command through the agent-bash spooler.
 *
 * Install: copy to `~/.config/opencode/tools/bash.ts` (the filename `bash` makes it REPLACE the
 * built-in bash tool — opencode gives a same-named custom tool precedence).
 *
 * Behavior: ALWAYS background (the spooler detaches the workload; no opencode bash timeout applies).
 * The call waits up to AGENT_BASH_TOOL_WAIT_MS for a fast result; if the command finishes in time you
 * get its output immediately. Otherwise it keeps running detached and you are WOKEN with the result
 * when it completes (delivered into a later turn by agent-runner's mailbox/resume), or you can poll by
 * calling bash again with { handle }.
 */

const AGENT_BASH = process.env.AGENT_BASH_BIN || `${process.env.HOME}/.local/bin/agent-bash`
const WAIT_MS = Number(process.env.AGENT_BASH_TOOL_WAIT_MS || 8000)
const POLL_MS = Number(process.env.AGENT_BASH_TOOL_POLL_MS || 500)

function stateRoot(): string | undefined {
  if (process.env.XDG_STATE_HOME) return join(process.env.XDG_STATE_HOME, "agent-bash")
  if (process.env.HOME) return join(process.env.HOME, ".local/state/agent-bash")
  return undefined
}

function stateDirForHandle(handle: string): string | undefined {
  const root = stateRoot()
  if (!root) return undefined
  return join(root, handle)
}

async function markConsumed(stateDir: string | undefined) {
  if (!stateDir) return
  try {
    await Bun.write(join(stateDir, "consumed"), "")
  } catch {
    // Best-effort: failure only risks a harmless duplicate completion envelope.
  }
}

async function statusText(handle: string, headerOnly = false): Promise<string> {
  if (headerOnly) {
    return (await Bun.$`${AGENT_BASH} status --tail-bytes 0 ${handle}`.nothrow().text()).trim()
  }
  return (await Bun.$`${AGENT_BASH} status ${handle}`.nothrow().text()).trim()
}

async function terminalStatus(handle: string, stateDir: string | undefined): Promise<string | undefined> {
  const status = await statusText(handle, true)
  if (!status.startsWith("DONE")) return undefined
  await markConsumed(stateDir)
  return statusText(handle)
}

export default tool({
  description:
    "Run a shell command. It ALWAYS runs in the background via the agent-bash spooler (detached, no timeout). " +
    `This call waits up to ${WAIT_MS}ms for a quick result; if the command finishes in time you get its output now. ` +
    "If it is still running you get a { handle } and the command keeps running detached — you will be WOKEN with the " +
    "result when it completes (delivered into a later turn), or poll by calling bash again with { handle }. " +
    "Use this for everything you would use a shell for, including dispatching `agents` child invocations " +
    "(they run in the background and wake you on completion).",
  args: {
    command: tool.schema.string().describe("the shell command to run").optional(),
    handle: tool.schema.string().describe("poll an existing background command by its handle instead of running").optional(),
  },
  async execute(args) {
    if (args.handle) {
      return (await terminalStatus(args.handle, stateDirForHandle(args.handle))) ?? statusText(args.handle)
    }
    if (!args.command) {
      return "error: provide `command` (to run) or `handle` (to poll an existing background command)"
    }

    const runOut = (await Bun.$`${AGENT_BASH} run -- bash -lc ${args.command}`.nothrow().text()).trim()
    let handle: string
    let stateDir: string | undefined
    try {
      const run = JSON.parse(runOut)
      handle = run.handle
      stateDir = run.state_dir
    } catch {
      return `agent-bash spooler error (could not dispatch): ${runOut}`
    }

    const deadline = Date.now() + WAIT_MS
    while (Date.now() < deadline) {
      const status = await terminalStatus(handle, stateDir)
      if (status) return status
      await new Promise((r) => setTimeout(r, POLL_MS))
    }
    const status = await statusText(handle)
    return (
      `Still running in background (handle=${handle}). You will be woken with the result when it completes, ` +
      `or call bash with { handle: "${handle}" } to poll.\n${status}`
    )
  },
})
