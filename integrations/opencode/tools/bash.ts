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
  if (!isTerminalStatus(status)) return undefined
  await markConsumed(stateDir)
  return statusText(handle)
}

function isTerminalStatus(status: string): boolean {
  return status.startsWith("DONE")
}

function commandProvided(command: string | undefined): command is string {
  return Boolean(command)
}

function missingCommandResponse(): string {
  return "error: provide `command` (to run) or `handle` (to poll an existing background command)"
}

type RunDispatch = {
  handle: string
  stateDir: string | undefined
}

function parseRunDispatch(runOut: string): RunDispatch | undefined {
  try {
    return runDispatchFromJson(JSON.parse(runOut))
  } catch {
    return undefined
  }
}

function runDispatchFromJson(run: { handle: string; state_dir?: string }): RunDispatch {
  return {
    handle: run.handle,
    stateDir: run.state_dir,
  }
}

function dispatchErrorResponse(runOut: string): string {
  return `agent-bash spooler error (could not dispatch): ${runOut}`
}

function waitDeadline(): number {
  return Date.now() + WAIT_MS
}

function beforeDeadline(deadline: number): boolean {
  return Date.now() < deadline
}

function foundStatus(status: string | undefined): status is string {
  return status !== undefined
}

async function sleepPollInterval(): Promise<void> {
  await new Promise((r) => setTimeout(r, POLL_MS))
}

async function waitForTerminalStatus(handle: string, stateDir: string | undefined): Promise<string | undefined> {
  const deadline = waitDeadline()
  while (beforeDeadline(deadline)) {
    const status = await terminalStatus(handle, stateDir)
    if (foundStatus(status)) return status
    await sleepPollInterval()
  }
  return undefined
}

function backgroundStatusResponse(handle: string, status: string): string {
  return (
    `Still running in background (handle=${handle}). You will be woken with the result when it completes, ` +
    `or call bash with { handle: "${handle}" } to poll.\n${status}`
  )
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
    if (!commandProvided(args.command)) {
      return missingCommandResponse()
    }

    const runOut = (await Bun.$`${AGENT_BASH} run -- bash -lc ${args.command}`.nothrow().text()).trim()
    const dispatch = parseRunDispatch(runOut)
    if (!dispatch) return dispatchErrorResponse(runOut)

    const status = await waitForTerminalStatus(dispatch.handle, dispatch.stateDir)
    if (status) return status
    return backgroundStatusResponse(dispatch.handle, await statusText(dispatch.handle))
  },
})
