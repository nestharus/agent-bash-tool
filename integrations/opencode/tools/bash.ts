import { tool } from "@opencode-ai/plugin"

/**
 * opencode `bash` tool override. Workloads survive shell timeouts under agent-bash, but remain
 * leased to this opencode process so aborting the tool or closing the session cancels the tree.
 */

const AGENT_BASH = process.env.AGENT_BASH_BIN || `${process.env.HOME}/.local/bin/agent-bash`
const AGENTS = process.env.AGENT_BASH_AGENT_RUNNER_BIN || `${process.env.HOME}/.local/bin/agents`
const POLL_MS = Number(process.env.AGENT_BASH_TOOL_POLL_MS || 500)

type DeliveryMode = "sync" | "async"

type RunDispatch = {
  handle: string
}

type ShellCommand = {
  prefix: string
  body: string
}

function runEnv() {
  return {
    ...process.env,
    AGENT_BASH_AGENT_RUNNER_BIN: AGENTS,
  }
}

async function statusText(handle: string, headerOnly = false): Promise<string> {
  if (headerOnly) {
    return (await Bun.$`${AGENT_BASH} status --tail-bytes 0 ${handle}`.env(runEnv()).nothrow().text()).trim()
  }
  return (await Bun.$`${AGENT_BASH} status ${handle}`.env(runEnv()).nothrow().text()).trim()
}

async function modeText(handle: string): Promise<string> {
  return (await Bun.$`${AGENT_BASH} mode ${handle}`.env(runEnv()).nothrow().text()).trim()
}

function isTerminalStatus(status: string): boolean {
  return status.startsWith("DONE") || status.startsWith("ERROR")
}

function commandProvided(command: string | undefined): command is string {
  return Boolean(command)
}

function validDeliveryMode(value: string | undefined): value is DeliveryMode {
  return value === "sync" || value === "async"
}

function missingCommandResponse(): string {
  return "error: provide `command` (to run) or `handle` (to poll an existing background command)"
}

function invalidDeliveryResponse(value: string): string {
  return `error: delivery must be \"sync\" or \"async\", got ${JSON.stringify(value)}`
}

function parseRunDispatch(runOut: string): RunDispatch | undefined {
  try {
    const parsed = JSON.parse(runOut)
    return typeof parsed.handle === "string" ? { handle: parsed.handle } : undefined
  } catch {
    return undefined
  }
}

function dispatchErrorResponse(runOut: string): string {
  return `agent-bash spooler error (could not dispatch): ${runOut}`
}

function startsWithToken(command: string, token: string): boolean {
  return command === token || command.startsWith(`${token} `)
}

function splitShellCommand(command: string): ShellCommand {
  const leadingWhitespace = command.match(/^\s*/)?.[0] || ""
  let body = command.slice(leadingWhitespace.length)
  let environmentPrefix = ""
  const assignment = /^[A-Za-z_][A-Za-z0-9_]*=(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s]*)\s+/
  while (true) {
    const matched = body.match(assignment)?.[0]
    if (!matched) break
    environmentPrefix += matched
    body = body.slice(matched.length)
  }
  return { prefix: leadingWhitespace + environmentPrefix, body }
}

function agentBashRunPrefix(command: string): string | undefined {
  const { body } = splitShellCommand(command)
  return [`${AGENT_BASH} run`, "agent-bash run"].find((prefix) => startsWithToken(body, prefix))
}

function isAgentBashRun(command: string): boolean {
  return agentBashRunPrefix(command) !== undefined
}

function isAgentDispatch(command: string): boolean {
  const { body } = splitShellCommand(command)
  if (
    startsWithToken(body, "agents") ||
    startsWithToken(body, AGENTS) ||
    startsWithToken(body, "oulipoly-agent-runner")
  ) {
    return true
  }
  return isAgentBashRun(body) && /\s--\s+(?:[^\s]+\/)?(?:agents|oulipoly-agent-runner)(?:\s|$)/.test(body)
}

function isHeadlessCaller(): boolean {
  return process.stdin.isTTY !== true
}

function selectedDelivery(command: string, requested: string | undefined): DeliveryMode {
  if (isAgentDispatch(command) && isHeadlessCaller()) return "async"
  if (validDeliveryMode(requested)) return requested
  return isAgentDispatch(command) ? "async" : "sync"
}

function commandWithDelivery(command: string, delivery: DeliveryMode): string {
  const shellCommand = splitShellCommand(command)
  const prefix = agentBashRunPrefix(shellCommand.body)
  if (!prefix) return command
  const suffix = shellCommand.body.slice(prefix.length)
  const normalizedSuffix = suffix.replace(/^\s+--delivery\s+(?:sync|async)\b/, "")
  return (
    `${shellCommand.prefix}${prefix} --cancel-on-owner-exit --owner-pid ${process.pid} ` +
    `--delivery ${delivery}${normalizedSuffix}`
  )
}

async function dispatchCommand(command: string, delivery: DeliveryMode): Promise<string> {
  if (isAgentBashRun(command)) {
    const explicitRun = commandWithDelivery(command, delivery)
    return (await Bun.$`bash -lc ${explicitRun}`.env(runEnv()).nothrow().text()).trim()
  }
  return (
    await Bun.$`${AGENT_BASH} run --cancel-on-owner-exit --owner-pid ${process.pid} --delivery ${delivery} -- bash -lc ${command}`
      .env(runEnv())
      .nothrow()
      .text()
  ).trim()
}

async function cancelResult(handle: string): Promise<string> {
  const result = (await Bun.$`${AGENT_BASH} cancel ${handle}`.env(runEnv()).nothrow().text()).trim()
  return `Cancellation requested (handle=${handle}). ${result}`
}

async function waitForSyncResult(handle: string, abort: AbortSignal): Promise<string> {
  const aborted = new Promise<void>((resolve) => {
    if (abort.aborted) resolve()
    else abort.addEventListener("abort", () => resolve(), { once: true })
  })
  while (true) {
    if (abort.aborted) return cancelResult(handle)
    const status = await statusText(handle, true)
    if (isTerminalStatus(status)) return statusText(handle)
    if ((await modeText(handle)) === "async") return asyncDispatchResponse(handle)
    await Promise.race([Bun.sleep(POLL_MS), aborted])
  }
}

function asyncDispatchResponse(handle: string, endHeadlessTurn = false): string {
  const response =
    `Running asynchronously (handle=${handle}). You will be woken with the result when it completes, ` +
    `or call bash with { handle: "${handle}" } to poll.`
  return endHeadlessTurn ? `${response} End this headless turn now so the notification can resume it.` : response
}

export default tool({
  description:
    "Run a shell command under a detached supervisor. Ordinary commands default to synchronous in-band completion; " +
    "child-agent dispatches default to asynchronous mailbox delivery and return a handle immediately. Set `delivery` " +
    "to override either default. Headless child-agent dispatches remain asynchronous so their caller can end its turn. " +
    "A synchronous call can be detached externally without terminating its workload.",
  args: {
    command: tool.schema.string().describe("the shell command to run").optional(),
    handle: tool.schema.string().describe("poll an existing asynchronous command by its handle").optional(),
    delivery: tool.schema.string().describe('completion delivery: "sync" or "async"').optional(),
  },
  async execute(args, context) {
    if (args.handle) return statusText(args.handle)
    if (!commandProvided(args.command)) return missingCommandResponse()
    if (args.delivery !== undefined && !validDeliveryMode(args.delivery)) {
      return invalidDeliveryResponse(args.delivery)
    }

    if (context.abort.aborted) return "Cancellation requested before dispatch."
    const delivery = selectedDelivery(args.command, args.delivery)
    const runOut = await dispatchCommand(args.command, delivery)
    const dispatch = parseRunDispatch(runOut)
    if (!dispatch) return dispatchErrorResponse(runOut)
    if (context.abort.aborted) return cancelResult(dispatch.handle)
    if (delivery === "async") {
      return asyncDispatchResponse(dispatch.handle, isAgentDispatch(args.command) && isHeadlessCaller())
    }
    return waitForSyncResult(dispatch.handle, context.abort)
  },
})
