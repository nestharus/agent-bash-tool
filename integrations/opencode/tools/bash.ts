import { tool } from "@opencode-ai/plugin"

/**
 * opencode `bash` tool override. All workloads survive opencode's shell timeout under agent-bash;
 * delivery mode controls whether completion returns in this call or through the agent mailbox.
 */

const AGENT_BASH = process.env.AGENT_BASH_BIN || `${process.env.HOME}/.local/bin/agent-bash`
const AGENTS = process.env.AGENT_BASH_AGENT_RUNNER_BIN || `${process.env.HOME}/.local/bin/agents`
const POLL_MS = Number(process.env.AGENT_BASH_TOOL_POLL_MS || 500)

type DeliveryMode = "sync" | "async"

type RunDispatch = {
  handle: string
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

function agentBashRunPrefix(command: string): string | undefined {
  const trimmed = command.trimStart()
  return [`${AGENT_BASH} run`, "agent-bash run"].find((prefix) => startsWithToken(trimmed, prefix))
}

function isAgentBashRun(command: string): boolean {
  return agentBashRunPrefix(command) !== undefined
}

function isAgentDispatch(command: string): boolean {
  const trimmed = command.trimStart()
  if (
    startsWithToken(trimmed, "agents") ||
    startsWithToken(trimmed, AGENTS) ||
    startsWithToken(trimmed, "oulipoly-agent-runner")
  ) {
    return true
  }
  return isAgentBashRun(trimmed) && /\s--\s+(?:[^\s]+\/)?(?:agents|oulipoly-agent-runner)(?:\s|$)/.test(trimmed)
}

function selectedDelivery(command: string, requested: string | undefined): DeliveryMode {
  if (validDeliveryMode(requested)) return requested
  return isAgentDispatch(command) ? "async" : "sync"
}

function commandWithDelivery(command: string, delivery: DeliveryMode): string {
  const trimmed = command.trimStart()
  const leadingWhitespace = command.slice(0, command.length - trimmed.length)
  const prefix = agentBashRunPrefix(trimmed)
  if (!prefix) return command
  const suffix = trimmed.slice(prefix.length)
  const normalizedSuffix = suffix.replace(/^\s+--delivery\s+(?:sync|async)\b/, "")
  return `${leadingWhitespace}${prefix} --delivery ${delivery}${normalizedSuffix}`
}

async function dispatchCommand(command: string, delivery: DeliveryMode): Promise<string> {
  if (isAgentBashRun(command)) {
    const explicitRun = commandWithDelivery(command, delivery)
    return (await Bun.$`bash -lc ${explicitRun}`.env(runEnv()).nothrow().text()).trim()
  }
  return (
    await Bun.$`${AGENT_BASH} run --delivery ${delivery} -- bash -lc ${command}`.env(runEnv()).nothrow().text()
  ).trim()
}

async function waitForSyncResult(handle: string): Promise<string> {
  while (true) {
    const status = await statusText(handle, true)
    if (isTerminalStatus(status)) return statusText(handle)
    if ((await modeText(handle)) === "async") return asyncDispatchResponse(handle)
    await Bun.sleep(POLL_MS)
  }
}

function asyncDispatchResponse(handle: string): string {
  return (
    `Running asynchronously (handle=${handle}). You will be woken with the result when it completes, ` +
    `or call bash with { handle: "${handle}" } to poll.`
  )
}

export default tool({
  description:
    "Run a shell command under a detached supervisor. Ordinary commands default to synchronous in-band completion; " +
    "child-agent dispatches default to asynchronous mailbox delivery and return a handle immediately. Set `delivery` " +
    "to override either default. A synchronous call can be detached externally without terminating its workload.",
  args: {
    command: tool.schema.string().describe("the shell command to run").optional(),
    handle: tool.schema.string().describe("poll an existing asynchronous command by its handle").optional(),
    delivery: tool.schema.string().describe('completion delivery: "sync" or "async"').optional(),
  },
  async execute(args) {
    if (args.handle) return statusText(args.handle)
    if (!commandProvided(args.command)) return missingCommandResponse()
    if (args.delivery !== undefined && !validDeliveryMode(args.delivery)) {
      return invalidDeliveryResponse(args.delivery)
    }

    const delivery = selectedDelivery(args.command, args.delivery)
    const runOut = await dispatchCommand(args.command, delivery)
    const dispatch = parseRunDispatch(runOut)
    if (!dispatch) return dispatchErrorResponse(runOut)
    if (delivery === "async") return asyncDispatchResponse(dispatch.handle)
    return waitForSyncResult(dispatch.handle)
  },
})
