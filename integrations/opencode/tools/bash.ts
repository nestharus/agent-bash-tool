import { tool } from "@opencode-ai/plugin"
import { join } from "node:path"

/**
 * opencode `bash` tool override. Workloads survive shell timeouts under agent-bash, but remain
 * leased to this opencode process so aborting the tool or closing the session cancels the tree.
 * Exact `agent-bash list [--all] [--json]` observations and standalone sleeps run attached without
 * creating a workload. Session ownership metadata lets resumed processes rediscover their handles.
 */

const AGENT_BASH = process.env.AGENT_BASH_BIN || `${process.env.HOME}/.local/bin/agent-bash`
const AGENTS = process.env.AGENT_BASH_AGENT_RUNNER_BIN || `${process.env.HOME}/.local/bin/agents`
const POLL_MS = Number(process.env.AGENT_BASH_TOOL_POLL_MS || 500)
const CONSUMER_GRACE_MS = Number(process.env.AGENT_BASH_CONSUMER_GRACE_MS || Math.max(POLL_MS * 3, 1500))
const MAX_FOREGROUND_SLEEP_MS = Number(process.env.AGENT_BASH_TOOL_MAX_FOREGROUND_SLEEP_MS || 300000)

type DeliveryMode = "sync" | "async"
type CompletionScope = "root" | "tree"

type RunDispatch = {
  handle: string
  stateDir: string | undefined
}

type ShellCommand = {
  prefix: string
  body: string
}

type ProcessResult = {
  exitCode: number
  stdout: string
  stderr: string
}

function ownerInvocationUuid(): string | undefined {
  const raw = process.env.OULIPOLY_PARENT_INVOCATION
  if (!raw) return undefined
  try {
    const parsed = JSON.parse(raw)
    return typeof parsed.id === "string" && parsed.id.length > 0 ? parsed.id : undefined
  } catch {
    return undefined
  }
}

function runEnv(ownerSessionId?: string) {
  const invocationUuid = ownerInvocationUuid()
  return {
    ...process.env,
    AGENT_BASH_AGENT_RUNNER_BIN: AGENTS,
    AGENT_BASH_CONSUMER_GRACE_MS: String(CONSUMER_GRACE_MS),
    ...(ownerSessionId ? { AGENT_BASH_OWNER_SESSION_ID: ownerSessionId } : {}),
    ...(invocationUuid ? { AGENT_BASH_OWNER_INVOCATION_UUID: invocationUuid } : {}),
  }
}

async function runProcess(argv: string[], ownerSessionId?: string): Promise<ProcessResult> {
  const child = Bun.spawn(argv, { env: runEnv(ownerSessionId), stdout: "pipe", stderr: "pipe" })
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ])
  return { exitCode, stdout, stderr }
}

function processFailure(operation: string, result: ProcessResult): Error {
  const detail = result.stderr.trim() || result.stdout.trim()
  return new Error(`${operation} failed with exit code ${result.exitCode}${detail ? `: ${detail}` : ""}`)
}

async function checkedProcessText(
  argv: string[],
  operation: string,
  ownerSessionId?: string,
): Promise<string> {
  const result = await runProcess(argv, ownerSessionId)
  if (result.exitCode !== 0) throw processFailure(operation, result)
  return result.stdout.trim()
}

function stateRoot(): string | undefined {
  if (process.env.XDG_STATE_HOME) return join(process.env.XDG_STATE_HOME, "agent-bash")
  if (process.env.HOME) return join(process.env.HOME, ".local/state/agent-bash")
  return undefined
}

function stateDirForHandle(handle: string): string | undefined {
  const root = stateRoot()
  return root ? join(root, handle) : undefined
}

async function markConsumed(stateDir: string | undefined) {
  if (!stateDir) return
  try {
    await Bun.write(join(stateDir, "consumed"), "")
  } catch {
    // Best-effort: failure only risks a duplicate completion notification.
  }
}

async function statusText(handle: string, headerOnly = false, ownerSessionId?: string): Promise<string> {
  const args = [AGENT_BASH, "status"]
  if (headerOnly) args.push("--tail-bytes", "0")
  args.push(handle)
  return checkedProcessText(args, "agent-bash status", ownerSessionId)
}

async function terminalStatus(
  handle: string,
  stateDir: string | undefined,
  ownerSessionId?: string,
): Promise<string | undefined> {
  const status = await statusText(handle, true, ownerSessionId)
  if (!isTerminalStatus(status)) return undefined
  await markConsumed(stateDir)
  return statusText(handle, false, ownerSessionId)
}

async function modeText(handle: string, ownerSessionId: string): Promise<string> {
  return checkedProcessText([AGENT_BASH, "mode", handle], "agent-bash mode", ownerSessionId)
}

function isTerminalStatus(status: string): boolean {
  return status.startsWith("DONE") || status.startsWith("ERROR")
}

function commandProvided(command: string | undefined): command is string {
  return Boolean(command)
}

export function standaloneSleepMilliseconds(command: string): number | undefined {
  const match = /^\s*sleep\s+((?:\d+(?:\.\d*)?|\.\d+))\s*$/.exec(command)
  if (!match) return undefined

  const milliseconds = Math.ceil(Number(match[1]) * 1000)
  if (!Number.isFinite(milliseconds) || milliseconds < 0 || milliseconds > MAX_FOREGROUND_SLEEP_MS) {
    return undefined
  }
  return milliseconds
}

async function runStandaloneSleep(milliseconds: number): Promise<string> {
  await Bun.sleep(milliseconds)
  return "DONE rc=0\n--- output ---"
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

type ListControl = {
  all: boolean
  json: boolean
}

function classifyListControl(command: string): ListControl | undefined {
  const trimmed = command.trim()
  if (!trimmed) return undefined
  const tokens = trimmed.split(/\s+/)
  if (tokens.length < 2 || tokens.length > 4) return undefined
  if ((tokens[0] !== AGENT_BASH && tokens[0] !== "agent-bash") || tokens[1] !== "list") return undefined

  let all = false
  let json = false
  for (const token of tokens.slice(2)) {
    if (token === "--all" && !all) {
      all = true
    } else if (token === "--json" && !json) {
      json = true
    } else {
      return undefined
    }
  }
  return { all, json }
}

async function executeListControl(control: ListControl, ownerSessionId: string): Promise<string> {
  const argv = [AGENT_BASH, "list"]
  if (control.all) argv.push("--all")
  if (control.json) argv.push("--json")

  const child = Bun.spawn(argv, { env: runEnv(ownerSessionId), stdout: "pipe", stderr: "pipe" })
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited,
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
  ])
  if (exitCode !== 0) {
    const detail = stderr.trim()
    throw new Error(`agent-bash list failed with exit code ${exitCode}${detail ? `: ${detail}` : ""}`)
  }
  return stdout
}

function parseRunDispatch(runOut: string): RunDispatch | undefined {
  try {
    const parsed = JSON.parse(runOut)
    return typeof parsed.handle === "string"
      ? { handle: parsed.handle, stateDir: typeof parsed.state_dir === "string" ? parsed.state_dir : undefined }
      : undefined
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

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
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

function pinAgentRunnerBinary(command: string): string {
  const shellCommand = splitShellCommand(command)
  let body = shellCommand.body
  for (const token of ["agents", "oulipoly-agent-runner"]) {
    if (startsWithToken(body, token)) {
      return `${shellCommand.prefix}${shellQuote(AGENTS)}${body.slice(token.length)}`
    }
  }
  body = body.replace(/(\s--\s+)(?:agents|oulipoly-agent-runner)(?=\s|$)/, `$1${shellQuote(AGENTS)}`)
  return `${shellCommand.prefix}${body}`
}

function isHeadlessCaller(): boolean {
  return process.stdin.isTTY !== true
}

function selectedDelivery(command: string, requested: string | undefined): DeliveryMode {
  if (isAgentDispatch(command) && isHeadlessCaller()) return "async"
  if (validDeliveryMode(requested)) return requested
  return isAgentDispatch(command) ? "async" : "sync"
}

function leaseToCaller(delivery: DeliveryMode): boolean {
  return delivery === "sync" || !isHeadlessCaller()
}

function selectedCompletionScope(command: string): CompletionScope {
  return isAgentDispatch(command) ? "tree" : "root"
}

function commandWithDelivery(command: string, delivery: DeliveryMode, ownerLease: boolean): string {
  const shellCommand = splitShellCommand(command)
  const prefix = agentBashRunPrefix(shellCommand.body)
  if (!prefix) return command
  const suffix = shellCommand.body.slice(prefix.length)
  const normalizedSuffix = suffix.replace(/^\s+--delivery\s+(?:sync|async)\b/, "")
  const lease = ownerLease ? ` --cancel-on-owner-exit --owner-pid ${process.pid}` : ""
  return `${shellCommand.prefix}${prefix}${lease} --delivery ${delivery}${normalizedSuffix}`
}

async function dispatchCommand(
  command: string,
  delivery: DeliveryMode,
  ownerLease: boolean,
  completionScope: CompletionScope,
  ownerSessionId: string,
): Promise<string> {
  command = pinAgentRunnerBinary(command)
  if (isAgentBashRun(command)) {
    const explicitRun = commandWithDelivery(command, delivery, ownerLease)
    return checkedProcessText(["bash", "-lc", explicitRun], "agent-bash dispatch", ownerSessionId)
  }
  const args = [AGENT_BASH, "run"]
  if (!ownerLease) {
    args.push("--completion-scope", completionScope, "--delivery", delivery)
  } else {
    args.push(
      "--cancel-on-owner-exit",
      "--owner-pid",
      String(process.pid),
      "--completion-scope",
      completionScope,
      "--delivery",
      delivery,
    )
  }
  args.push("--", "bash", "-lc", command)
  return checkedProcessText(args, "agent-bash dispatch", ownerSessionId)
}

async function cancelResult(handle: string, ownerSessionId: string): Promise<string> {
  const result = await checkedProcessText(
    [AGENT_BASH, "cancel", handle],
    "agent-bash cancel",
    ownerSessionId,
  )
  return `Cancellation requested (handle=${handle}). ${result}`
}

async function waitForSyncResult(
  handle: string,
  stateDir: string | undefined,
  abort: AbortSignal,
  ownerSessionId: string,
): Promise<string> {
  const aborted = new Promise<void>((resolve) => {
    if (abort.aborted) resolve()
    else abort.addEventListener("abort", () => resolve(), { once: true })
  })
  while (true) {
    if (abort.aborted) return cancelResult(handle, ownerSessionId)
    const status = await terminalStatus(handle, stateDir, ownerSessionId)
    if (status !== undefined) return status
    if ((await modeText(handle, ownerSessionId)) === "async") return asyncDispatchResponse(handle)
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
    "ordinary commands complete with their root process, while child-agent dispatches retain full-tree completion. " +
    "Child-agent dispatches default to asynchronous mailbox delivery and return a handle immediately. Set `delivery` " +
    "to override either default. Headless child-agent dispatches remain asynchronous so their caller can end its turn. " +
    "A synchronous call can be detached externally without terminating its workload. Exact " +
    "`agent-bash list [--all] [--json]` observations and bounded standalone sleeps run attached without creating a " +
    `workload handle. Leading agent-runner commands are pinned to ${AGENTS}.`,
  args: {
    command: tool.schema.string().describe("the shell command to run").optional(),
    handle: tool.schema.string().describe("poll an existing asynchronous command by its handle").optional(),
    delivery: tool.schema.string().describe('completion delivery: "sync" or "async"').optional(),
  },
  async execute(args, context) {
    if (args.handle) {
      return (
        (await terminalStatus(args.handle, stateDirForHandle(args.handle), context.sessionID)) ??
        statusText(args.handle, false, context.sessionID)
      )
    }
    if (!commandProvided(args.command)) return missingCommandResponse()
    if (args.delivery !== undefined && !validDeliveryMode(args.delivery)) {
      return invalidDeliveryResponse(args.delivery)
    }
    const listControl = classifyListControl(args.command)
    if (listControl) {
      return executeListControl(listControl, context.sessionID)
    }

    if (context.abort.aborted) return "Cancellation requested before dispatch."
    const delivery = selectedDelivery(args.command, args.delivery)
    const sleepMilliseconds = standaloneSleepMilliseconds(args.command)
    if (delivery === "sync" && sleepMilliseconds !== undefined) {
      return runStandaloneSleep(sleepMilliseconds)
    }
    const runOut = await dispatchCommand(
      args.command,
      delivery,
      leaseToCaller(delivery),
      selectedCompletionScope(args.command),
      context.sessionID,
    )
    const dispatch = parseRunDispatch(runOut)
    if (!dispatch) return dispatchErrorResponse(runOut)
    if (context.abort.aborted) return cancelResult(dispatch.handle, context.sessionID)
    if (delivery === "async") {
      return asyncDispatchResponse(dispatch.handle, isAgentDispatch(args.command) && isHeadlessCaller())
    }
    return waitForSyncResult(dispatch.handle, dispatch.stateDir, context.abort, context.sessionID)
  },
})
