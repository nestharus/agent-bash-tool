import { tool } from "@opencode-ai/plugin"
import { createConnection } from "node:net"
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
const PROCESS_TIMEOUT_MS = Number(process.env.AGENT_BASH_TOOL_PROCESS_TIMEOUT_MS || 10000)
const LIVE_SESSION_BIND_TIMEOUT_MS = 5000
const MAX_LIVE_SESSION_RESPONSE_BYTES = 16 * 1024

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

type LiveSessionResponse = {
  ok?: boolean
  session_id?: string
  error?: string
}

let liveSessionBinding: Promise<void> | undefined

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

function reportLiveSession(
  socketPath: string,
  token: string,
  invocationUuid: string,
  providerSessionId: string,
): Promise<void> {
  return new Promise((resolve, reject) => {
    const socket = createConnection({ path: socketPath })
    let responseBytes = ""
    let settled = false
    const timeout = setTimeout(
      () => finish(new Error(`live session binding timed out after ${LIVE_SESSION_BIND_TIMEOUT_MS}ms`)),
      LIVE_SESSION_BIND_TIMEOUT_MS,
    )
    const finish = (error?: Error) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      socket.destroy()
      if (error) reject(error)
      else resolve()
    }

    socket.setEncoding("utf8")
    socket.on("connect", () => {
      socket.write(
        `${JSON.stringify({
          schema_version: 1,
          token,
          invocation_uuid: invocationUuid,
          provider_session_id: providerSessionId,
        })}\n`,
      )
    })
    socket.on("data", (chunk: string) => {
      responseBytes += chunk
      if (Buffer.byteLength(responseBytes) > MAX_LIVE_SESSION_RESPONSE_BYTES) {
        finish(new Error("live session binding response exceeded the size limit"))
        return
      }
      const newline = responseBytes.indexOf("\n")
      if (newline < 0) return
      try {
        const response = JSON.parse(responseBytes.slice(0, newline)) as LiveSessionResponse
        if (response.ok !== true) {
          finish(new Error(`live session binding was rejected: ${response.error || "unknown error"}`))
        } else if (response.session_id !== providerSessionId) {
          finish(new Error("live session binding acknowledged a different provider session"))
        } else {
          finish()
        }
      } catch (error) {
        finish(new Error(`live session binding returned invalid JSON: ${String(error)}`))
      }
    })
    socket.on("error", (error) => finish(new Error(`live session binding failed: ${error.message}`)))
    socket.on("end", () => finish(new Error("live session binding closed without an acknowledgement")))
  })
}

function ensureLiveSessionBinding(providerSessionId: string): Promise<void> | undefined {
  const socketPath = process.env.OULIPOLY_LIVE_SESSION_BIND_SOCKET
  const token = process.env.OULIPOLY_LIVE_SESSION_BIND_TOKEN
  if (!socketPath && !token) return undefined
  const invocationUuid = ownerInvocationUuid()
  if (!socketPath || !token || !invocationUuid) {
    throw new Error("live session binding environment is incomplete")
  }
  if (!liveSessionBinding) {
    liveSessionBinding = reportLiveSession(socketPath, token, invocationUuid, providerSessionId).catch((error) => {
      liveSessionBinding = undefined
      throw error
    })
  }
  return liveSessionBinding
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

async function runProcess(argv: string[], ownerSessionId?: string, abort?: AbortSignal): Promise<ProcessResult> {
  const child = Bun.spawn(argv, { env: runEnv(ownerSessionId), stdout: "pipe", stderr: "pipe" })
  let timeout: ReturnType<typeof setTimeout> | undefined
  const stopped = new Promise<never>((_, reject) => {
    const stop = (message: string) => {
      child.kill()
      reject(new Error(message))
    }
    timeout = setTimeout(() => stop(`subprocess timed out after ${PROCESS_TIMEOUT_MS}ms`), PROCESS_TIMEOUT_MS)
    if (abort) {
      if (abort.aborted) stop("subprocess aborted")
      else abort.addEventListener("abort", () => stop("subprocess aborted"), { once: true })
    }
  })
  try {
    const completed = Promise.all([
      child.exited,
      new Response(child.stdout).text(),
      new Response(child.stderr).text(),
    ]).then(([exitCode, stdout, stderr]) => ({ exitCode, stdout, stderr }))
    return await Promise.race([completed, stopped])
  } finally {
    if (timeout) clearTimeout(timeout)
  }
}

function processFailure(operation: string, result: ProcessResult): Error {
  const detail = result.stderr.trim() || result.stdout.trim()
  return new Error(`${operation} failed with exit code ${result.exitCode}${detail ? `: ${detail}` : ""}`)
}

async function checkedProcessText(
  argv: string[],
  operation: string,
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string> {
  const result = await runProcess(argv, ownerSessionId, abort)
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

async function statusText(
  handle: string,
  headerOnly = false,
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string> {
  const args = [AGENT_BASH, "status"]
  if (headerOnly) args.push("--tail-bytes", "0")
  args.push(handle)
  const status = await checkedProcessText(args, "agent-bash status", ownerSessionId, abort)
  const header = status.split("\n", 1)[0]
  if (!/^(RUNNING|DONE rc=-?\d+|ERROR rc=-?\d+) handle=/.test(header) || !header.includes(`handle=${handle}`)) {
    throw new Error(`agent-bash status returned invalid output: ${header || "<empty>"}`)
  }
  return status
}

async function terminalStatus(
  handle: string,
  stateDir: string | undefined,
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string | undefined> {
  const status = await statusText(handle, true, ownerSessionId, abort)
  if (!isTerminalStatus(status)) return undefined
  await markConsumed(stateDir)
  return statusText(handle, false, ownerSessionId, abort)
}

async function modeText(handle: string, ownerSessionId: string, abort?: AbortSignal): Promise<DeliveryMode> {
  const mode = await checkedProcessText([AGENT_BASH, "mode", handle], "agent-bash mode", ownerSessionId, abort)
  if (!validDeliveryMode(mode)) throw new Error(`agent-bash mode returned invalid output: ${mode || "<empty>"}`)
  return mode
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

async function executeListControl(control: ListControl, ownerSessionId: string, abort?: AbortSignal): Promise<string> {
  const argv = [AGENT_BASH, "list"]
  if (control.all) argv.push("--all")
  if (control.json) argv.push("--json")

  const result = await runProcess(argv, ownerSessionId, abort)
  if (result.exitCode !== 0) throw processFailure("agent-bash list", result)
  return result.stdout
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
    const status = await terminalStatus(handle, stateDir, ownerSessionId, abort)
    if (status !== undefined) return status
    if ((await modeText(handle, ownerSessionId, abort)) === "async") return asyncDispatchResponse(handle)
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
        (await terminalStatus(args.handle, stateDirForHandle(args.handle), context.sessionID, context.abort)) ??
        statusText(args.handle, false, context.sessionID, context.abort)
      )
    }
    if (!commandProvided(args.command)) return missingCommandResponse()
    if (args.delivery !== undefined && !validDeliveryMode(args.delivery)) {
      return invalidDeliveryResponse(args.delivery)
    }
    const listControl = classifyListControl(args.command)
    if (listControl) {
      return executeListControl(listControl, context.sessionID, context.abort)
    }

    if (context.abort.aborted) return "Cancellation requested before dispatch."
    const delivery = selectedDelivery(args.command, args.delivery)
    const sleepMilliseconds = standaloneSleepMilliseconds(args.command)
    if (delivery === "sync" && sleepMilliseconds !== undefined) {
      return runStandaloneSleep(sleepMilliseconds)
    }
    const binding = ensureLiveSessionBinding(context.sessionID)
    if (binding) await binding
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
