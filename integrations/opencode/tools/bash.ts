import { tool } from "@opencode-ai/plugin"
import { createConnection } from "node:net"

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
const PROCESS_TIMEOUT_MS = Number(process.env.AGENT_BASH_TOOL_PROCESS_TIMEOUT_MS || 30000)
const LIVE_SESSION_BIND_TIMEOUT_MS = 5000
const MAX_LIVE_SESSION_RESPONSE_BYTES = 16 * 1024

type DeliveryMode = "sync" | "async"
type CompletionScope = "root" | "tree"

type RunDispatch = {
  handle: string
}

type ShellCommand = {
  prefix: string
  body: string
}

type ExplicitRunAdmission =
  | { kind: "ordinary" }
  | { kind: "unsupported" }
  | { kind: "direct"; argv: string[]; environment: Record<string, string> }

const RESERVED_SPOOLER_ASSIGNMENTS = new Set([
  "AGENT_BASH_AGENT_RUNNER_BIN",
  "OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY",
])

function adapterOwnsAssignment(name: string): boolean {
  return RESERVED_SPOOLER_ASSIGNMENTS.has(name)
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

class LiveSessionBindingTransportError extends Error {
  constructor(message: string, readonly code?: string) {
    super(message)
  }
}

let liveSessionBinding: Promise<void> | undefined

function clearLiveSessionBindingEnvironment() {
  delete process.env.OULIPOLY_LIVE_SESSION_BIND_SOCKET
  delete process.env.OULIPOLY_LIVE_SESSION_BIND_TOKEN
}

function liveSessionBindingTransportIsGone(error: unknown): boolean {
  return (
    error instanceof LiveSessionBindingTransportError &&
    (error.code === "ENOENT" || error.code === "ECONNREFUSED")
  )
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
    socket.on("error", (error) => {
      const code = (error as Error & { code?: string }).code
      finish(new LiveSessionBindingTransportError(`live session binding failed: ${error.message}`, code))
    })
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
      if (liveSessionBindingTransportIsGone(error)) {
        clearLiveSessionBindingEnvironment()
        return
      }
      liveSessionBinding = undefined
      throw error
    })
  }
  return liveSessionBinding
}

function runEnv(ownerSessionId?: string) {
  const invocationUuid = ownerInvocationUuid()
  const env = { ...process.env }
  // The handshake capability is scoped to this adapter and is never a workload credential.
  delete env.OULIPOLY_LIVE_SESSION_BIND_SOCKET
  delete env.OULIPOLY_LIVE_SESSION_BIND_TOKEN
  return {
    ...env,
    AGENT_BASH_AGENT_RUNNER_BIN: AGENTS,
    AGENT_BASH_CONSUMER_GRACE_MS: String(CONSUMER_GRACE_MS),
    ...(ownerSessionId ? { AGENT_BASH_OWNER_SESSION_ID: ownerSessionId } : {}),
    ...(invocationUuid ? { AGENT_BASH_OWNER_INVOCATION_UUID: invocationUuid } : {}),
  }
}

async function runProcess(
  argv: string[],
  ownerSessionId?: string,
  abort?: AbortSignal,
  operation = "subprocess",
  environment: Record<string, string> = {},
): Promise<ProcessResult> {
  const child = Bun.spawn(argv, {
    env: { ...runEnv(ownerSessionId), ...environment },
    stdout: "pipe",
    stderr: "pipe",
  })
  let timeout: ReturnType<typeof setTimeout> | undefined
  const stopped = new Promise<never>((_, reject) => {
    const stop = (message: string) => {
      child.kill()
      reject(new Error(message))
    }
    timeout = setTimeout(() => stop(`${operation} timed out after ${PROCESS_TIMEOUT_MS}ms`), PROCESS_TIMEOUT_MS)
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
  environment?: Record<string, string>,
): Promise<string> {
  const result = await runProcess(argv, ownerSessionId, abort, operation, environment)
  if (result.exitCode !== 0) throw processFailure(operation, result)
  return result.stdout.trim()
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
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string | undefined> {
  const status = await statusText(handle, true, ownerSessionId, abort)
  if (!isTerminalStatus(status)) return undefined
  const consume = await runProcess([AGENT_BASH, "consume", handle], ownerSessionId, abort, "agent-bash consume")
  if (consume.exitCode !== 0 && consume.exitCode !== 77) throw processFailure("agent-bash consume", consume)
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

  const result = await runProcess(argv, ownerSessionId, abort, "agent-bash list")
  if (result.exitCode !== 0) throw processFailure("agent-bash list", result)
  return result.stdout
}

function parseRunDispatch(runOut: string): RunDispatch | undefined {
  try {
    const parsed = JSON.parse(runOut)
    return typeof parsed.handle === "string"
      ? { handle: parsed.handle }
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
    const name = matched.slice(0, matched.indexOf("="))
    if (!adapterOwnsAssignment(name)) environmentPrefix += matched
    body = body.slice(matched.length)
  }
  return { prefix: leadingWhitespace + environmentPrefix, body }
}

// This intentionally broad recognizer only routes potentially privileged input to the
// authoritative structured admission parser; it never authorizes direct execution itself.
function conservativelyRecognizesExplicitRun(command: string): boolean {
  const { body } = splitShellCommand(command)
  return [`${AGENT_BASH} run`, "agent-bash run"].some((prefix) => startsWithToken(body, prefix))
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
  return (
    conservativelyRecognizesExplicitRun(body) &&
    /\s--\s+(?:[^\s]+\/)?(?:agents|oulipoly-agent-runner)(?:\s|$)/.test(body)
  )
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

function structuredShellWords(command: string): string[] | undefined {
  const words: string[] = []
  let word = ""
  let started = false
  let quote: "single" | "double" | undefined
  for (let index = 0; index < command.length; index += 1) {
    const character = command[index]
    if (quote === "single") {
      if (character === "'") quote = undefined
      else word += character
      continue
    }
    if (quote === "double") {
      if (character === '"') {
        quote = undefined
      } else if (character === "\\") {
        index += 1
        if (index >= command.length) return undefined
        word += command[index]
      } else if (character === "$" || character === "`") {
        return undefined
      } else {
        word += character
      }
      continue
    }
    if (character === "\n" || character === "\r") return undefined
    if (/\s/.test(character)) {
      if (started) {
        words.push(word)
        word = ""
        started = false
      }
    } else if (character === "'") {
      quote = "single"
      started = true
    } else if (character === '"') {
      quote = "double"
      started = true
    } else if (character === "\\") {
      index += 1
      if (index >= command.length) return undefined
      word += command[index]
      started = true
    } else if ("$`;|&<>()".includes(character)) {
      return undefined
    } else {
      word += character
      started = true
    }
  }
  if (quote) return undefined
  if (started) words.push(word)
  return words
}

function parseStructuredExplicitRun(
  command: string,
  delivery: DeliveryMode,
  ownerLease: boolean,
): { argv: string[]; environment: Record<string, string> } | undefined {
  const words = structuredShellWords(command)
  if (!words) return undefined
  const environment: Record<string, string> = {}
  while (words[0]?.match(/^[A-Za-z_][A-Za-z0-9_]*=/)) {
    const assignment = words.shift()!
    const separator = assignment.indexOf("=")
    const name = assignment.slice(0, separator)
    if (!adapterOwnsAssignment(name)) return undefined
  }
  if ((words[0] !== AGENT_BASH && words[0] !== "agent-bash") || words[1] !== "run") return undefined
  words[0] = AGENT_BASH
  const separator = words.indexOf("--")
  const optionsEnd = separator < 0 ? words.length : separator
  for (let index = 2; index < optionsEnd; index += 1) {
    if (words[index] === "--delivery") {
      words.splice(index, 2)
      break
    }
  }
  const controls = ["--delivery", delivery]
  if (ownerLease) controls.unshift("--cancel-on-owner-exit", "--owner-pid", String(process.pid))
  words.splice(2, 0, ...controls)
  const workload = words.indexOf("--") + 1
  if (workload > 0 && ["agents", "oulipoly-agent-runner"].includes(words[workload])) words[workload] = AGENTS
  return { argv: words, environment }
}

function admitExplicitRun(
  command: string,
  delivery: DeliveryMode,
  ownerLease: boolean,
): ExplicitRunAdmission {
  if (!conservativelyRecognizesExplicitRun(command)) return { kind: "ordinary" }
  const direct = parseStructuredExplicitRun(command, delivery, ownerLease)
  return direct ? { kind: "direct", ...direct } : { kind: "unsupported" }
}

async function dispatchCommand(
  command: string,
  delivery: DeliveryMode,
  ownerLease: boolean,
  completionScope: CompletionScope,
  ownerSessionId: string,
): Promise<string> {
  const explicitRun = admitExplicitRun(command, delivery, ownerLease)
  if (explicitRun.kind === "unsupported") {
    throw new Error("explicit agent-bash run requires structured arguments without shell expansion")
  }
  if (explicitRun.kind === "direct") {
    return checkedProcessText(
      explicitRun.argv,
      "agent-bash dispatch",
      ownerSessionId,
      undefined,
      explicitRun.environment,
    )
  }
  command = pinAgentRunnerBinary(command)
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
  abort: AbortSignal,
  ownerSessionId: string,
): Promise<string> {
  const aborted = new Promise<void>((resolve) => {
    if (abort.aborted) resolve()
    else abort.addEventListener("abort", () => resolve(), { once: true })
  })
  while (true) {
    if (abort.aborted) return cancelResult(handle, ownerSessionId)
    try {
      const status = await terminalStatus(handle, ownerSessionId, abort)
      if (status !== undefined) return status
      if ((await modeText(handle, ownerSessionId, abort)) === "async") return asyncDispatchResponse(handle)
    } catch (error) {
      if (abort.aborted) return cancelResult(handle, ownerSessionId)
      throw error
    }
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
        (await terminalStatus(args.handle, context.sessionID, context.abort)) ??
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
    return waitForSyncResult(dispatch.handle, context.abort, context.sessionID)
  },
})
