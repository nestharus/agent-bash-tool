import { tool } from "@opencode-ai/plugin"
import { createConnection } from "node:net"
import { createHash } from "node:crypto"

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
  dispatchState: "running" | "registration-outcome-unknown" | "root-accepted" | "effects-possible-no-replay" | "broker-k-consumed"
  retrySafe: boolean
  effectsPossible: boolean
}

type StatusReadPolicy = {
  detail: "header" | "tail"
  progression: "observe-only" | "request-progress"
}

type SnapshotIdentity = {
  version: 1
  handle: string
  created_at_unix_ms: number
  bytes: number
  sha256: string
  encoding: "hex"
}

type AcquiredOutput = {
  snapshot: SnapshotIdentity
  status: string
  output: string
  representation: "utf8" | "hex"
}

type ShellCommandWithoutAdapterControls = {
  prefix: string
  body: string
}

type CommandPolicy = {
  agentDispatch: boolean
  delivery: DeliveryMode
  ownerLease: boolean
  completionScope: CompletionScope
}

type CommandAdmission = CommandPolicy &
  (
    | { kind: "ordinary"; command: string }
    | { kind: "unsupported" }
    | { kind: "direct"; argv: string[] }
  )

const RESERVED_SPOOLER_ASSIGNMENTS = new Set([
  "AGENT_BASH_AGENT_RUNNER_BIN",
  "OULIPOLY_COMPLETION_REGISTRATION_AUTHORITY",
])

function isReservedSpoolerAssignment(name: string): boolean {
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
  workdir?: string,
  timeoutMs: number | null = PROCESS_TIMEOUT_MS,
  strictStdout = false,
): Promise<ProcessResult> {
  const child = Bun.spawn(argv, {
    env: { ...runEnv(ownerSessionId), ...environment },
    cwd: workdir,
    stdout: "pipe",
    stderr: "pipe",
  })
  let timeout: ReturnType<typeof setTimeout> | undefined
  const stopped = new Promise<never>((_, reject) => {
    const stop = (message: string) => {
      child.kill()
      reject(new Error(message))
    }
    if (timeoutMs !== null) {
      timeout = setTimeout(() => stop(`${operation} timed out after ${timeoutMs}ms`), timeoutMs)
    }
    if (abort) {
      if (abort.aborted) stop("subprocess aborted")
      else abort.addEventListener("abort", () => stop("subprocess aborted"), { once: true })
    }
  })
  try {
    const stdoutText = strictStdout
      ? new Response(child.stdout).arrayBuffer().then((raw) => {
          const bytes = Buffer.from(raw)
          try {
            return new TextDecoder("utf-8", { fatal: true }).decode(bytes)
          } catch {
            throw new Error(`agent-bash run stdout was not UTF-8; raw hex: ${bytes.toString("hex")}`)
          }
        })
      : new Response(child.stdout).text()
    const completed = Promise.all([
      child.exited,
      stdoutText,
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
  workdir?: string,
  timeoutMs?: number | null,
): Promise<string> {
  const result = await runProcess(argv, ownerSessionId, abort, operation, environment, workdir, timeoutMs)
  if (result.exitCode !== 0) throw processFailure(operation, result)
  return result.stdout.trim()
}

async function statusText(
  handle: string,
  policy: StatusReadPolicy,
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string> {
  const args = [AGENT_BASH, "status"]
  if (policy.detail === "header") args.push("--tail-bytes", "0")
  if (policy.progression === "observe-only") args.push("--observe-only")
  args.push(handle)
  const result = await runProcess(args, ownerSessionId, abort, "agent-bash status")
  if (result.exitCode !== 0) throw processFailure("agent-bash status", result)
  const status = result.stdout
  const header = status.split("\n", 1)[0]
  if (!/^(RUNNING|DONE rc=-?\d+|ERROR rc=-?\d+) handle=/.test(header) || !header.split(/\s+/).includes(`handle=${handle}`)) {
    throw new Error(`agent-bash status returned invalid output: ${header || "<empty>"}`)
  }
  return status
}

async function observeVisibleHandle(
  handle: string,
  runningDetail: "omit" | "tail",
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string | undefined> {
  const header = await statusText(
    handle,
    { detail: "header", progression: "observe-only" },
    ownerSessionId,
    abort,
  )
  if (isTerminalStatus(header)) {
    return retainedTerminalOutput(handle, ownerSessionId, abort)
  }
  if (runningDetail === "omit") return undefined

  const status = await statusText(
    handle,
    { detail: "tail", progression: "observe-only" },
    ownerSessionId,
    abort,
  )
  if (!isTerminalStatus(status)) return status
  try {
    return await retainedTerminalOutput(handle, ownerSessionId, abort)
  } catch {
    // The running read raced a terminal transition. Preserve that already acquired
    // textual observation even if the exact snapshot source is now unavailable.
    return status.replace("\n", "\nlocal receipt: unconfirmed; remote ACK: unconfirmed; physical drain: unconfirmed; exact snapshot unavailable; textual observation only\n")
  }
}

function sameSnapshot(value: any, expected: SnapshotIdentity): boolean {
  return value !== null && typeof value === "object" &&
    Object.keys(value).length === Object.keys(expected).length &&
    Object.entries(expected).every(([key, entry]) => value[key] === entry)
}

function acquireOutput(handle: string, response: string): AcquiredOutput {
  const value = JSON.parse(response)
  const snapshot = value.snapshot as SnapshotIdentity
  if (!snapshot || snapshot.version !== 1 || snapshot.handle !== handle || snapshot.encoding !== "hex" ||
      !Number.isSafeInteger(snapshot.created_at_unix_ms) || snapshot.created_at_unix_ms < 0 ||
      !Number.isSafeInteger(snapshot.bytes) || snapshot.bytes < 0 ||
      typeof snapshot.sha256 !== "string" || !/^[0-9a-f]{64}$/.test(snapshot.sha256) ||
      typeof value.output !== "string" || !/^(?:[0-9a-f]{2})*$/.test(value.output) ||
      value.output.length / 2 !== snapshot.bytes ||
      typeof value.status !== "string" || value.status.includes("\n") ||
      !/^(DONE|ERROR) rc=-?\d+ handle=/.test(value.status) ||
      !value.status.split(/\s+/).includes(`handle=${handle}`)) {
    throw new Error("agent-bash snapshot returned an invalid or incomplete identity/representation")
  }
  const bytes = Buffer.from(value.output, "hex")
  if (createHash("sha256").update(bytes).digest("hex") !== snapshot.sha256) {
    throw new Error("agent-bash snapshot output hash mismatch")
  }
  const text = bytes.toString("utf8")
  const utf8 = Buffer.from(text, "utf8").equals(bytes)
  return { snapshot, status: value.status, output: utf8 ? text : value.output, representation: utf8 ? "utf8" : "hex" }
}

async function retainedTerminalOutput(handle: string, ownerSessionId?: string, abort?: AbortSignal): Promise<string> {
  // Acquisition is observe-only and complete before any local receipt/progression.
  const result = await runProcess([AGENT_BASH, "snapshot", handle], ownerSessionId, abort, "agent-bash snapshot")
  if (result.exitCode !== 0) throw processFailure("agent-bash snapshot", result)
  const retained = acquireOutput(handle, result.stdout)
  let acceptance = "unconfirmed"
  let progression = "not requested"
  try {
    acceptance = await attemptLocalReceipt(retained.snapshot, ownerSessionId, abort)
    await statusText(handle, { detail: "header", progression: "request-progress" }, ownerSessionId, abort)
    progression = "requested (not remote settlement evidence)"
  } catch (error) {
    // Never replace an acquired command result with a control/transport failure.
    progression = `unconfirmed: ${error instanceof Error ? error.message : String(error)}`
  }
  return `${retained.status}\nlocal receipt: ${acceptance}; remote ACK: unconfirmed; physical drain: unconfirmed` +
    `\nprogression: ${progression}\nsnapshot: ${JSON.stringify(retained.snapshot)}` +
    `\noutput representation: ${retained.representation}; acquired bounded bytes only, not an atomic historical log; later append data unknown` +
    `\n--- output ---\n${retained.output}`
}

async function attemptLocalReceipt(
  snapshot: SnapshotIdentity,
  ownerSessionId?: string,
  abort?: AbortSignal,
): Promise<string> {
  const receipt = await runProcess(
    [AGENT_BASH, "accept-output", snapshot.handle, "--snapshot", JSON.stringify(snapshot)],
    ownerSessionId, abort, "agent-bash accept-output",
  )
  if (receipt.exitCode === 77) return "ineligible"
  if (receipt.exitCode !== 0) throw processFailure("agent-bash accept-output", receipt)
  const reply = JSON.parse(receipt.stdout)
  if (reply.version !== 1 || reply.handle !== snapshot.handle || reply.local_receipt !== "durable" ||
      typeof reply.receipt_updated !== "boolean" || !sameSnapshot(reply.snapshot, snapshot) ||
      reply.remote_ack !== "unconfirmed" || reply.physical_drain !== "unconfirmed") {
    throw new Error("agent-bash accept-output returned invalid local receipt; remote settlement unconfirmed")
  }
  return "durable bounded snapshot"
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

type AgentBashControl =
  | { kind: "list"; options: ListControl }
  | { kind: "cancel"; handle: string }

function classifyAgentBashControl(command: string): AgentBashControl | undefined {
  const trimmed = command.trim()
  if (!trimmed) return undefined
  const tokens = trimmed.split(/\s+/)
  if (tokens[0] !== AGENT_BASH && tokens[0] !== "agent-bash") return undefined

  if (tokens[1] === "cancel" && tokens.length === 3 && /^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(tokens[2])) {
    return { kind: "cancel", handle: tokens[2] }
  }
  if (tokens.length < 2 || tokens.length > 4) return undefined
  if (tokens[1] !== "list") return undefined

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
  return { kind: "list", options: { all, json } }
}

async function executeAgentBashControl(
  control: AgentBashControl,
  ownerSessionId: string,
  abort?: AbortSignal,
): Promise<string> {
  if (control.kind === "cancel") {
    return checkedProcessText([AGENT_BASH, "cancel", control.handle], "agent-bash cancel", ownerSessionId)
  }

  const argv = [AGENT_BASH, "list"]
  if (control.options.all) argv.push("--all")
  if (control.options.json) argv.push("--json")

  const result = await runProcess(argv, ownerSessionId, abort, "agent-bash list")
  if (result.exitCode !== 0) throw processFailure("agent-bash list", result)
  return result.stdout
}

function parseRunDispatch(runOut: string): RunDispatch | undefined {
  try {
    const parsed = JSON.parse(runOut)
    if (parsed?.schema_version === 30 && parsed.dispatch_state === "broker-k-consumed" &&
        typeof parsed.handle === "string" && parsed.handle.length > 0 &&
        parsed.delivery_mode === "async" && parsed.effects_possible === true &&
        typeof parsed.request_id === "string" && parsed.request_id.length > 0 &&
        typeof parsed.physical_grant_id === "string" && parsed.physical_grant_id.length > 0) {
      return { handle: parsed.handle, dispatchState: "broker-k-consumed", retrySafe: false, effectsPossible: true }
    }
    return typeof parsed.handle === "string" &&
      ["running", "registration-outcome-unknown", "root-accepted", "effects-possible-no-replay"].includes(parsed.dispatch_state) &&
      typeof parsed.retry_safe === "boolean" && typeof parsed.effects_possible === "boolean"
      ? {
          handle: parsed.handle,
          dispatchState: parsed.dispatch_state,
          retrySafe: parsed.retry_safe,
          effectsPossible: parsed.effects_possible,
        }
      : undefined
  } catch {
    return undefined
  }
}

function dispatchErrorResponse(runOut: string): string {
  return `agent-bash response unresolved (could not identify dispatch or child publication; do not replay): ${runOut}`
}

function requiredObject(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`version-31 ${label} missing or invalid`)
  }
  return value as Record<string, unknown>
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== "string" || value.length === 0) throw new Error(`version-31 ${label} missing or invalid`)
  return value
}

function sameBinding(left: unknown, right: unknown, label: string): void {
  if (requiredString(left, label) !== right) throw new Error(`version-31 ${label} binding mismatch`)
}

function decodeChildStream(encoded: unknown, encoding: unknown, length: unknown, digest: unknown, label: string): {
  bytes: Buffer; representation: "utf8" | "hex"; output: string
} {
  if (encoding !== "base64" || typeof encoded !== "string" ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded) ||
      !Number.isSafeInteger(length) || (length as number) < 0 ||
      typeof digest !== "string" || !/^[0-9a-f]{64}$/.test(digest)) {
    throw new Error(`version-31 ${label} encoding, length, or digest invalid`)
  }
  const bytes = Buffer.from(encoded, "base64")
  if (bytes.length !== length || bytes.toString("base64") !== encoded) {
    throw new Error(`version-31 ${label} base64 or byte length mismatch`)
  }
  if (createHash("sha256").update(bytes).digest("hex") !== digest) {
    throw new Error(`version-31 ${label} digest mismatch`)
  }
  const decoded = bytes.toString("utf8")
  // NUL is valid UTF-8 but invisible in the tool UI, so show that stream as hex too.
  const utf8 = !bytes.includes(0) && Buffer.from(decoded, "utf8").equals(bytes)
  return { bytes, representation: utf8 ? "utf8" : "hex", output: utf8 ? decoded : bytes.toString("hex") }
}

function childOutcome(publication: Record<string, unknown>, event: Record<string, unknown>): string {
  const wait = event.wait_status
  if (!Number.isSafeInteger(wait) || (wait as number) < 0 || (wait as number) > 65535 ||
      typeof event.cancelled !== "boolean") throw new Error("version-31 child wait/cancel facts invalid")
  if (event.cancelled) {
    if (publication.outcome !== "cancelled" || publication.exit_code !== null || publication.signal !== null ||
        typeof event.cancel_grant_id !== "string" || event.cancel_grant_id.length === 0) {
      throw new Error("version-31 cancelled outcome mismatch")
    }
    return `cancelled (source wait status ${wait})`
  }
  if (event.cancel_grant_id !== null) throw new Error("version-31 unexpected cancel grant")
  if (((wait as number) & 0x7f) === 0) {
    const exit = ((wait as number) >> 8) & 0xff
    if (publication.outcome !== "exited" || publication.exit_code !== exit || publication.signal !== null) {
      throw new Error("version-31 exit outcome mismatch")
    }
    return `exited with code ${exit} (source wait status ${wait})`
  }
  const signal = (wait as number) & 0x7f
  if (signal < 1 || signal > 126 || publication.outcome !== "signaled" ||
      publication.signal !== signal || publication.exit_code !== null) {
    throw new Error("version-31 signal outcome mismatch")
  }
  return `signaled with signal ${signal} (source wait status ${wait})`
}

function parseVersion31Response(runOut: string, delivery: DeliveryMode): string | undefined {
  let value: unknown
  try {
    value = JSON.parse(runOut)
  } catch {
    if (/"schema_version"\s*:\s*31|"dispatch_state"\s*:\s*"sync-(?:child-result|publication-unknown)/.test(runOut)) {
      throw new Error(`version-31 response incomplete or malformed; publication unresolved; raw stdout: ${runOut}`)
    }
    return undefined
  }
  const envelope = requiredObject(value, "response")
  if (envelope.schema_version !== 31 && envelope.dispatch_state !== "sync-child-result" &&
      envelope.dispatch_state !== "sync-publication-unknown") return undefined
  if (envelope.schema_version !== 31 || delivery !== "sync" ||
      !["sync-child-result", "sync-publication-unknown"].includes(String(envelope.dispatch_state))) {
    throw new Error("version-31 response schema, state, or delivery mismatch; publication unresolved")
  }
  const publication = requiredObject(envelope.publication, "publication")
  const child = requiredObject(publication.child, "child")
  const session = requiredObject(child.session, "child session")
  const actor = requiredObject(child.actor, "child actor")
  const event = requiredObject(publication.event, "source event")
  if (publication.version !== 1 || publication.phase !== "unknown" ||
      (child.listener_policy !== undefined && child.listener_policy !== "response_only") ||
      event.completion_policy !== "tree" || event.tree_drained !== true || event.output_closed !== true) {
    throw new Error("version-31 publication source or phase invalid")
  }
  for (const key of ["request_id", "d_key", "invocation_uuid", "handle", "root_id",
    "parent_invocation_uuid", "parent_work_grant_id", "parent_work_id", "registration_authority"]) {
    requiredString(child[key], `child ${key}`)
  }
  for (const key of ["host_pid", "starttime_ticks", "pidns_dev", "pidns_ino"]) {
    if (!Number.isSafeInteger(actor[key]) || (actor[key] as number) < (key === "pidns_dev" || key === "pidns_ino" ? 0 : 1)) {
      throw new Error(`version-31 child actor ${key} invalid`)
    }
  }
  requiredString(actor.boot_id, "child actor boot_id")
  for (const key of ["lane_id", "source_generation", "session_id", "allocation_id"]) {
    requiredString(session[key], `child session ${key}`)
  }
  sameBinding(session.request_id, child.d_key, "session request_id")
  for (const [eventKey, childKey] of [
    ["request_id", "request_id"], ["source_id", "handle"], ["root_id", "root_id"],
    ["attempt_id", "invocation_uuid"],
    ["parent_work_grant_id", "parent_work_grant_id"], ["parent_work_id", "parent_work_id"],
  ]) sameBinding(event[eventKey], child[childKey], `source ${eventKey}`)
  for (const key of ["lane_id", "source_generation", "session_id"]) {
    sameBinding(event[key], session[key], `source ${key}`)
  }
  for (const key of ["attempt_id", "state_admission_id", "physical_grant_id", "physical_work_id",
    "owner_generation", "selected_kind"]) requiredString(event[key], `source ${key}`)
  if (event.selected_kind !== (event.cancelled ? "cancelled" : "tree_drained")) {
    throw new Error("version-31 source kind/cancellation mismatch")
  }
  if (typeof event.registration_digest !== "string" || !/^[0-9a-f]{64}$/.test(event.registration_digest)) {
    throw new Error("version-31 source registration digest invalid")
  }
  const outcome = childOutcome(publication, event)
  const identity = `request_id=${child.request_id} handle=${child.handle} physical_grant_id=${event.physical_grant_id}`
  if (envelope.dispatch_state === "sync-publication-unknown") {
    if ("stdout_base64" in envelope || "stderr_base64" in envelope ||
        "stdout_encoding" in envelope || "stderr_encoding" in envelope) {
      throw new Error("version-31 unknown publication unexpectedly contains output; publication unresolved")
    }
    return `Sync child publication unresolved (${identity}): ${outcome}. Source output exists, but this caller response may have been lost or partial. Do not replay. Consumer ACK: unconfirmed; remote ACK: unconfirmed; overall physical drain: unconfirmed.`
  }
  const stdout = decodeChildStream(envelope.stdout_base64, envelope.stdout_encoding,
    event.stdout_len, event.stdout_sha256, "stdout")
  const stderr = decodeChildStream(envelope.stderr_base64, envelope.stderr_encoding,
    event.stderr_len, event.stderr_sha256, "stderr")
  return `Sync child result (${identity}): ${outcome}. Source tree drained: true; output closed: true; ` +
    `publication phase: unknown; consumer ACK: unconfirmed; remote ACK: unconfirmed; overall physical drain: unconfirmed.` +
    `\nstdout: ${stdout.bytes.length} bytes, sha256=${event.stdout_sha256}, representation=${stdout.representation}` +
    `\n--- stdout ---\n${stdout.output}` +
    `\nstderr: ${stderr.bytes.length} bytes, sha256=${event.stderr_sha256}, representation=${stderr.representation}` +
    `\n--- stderr ---\n${stderr.output}`
}

const ROOT_V1_ENV = "OULIPOLY_ROOT_BASH_V1"
const ROOT_V1_SURFACE = "agent-bash-root-v1"
const ROOT_V1_OUTCOMES = ["refused", "not-started", "ended", "ended-output-unproven", "unknown"]

// Inside a new-lineage root, its own Bash ingress is the only route.
function rootV1Context(): boolean {
  return process.env[ROOT_V1_ENV] !== undefined
}

function rootV1Unresolved(reason: string, run: ProcessResult): Error {
  return new Error(`root v1 result unresolved (${reason}); the command may have run; do not replay.` +
    `\nexit: ${run.exitCode}\nstdout: ${run.stdout}\nstderr: ${run.stderr}`)
}

function rootV1Stage(stage: any): string {
  const name = String(stage?.event)
  if (name === "accepted") return `accepted(work=${stage.work}, durable=${stage.durable})`
  if (name === "output-closed") return `output-closed(bytes=${stage.bytes})`
  if (name === "end") return `end(${stage.status}, observer=${stage.observer}, output=${stage.output?.state})`
  if (name === "output") return `output(chunks=${stage.chunks}, bytes=${stage.bytes})`
  return stage?.reason === undefined ? name : `${name}(${stage.reason})`
}

// OpenCode 1.18.30 applies its generic 50 KiB / 2000-line truncator to
// every custom-tool return. Leave room for the ordinary root receipt and
// abort note; budget rendered bytes (hex doubles stream bytes), not JS chars.
const ROOT_V1_PAYLOAD_RENDERED_BYTES = 48 * 1024
const ROOT_V1_PAYLOAD_LINES = 1900

function rootV1Utf8Prefix(bytes: Buffer): Buffer {
  let prefix = bytes.subarray(0, ROOT_V1_PAYLOAD_RENDERED_BYTES)
  // The carried stream is valid UTF-8, so only the final codepoint can be
  // incomplete after the byte cut. Omit it, never insert replacement bytes.
  while (!Buffer.from(prefix.toString("utf8"), "utf8").equals(prefix)) {
    prefix = prefix.subarray(0, prefix.length - 1)
  }
  return prefix
}

function rootV1InlinePrefix(bytes: Buffer): { bytes: Buffer; utf8: boolean; text: string } {
  const decoded = bytes.toString("utf8")
  const utf8 = !bytes.includes(0) && Buffer.from(decoded, "utf8").equals(bytes)
  if (!utf8) {
    const prefix = bytes.subarray(0, ROOT_V1_PAYLOAD_RENDERED_BYTES / 2)
    return { bytes: prefix, utf8, text: prefix.toString("hex") }
  }
  // Splitting with a limit keeps a literal prefix, including intervening LFs,
  // but excludes the LF that would introduce a line beyond the budget.
  const text = rootV1Utf8Prefix(bytes).toString("utf8").split("\n", ROOT_V1_PAYLOAD_LINES).join("\n")
  return { bytes: Buffer.from(text, "utf8"), utf8, text }
}

// Renders only what the root's stage lines established. The command's wait
// status is read from the result object, never from agent-bash's exit code.
function rootV1Response(run: ProcessResult): string {
  if (run.exitCode !== 0) throw rootV1Unresolved("agent-bash did not complete its result", run)
  let value: any
  try {
    value = JSON.parse(run.stdout)
  } catch {
    throw rootV1Unresolved("result is not one JSON object", run)
  }
  const output = value?.output
  if (value?.result_surface !== ROOT_V1_SURFACE || value.version !== 1 || value.delivery_mode !== "sync" ||
      !ROOT_V1_OUTCOMES.includes(value.outcome) || typeof value.effects_possible !== "boolean" ||
      typeof value.retry_safe !== "boolean" || !Array.isArray(value.stages) || !Array.isArray(value.faults) ||
      !output || typeof output.base64 !== "string" || !Number.isSafeInteger(output.bytes) ||
      !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(output.base64)) {
    throw rootV1Unresolved("result surface invalid", run)
  }
  const bytes = Buffer.from(output.base64, "base64")
  const presented = output.presented_bytes ?? output.bytes
  const omitted = output.omitted_bytes ?? 0
  if (!Number.isSafeInteger(presented) || !Number.isSafeInteger(omitted) ||
      presented < 0 || omitted < 0 || presented + omitted !== output.bytes ||
      bytes.length !== presented || bytes.toString("base64") !== output.base64 ||
      (omitted > 0 && output.remainder !== "discarded")) {
    throw rootV1Unresolved("output length or encoding mismatch", run)
  }
  const ended = value.outcome === "ended" || value.outcome === "ended-output-unproven"
  if (ended !== (value.wait !== null && typeof value.wait === "object") ||
      value.effects_possible !== !["refused", "not-started"].includes(value.outcome)) {
    throw rootV1Unresolved("result outcome inconsistent", run)
  }
  const stages = `stages: ${value.stages.map(rootV1Stage).join(" -> ") || "none"}`
  const faults = value.faults.length ? `\nfaults: ${value.faults.join("; ")}` : ""
  const inline = rootV1InlinePrefix(bytes)
  const additionallyOmitted = presented - inline.bytes.length
  const partial = omitted > 0 || additionallyOmitted > 0
    ? `\nProducer output: ${output.bytes} received stream bytes; ${presented} stream bytes carried; ` +
      `${omitted} bytes omitted and discarded (not retained).` +
      `\nOpenCode presentation: first ${inline.bytes.length} of ${presented} producer-carried stream bytes shown inline; ` +
      `${additionallyOmitted} additional stream bytes omitted here (not retained for recovery); ` +
      `${Buffer.byteLength(inline.text)} rendered UTF-8 bytes.`
    : ""
  const body = partial + `\n--- output (stderr joined; ${inline.bytes.length} bytes` +
    `${omitted || additionallyOmitted ? " shown inline" : ""}, ${inline.utf8 ? "utf8" : "hex"}) ---\n` + inline.text
  switch (value.outcome) {
    case "refused":
      return `Root v1 refused by ${value.refusal?.by} (${value.refusal?.reason})` +
        `${value.refusal?.detail ? `: ${value.refusal.detail}` : ""}. Nothing was run; ` +
        `no other route was tried and the request was not converted.\n${stages}`
    case "not-started":
      return `Root v1 accepted the command, then reported a positive no-start; nothing was run.\n${stages}${faults}`
    case "unknown":
      return `Root v1 outcome unknown (${value.meaning}): the command may have run. Effects possible: yes; ` +
        `retry safe: no. Do not replay; there is no root v1 cancel or status for it here.\n${stages}${faults}` +
        (bytes.length ? `${body}\n(output above is partial and unproven)` : "")
    default: {
      const wait = value.wait.exit?.code !== undefined
        ? `exited with code ${value.wait.exit.code}`
        : `signaled with signal ${value.wait.exit?.signal}`
      const delivery = value.outcome === "ended"
        ? omitted > 0 || additionallyOmitted > 0
          ? "output partial; full stream counted, closed, matched by the end"
          : "output complete (counted, closed, matched by the end)"
        : "output delivery unproven: the command ran and its wait is known, but the output below may be incomplete; do not replay"
      return `Root v1 work ended: ${wait} (${value.wait.status}, observer ${value.wait.observer}); ${delivery}.` +
        `\n${stages}${faults}${body}`
    }
  }
}

async function rootV1Execute(admission: CommandAdmission, ownerSessionId: string, workdir?: string): Promise<string> {
  if (admission.agentDispatch) {
    return "Root v1 refused child-agent dispatch: it needs asynchronous completion, which root v1 does not serve. " +
      "Nothing was run; it was not converted to a synchronous run."
  }
  if (admission.kind === "direct" && admission.delivery === "async") {
    return "Root v1 refused by bash-adapter (async-delivery-unavailable-under-root-v1): synchronous commands only. " +
      "Nothing was run; no other route was tried and the request was not converted."
  }
  let args: string[]
  if (admission.kind === "unsupported") {
    throw new Error("explicit agent-bash run requires structured arguments without shell expansion")
  } else if (admission.kind === "direct") {
    args = admission.argv
  } else {
    args = [AGENT_BASH, "run", "--delivery", admission.delivery, "--", "bash", "-lc", admission.command]
  }
  let run: ProcessResult
  try {
    run = await runProcess(args, ownerSessionId, undefined, "agent-bash root v1 run", undefined, workdir, null, true)
  } catch (error) {
    throw new Error(`root v1 result unresolved: ${error instanceof Error ? error.message : String(error)}; ` +
      "the command may have run; do not replay.")
  }
  return rootV1Response(run)
}

function noReplayResponse(dispatch: RunDispatch): string {
  if (dispatch.dispatchState === "registration-outcome-unknown") {
    return (
      `Dispatch unresolved (handle=${dispatch.handle}): completion registration was admitted but its outcome is unknown. ` +
      `Effects possible: ${dispatch.effectsPossible ? "yes" : "no"}; retry safe: ${dispatch.retrySafe ? "yes" : "no"}. ` +
      "The retained handle is terminal, the workload was not started, and registration will not be replayed."
    )
  }
  return (
    `Dispatch unresolved (handle=${dispatch.handle}): root acceptance reply was lost or ambiguous. ` +
    `Effects possible: ${dispatch.effectsPossible ? "yes" : "no"}; retry safe: ${dispatch.retrySafe ? "yes" : "no"}. ` +
    "Do not replay this command. Inspect or poll the retained handle for its terminal disposition."
  )
}

function acceptedDispatchDetail(dispatch: RunDispatch): string {
  const owner = dispatch.dispatchState === "root-accepted" ? "root guardian"
    : dispatch.dispatchState === "broker-k-consumed" ? "private broker K" : "local supervisor"
  return `Dispatch accepted by ${owner} (handle=${dispatch.handle}); effects possible: ` +
    `${dispatch.effectsPossible ? "yes" : "no"}; retry safe: ${dispatch.retrySafe ? "yes" : "no"}.`
}

function startsWithToken(command: string, token: string): boolean {
  return command === token || command.startsWith(`${token} `)
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`
}

// Reserved spooler assignments are neutralized for classification and shell
// rewriting. Ordinary assignments and shell semantics remain; direct execution
// still requires parseStructuredExplicitRun admission.
function stripReservedSpoolerAssignmentsForShellRouting(command: string): ShellCommandWithoutAdapterControls {
  const leadingWhitespace = command.match(/^\s*/)?.[0] || ""
  let body = command.slice(leadingWhitespace.length)
  let environmentPrefix = ""
  const assignment = /^[A-Za-z_][A-Za-z0-9_]*=(?:"(?:[^"\\]|\\.)*"|'[^']*'|[^\s]*)\s+/
  while (true) {
    const matched = body.match(assignment)?.[0]
    if (!matched) break
    const name = matched.slice(0, matched.indexOf("="))
    if (!isReservedSpoolerAssignment(name)) environmentPrefix += matched
    body = body.slice(matched.length)
  }
  return { prefix: leadingWhitespace + environmentPrefix, body }
}

// This intentionally broad recognizer routes potentially privileged input to structured
// admission. The resulting admission record owns every semantic fact consumed by callers.
function conservativelyRecognizesExplicitRun(command: string): boolean {
  const { body } = stripReservedSpoolerAssignmentsForShellRouting(command)
  if (rootV1Context()) {
    const words = structuredShellWords(body)
    if (words && [AGENT_BASH, "agent-bash"].includes(words[0]) && words[1] === "run") return true
  }
  return [`${AGENT_BASH} run`, "agent-bash run"].some((prefix) => startsWithToken(body, prefix))
}

function recognizesAgentDispatchForAdmission(command: string): boolean {
  const { body } = stripReservedSpoolerAssignmentsForShellRouting(command)
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
  const shellCommand = stripReservedSpoolerAssignmentsForShellRouting(command)
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

function selectedDelivery(agentDispatch: boolean, requested: string | undefined): DeliveryMode {
  if (agentDispatch && isHeadlessCaller()) return "async"
  if (validDeliveryMode(requested)) return requested
  return agentDispatch ? "async" : "sync"
}

function leaseToCaller(delivery: DeliveryMode): boolean {
  return delivery === "sync" || !isHeadlessCaller()
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
): string[] | undefined {
  const words = structuredShellWords(command)
  if (!words) return undefined
  while (words[0]?.match(/^[A-Za-z_][A-Za-z0-9_]*=/)) {
    const assignment = words.shift()!
    const separator = assignment.indexOf("=")
    const name = assignment.slice(0, separator)
    if (!isReservedSpoolerAssignment(name)) return undefined
  }
  if ((words[0] !== AGENT_BASH && words[0] !== "agent-bash") || words[1] !== "run") return undefined
  words[0] = AGENT_BASH
  const separator = words.indexOf("--")
  const optionsEnd = separator < 0 ? words.length : separator
  // Root requests keep their explicit mode, including --delivery=async.
  // Tool-level async is refused separately, so neither spelling wins by
  // silently replacing the other. Legacy mode selection stays unchanged.
  const explicitRootDelivery = rootV1Context() && words.slice(2, optionsEnd)
    .some(word => word === "--delivery" || word.startsWith("--delivery="))
  for (let index = 2; index < optionsEnd; index += 1) {
    if (!rootV1Context() && words[index] === "--delivery") {
      words.splice(index, 2)
      break
    }
  }
  const controls = explicitRootDelivery ? [] : ["--delivery", delivery]
  if (ownerLease) controls.unshift("--cancel-on-owner-exit", "--owner-pid", String(process.pid))
  words.splice(2, 0, ...controls)
  const workload = words.indexOf("--") + 1
  if (workload > 0 && ["agents", "oulipoly-agent-runner"].includes(words[workload])) words[workload] = AGENTS
  return words
}

function admitCommand(command: string, requestedDelivery: string | undefined): CommandAdmission {
  const agentDispatch = recognizesAgentDispatchForAdmission(command)
  const delivery = selectedDelivery(agentDispatch, requestedDelivery)
  // The private v31 sync route owns an independent physical child and only
  // admits tree completion. It has no owner-exit cancellation grant. Keep the
  // older handle path unchanged unless the source-only selector is explicit.
  const privateSync = !rootV1Context() && process.env.AGENT_BASH_PRIVATE_V31_SYNC === "1" && delivery === "sync"
  // Root v1 has no owner-exit lease; the root owns its work's lifetime.
  const ownerLease = !rootV1Context() && !privateSync && leaseToCaller(delivery)
  const completionScope = privateSync || agentDispatch ? "tree" : "root"
  const policy = { agentDispatch, delivery, ownerLease, completionScope } as const
  if (!conservativelyRecognizesExplicitRun(command)) return { ...policy, kind: "ordinary", command }
  const argv = parseStructuredExplicitRun(command, delivery, ownerLease)
  return argv ? { ...policy, kind: "direct", argv } : { ...policy, kind: "unsupported" }
}

async function dispatchCommand(
  admission: CommandAdmission,
  ownerSessionId: string,
  workdir?: string,
): Promise<ProcessResult> {
  if (admission.kind === "unsupported") {
    throw new Error("explicit agent-bash run requires structured arguments without shell expansion")
  }
  if (admission.kind === "direct") {
    return runProcess(admission.argv, ownerSessionId, undefined, "agent-bash dispatch", undefined, workdir, null, true)
  }
  const command = pinAgentRunnerBinary(admission.command)
  const args = [AGENT_BASH, "run"]
  if (!admission.ownerLease) {
    args.push("--completion-scope", admission.completionScope, "--delivery", admission.delivery)
  } else {
    args.push(
      "--cancel-on-owner-exit",
      "--owner-pid",
      String(process.pid),
      "--completion-scope",
      admission.completionScope,
      "--delivery",
      admission.delivery,
    )
  }
  args.push("--", "bash", "-lc", command)
  return runProcess(args, ownerSessionId, undefined, "agent-bash dispatch", undefined, workdir, null, true)
}

async function cancelResult(handle: string, ownerSessionId: string): Promise<string> {
  const result = await checkedProcessText(
    [AGENT_BASH, "cancel", handle],
    "agent-bash cancel",
    ownerSessionId,
  )
  let receipt: { requested?: unknown; root_status?: unknown; root_detail?: unknown }
  try {
    receipt = JSON.parse(result)
  } catch {
    return `Cancellation unconfirmed (handle=${handle}): invalid cancel receipt. ${result}`
  }
  if (receipt.requested === true) return `Cancellation accepted (handle=${handle}). ${result}`
  if (receipt.requested !== false) return `Cancellation unconfirmed (handle=${handle}). ${result}`
  if (receipt.root_status === "cancellation_pending_receipt") {
    return `Cancellation pending durable receipt (handle=${handle}); no cancellation effect is confirmed. ${result}`
  }
  if (receipt.root_status === "rejected") return `Cancellation rejected (handle=${handle}). ${result}`
  return `Cancellation was not accepted by this request (handle=${handle}). ${result}`
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
      const status = await observeVisibleHandle(handle, "omit", ownerSessionId, abort)
      if (status !== undefined) {
        if (!abort.aborted) return status
        // Retention must not discharge this synchronous caller's cancellation duty.
        // Cancel without the aborted signal, and keep the acquired output even if
        // cancellation itself fails. Explicit async polls do not gain this duty.
        let cancellation: string
        try {
          cancellation = await cancelResult(handle, ownerSessionId)
        } catch (error) {
          cancellation = `Cancellation unconfirmed: ${error instanceof Error ? error.message : String(error)}`
        }
        return status.replace("\n", `\ncancellation after acquisition: ${cancellation}\n`)
      }
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
    `workload handle. Leading agent-runner commands are pinned to ${AGENTS}. An optional workdir sets the supervised ` +
    "process working directory. Inside a root v1 context, commands run synchronously through that root only; " +
    "asynchronous delivery, child-agent dispatch and legacy handle/controls are refused there, not converted; " +
    "standalone sleeps also use that root's command result.",
  args: {
    command: tool.schema.string().describe("the shell command to run").optional(),
    handle: tool.schema.string().describe("poll an existing asynchronous command by its handle").optional(),
    delivery: tool.schema.string().describe('completion delivery: "sync" or "async"').optional(),
    workdir: tool.schema.string().describe("working directory for the supervised process").optional(),
  },
  async execute(args, context) {
    if (rootV1Context()) {
      const words = args.command && structuredShellWords(stripReservedSpoolerAssignmentsForShellRouting(args.command).body)
      const control = words && [AGENT_BASH, "agent-bash"].includes(words[0]) &&
        ["list", "cancel", "detach", "status", "snapshot", "mode", "accept-output", "completion-reconcile-v2"].includes(words[1])
      if (args.handle || control) {
        return "Root v1 refused legacy handle/control request: only synchronous commands are supported. " +
          "No legacy state was accessed; no other route was tried."
      }
    }
    if (args.handle) {
      return observeVisibleHandle(args.handle, "tail", context.sessionID, context.abort)
    }
    if (!commandProvided(args.command)) return missingCommandResponse()
    if (args.delivery !== undefined && !validDeliveryMode(args.delivery)) {
      return invalidDeliveryResponse(args.delivery)
    }
    const agentBashControl = classifyAgentBashControl(args.command)
    if (agentBashControl) {
      if (agentBashControl.kind === "cancel") {
        const binding = ensureLiveSessionBinding(context.sessionID)
        if (binding) await binding
      }
      return executeAgentBashControl(agentBashControl, context.sessionID, context.abort)
    }

    if (context.abort.aborted) return "Cancellation requested before dispatch."
    const admission = admitCommand(args.command, args.delivery)
    const sleepMilliseconds = standaloneSleepMilliseconds(args.command)
    if (!rootV1Context() && admission.delivery === "sync" && sleepMilliseconds !== undefined) {
      return runStandaloneSleep(sleepMilliseconds)
    }
    if (rootV1Context()) {
      const result = await rootV1Execute(admission, context.sessionID, args.workdir)
      return context.abort.aborted ? `${result}\nTool abort: root v1 has no cancel; the work was not cancelled.` : result
    }
    const binding = ensureLiveSessionBinding(context.sessionID)
    if (binding) await binding
    let run: ProcessResult
    try {
      run = await dispatchCommand(admission, context.sessionID, args.workdir)
    } catch (error) {
      throw new Error(`agent-bash run response unresolved: ${error instanceof Error ? error.message : String(error)}; do not replay.`)
    }
    if (run.exitCode !== 0) {
      throw new Error(`agent-bash run exited ${run.exitCode}; child publication unresolved; do not replay.` +
        `\nstdout: ${run.stdout}\nstderr: ${run.stderr}`)
    }
    const runOut = run.stdout.trim()
    let childResponse: string | undefined
    try {
      childResponse = parseVersion31Response(runOut, admission.delivery)
    } catch (error) {
      throw new Error(`Sync child response unresolved: ${error instanceof Error ? error.message : String(error)}; do not replay.`)
    }
    if (childResponse !== undefined) return childResponse
    const dispatch = parseRunDispatch(runOut)
    if (!dispatch) return dispatchErrorResponse(runOut)
    if (dispatch.dispatchState === "broker-k-consumed" && admission.delivery !== "async") {
      throw new Error("agent-bash private async dispatch was returned to a sync call; outcome unresolved; do not replay")
    }
    if (dispatch.dispatchState === "registration-outcome-unknown" ||
        dispatch.dispatchState === "effects-possible-no-replay") {
      return noReplayResponse(dispatch)
    }
    const accepted = dispatch.dispatchState === "root-accepted" || dispatch.dispatchState === "broker-k-consumed"
      ? `${acceptedDispatchDetail(dispatch)}\n`
      : ""
    if (context.abort.aborted) return `${accepted}${await cancelResult(dispatch.handle, context.sessionID)}`
    if (admission.delivery === "async") {
      return `${accepted}${asyncDispatchResponse(dispatch.handle, admission.agentDispatch && isHeadlessCaller())}`
    }
    return `${accepted}${await waitForSyncResult(dispatch.handle, context.abort, context.sessionID)}`
  },
})
