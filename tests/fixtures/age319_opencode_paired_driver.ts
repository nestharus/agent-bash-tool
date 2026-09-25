import { mock } from "bun:test"
import { writeFileSync } from "node:fs"

const tool = Object.assign((definition: unknown) => definition, {
  schema: { string: () => ({ describe: () => ({ optional: () => ({}) }) }) },
})
mock.module("@opencode-ai/plugin", () => ({ tool }))

const adapter = (await import(process.argv[2])).default
const argv = JSON.parse(process.argv[3]) as string[]
const quote = (value: string) => `'${value.replaceAll("'", "'\\''")}'`
const command = `agent-bash run --completion-scope tree -- ${argv.map(quote).join(" ")}`
let reply: Record<string, string>
try {
  reply = { result: await adapter.execute({ command, delivery: "sync" }, {
    sessionID: "age319-paired-opencode", abort: new AbortController().signal,
  }) }
} catch (error) {
  reply = { error: String(error) }
}
writeFileSync(process.env.AGE319_PAIRED_ADAPTER_RESULT!, JSON.stringify(reply))
