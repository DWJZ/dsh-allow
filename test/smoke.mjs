/**
 * dsh-allow smoke test — drives the approval listener and `/allow` against a
 * fake session and a recording question service. No host, no network.
 *
 * Usage: `node test/smoke.mjs`.
 */
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const plugin = await import(pathToFileURL(join(PLUGIN, 'src/index.js')).href)

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-'))
const file = join(root, 'dsh-allow.json')

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

/** One fake session holding the given `tool/call` events. */
const makeSession = (calls) => ({
  seq: calls.length,
  eventAt: (seq) => (calls[seq] === undefined ? undefined : { type: 'tool/call', data: calls[seq] }),
})

const call = (callId, args) => ({ callId, name: 'bash', arguments: JSON.stringify(args) })
const escalation = (command, mode = 'danger-full-access') => call('c1', { command, sandbox_permissions: mode, justification: '需要写 profile' })

/** One approval request for `c1`. */
const request = (session) => ({ agent: { session }, toolName: 'bash', callId: 'c1', reason: 'escalate sandbox to danger-full-access: 需要写 profile' })

/** A question service that answers with one label and records the questions. */
const answering = (label) => ({
  asked: [],
  ask(ask) {
    this.asked.push(ask)
    return Promise.resolve({ answers: [{ id: ask.questions[0].id, selected: [typeof label === 'function' ? label(ask.questions[0]) : label] }] })
  },
})

const logger = { info: () => {}, warn: () => {}, error: () => {} }
const listenerWith = (questions, rulesFile = file) => plugin.createApprovalListener({
  file: rulesFile,
  logger,
  questionsFor: () => questions,
})

console.log('command prefix')
const prefixes = [
  ['pnpm dsh plugin --profile web add link:/Users/x', 'pnpm dsh plugin'],
  ['CI=true pnpm dsh plugin --profile web remove dsh-balance', 'pnpm dsh plugin'],
  ['cd /tmp && brew install gh', 'brew install gh'],
  ['git push -u origin main', 'git push'],
  ['node /tmp/script.mjs 25000', 'node'],
  ['rm -rf /', 'rm'],
  ['/opt/homebrew/bin/gh repo view DWJZ/dsh-allow --json name 2>&1 | head -3', 'gh repo view'],
  ['/bin/rm -rf /tmp/x', 'rm'],
  ['cd /tmp && /usr/local/bin/node script.mjs', 'node script.mjs'],
  ['~/bin/tool --flag', 'tool'],
  ['   ', ''],
]
for (const [command, expected] of prefixes) {
  check(`"${command}" → "${expected}"`, plugin.commandPrefix(command) === expected, plugin.commandPrefix(command))
}

console.log('escalation shape')
check('a sandbox escalation is recognized', plugin.escalationOf({ command: 'ls /root', sandbox_permissions: 'danger-full-access' })?.mode === 'danger-full-access')
check('an ordinary call is not an escalation', plugin.escalationOf({ command: 'ls' }) === null)
check('an escalation without a command is ignored', plugin.escalationOf({ sandbox_permissions: 'danger-full-access' }) === null)

console.log('tool call lookup')
const session = makeSession([call('other', { command: 'ls' }), escalation('pnpm dsh plugin --profile web add x')])
check('the logged call is found by id', plugin.toolCallArguments(session, 'c1')?.command === 'pnpm dsh plugin --profile web add x')
check('an unknown call id yields null', plugin.toolCallArguments(session, 'nope') === null)

console.log('rules file')
rmSync(file, { force: true })
check('a missing file reads as no rules', plugin.readRules(file).length === 0)
const stored = plugin.addRule(file, { tool: 'bash', mode: 'danger-full-access', prefix: 'pnpm dsh plugin' })
check('a rule is stored with an id', typeof stored.id === 'string' && plugin.readRules(file).length === 1)
plugin.addRule(file, { tool: 'bash', mode: 'danger-full-access', prefix: 'pnpm dsh plugin' })
check('an identical rule is not duplicated', plugin.readRules(file).length === 1)
check('a matching query finds the rule', plugin.matchRule(plugin.readRules(file), { tool: 'bash', mode: 'danger-full-access', prefix: 'pnpm dsh plugin' }) !== null)
check('another tool does not match', plugin.matchRule(plugin.readRules(file), { tool: 'write', mode: 'danger-full-access', prefix: 'pnpm dsh plugin' }) === null)
check('another mode does not match', plugin.matchRule(plugin.readRules(file), { tool: 'bash', mode: 'workspace-write', prefix: 'pnpm dsh plugin' }) === null)
check('another prefix does not match', plugin.matchRule(plugin.readRules(file), { tool: 'bash', mode: 'danger-full-access', prefix: 'pnpm install' }) === null)

console.log('approval listener')
rmSync(file, { force: true })
let nextCalls = 0
const next = () => { nextCalls += 1; return Promise.resolve('delegated') }

const asking = answering((question) => question.options[1].label)
let outcome = await listenerWith(asking)(request(session), next)
check('"always allow" grants the call', outcome === 'allowed-once', outcome)
check('and stores exactly one rule', plugin.readRules(file).length === 1, JSON.stringify(plugin.readRules(file)))
check('the rule carries the derived prefix', plugin.readRules(file)[0]?.prefix === 'pnpm dsh plugin', JSON.stringify(plugin.readRules(file)[0]))
check('the question offered three answers', asking.asked[0]?.questions[0]?.options?.length === 3)
check('the question names the mode', String(asking.asked[0]?.questions[0]?.question).includes('danger-full-access'))
check('the question shows the command and reason', String(asking.asked[0]?.questions[0]?.detail).includes('需要写 profile'))

const silent = answering('unused')
outcome = await listenerWith(silent)(request(session), next)
check('a stored rule allows without asking', outcome === 'allowed-once', outcome)
check('and no question was put to the user', silent.asked.length === 0, String(silent.asked.length))
check('the hit is counted', plugin.readRules(file)[0]?.hits === 1, JSON.stringify(plugin.readRules(file)[0]))

rmSync(file, { force: true })
const once = answering((question) => question.options[0].label)
outcome = await listenerWith(once)(request(session), next)
check('"allow once" grants without remembering', outcome === 'allowed-once' && plugin.readRules(file).length === 0, `${outcome} / ${String(plugin.readRules(file).length)}`)

const rejecting = answering((question) => question.options[2].label)
outcome = await listenerWith(rejecting)(request(session), next)
check('rejecting denies the call', outcome === 'rejected', outcome)

const kept = nextCalls
const plainSession = makeSession([call('c1', { command: 'ls /root' })])
outcome = await listenerWith(answering('允许一次'))(
  { agent: { session: plainSession }, toolName: 'bash', callId: 'c1' },
  next,
)
check('a request without a logged escalation delegates', outcome === 'delegated' && nextCalls === kept + 1, `${outcome} / ${String(nextCalls)}`)

outcome = await listenerWith(undefined)(request(session), next)
check('without a question service the request delegates', outcome === 'delegated', outcome)

const noProvider = { ask: () => Promise.reject(Object.assign(new Error('no provider'), { code: 'NO_PROVIDER' })) }
outcome = await listenerWith(noProvider)(request(session), next)
check('a failing question service delegates to the built-in answerer', outcome === 'delegated', outcome)

const aborted = { ask: () => Promise.reject(Object.assign(new Error('aborted'), { code: 'ASK_ABORTED' })) }
outcome = await listenerWith(aborted)(request(session), next)
check('an aborted ask reports a cancellation', outcome === 'cancelled', outcome)

console.log('/allow command')
check('an empty list explains itself', plugin.runAllowCommand(file, '').text.includes('还没有记住任何命令'))
const added = plugin.runAllowCommand(file, 'add bash danger-full-access make build')
check('add stores a rule', added.kind === 'success' && plugin.readRules(file).length === 1, JSON.stringify(added))
check('list renders the rule', plugin.runAllowCommand(file, 'list').text.includes('make build'), plugin.runAllowCommand(file, 'list').text)
check('remove needs a valid index', plugin.runAllowCommand(file, 'remove 9').kind === 'error')
check('remove drops the rule', plugin.runAllowCommand(file, 'remove 1').kind === 'success' && plugin.readRules(file).length === 0)
plugin.runAllowCommand(file, 'add bash danger-full-access make build')
check('clear empties the file', plugin.runAllowCommand(file, 'clear').kind === 'success' && plugin.readRules(file).length === 0)
check('an unknown verb explains the usage', plugin.runAllowCommand(file, 'wat').kind === 'error')

console.log('apply')
const registered = { listeners: [], commands: [] }
const ctx = {
  logger,
  on: (name, listener, options) => { registered.listeners.push({ name, options }); registered.listener = listener },
  get: () => undefined,
  inject: (_names, factory) => factory({ effect: (create) => create(), commands: { register: (definition) => { registered.commands.push(definition); return () => {} } } }),
}
plugin.apply(ctx, { rulesFile: file })
check('the approval listener is prepended', registered.listeners[0]?.name === 'approval/request' && registered.listeners[0]?.options?.prepend === true, JSON.stringify(registered.listeners))
check('/allow is registered', registered.commands[0]?.name === 'allow' && registered.commands[0]?.description.includes('approval'))
check('an invalid rulesFile config fails loud', (() => {
  try {
    plugin.apply(ctx, { rulesFile: '' })
    return false
  }
  catch {
    return true
  }
})())

console.log('persistence')
plugin.runAllowCommand(file, 'add bash danger-full-access make build')
check('the file is valid JSON with a version', JSON.parse(readFileSync(file, 'utf8')).version === 1)

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
