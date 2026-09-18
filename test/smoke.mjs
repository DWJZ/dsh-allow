/**
 * Host wiring suite: the pre-execute gate, the card routes, the rule store, the
 * audit log, and `/allow`. No host, no network.
 *
 * Usage: `node test/smoke.mjs`.
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { createRequire } from 'node:module'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const host = await import(pathToFileURL(join(PLUGIN, 'src/index.js')).href)
const store = await import(pathToFileURL(join(PLUGIN, 'src/store.js')).href)

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-'))
const rulesFile = join(root, 'rules.json')
const auditFile = join(root, 'audit.ndjson')
const config = { rulesFile, auditFile, audit: true, defaultDecision: 'allow' }
const HOME = '/Users/tester'
const CWD = '/Users/tester/project'

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const require = createRequire(import.meta.url)
const logger = { info: () => {}, warn: () => {}, error: () => {} }
const session = { id: 's1', header: { cwd: CWD } }
const exec = (command, { name = 'bash', callId = 'c1', workdir } = {}) => ({
  name,
  callId,
  arguments: { command, ...(workdir === undefined ? {} : { workdir }) },
  agent: { session },
})

/** A Web route request. */
function fakeRequest({ method = 'GET', url = '/', headers = {}, body, remoteAddress = '127.0.0.1' } = {}) {
  return {
    method,
    url,
    headers: { host: '127.0.0.1:3080', ...headers },
    socket: { remoteAddress },
    async *[Symbol.asyncIterator]() {
      if (body !== undefined) yield Buffer.from(body)
    },
  }
}

/** A response object recording what a handler wrote. */
function fakeResponse() {
  return {
    statusCode: 0,
    body: '',
    writeHead(code) { this.statusCode = code },
    end(chunk) { if (chunk !== undefined) this.body += String(chunk) },
  }
}

console.log('rule store')
rmSync(rulesFile, { force: true })
check('a missing file reads as no rules', store.readRules(rulesFile).length === 0)
const rule = store.addRule(rulesFile, { decision: 'allow', executable: 'git', argvPrefix: ['status'] })
check('a rule is stored with an id and a prefix', rule.id !== undefined && rule.argvPrefix[0] === 'status', JSON.stringify(rule))
store.addRule(rulesFile, { decision: 'allow', executable: 'git', argvPrefix: ['status'] })
check('an identical rule is not duplicated', store.readRules(rulesFile).length === 1)
check('removing by position works', store.removeRule(rulesFile, 1)?.executable === 'git' && store.readRules(rulesFile).length === 0)
check('an out-of-range removal is refused', store.removeRule(rulesFile, 5) === null)
store.addRule(rulesFile, { decision: 'allow', executable: 'touch', argvPrefix: [] })
check('clear empties the file', store.clearRules(rulesFile) === 1 && store.readRules(rulesFile).length === 0)

console.log('pending store')
const clock = { now: 1000 }
const pendings = store.createPendingStore({ ttlMs: 100, now: () => clock.now })
pendings.remember('s1', 'c1', { command: 'rm x', suggestion: { decision: 'allow', executable: 'rm', argvPrefix: [] } })
check('a pending record is readable', pendings.get('s1', 'c1')?.command === 'rm x')
check('another call id is not', pendings.get('s1', 'c2') === null)
clock.now += 500
check('an expired record is pruned', pendings.get('s1', 'c1') === null)

console.log('pre-execute gate')
rmSync(rulesFile, { force: true })
rmSync(auditFile, { force: true })
const gatePendings = store.createPendingStore()
const gate = host.createGate({ config, home: HOME, logger, pendings: gatePendings })
let nextCalls = 0
const next = () => { nextCalls += 1; return Promise.resolve({ kind: 'allow' }) }

let decision = await gate(exec('ls -la'), next)
check('an unremarkable command continues to the sandbox', decision.kind === 'allow' && nextCalls === 1, JSON.stringify(decision))

decision = await gate(exec('git reset --hard'), next)
check('a destructive command asks for approval', decision.kind === 'ask', JSON.stringify(decision))
check('and the prompt carries the card marker', String(decision.reason).startsWith(host.POLICY_REASON_PREFIX), decision.reason)
check('and the reason names the command', String(decision.reason).includes('git reset --hard'), decision.reason)
check('and a pending record exists for the card', gatePendings.get('s1', 'c1')?.suggestions?.[0]?.executable === 'git', JSON.stringify(gatePendings.get('s1', 'c1')))
check('the suggested rule keeps the subcommand', gatePendings.get('s1', 'c1')?.label === 'git reset', String(gatePendings.get('s1', 'c1')?.label))

decision = await gate(exec('rm -rf /'), next)
check('a catastrophic command is denied outright', decision.kind === 'deny', JSON.stringify(decision))

const before = nextCalls
decision = await gate(exec('ls', { name: 'read' }), next)
check('a non-shell tool is untouched', decision.kind === 'allow' && nextCalls === before + 1, JSON.stringify(decision))

store.addRule(rulesFile, { decision: 'allow', executable: 'git', argvPrefix: ['status'] })
decision = await gate(exec('git status'), next)
check('a stored rule allows the covered command', decision.kind === 'allow', JSON.stringify(decision))
check('and counts the hit', store.readRules(rulesFile)[0]?.hits === 1, JSON.stringify(store.readRules(rulesFile)[0]))

decision = await gate(exec('touch x && rm -rf /'), next)
check('a chained catastrophic command is still denied', decision.kind === 'deny', JSON.stringify(decision))

console.log('audit log')
const lines = readFileSync(auditFile, 'utf8').trim().split('\n').map(line => JSON.parse(line))
check('every decision is logged', lines.length >= 5, String(lines.length))
check('the log records the decision and the parsed commands', lines.some(line => line.decision === 'forbidden' && Array.isArray(line.commands)), JSON.stringify(lines.at(-1)))
const secretGate = host.createGate({
  config: { ...config, auditFile: join(root, 'secret.ndjson') },
  home: HOME,
  logger,
  pendings: store.createPendingStore(),
})
await secretGate(exec('curl -H "Authorization: Bearer abc123" https://x'), next)
const secretLine = readFileSync(join(root, 'secret.ndjson'), 'utf8')
check('credential-shaped text is redacted', secretLine.includes('[redacted]') && !secretLine.includes('abc123'), secretLine.slice(0, 200))

console.log('card routes')
const routePendings = store.createPendingStore()
routePendings.remember('s1', 'c1', {
  command: 'rm -rf build',
  cwd: CWD,
  decision: 'prompt',
  reason: 'rm deletes files',
  risk: 'destructive',
  analyzable: true,
  label: 'rm',
  labels: ['rm'],
  suggestions: [{ decision: 'allow', executable: 'rm', argvPrefix: [] }],
  triggers: ['rm -rf build'],
})
const pendingHandler = host.createPendingHandler({ pendings: routePendings })
let response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1' }), response)
const payload = JSON.parse(response.body)
check('the card learns the label, risk, and cwd', payload.label === 'rm' && payload.risk === 'destructive' && payload.cwd === CWD, response.body)
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=none' }), response)
check('an unknown approval is a 404', response.statusCode === 404, String(response.statusCode))
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1', remoteAddress: '10.0.0.5' }), response)
check('the route is loopback only', response.statusCode === 403, String(response.statusCode))
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending', method: 'POST' }), response)
check('the route refuses POST', response.statusCode === 405, String(response.statusCode))

{
  const rememberFile = join(root, 'remember.json')
  const rememberPendings = store.createPendingStore()
  rememberPendings.remember('s1', 'c1', {
    command: 'git reset --hard', cwd: CWD, decision: 'prompt', reason: 'discards changes', risk: 'destructive',
    analyzable: true, label: 'git reset', labels: ['git reset'],
    suggestions: [{ decision: 'allow', executable: 'git', argvPrefix: ['reset'] }], triggers: [],
  })
  const rememberHandler = host.createRememberHandler({ pendings: rememberPendings, config: { ...config, rulesFile: rememberFile }, logger })
  let res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST',
    url: '/dsh-allow/remember',
    headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'c1' }),
  }), res)
  check('always-allow stores the suggested rule', res.statusCode === 200 && JSON.parse(res.body).label === 'git reset', res.body)
  check('and the rule landed in the file', store.readRules(rememberFile)[0]?.argvPrefix?.[0] === 'reset', JSON.stringify(store.readRules(rememberFile)))
  res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST', url: '/dsh-allow/remember',
    headers: { origin: 'http://evil.test', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'c1' }),
  }), res)
  check('a cross-origin remember is refused', res.statusCode === 403, String(res.statusCode))

  const forbiddenPendings = store.createPendingStore()
  forbiddenPendings.remember('s1', 'c9', {
    command: 'rm -rf /', cwd: CWD, decision: 'forbidden', reason: 'filesystem root', risk: 'catastrophic',
    analyzable: true, label: null, labels: [], suggestions: [], triggers: [],
  })
  res = fakeResponse()
  await host.createRememberHandler({ pendings: forbiddenPendings, config, logger })(fakeRequest({
    method: 'POST', url: '/dsh-allow/remember',
    headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'c9' }),
  }), res)
  check('a forbidden command can never be remembered', res.statusCode === 409, String(res.statusCode))
}

console.log('escalation listener')
{
  const escalationFile = join(root, 'escalation.json')
  const escalationPendings = store.createPendingStore()
  const listenerConfig = { ...config, rulesFile: escalationFile, auditFile: join(root, 'escalation.ndjson') }
  const listener = host.createApprovalListener({ config: listenerConfig, home: HOME, pendings: escalationPendings, logger })
  const delegate = () => Promise.resolve('delegated')
  const call = (command, callId) => ({
    callId,
    agent: {
      session: {
        id: 's1',
        header: { cwd: CWD },
        seq: 1,
        eventAt: () => ({ type: 'tool/call', data: { callId, name: 'bash', arguments: JSON.stringify({ command }) } }),
      },
    },
  })

  let outcome = await listener(call('cp /a /b && echo copied', 'c1'), delegate)
  check('an uncovered escalation reaches the card', outcome === 'delegated', outcome)
  check('and the card is offered a rule per command', escalationPendings.get('s1', 'c1')?.labels?.join(' + ') === 'cp + echo', JSON.stringify(escalationPendings.get('s1', 'c1')?.labels))

  store.addRule(escalationFile, { decision: 'allow', executable: 'cp', argvPrefix: [] })
  store.addRule(escalationFile, { decision: 'allow', executable: 'echo', argvPrefix: [] })
  outcome = await listener(call('cp /a /b && echo copied', 'c2'), delegate)
  check('a fully remembered escalation is approved without a card', outcome === 'allowed-once', outcome)
  check('and it does not double-count the rule use', store.readRules(escalationFile).every(rule => (rule.hits ?? 0) <= 1), JSON.stringify(store.readRules(escalationFile).map(rule => [rule.executable, rule.hits])))

  const manualPendings = store.createPendingStore()
  const manualListener = host.createApprovalListener({
    config: { ...listenerConfig, autoApproveEscalations: false },
    home: HOME,
    pendings: manualPendings,
    logger,
  })
  outcome = await manualListener(call('cp /a /b && echo copied', 'c5'), delegate)
  check('the escalation can be kept manual by configuration', outcome === 'delegated', outcome)

  store.addRule(escalationFile, { decision: 'allow', executable: 'rm', argvPrefix: [] })
  outcome = await listener(call('rm -rf /', 'c3'), delegate)
  check('a catastrophic escalation is rejected outright', outcome === 'rejected', outcome)

  const inlinePendings = store.createPendingStore()
  const inlineListener = host.createApprovalListener({ config: listenerConfig, home: HOME, pendings: inlinePendings, logger })
  outcome = await inlineListener(call('node -e "x"', 'c4'), delegate)
  check('an unpinned inline escalation reaches the card', outcome === 'delegated', outcome)
  check('and the card offers an exact rule', inlinePendings.get('s1', 'c4')?.exact === true && inlinePendings.get('s1', 'c4')?.labels?.[0] === 'node -e x', JSON.stringify(inlinePendings.get('s1', 'c4')?.labels))
  store.addRule(escalationFile, { decision: 'allow', executable: 'node', argvPrefix: ['-e', 'x'] })
  outcome = await inlineListener(call('node -e "x"', 'c6'), delegate)
  check('the same inline command is then approved silently', outcome === 'allowed-once', outcome)
  outcome = await inlineListener(call('node -e "y"', 'c7'), delegate)
  check('different inline code still asks', outcome === 'delegated', outcome)
}

console.log('broad capability rules are refused')
{
  const broadFile = join(root, 'broad.json')
  for (const [executable, argvPrefix] of [['bash', []], ['bash', ['-c']], ['python', ['-c']], ['node', ['-e']], ['python', ['-']]]) {
    let refused = false
    try {
      store.addRule(broadFile, { decision: 'allow', executable, argvPrefix })
    }
    catch {
      refused = true
    }
    check(`the store refuses "${[executable, ...argvPrefix].join(' ')}"`, refused)
  }
  store.addRule(broadFile, { decision: 'allow', executable: 'python', argvPrefix: ['tools/check.py'] })
  check('and accepts a pinned one', store.readRules(broadFile).length === 1, JSON.stringify(store.readRules(broadFile)))
  check('a broad rule already on disk is ignored by the reader', (() => {
    const { writeFileSync } = require('node:fs')
    writeFileSync(broadFile, JSON.stringify({ version: 2, rules: [
      { id: 'stale', decision: 'allow', executable: 'python', argvPrefix: ['-c'] },
      { id: 'good', decision: 'allow', executable: 'python', argvPrefix: ['tools/check.py'] },
    ] }))
    return store.readRules(broadFile).length === 1 && store.readRules(broadFile)[0].id === 'good'
  })())
}

console.log('/allow command')
rmSync(rulesFile, { force: true })
check('an empty list explains itself', host.runAllowCommand(rulesFile, '').text.includes('还没有记住任何规则'))
check('add stores a structured rule', host.runAllowCommand(rulesFile, 'add allow git status').kind === 'success' && store.readRules(rulesFile)[0]?.argvPrefix?.[0] === 'status')
check('list renders it', host.runAllowCommand(rulesFile, 'list').text.includes('allow · git status'), host.runAllowCommand(rulesFile, 'list').text)
check('an invalid decision is refused', host.runAllowCommand(rulesFile, 'add sometimes git').kind === 'error')
check('a broad interpreter rule is refused with a reason', (() => {
  const result = host.runAllowCommand(rulesFile, 'add allow python -c')
  return result.kind === 'error' && result.text.includes('内联代码')
})(), JSON.stringify(host.runAllowCommand(rulesFile, 'add allow python -c')))
check('a pinned interpreter rule is accepted', host.runAllowCommand(rulesFile, 'add allow python tools/check.py').kind === 'success')
check('remove drops the pinned rule', host.runAllowCommand(rulesFile, 'remove 2').kind === 'success' && store.readRules(rulesFile).length === 1, JSON.stringify(store.readRules(rulesFile)))
check('an unknown verb explains the usage', host.runAllowCommand(rulesFile, 'wat').kind === 'error')

console.log('apply')
const registered = { listeners: [], commands: [], routes: [] }
const ctx = {
  logger,
  on: (name, listener, options) => { registered.listeners.push({ name, options }) },
  get: () => undefined,
  inject: (names, factory) => {
    if (names.includes('webServer')) {
      factory({ effect: create => create(), webServer: { register: route => { registered.routes.push(route); return () => {} } } })
      return
    }
    factory({ effect: create => create(), commands: { register: definition => { registered.commands.push(definition); return () => {} } } })
  },
}
host.apply(ctx, { rulesFile, auditFile })
check('the forbidden-pin switch defaults off', store.resolveConfig({}, '/tmp').allowForbiddenSource === false)
check('and can be turned on by configuration', store.resolveConfig({ allowForbiddenSource: true }, '/tmp').allowForbiddenSource === true)
check('both listeners are prepended', registered.listeners.every(entry => entry.options?.prepend === true), JSON.stringify(registered.listeners))
check('the gate listens on tools/pre-execute', registered.listeners.some(entry => entry.name === 'tools/pre-execute'))
check('the card listens on approval/request', registered.listeners.some(entry => entry.name === 'approval/request'))
check('both routes are registered', registered.routes.map(route => route.path).join(',') === '/dsh-allow/pending,/dsh-allow/remember', JSON.stringify(registered.routes.map(route => route.path)))
check('/allow is registered', registered.commands[0]?.name === 'allow')
check('a bad config fails loud', (() => {
  try {
    host.apply(ctx, { defaultDecision: 'maybe' })
    return false
  }
  catch {
    return true
  }
})())

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
