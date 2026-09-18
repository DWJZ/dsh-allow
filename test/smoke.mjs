/**
 * dsh-allow host smoke test — drives the approval listener, the pending store,
 * the card's two routes, and `/allow` against a fake session and fake HTTP
 * objects. No host, no network.
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
const makeSession = (calls, id = 's1') => ({
  id,
  seq: calls.length,
  eventAt: (seq) => (calls[seq] === undefined ? undefined : { type: 'tool/call', data: calls[seq] }),
})

const call = (callId, args) => ({ callId, name: 'bash', arguments: JSON.stringify(args) })
const escalationCall = (callId, command, mode = 'danger-full-access') => call(callId, { command, sandbox_permissions: mode, justification: '需要写 profile' })

/** One approval request for a session's call. */
const request = (session, callId = 'c1', toolName = 'bash') => ({ agent: { session }, toolName, callId, reason: 'escalate sandbox to danger-full-access: 需要写 profile' })

/** A request object as a Web route sees it. */
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

/** A response object recording what the handler wrote. */
function fakeResponse() {
  return {
    statusCode: 0,
    body: '',
    writeHead(code) { this.statusCode = code },
    end(chunk) { if (chunk !== undefined) this.body += String(chunk) },
  }
}

const logger = { info: () => {}, warn: () => {}, error: () => {} }

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
const session = makeSession([call('other', { command: 'ls' }), escalationCall('c1', 'pnpm dsh plugin --profile web add x')])
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

console.log('pending store')
const clock = { now: 1000 }
const pendings = plugin.createPendingStore({ ttlMs: 100, now: () => clock.now })
pendings.remember(request(session), { tool: 'bash', mode: 'danger-full-access', prefix: 'mkdir' }, 'mkdir -p /x')
check('a remembered escalation is readable by ids', pendings.get('s1', 'c1')?.prefix === 'mkdir')
check('an unknown call id reads as null', pendings.get('s1', 'c2') === null)
check('another session does not see it', pendings.get('s2', 'c1') === null)
clock.now += 500
check('an expired entry is pruned', pendings.get('s1', 'c1') === null)
check('a request without a session id is not remembered',
  (() => {
    const other = plugin.createPendingStore()
    other.remember({ callId: 'c9' }, { tool: 'bash', mode: 'm', prefix: 'p' }, 'p')
    return other.get(undefined, 'c9') === null
  })())

console.log('approval listener')
rmSync(file, { force: true })
const pendingStore = plugin.createPendingStore()
const listener = plugin.createApprovalListener({ file, logger, pendings: pendingStore })
let nextCalls = 0
const next = () => { nextCalls += 1; return Promise.resolve('delegated') }

let outcome = await listener(request(session), next)
check('an unmatched escalation is delegated to the card', outcome === 'delegated', outcome)
check('and recorded for the card button', pendingStore.get('s1', 'c1')?.prefix === 'pnpm dsh plugin', JSON.stringify(pendingStore.get('s1', 'c1')))
check('the record carries the command', pendingStore.get('s1', 'c1')?.command.startsWith('pnpm dsh plugin'), pendingStore.get('s1', 'c1')?.command)

plugin.addRule(file, { tool: 'bash', mode: 'danger-full-access', prefix: 'pnpm dsh plugin' })
outcome = await listener(request(session), next)
check('a stored rule allows without any card', outcome === 'allowed-once', outcome)
check('the hit is counted', plugin.readRules(file)[0]?.hits === 1, JSON.stringify(plugin.readRules(file)[0]))

const plainSession = makeSession([call('c1', { command: 'ls /root' })])
const before = nextCalls
outcome = await listener(request(plainSession), next)
check('a non-escalation delegates', outcome === 'delegated' && nextCalls === before + 1, `${outcome} / ${String(nextCalls)}`)

console.log('card routes')
const routeStore = plugin.createPendingStore()
routeStore.remember(request(session), { tool: 'bash', mode: 'danger-full-access', prefix: 'mkdir' }, 'mkdir -p /x')
const pendingHandler = plugin.createPendingHandler({ pendings: routeStore })

let response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1' }), response)
check('the pending route answers the card', response.statusCode === 200 && JSON.parse(response.body).prefix === 'mkdir', response.body)
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=nope' }), response)
check('an unknown pending is a 404', response.statusCode === 404, String(response.statusCode))
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1', remoteAddress: '10.0.0.5' }), response)
check('the pending route is loopback only', response.statusCode === 403, String(response.statusCode))
response = fakeResponse()
pendingHandler(fakeRequest({ url: '/dsh-allow/pending', method: 'POST' }), response)
check('the pending route refuses POST', response.statusCode === 405, String(response.statusCode))

{
  const ruleFile = join(root, 'remember.json')
  const rememberStore = plugin.createPendingStore()
  rememberStore.remember(request(session), { tool: 'bash', mode: 'danger-full-access', prefix: 'gh repo view' }, 'gh repo view x')
  const rememberHandler = plugin.createRememberHandler({ pendings: rememberStore, file: ruleFile, logger })

  let res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST',
    url: '/dsh-allow/remember',
    headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'c1' }),
  }), res)
  check('the remember route stores the rule', res.statusCode === 200 && JSON.parse(res.body).prefix === 'gh repo view', res.body)
  check('and the rules file gained it', plugin.readRules(ruleFile).some((rule) => rule.prefix === 'gh repo view'), JSON.stringify(plugin.readRules(ruleFile)))

  res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST',
    url: '/dsh-allow/remember',
    headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'gone' }),
  }), res)
  check('an unknown pending is refused', res.statusCode === 404, String(res.statusCode))

  res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST',
    url: '/dsh-allow/remember',
    headers: { origin: 'http://evil.test', 'content-type': 'application/json' },
    body: JSON.stringify({ sessionId: 's1', callId: 'c1' }),
  }), res)
  check('a cross-origin remember is refused', res.statusCode === 403, String(res.statusCode))

  res = fakeResponse()
  await rememberHandler(fakeRequest({
    method: 'POST',
    url: '/dsh-allow/remember',
    headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
    body: 'not json',
  }), res)
  check('a malformed body is a 400', res.statusCode === 400, String(res.statusCode))
}

console.log('/allow command')
rmSync(file, { force: true })
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
const registered = { listeners: [], commands: [], routes: [] }
const ctx = {
  logger,
  on: (name, listener, options) => { registered.listeners.push({ name, options }); registered.listener = listener },
  get: () => undefined,
  inject: (names, factory) => {
    if (names.includes('webServer')) {
      factory({
        effect: (create) => create(),
        webServer: { register: (route) => { registered.routes.push(route); return () => {} } },
      })
      return
    }
    factory({ effect: (create) => create(), commands: { register: (definition) => { registered.commands.push(definition); return () => {} } } })
  },
}
plugin.apply(ctx, { rulesFile: file })
check('the approval listener is prepended', registered.listeners[0]?.name === 'approval/request' && registered.listeners[0]?.options?.prepend === true, JSON.stringify(registered.listeners))
check('both card routes are registered', registered.routes.map((route) => route.path).join(',') === '/dsh-allow/pending,/dsh-allow/remember', JSON.stringify(registered.routes.map((route) => route.path)))
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
