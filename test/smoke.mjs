/**
 * Host wiring suite: the pre-execute gate, the approval listener, the card
 * routes, the rule store, the audit log, and `/allow`. No host, no network.
 *
 * Usage: `node test/smoke.mjs`.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const host = await import(pathToFileURL(join(PLUGIN, 'src/index.js')).href)
const store = await import(pathToFileURL(join(PLUGIN, 'src/store.js')).href)
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)
const reviewerModule = await import(pathToFileURL(join(PLUGIN, 'src/reviewer.js')).href)

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-smoke-'))
const rulesFile = join(root, 'rules.json')
const auditFile = join(root, 'audit.ndjson')
const HOME = '/Users/tester'
const WORKSPACE = `${HOME}/project`
const CWD = WORKSPACE
const config = {
  ...store.resolveConfig({ rulesFile, auditFile, audit: true }, root),
  harnessHome: root,
}

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const logger = { info: () => {}, warn: () => {}, error: () => {} }
const session = { id: 's1', seq: 0, header: { cwd: CWD }, eventAt: () => undefined }
const otherSession = { id: 's2', seq: 0, header: { cwd: CWD }, eventAt: () => undefined }
const exec = (command, { name = 'bash', callId = 'c1', workdir, agent = { session } } = {}) => ({
  name,
  callId,
  arguments: { command, ...(workdir === undefined ? {} : { workdir }) },
  agent,
})
const ctx = { get: name => (name === 'sandboxPolicy' ? { resolve: () => ({ mode: 'workspace-write', workspaceRoot: WORKSPACE }) } : undefined) }
const pendings = store.createPendingStore()
const grants = store.createGrantStore()
const engine = host.createEngine({ config, home: HOME, grants, pendings, ctx })
const gate = host.createGate({ engine, pendings, logger, config })
const approval = host.createApprovalListener({ engine, pendings, logger })

let nextCalls = 0
const next = () => { nextCalls += 1; return Promise.resolve({ kind: 'allow' }) }

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

/** Drive one route handler and return its parsed answer. */
async function call(handler, request) {
  const response = fakeResponse()
  await handler(request, response)
  return { status: response.statusCode, json: response.body === '' ? null : JSON.parse(response.body) }
}

const post = (path, body) => fakeRequest({
  method: 'POST',
  url: path,
  headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
  body: JSON.stringify(body),
})
const pendingHandler = host.createPendingHandler({ pendings })
const rememberHandler = host.createRememberHandler({ pendings, config, logger })
const onceHandler = host.createOnceHandler({ pendings, grants, logger })

console.log('rule store')
rmSync(rulesFile, { force: true })
check('a missing file reads as no rules', store.readRules(rulesFile).length === 0)
const stored = store.addRule(rulesFile, { path: `${WORKSPACE}/build`, recursive: true, access: { delete: true } })
check('a rule is stored with a canonical path', stored.path === `${WORKSPACE}/build`, JSON.stringify(stored))
store.addRule(rulesFile, { path: `${WORKSPACE}/build`, recursive: true, access: { delete: true } })
check('an identical rule is not duplicated', store.readRules(rulesFile).length === 1)
check('removing by position works', store.removeRule(rulesFile, 1)?.access.delete === true && store.readRules(rulesFile).length === 0)
check('an out-of-range removal is refused', store.removeRule(rulesFile, 5) === null)
const refuses = (fields) => {
  try {
    store.addRule(rulesFile, fields)
    return false
  }
  catch {
    return true
  }
}
check('a rule that grants nothing is refused', refuses({ path: '/w', access: {} }))
check('a write-everything rule is refused', refuses({ path: '/', recursive: true, access: { write: true } }))
store.addRule(rulesFile, { path: `${WORKSPACE}/build`, access: { write: true } })
check('clear empties the file', store.clearRules(rulesFile) === 1 && store.readRules(rulesFile).length === 0)
writeFileSync(rulesFile, `${JSON.stringify({ version: 2, rules: [{ id: 'old', decision: 'allow', executable: 'rm', argvPrefix: [] }] })}\n`)
check('an older rule model reads as no rules', store.readRules(rulesFile).length === 0)
store.addRule(rulesFile, { path: `${WORKSPACE}/build`, access: { delete: true } })
check('its file is kept as a backup', existsSync(`${rulesFile}.v2.bak`), `${rulesFile}.v2.bak`)
check('and the new rules are readable', store.readRules(rulesFile).length === 1)
rmSync(rulesFile, { force: true })

console.log('pre-execute gate')
let decision = await gate(exec('ls -la'), next)
check('a granted command continues to the sandbox', decision.kind === 'allow' && nextCalls === 1, JSON.stringify(decision))

decision = await gate(exec('rm -rf build'), next)
check('an ungranted delete asks', decision.kind === 'ask', JSON.stringify(decision))
check('the prompt carries the card marker', String(decision.reason).startsWith(host.POLICY_REASON_PREFIX), decision.reason)
check('and names the missing capability', String(decision.reason).includes('delete'), decision.reason)
const record = pendings.get('s1', 'c1')
check('a pending record exists for the card', record !== null && record.missing[0]?.operation === 'delete', JSON.stringify(record?.missing))
check('with exactly one, narrow suggestion', record.suggestions.length === 1
  && record.suggestions[0].path === `${WORKSPACE}/build`
  && record.suggestions[0].recursive === false, JSON.stringify(record.suggestions))

const before = nextCalls
decision = await gate(exec('ls', { name: 'read' }), next)
check('a non-shell tool is untouched', decision.kind === 'allow' && nextCalls === before + 1, JSON.stringify(decision))

decision = await gate(exec('rm -rf /System/Library/x', { callId: 'cf' }), next)
check('a platform-protected path is denied outright', decision.kind === 'deny', JSON.stringify(decision))

console.log('card routes')
let answer = await call(pendingHandler, fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1' }))
check('the pending route describes the decision', answer.status === 200 && answer.json.rememberable === true, JSON.stringify(answer.json))
check('and lists the operation and the path', answer.json.missing[0].operation === 'delete'
  && answer.json.missing[0].path === `${WORKSPACE}/build`, JSON.stringify(answer.json.missing))
check('and the sandbox mode', answer.json.mode === 'workspace-write', JSON.stringify(answer.json.mode))
answer = await call(pendingHandler, fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=nope' }))
check('an unknown pending is a 404', answer.status === 404)
answer = await call(pendingHandler, fakeRequest({ url: '/dsh-allow/pending?sessionId=s1&callId=c1', remoteAddress: '10.0.0.9' }))
check('a non-loopback read is refused', answer.status === 403)
answer = await call(pendingHandler, fakeRequest({ url: '/dsh-allow/pending', method: 'POST' }))
check('a wrong method is refused', answer.status === 405)

console.log('always allow')
answer = await call(rememberHandler, post('/dsh-allow/remember', { sessionId: 's1', callId: 'c1' }))
check('remembering succeeds', answer.status === 200 && answer.json.ok === true, JSON.stringify(answer.json))
check('and writes exactly one rule, the one the button named', store.readRules(rulesFile).length === 1
  && store.readRules(rulesFile)[0].path === `${WORKSPACE}/build`
  && store.readRules(rulesFile)[0].recursive === false
  && store.readRules(rulesFile)[0].access.delete === true, JSON.stringify(store.readRules(rulesFile)))
decision = await gate(exec('rm -rf build'), next)
check('the same command no longer asks', decision.kind === 'allow', JSON.stringify(decision))
decision = await gate(exec('rm -rf build/nested', { callId: 'c6' }), next)
check('a path beside it still asks: the folder was not opened', decision.kind === 'ask', JSON.stringify(decision))
answer = await call(rememberHandler, post('/dsh-allow/remember', { sessionId: 's1', callId: 'c6' }))
check('and its own grant stays narrow too', answer.status === 200
  && store.readRules(rulesFile).length === 2
  && store.readRules(rulesFile)[1].path === `${WORKSPACE}/build/nested`
  && store.readRules(rulesFile)[1].recursive === false, JSON.stringify(store.readRules(rulesFile)))
decision = await gate(exec('rm -rf build/nested', { callId: 'c7' }), next)
check('which then covers that path', decision.kind === 'allow', JSON.stringify(decision))
answer = await call(rememberHandler, post('/dsh-allow/remember', { sessionId: 's1', callId: 'c1' }))
check('remembering a stale approval is a 404', answer.status === 404)
answer = await call(rememberHandler, fakeRequest({
  method: 'POST', url: '/dsh-allow/remember', headers: { origin: 'http://evil.invalid' }, body: '{}',
}))
check('a cross-origin write is refused', answer.status === 403)

console.log('allow once')
await gate(exec('rm -rf unopened', { callId: 'c2' }), next)
check('a second path is pending', pendings.get('s1', 'c2') !== null)
const rulesBefore = store.readRules(rulesFile).length
answer = await call(onceHandler, post('/dsh-allow/once', { sessionId: 's1', callId: 'c2' }))
check('the once route grants it', answer.status === 200 && answer.json.ok === true, JSON.stringify(answer.json))
check('as a one-shot rule, not a stored one', grants.rulesFor('s1', 'c2').length > 0
  && grants.rulesFor('s1', 'c2')[0].source === 'session'
  && store.readRules(rulesFile).length === rulesBefore, JSON.stringify(grants.rulesFor('s1', 'c2')))
decision = await gate(exec('rm -rf unopened', { callId: 'c2' }), next)
check('and that call can run it', decision.kind === 'allow', JSON.stringify(decision))
decision = await gate(exec('rm -rf unopened', { callId: 'c3' }), next)
check('but the next call asks again', decision.kind === 'ask', JSON.stringify(decision))
decision = await gate(exec('rm -rf unopened', { callId: 'c4', agent: { session: otherSession } }), next)
check('and another session always asks', decision.kind === 'ask', JSON.stringify(decision))
decision = await gate(exec('rm -rf build', { callId: 'c5', agent: { session: otherSession } }), next)
check('the stored rule holds for every session', decision.kind === 'allow', JSON.stringify(decision))

console.log('a one-shot grant is spent by the call it was given to')
const settle = host.createSettleListener({ grants, logger })
check('the one-shot is still live for its call', grants.rulesFor('s1', 'c2').length === 1)
check('the profile sees it only for the approved command',
  grants.forCommand('s1', 'rm -rf unopened').length === 1
  && grants.forCommand('s1', 'rm -rf something-else').length === 0)
check('another call in the session is told to wait', grants.holder('s1', 'cX') === 'c2'
  && grants.holder('s1', 'c2') === null)
let released = false
const waiting = grants.released('s1', 'c2').then(() => { released = true })
await settle(exec('rm -rf unopened', { callId: 'c2' }), { kind: 'accepted' }, next)
await waiting
check('settling that call releases the waiter', released === true)
check('and drops the grant', grants.rulesFor('s1', 'c2').length === 0
  && grants.forCommand('s1', 'rm -rf unopened').length === 0)
check('a settle with nothing to drop is harmless', grants.consume('s1', 'c9') === 0)
const onceStore = store.createGrantStore()
onceStore.grant('s1', 'k1', 'rm -rf gone', [{ path: `${WORKSPACE}/gone`, recursive: false, access: { delete: true } }])
check('a grant belongs to its call', onceStore.rulesFor('s1', 'k1').length === 1 && onceStore.rulesFor('s1', 'k2').length === 0)
check('other sessions never see it', onceStore.forCommand('s2', 'rm -rf gone').length === 0)
check('the command view carries it for the profile', onceStore.forCommand('s1', 'rm -rf gone').length === 1)
check('and consuming the call drops it',
  onceStore.consume('s1', 'k1') === 1 && onceStore.forCommand('s1', 'rm -rf gone').length === 0)
check('a command with no grant stays empty', onceStore.forCommand('s1', 'rm -rf gone').length === 0)

console.log('audit')
const audit = readFileSync(auditFile, 'utf8').trim().split('\n').map(line => JSON.parse(line))
check('the audit log recorded decisions', audit.length > 0, String(audit.length))
check('with the effect paths and the decision',
  audit.some(entry => entry.decision === 'prompt' && entry.effects.some(effect => effect.operation === 'delete')), JSON.stringify(audit[0]))
const secretAudit = join(root, 'secret.ndjson')
const secretGate = host.createGate({
  engine: host.createEngine({
    config: { ...config, auditFile: secretAudit },
    home: HOME,
    grants,
    pendings: store.createPendingStore(),
    ctx,
  }),
  pendings: store.createPendingStore(),
  logger,
})
await secretGate(exec('curl -H "Authorization: Bearer abc123" https://example.invalid'), next)
const secretLine = readFileSync(secretAudit, 'utf8')
check('credential-shaped text is redacted', secretLine.includes('[redacted]') && !secretLine.includes('abc123'), secretLine.slice(0, 200))

console.log('approval listener')
const escalation = (command, callId, id = 's3') => ({
  agent: {
    session: {
      id,
      seq: 1,
      header: { cwd: CWD },
      eventAt: () => ({ type: 'tool/call', data: { callId, name: 'bash', arguments: JSON.stringify({ command }) } }),
    },
  },
  callId,
})
let outcome = await approval(escalation('rm -rf build', 'e1'), next)
check('an escalation is never approved automatically, even for a granted command',
  outcome?.kind === 'allow', JSON.stringify(outcome))
check('and it is on the card', pendings.get('s3', 'e1') !== null)
outcome = await approval(escalation('rm -rf /System/Library/x', 'e2'), next)
check('an escalation for a protected path is rejected', outcome === 'rejected', String(outcome))
outcome = await approval(escalation('rm -rf unopened', 'e3'), next)
check('an escalation for an ungranted command reaches the card', outcome?.kind === 'allow', JSON.stringify(outcome))
check('and has a pending record of its own', pendings.get('s3', 'e3') !== null)
outcome = await approval(escalation('rm -rf unopened', 'e4', 's4'), next)
check('a session grant belongs to one session only', outcome?.kind === 'allow', JSON.stringify(outcome))

console.log('a checked-in workspace rule grants nothing')
{
  const repo = join(root, 'repo')
  mkdirSync(repo, { recursive: true })
  writeFileSync(join(repo, '.dsh-allow.json'), `${JSON.stringify({
    version: 3,
    rules: [{ path: `${HOME}/.ssh`, recursive: true, access: { read: true, write: true, delete: true } }],
  })}\n`)
  const repoCtx = {
    get: name => (name === 'sandboxPolicy' ? { resolve: () => ({ mode: 'workspace-write', workspaceRoot: repo }) } : undefined),
  }
  const repoGate = host.createGate({
    engine: host.createEngine({ config, home: HOME, grants: store.createGrantStore(), pendings: store.createPendingStore(), ctx: repoCtx }),
    pendings: store.createPendingStore(),
    logger,
    config,
  })
  const repoDecision = await repoGate(exec('cat /Users/tester/.ssh/id_rsa', { callId: 'r1' }), next)
  check('reading a host secret still asks', repoDecision.kind === 'ask', JSON.stringify(repoDecision))
  const repoWrite = await repoGate(exec('echo x >> /Users/tester/.ssh/authorized_keys', { callId: 'r2' }), next)
  check('and writing one does too', repoWrite.kind === 'ask', JSON.stringify(repoWrite))
}

console.log('auto reviewer')
{
  const reviewSession = {
    id: 'sr1',
    seq: 2,
    header: { cwd: CWD },
    eventAt: seq => [
      { type: 'user/message', data: { id: 'm1', role: 'user', content: [{ type: 'text', text: '删除 review-only 目录' }], source: { kind: 'user' } } },
      { type: 'model/selection', data: { provider: 'test-provider', model: 'test-model' } },
    ][seq],
  }
  const reviewConfig = { ...store.resolveConfig({ rulesFile, auditFile, autoReview: { enabled: true, timeoutMs: 500 } }, root), harnessHome: root, home: HOME }
  const reviewGrants = store.createGrantStore()
  const reviewPendings = store.createPendingStore()
  const reviewAudit = join(root, 'review.ndjson')
  const reviewEngine = host.createEngine({
    config: { ...reviewConfig, auditFile: reviewAudit },
    home: HOME,
    grants: reviewGrants,
    pendings: reviewPendings,
    ctx,
  })
  const scripted = text => ({
    calls: [],
    async *stream(options) { this.calls.push(options); yield { type: 'text-delta', index: 0, text }; yield { type: 'finish', reason: { kind: 'stop' } } },
  })
  const gateWith = (llm) => host.createGate({
    engine: reviewEngine,
    pendings: reviewPendings,
    logger,
    config: { ...reviewConfig, auditFile: reviewAudit },
    grants: reviewGrants,
    reviewer: reviewerModule.createReviewer({ config: reviewConfig, logger, llmOf: () => llm }),
  })

  const rulesBeforeReview = store.readRules(rulesFile).length
  let llm = scripted('{"verdict":"ALLOW","reason":"the user asked to delete build"}')
  let gateReview = gateWith(llm)
  let reviewDecision = await gateReview(exec('rm -rf review-only', { callId: 'rc1', agent: { session: reviewSession } }), next)
  check('an ALLOW runs the call without a card', reviewDecision.kind === 'allow', JSON.stringify(reviewDecision))
  check('J: no persistent rule was written', store.readRules(rulesFile).length === rulesBeforeReview)
  check('K: the existing one-shot grant was used', reviewGrants.rulesFor('sr1', 'rc1').length === 1
    && reviewGrants.rulesFor('sr1', 'rc1')[0].source === 'session', JSON.stringify(reviewGrants.rulesFor('sr1', 'rc1')))
  check('K: and it is bound to that call only', reviewGrants.rulesFor('sr1', 'rc2').length === 0
    && reviewGrants.holder('sr1', 'rc2') === 'rc1')
  check('no card record was left behind', reviewPendings.get('sr1', 'rc1') === null)
  check('the LLM saw the user message and the missing capability',
    llm.calls[0].messages[0].content[0].text.includes('删除 review-only 目录')
    && llm.calls[0].messages[0].content[0].text.includes('delete'), llm.calls[0].messages[0].content[0].text.slice(0, 200))
  const reviewLines = readFileSync(reviewAudit, 'utf8').trim().split('\n').map(line => JSON.parse(line))
  check('the audit records the verdict and the route',
    reviewLines.some(line => line.decision === 'allow' && line.review?.verdict === 'ALLOW' && line.review?.route?.model === 'test-model'),
    JSON.stringify(reviewLines.at(-1)))
  const reviewSettle = host.createSettleListener({ grants: reviewGrants, logger })
  await reviewSettle(exec('rm -rf review-only', { callId: 'rc1', agent: { session: reviewSession } }), { kind: 'accepted' }, next)
  check('K: the grant is spent when the call settles', reviewGrants.rulesFor('sr1', 'rc1').length === 0)

  llm = scripted('{"verdict":"ASK","reason":"the request is not clearly the user\'s"}')
  gateReview = gateWith(llm)
  reviewDecision = await gateReview(exec('rm -rf review-only', { callId: 'rc2', agent: { session: reviewSession } }), next)
  check('an ASK falls back to the card', reviewDecision.kind === 'ask'
    && String(reviewDecision.reason).startsWith(host.POLICY_REASON_PREFIX), JSON.stringify(reviewDecision))
  check('and the card has its record', reviewPendings.get('sr1', 'rc2') !== null)
  check('and no grant was created', reviewGrants.rulesFor('sr1', 'rc2').length === 0)

  const failing = { async *stream() { throw new Error('provider down') } }
  reviewDecision = await gateWith(failing)(exec('rm -rf review-only', { callId: 'rc3', agent: { session: reviewSession } }), next)
  check('a failing reviewer falls back to the card too', reviewDecision.kind === 'ask', JSON.stringify(reviewDecision))

  const plainConfig = { ...store.resolveConfig({ rulesFile, auditFile }, root), harnessHome: root, home: HOME }
  const plainPendings = store.createPendingStore()
  const plainEngine = host.createEngine({ config: plainConfig, home: HOME, grants: store.createGrantStore(), pendings: plainPendings, ctx })
  let unusedLlm = scripted('{"verdict":"ALLOW","reason":"should never be called"}')
  const plainGate = host.createGate({
    engine: plainEngine,
    pendings: plainPendings,
    logger,
    config: plainConfig,
    grants: store.createGrantStore(),
    reviewer: reviewerModule.createReviewer({ config: plainConfig, logger, llmOf: () => unusedLlm }),
  })
  reviewDecision = await plainGate(exec('rm -rf review-only', { callId: 'rc4', agent: { session: reviewSession } }), next)
  check('a disabled reviewer leaves the card in charge', reviewDecision.kind === 'ask' && unusedLlm.calls.length === 0,
    JSON.stringify(reviewDecision))
}

console.log('/allow')
const allow = input => host.runAllowCommand({
  file: rulesFile,
  workspaceRoot: WORKSPACE,
  mode: 'workspace-write',
  enforcement: { state: 'partial', reason: 'write, create and delete are fenced; read and execute are not', capabilities: { read: false, write: true, create: true, delete: true, execute: false } },
}, input)
check('list names the stored rule', allow('').text.includes('delete') && allow('').text.includes(`${WORKSPACE}/build`), allow('').text)
check('status reports what the kernel fences',
  allow('status').text.includes('进程沙箱：partial')
  && allow('status').text.includes('delete=内核强制')
  && allow('status').text.includes('read=仅命令层'), allow('status').text)
check('add writes a rule', allow('add delete,write other folder').kind === 'success'
  && store.readRules(rulesFile).some(rule => rule.path === `${WORKSPACE}/other` && rule.access.write === true))
check('add can pin one exact file', allow('add read notes.txt file').kind === 'success'
  && store.readRules(rulesFile).some(rule => rule.path === `${WORKSPACE}/notes.txt` && rule.recursive === false))
check('add refuses an unknown operation', allow('add destroy other').kind === 'error')
check('add refuses a whole-disk rule', allow('add write / folder').kind === 'error')
check('remove drops one', allow('remove 1').kind === 'success')
check('clear empties the file', allow('clear').kind === 'success' && store.readRules(rulesFile).length === 0)
check('an unknown verb is an error', allow('nonsense').kind === 'error')

console.log('one-shot grants expire')
const clock = { now: 1000 }
const expiring = store.createGrantStore({ ttlMs: 100, now: () => clock.now })
expiring.grant('s1', 'c1', 'rm -rf gone', [{ path: `${WORKSPACE}/gone`, recursive: false, access: { delete: true } }])
check('a grant is readable', expiring.rulesFor('s1', 'c1').length === 1)
clock.now += 500
check('and expires even if the call never settles', expiring.rulesFor('s1', 'c1').length === 0)

console.log('config')
check('grants are accepted from configuration',
  store.resolveConfig({ grants: [{ path: `${WORKSPACE}/out`, access: { write: true } }] }, root).grants[0].path === `${WORKSPACE}/out`)
check('a grant without a path is refused',
  (() => { try { store.resolveConfig({ grants: [{}] }, root); return false } catch { return true } })())
check('a grant with no operation is refused',
  (() => { try { store.resolveConfig({ grants: [{ path: '/w', access: {} }] }, root); return false } catch { return true } })())
check('an invalid ttl is refused',
  (() => { try { store.resolveConfig({ sessionGrantTtlMs: 0 }, root); return false } catch { return true } })())
check('configured paths are canonical',
  fspolicy.pathWithin(WORKSPACE, store.resolveConfig({ grants: [{ path: `${WORKSPACE}/a/../b`, access: { read: true } }] }, root).grants[0].path))
check('the permission store is protected by default',
  store.resolveConfig({}, root).protectedFiles.some(file => file.endsWith('/dsh-allow.json'))
  && store.resolveConfig({}, root).protectedFiles.some(file => file.endsWith('/dsh-allow-audit.ndjson')))
check('a configured rules file is protected where it points',
  store.resolveConfig({ rulesFile: join(root, 'other.json') }, root).protectedFiles.includes(fspolicy.canonicalPath(join(root, 'other.json'), { cwd: '/', home: root })))
check('an unknown enforcement level is refused',
  (() => { try { store.resolveConfig({ enforce: 'maybe' }, root); return false } catch { return true } })())

console.log('apply')
const registered = { listeners: [], commands: [], routes: [], effects: [] }
const pluginCtx = {
  logger,
  on: (name, listener, options) => { registered.listeners.push({ name, options }) },
  get: () => undefined,
  effect: (create) => { registered.effects.push(create()); return () => {} },
  inject: (names, factory) => {
    if (names.includes('webServer')) {
      factory({ effect: create => create(), webServer: { register: route => { registered.routes.push(route); return () => {} } } })
      return
    }
    factory({ effect: create => create(), commands: { register: definition => { registered.commands.push(definition); return () => {} } } })
  },
}
host.apply(pluginCtx, { rulesFile, auditFile })
check('every listener is prepended', registered.listeners.every(entry => entry.options?.prepend === true), JSON.stringify(registered.listeners))
check('the gate listens on tools/pre-execute', registered.listeners.some(entry => entry.name === 'tools/pre-execute'))
check('the card listens on approval/request', registered.listeners.some(entry => entry.name === 'approval/request'))
check('the one-shot grants settle on tools/post-execute', registered.listeners.some(entry => entry.name === 'tools/post-execute'))
check('all three routes are registered',
  registered.routes.map(route => route.path).join(',') === '/dsh-allow/pending,/dsh-allow/remember,/dsh-allow/once',
  JSON.stringify(registered.routes.map(route => route.path)))
check('/allow is registered', registered.commands[0]?.name === 'allow')
check('the process fence is installed as an effect', registered.effects.length >= 1)
check('a bad config fails loud', (() => {
  try {
    host.apply(pluginCtx, { sessionGrantTtlMs: -1 })
    return false
  }
  catch {
    return true
  }
})())

console.log('non-shell file tools')
check('a write of the permission store is refused',
  (await gate({ name: 'write', callId: 'w1', arguments: { path: join(root, 'dsh-allow.json'), content: '{}' }, agent: { session } }, next)).kind === 'deny')
check('an edit of the audit log is refused',
  (await gate({ name: 'edit', callId: 'w2', arguments: { file_path: join(root, 'dsh-allow-audit.ndjson') }, agent: { session } }, next)).kind === 'deny')
check('an ordinary file write is left to the harness fence',
  (await gate({ name: 'write', callId: 'w3', arguments: { path: join(WORKSPACE, 'notes.md'), content: 'x' }, agent: { session } }, next)).kind === 'allow')
check('an unknown tool is untouched',
  (await gate({ name: 'present', callId: 'w4', arguments: {}, agent: { session } }, next)).kind === 'allow')

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
