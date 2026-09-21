/**
 * Audit-ledger suite: what one decision records about the layer that answered
 * it, what a human decision adds, how the log is read back from its end, and
 * what the approval tab's route answers. No host, no network.
 *
 * Usage: `node test/audit.spec.mjs`.
 */
import { appendFileSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const host = await import(pathToFileURL(join(PLUGIN, 'src/index.js')).href)
const store = await import(pathToFileURL(join(PLUGIN, 'src/store.js')).href)

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-audit-'))
const HOME = '/Users/tester'
const WORKSPACE = `${HOME}/project`
const CWD = WORKSPACE

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const logger = { info: () => {}, warn: () => {}, error: () => {} }
const config = {
  ...store.resolveConfig({ rulesFile: join(root, 'rules.json'), auditFile: join(root, 'audit.ndjson'), audit: true }, root),
  harnessHome: root,
}
const sessionOf = (id) => ({ id, seq: 0, header: { cwd: CWD }, eventAt: () => undefined })
const exec = (command, { callId = 'c1', session = sessionOf('s1') } = {}) => ({
  name: 'bash',
  callId,
  arguments: { command },
  agent: { session },
})
const ctx = { get: name => (name === 'sandboxPolicy' ? { resolve: () => ({ mode: 'workspace-write', workspaceRoot: WORKSPACE }) } : undefined) }
const next = () => Promise.resolve({ kind: 'allow' })

/** Read the audit file back as records. */
const auditOf = (file) => store.readAuditTail(file, { limit: 10_000, includeBaseline: true }).entries

/** The records one call produced, in order. */
const recordsOf = (file, callId) => auditOf(file).filter(entry => entry.callId === callId)

/** The one decision the user made about a call, or undefined. */
const humanRecordOf = (file, callId) => recordsOf(file, callId).find(entry => entry.origin === 'human')

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

/** Drive one route handler and return its parsed answer. */
async function call(handler, request) {
  const response = {
    statusCode: 0,
    body: '',
    writeHead(code) { this.statusCode = code },
    end(chunk) { if (chunk !== undefined) this.body += String(chunk) },
  }
  await handler(request, response)
  return { status: response.statusCode, json: response.body === '' ? null : JSON.parse(response.body) }
}

const post = (path, body) => fakeRequest({
  method: 'POST',
  url: path,
  headers: { origin: 'http://127.0.0.1:3080', 'content-type': 'application/json' },
  body: JSON.stringify(body),
})

console.log('who answered a decision')
{
  const file = join(root, 'origin.ndjson')
  const where = { ...config, auditFile: file }
  const pendings = store.createPendingStore()
  const grants = store.createGrantStore()
  const engine = host.createEngine({ config: where, home: HOME, grants, pendings, ctx })
  const gate = host.createGate({ engine, pendings, logger, config: where })

  await gate(exec('ls -la', { callId: 'o1' }), next)
  await gate(exec('rm -rf build', { callId: 'o2' }), next)
  await gate(exec('rm -rf /System/Library/x', { callId: 'o3' }), next)
  const records = auditOf(file)
  check('a command the baseline covers is recorded as such',
    records[0]?.origin === 'baseline' && records[0]?.decision === 'allow', JSON.stringify(records[0]))
  check('a prompt the baseline cannot answer is still the baseline\'s',
    records[1]?.origin === 'baseline' && records[1]?.decision === 'prompt', JSON.stringify(records[1]))
  check('a platform-protected path is the policy\'s own refusal',
    records[2]?.origin === 'policy' && records[2]?.decision === 'forbidden', JSON.stringify(records[2]))
  check('every record names its session and call',
    records.every(entry => entry.sessionId === 's1' && typeof entry.callId === 'string'), JSON.stringify(records.map(r => [r.sessionId, r.callId])))
  check('a baseline allow matches no user rule', Array.isArray(records[0]?.matchedRules) && records[0].matchedRules.length > 0
    && records[0].matchedRules.every(rule => rule.source === 'system'), JSON.stringify(records[0]?.matchedRules))

  store.addRule(where.rulesFile, { path: `${WORKSPACE}/build`, recursive: true, access: { delete: true } })
  await gate(exec('rm -rf build', { callId: 'o4' }), next)
  const ruled = auditOf(file).at(-1)
  check('a stored rule answers as the rule, not the baseline',
    ruled?.origin === 'rule' && ruled?.decision === 'allow', JSON.stringify(ruled))
  check('and the record names the rule that granted it',
    ruled?.matchedRules?.some(rule => rule.path === `${WORKSPACE}/build` && rule.source === 'user' && rule.access.delete === true),
    JSON.stringify(ruled?.matchedRules))

  const broken = join(root, 'broken.ndjson')
  const brokenGate = host.createGate({
    engine: host.createEngine({ config: { ...config, auditFile: broken }, home: HOME, grants, pendings: store.createPendingStore(), ctx }),
    pendings: store.createPendingStore(),
    logger,
    config: { ...config, auditFile: broken },
  })
  const unparseable = await brokenGate(exec('if then fi )))', { callId: 'o5' }), next)
  check('an unparseable line is refused, not crashed on', unparseable?.kind === 'deny', JSON.stringify(unparseable))
  check('and it is recorded as a policy refusal with no matched rule',
    auditOf(broken)[0]?.origin === 'policy' && auditOf(broken)[0]?.matchedRules?.length === 0, JSON.stringify(auditOf(broken)[0]))
}

console.log('the auto reviewer is its own origin')
{
  // An ungranted path, and a rules file of its own: a stored rule would answer
  // before the reviewer is ever consulted.
  const file = join(root, 'review.ndjson')
  const where = { ...config, rulesFile: join(root, 'review-rules.json'), auditFile: file }
  const pendings = store.createPendingStore()
  // One grant store per gate: an ALLOW leaves a one-shot grant behind, and the
  // next call in the session would wait for a holder that never settles.
  const grants = store.createGrantStore()
  const gate = host.createGate({
    engine: host.createEngine({ config: where, home: HOME, grants, pendings, ctx }),
    pendings,
    logger,
    config: where,
    grants,
    reviewer: { enabled: true, review: () => Promise.resolve({ verdict: 'ALLOW', reason: 'the user asked for it', latencyMs: 12, route: 'deepseek/test' }) },
  })
  await gate(exec('rm -rf unopened', { callId: 'r1' }), next)
  const records = auditOf(file)
  check('one call produces exactly one audit record', records.length === 1, JSON.stringify(records))
  check('an auto-review allow is recorded as its own origin',
    records[0]?.origin === 'auto-review' && records[0]?.decision === 'allow', JSON.stringify(records[0]))
  check('with the verdict, the reason, the latency, and the route',
    records[0]?.review?.verdict === 'ALLOW' && records[0]?.review?.latencyMs === 12 && records[0]?.review?.route === 'deepseek/test',
    JSON.stringify(records[0]?.review))

  const deferred = join(root, 'deferred.ndjson')
  const deferredPendings = store.createPendingStore()
  const deferredGrants = store.createGrantStore()
  const askGate = host.createGate({
    engine: host.createEngine({ config: { ...where, auditFile: deferred }, home: HOME, grants: deferredGrants, pendings: deferredPendings, ctx }),
    pendings: deferredPendings,
    logger,
    config: { ...where, auditFile: deferred },
    grants: deferredGrants,
    reviewer: { enabled: true, review: () => Promise.resolve({ verdict: 'ASK', reason: 'not clear enough', latencyMs: 8, route: 'deepseek/test' }) },
  })
  const asked = await askGate(exec('rm -rf unopened', { callId: 'r2' }), next)
  check('an ASK still reaches the card', asked?.kind === 'ask', JSON.stringify(asked))
  const deferredRecords = auditOf(deferred)
  check('and leaves one record that says the reviewer deferred',
    deferredRecords.length === 1 && deferredRecords[0].review?.verdict === 'ASK'
    && deferredRecords[0].decision === 'prompt', JSON.stringify(deferredRecords))

  const off = join(root, 'review-off.ndjson')
  const offGate = host.createGate({
    engine: host.createEngine({ config: { ...where, auditFile: off }, home: HOME, grants: store.createGrantStore(), pendings: store.createPendingStore(), ctx }),
    pendings: store.createPendingStore(),
    logger,
    config: { ...where, auditFile: off },
    grants: store.createGrantStore(),
  })
  await offGate(exec('rm -rf unopened', { callId: 'r3' }), next)
  check('with the reviewer off the one record is the policy decision',
    auditOf(off).length === 1 && auditOf(off)[0].origin === 'baseline' && auditOf(off)[0].review === undefined, JSON.stringify(auditOf(off)))
}

console.log('what the user clicked')
{
  const file = join(root, 'human.ndjson')
  const where = { ...config, auditFile: file }
  const pendings = store.createPendingStore()
  const grants = store.createGrantStore()
  const decisions = store.createDecisionLog()
  const gate = host.createGate({
    engine: host.createEngine({ config: where, home: HOME, grants, pendings, ctx }),
    pendings,
    logger,
    config: where,
  })
  const approval = host.createApprovalListener({
    engine: host.createEngine({ config: where, home: HOME, grants, pendings, ctx }),
    pendings,
    logger,
    config: where,
    decisions,
  })
  const onceHandler = host.createOnceHandler({ pendings, grants, logger, decisions })
  const rememberHandler = host.createRememberHandler({ pendings, config: where, logger, decisions })

  // "allow once": the card grants through the route and then settles the approval.
  await gate(exec('rm -rf one', { callId: 'h1' }), next)
  let answer = await call(onceHandler, post('/dsh-allow/once', { sessionId: 's1', callId: 'h1' }))
  check('the once route still grants', answer.status === 200 && answer.json.ok === true, JSON.stringify(answer.json))
  const settled = await approval({ agent: { session: sessionOf('s1') }, callId: 'h1' }, () => Promise.resolve('allowed-once'))
  check('the approval outcome passes through unchanged', settled === 'allowed-once', String(settled))
  const onceRecord = humanRecordOf(file, 'h1')
  check('recorded as a human allow-once with the command it answered',
    onceRecord?.action === 'allow-once' && onceRecord?.command === 'rm -rf one', JSON.stringify(recordsOf(file, 'h1')))

  // "always allow": the route writes the rule and the note carries its label.
  await gate(exec('rm -rf two', { callId: 'h2' }), next)
  answer = await call(rememberHandler, post('/dsh-allow/remember', { sessionId: 's1', callId: 'h2' }))
  check('the remember route still writes the rule', answer.status === 200 && answer.json.ok === true, JSON.stringify(answer.json))
  await approval({ agent: { session: sessionOf('s1') }, callId: 'h2' }, () => Promise.resolve('allowed-once'))
  const alwaysRecord = humanRecordOf(file, 'h2')
  check('one call, one always-allow record', recordsOf(file, 'h2').filter(entry => entry.origin === 'human').length === 1,
    JSON.stringify(recordsOf(file, 'h2')))
  check('and it names the rules the button wrote',
    alwaysRecord?.action === 'always-allow' && alwaysRecord?.rules?.length === 1
    && alwaysRecord.rules[0].path === `${WORKSPACE}/two`, JSON.stringify(alwaysRecord))

  // A rejection settles through the built-in card: no route, no note.
  await gate(exec('rm -rf three', { callId: 'h3' }), next)
  const rejected = await approval({ agent: { session: sessionOf('s1') }, callId: 'h3' }, () => Promise.resolve('rejected'))
  check('a rejection passes through unchanged', rejected === 'rejected', String(rejected))
  const rejectedRecord = humanRecordOf(file, 'h3')
  check('and is recorded as a human refusal',
    rejectedRecord?.action === 'deny' && rejectedRecord?.decision === 'forbidden', JSON.stringify(recordsOf(file, 'h3')))
  check('with the prompt that preceded it still in the log',
    recordsOf(file, 'h3').some(entry => entry.origin === 'baseline' && entry.decision === 'prompt'), JSON.stringify(recordsOf(file, 'h3')))
  check('with the pending record dropped', pendings.get('s1', 'h3') === null)
  check('and the note store left empty', decisions.size() === 0, String(decisions.size()))

  for (const [outcome, action] of [['cancelled', 'cancelled'], ['unavailable', 'unavailable']]) {
    await gate(exec(`rm -rf ${outcome}`, { callId: `h-${outcome}` }), next)
    await approval({ agent: { session: sessionOf('s1') }, callId: `h-${outcome}` }, () => Promise.resolve(outcome))
    const record = humanRecordOf(file, `h-${outcome}`)
    check(`an ${outcome} approval is recorded`, record?.action === action, JSON.stringify(recordsOf(file, `h-${outcome}`)))
  }

  // A foreign approval this plugin never judged leaves no line at all.
  const before = auditOf(file).length
  await approval({ agent: { session: sessionOf('s9') }, callId: 'foreign' }, () => Promise.resolve('allowed-once'))
  check('a foreign approval records nothing', auditOf(file).length === before, String(auditOf(file).length))

  // A listener that answers with its own decision object is not a human outcome.
  await gate(exec('rm -rf four', { callId: 'h4' }), next)
  await approval({ agent: { session: sessionOf('s1') }, callId: 'h4' }, () => Promise.resolve({ kind: 'allow' }))
  check('an unrecognized outcome records no human decision', humanRecordOf(file, 'h4') === undefined, JSON.stringify(recordsOf(file, 'h4')))
  check('and leaves the card able to address it', pendings.get('s1', 'h4') !== null)

  // The settle listener is the last moment a note is still attributable.
  await gate(exec('rm -rf five', { callId: 'h5' }), next)
  await call(onceHandler, post('/dsh-allow/once', { sessionId: 's1', callId: 'h5' }))
  const settle = host.createSettleListener({ grants, logger, pendings, decisions, config: where })
  await settle(exec('rm -rf five', { callId: 'h5' }), { kind: 'accepted' }, next)
  const settledRecord = humanRecordOf(file, 'h5')
  check('a note no approval consumed is recorded when the call settles',
    settledRecord?.action === 'allow-once', JSON.stringify(recordsOf(file, 'h5')))

  // Auditing off means no line, whichever layer decided.
  const silent = join(root, 'silent.ndjson')
  const offConfig = { ...where, auditFile: silent, audit: false }
  const offDecision = store.createDecisionLog()
  const offPendings = store.createPendingStore()
  const offGrants = store.createGrantStore()
  const offEngine = host.createEngine({ config: offConfig, home: HOME, grants: offGrants, pendings: offPendings, ctx })
  const offGate = host.createGate({ engine: offEngine, pendings: offPendings, logger, config: offConfig })
  const offApproval = host.createApprovalListener({ engine: offEngine, pendings: offPendings, logger, config: offConfig, decisions: offDecision })
  await offGate(exec('rm -rf six', { callId: 'h6' }), next)
  await offApproval({ agent: { session: sessionOf('s1') }, callId: 'h6' }, () => Promise.resolve('rejected'))
  check('audit: false writes nothing, wherever the decision came from', auditOf(silent).length === 0, JSON.stringify(auditOf(silent)))
}

console.log('decision log')
{
  const decisions = store.createDecisionLog({ limit: 2 })
  check('a note without a call id is refused', decisions.note('s1', undefined, { action: 'allow-once' }) === false)
  decisions.note('s1', 'a', { action: 'allow-once' })
  check('a note is readable before it is taken', decisions.peek('s1', 'a')?.action === 'allow-once')
  check('taking it clears it', decisions.take('s1', 'a')?.action === 'allow-once' && decisions.peek('s1', 'a') === null)
  decisions.note('s1', 'b', { action: 'allow-once' })
  decisions.note('s1', 'c', { action: 'deny' })
  decisions.note('s1', 'd', { action: 'deny' })
  check('the oldest note is dropped past the cap', decisions.size() === 2 && decisions.peek('s1', 'b') === null)
  check('and another session is unaffected', decisions.peek('s2', 'd') === null)
}

console.log('reading the log from its end')
{
  const file = join(root, 'tail.ndjson')
  const write = (count, sessionId, origin) => {
    const lines = []
    for (let index = 0; index < count; index += 1) {
      lines.push(JSON.stringify({ at: `2026-01-01T00:00:${String(index % 60).padStart(2, '0')}.000Z`, sessionId, origin, decision: 'allow', index, pad: 'x'.repeat(200) }))
    }
    appendFileSync(file, `${lines.join('\n')}\n`)
  }
  check('a missing file reads as no records', store.readAuditTail(join(root, 'nope.ndjson')).entries.length === 0)
  check('and a null path too', store.readAuditTail(null).entries.length === 0)
  write(5, 's1', 'baseline')
  check('baseline allows are hidden by default',
    store.readAuditTail(file, { sessionId: 's1' }).entries.length === 0)
  check('and shown on request',
    store.readAuditTail(file, { sessionId: 's1', includeBaseline: true }).entries.length === 5)
  write(4, 's2', 'rule')
  check('another session is filtered out',
    store.readAuditTail(file, { sessionId: 's2' }).entries.length === 4)
  check('the newest records come first in the file and last in the answer',
    store.readAuditTail(file, { sessionId: 's2' }).entries.at(-1)?.index === 3,
    JSON.stringify(store.readAuditTail(file, { sessionId: 's2' }).entries.map(r => r.index)))
  check('a smaller limit keeps the newest',
    store.readAuditTail(file, { sessionId: 's2', limit: 2 }).entries.map(r => r.index).join(',') === '2,3')

  // The reader walks backwards across chunk boundaries: the pad above makes the
  // file larger than one 256 KiB chunk, so the first chunk alone cannot answer.
  const big = join(root, 'big.ndjson')
  const record = `${JSON.stringify({ sessionId: 's3', origin: 'rule', decision: 'allow', pad: 'y'.repeat(500) })}\n`
  writeFileSync(big, record.repeat(2))
  appendFileSync(big, `${JSON.stringify({ sessionId: 's3', origin: 'rule', decision: 'allow', marker: 'newest' })}\n`)
  const bigAnswer = store.readAuditTail(big, { sessionId: 's3', limit: 10_000 })
  check('a file larger than one chunk is read whole', bigAnswer.entries.length === 3, String(bigAnswer.entries.length))
  check('and its newest record is the last one', bigAnswer.entries.at(-1)?.marker === 'newest', JSON.stringify(bigAnswer.entries.at(-1)))
  check('a full answer from a larger file is not truncated', bigAnswer.truncated === false, JSON.stringify(bigAnswer))
  check('and it reports how much it read', bigAnswer.scannedBytes > 0, String(bigAnswer.scannedBytes))

  // A half-written trailing line is not a decision.
  const partial = join(root, 'partial.ndjson')
  writeFileSync(partial, `${JSON.stringify({ sessionId: 's4', origin: 'rule' })}\n{"sessionId":"s4","origin":"ru`)
  check('a half-written last line is dropped',
    store.readAuditTail(partial, { sessionId: 's4' }).entries.length === 1)
  check('and a blank line is not an entry',
    store.readAuditTail(`${partial}`, { sessionId: 's4', limit: 10 }).entries.length === 1)
  writeFileSync(partial, '\n\n\n')
  check('a file of blank lines answers nothing', store.readAuditTail(partial, { sessionId: 's4' }).entries.length === 0)
}

console.log('the audit route')
{
  const file = join(root, 'route.ndjson')
  const where = { ...config, auditFile: file }
  const handler = host.createAuditHandler({ config: where, logger })
  rmSync(file, { force: true })
  mkdirSync(dirname(file), { recursive: true })
  for (const [sessionId, origin, action] of [['s1', 'baseline', null], ['s1', 'rule', null], ['s1', 'human', 'allow-once'], ['s2', 'rule', null]]) {
    appendFileSync(file, `${JSON.stringify({ at: '2026-01-01T00:00:00.000Z', sessionId, origin, action, decision: 'allow', command: 'ls', tool: 'bash' })}\n`)
  }
  let answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1' }))
  check('the route answers', answer.status === 200 && answer.json.ok === true, JSON.stringify(answer.json))
  check('with the session\'s non-baseline records',
    answer.json.entries.length === 2 && answer.json.entries.every(entry => entry.sessionId === 's1'),
    JSON.stringify(answer.json.entries))
  check('and the shape the tab renders',
    answer.json.entries.at(-1)?.origin === 'human' && answer.json.entries.at(-1)?.action === 'allow-once'
    && answer.json.entries.at(-1)?.matchedRules?.length === 0, JSON.stringify(answer.json.entries.at(-1)))
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1&baseline=1' }))
  check('the baseline flag includes platform allows', answer.json.entries.length === 3, JSON.stringify(answer.json.entries.length))
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s2' }))
  check('another session sees only its own', answer.json.entries.length === 1 && answer.json.entries[0].sessionId === 's2')
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1&limit=1' }))
  check('the limit keeps the newest', answer.json.entries.length === 1 && answer.json.entries[0].action === 'allow-once', JSON.stringify(answer.json.entries))
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1&limit=99999' }))
  check('the limit is clamped to the route maximum', answer.json.limit === 500, String(answer.json.limit))
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1&limit=nonsense' }))
  check('a nonsense limit falls back to the default', answer.json.limit === 200, String(answer.json.limit))
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=unknown' }))
  check('an unknown session answers an empty list', answer.json.entries.length === 0)
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1', remoteAddress: '10.0.0.9' }))
  check('a non-loopback read is refused', answer.status === 403)
  answer = await call(handler, fakeRequest({ url: '/dsh-allow/audit', method: 'POST' }))
  check('a write method is refused', answer.status === 405)
  const empty = host.createAuditHandler({ config: { ...where, auditFile: join(root, 'none.ndjson') }, logger })
  answer = await call(empty, fakeRequest({ url: '/dsh-allow/audit?sessionId=s1' }))
  check('a missing log answers an empty list', answer.status === 200 && answer.json.entries.length === 0)
}

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
