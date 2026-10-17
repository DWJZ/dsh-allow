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
const { Session, SessionId, SESSION_FORMAT_VERSION, pluginRecordOf } = await import('@deepseek-ai/dsh-session')

/** Every plugin record one Session holds, in log order. */
const recordsOf = (target) => Array.from({ length: Number(target.seq) })
  .map((_unused, index) => target.eventAt(index))
  .map(event => (event === undefined ? undefined : pluginRecordOf(event)))
  .filter(record => record !== undefined)

/** One Session carrying the workspace this suite judges commands in. */
const sessionAt = (id) => {
  const sessionId = SessionId(id)
  return Session.create(sessionId, undefined, {
    version: SESSION_FORMAT_VERSION, id: sessionId, createdAt: Date.now(), cwd: CWD, isSeeded: false,
  })
}

/** The decision payloads a Session recorded, oldest first. */
const auditOf = (target) => recordsOf(target).map(record => record.data)

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
  ...store.resolveConfig({ rulesFile: join(root, 'rules.json'), appendSessionEvents: true }, root),
  harnessHome: root,
}
let ledger = sessionAt('ledger')
/** A fresh Session per block, the way each block used a fresh file before. */
const freshLedger = () => { ledger = sessionAt('ledger'); return ledger }
// One real Session backs every fixture: the records are the only ledger, so a stub Session
// would silently swallow them.
const sessionOf = () => ledger
const exec = (command, { callId = 'c1', session = sessionOf('ledger') } = {}) => ({
  name: 'bash',
  callId,
  arguments: { command },
  agent: { session },
})
const ctx = { get: name => (name === 'sandboxPolicy' ? { resolve: () => ({ mode: 'workspace-write', workspaceRoot: WORKSPACE }) } : undefined) }
const next = () => Promise.resolve({ kind: 'allow' })

/** The records one call produced, in order. */
const recordsIn = (target, callId) => auditOf(target).filter(entry => entry.callId === callId)

/** The one decision the user made about a call, or undefined. */
const humanRecordOf = (target, callId) => recordsIn(target, callId).find(entry => entry.origin === 'human')

console.log('who answered a decision')
{
  freshLedger()
    const where = { ...config }
  const pendings = store.createPendingStore()
  const grants = store.createGrantStore()
  const engine = host.createEngine({ config: where, home: HOME, grants, pendings, ctx })
  const gate = host.createGate({ engine, pendings, logger, config: where })

  await gate(exec('ls -la', { callId: 'o1' }), next)
  await gate(exec('rm -rf build', { callId: 'o2' }), next)
  await gate(exec('rm -rf /System/Library/x', { callId: 'o3' }), next)
  const records = auditOf(ledger)
  check('a command the baseline covers is recorded as such',
    records[0]?.origin === 'baseline' && records[0]?.decision === 'allow', JSON.stringify(records[0]))
  check('a prompt the baseline cannot answer is still the baseline\'s',
    records[1]?.origin === 'baseline' && records[1]?.decision === 'prompt', JSON.stringify(records[1]))
  check('a platform-protected path is the policy\'s own refusal',
    records[2]?.origin === 'policy' && records[2]?.decision === 'forbidden', JSON.stringify(records[2]))
  check('every record names its session and call',
    records.every(entry => entry.sessionId === 'ledger' && typeof entry.callId === 'string'), JSON.stringify(records.map(r => [r.sessionId, r.callId])))
  check('a baseline allow matches no user rule', Array.isArray(records[0]?.matchedRules) && records[0].matchedRules.length > 0
    && records[0].matchedRules.every(rule => rule.source === 'system'), JSON.stringify(records[0]?.matchedRules))

  store.addRule(where.rulesFile, { path: `${WORKSPACE}/build`, recursive: true, access: { delete: true } })
  await gate(exec('rm -rf build', { callId: 'o4' }), next)
  const ruled = auditOf(ledger).at(-1)
  check('a stored rule answers as the rule, not the baseline',
    ruled?.origin === 'rule' && ruled?.decision === 'allow', JSON.stringify(ruled))
  check('and the record names the rule that granted it',
    ruled?.matchedRules?.some(rule => rule.path === `${WORKSPACE}/build` && rule.source === 'user' && rule.access.delete === true),
    JSON.stringify(ruled?.matchedRules))

    const brokenGate = host.createGate({
    engine: host.createEngine({ config: { ...config }, home: HOME, grants, pendings: store.createPendingStore(), ctx }),
    pendings: store.createPendingStore(),
    logger,
    config: { ...config },
  })
  const unparseable = await brokenGate(exec('if then fi )))', { callId: 'o5' }), next)
  check('an unparseable line is refused, not crashed on', unparseable?.kind === 'deny', JSON.stringify(unparseable))
  check('and it is recorded as a policy refusal with no matched rule',
    recordsIn(ledger, 'o5')[0]?.origin === 'policy' && recordsIn(ledger, 'o5')[0]?.matchedRules?.length === 0, JSON.stringify(recordsIn(ledger, 'o5')[0]))
}

console.log('the auto reviewer is its own origin')
{
  freshLedger()
  // An ungranted path, and a rules file of its own: a stored rule would answer
  // before the reviewer is ever consulted.
    const where = { ...config, rulesFile: join(root, 'review-rules.json') }
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
  const records = auditOf(ledger)
  check('one call produces exactly one audit record', records.length === 1, JSON.stringify(records))
  check('an auto-review allow is recorded as its own origin',
    records[0]?.origin === 'auto-review' && records[0]?.decision === 'allow', JSON.stringify(records[0]))
  check('with the verdict, the reason, the latency, and the route',
    records[0]?.review?.verdict === 'ALLOW' && records[0]?.review?.latencyMs === 12 && records[0]?.review?.route === 'deepseek/test',
    JSON.stringify(records[0]?.review))

    const deferredPendings = store.createPendingStore()
  const deferredGrants = store.createGrantStore()
  const askGate = host.createGate({
    engine: host.createEngine({ config: { ...where}, home: HOME, grants: deferredGrants, pendings: deferredPendings, ctx }),
    pendings: deferredPendings,
    logger,
    config: { ...where},
    grants: deferredGrants,
    reviewer: { enabled: true, review: () => Promise.resolve({ verdict: 'ASK', reason: 'not clear enough', latencyMs: 8, route: 'deepseek/test' }) },
  })
  const asked = await askGate(exec('rm -rf unopened', { callId: 'r2' }), next)
  check('an ASK still reaches the card', asked?.kind === 'ask', JSON.stringify(asked))
  const deferredRecords = recordsIn(ledger, 'r2')
  check('and leaves one record that says the reviewer deferred',
    deferredRecords.length === 1 && deferredRecords[0].review?.verdict === 'ASK'
    && deferredRecords[0].decision === 'prompt', JSON.stringify(deferredRecords))

    const offGate = host.createGate({
    engine: host.createEngine({ config: { ...where}, home: HOME, grants: store.createGrantStore(), pendings: store.createPendingStore(), ctx }),
    pendings: store.createPendingStore(),
    logger,
    config: { ...where},
    grants: store.createGrantStore(),
  })
  await offGate(exec('rm -rf unopened', { callId: 'r3' }), next)
  check('with the reviewer off the one record is the policy decision',
    recordsIn(ledger, 'r3').length === 1 && recordsIn(ledger, 'r3')[0].origin === 'baseline' && recordsIn(ledger, 'r3')[0].review === undefined, JSON.stringify(recordsIn(ledger, 'r3')))
}

console.log('what the user clicked')
{
  freshLedger()
    const where = { ...config }
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
    grants,
    logger,
    config: where,
    decisions,
  })
  const rememberCall = host.createRememberCall({ pendings, config: where, logger, decisions })

  // "allow once": the card answers the approval, and this listener grants it.
  await gate(exec('rm -rf one', { callId: 'h1' }), next)
  const settled = await approval({ agent: { session: sessionOf(ledger.id) }, callId: 'h1' }, () => Promise.resolve('allowed-once'))
  check('the approval outcome passes through unchanged', settled === 'allowed-once', String(settled))
  const onceRecord = humanRecordOf(ledger, 'h1')
  check('recorded as a human allow-once with the command it answered',
    onceRecord?.action === 'allow-once' && onceRecord?.command === 'rm -rf one', JSON.stringify(recordsIn(ledger, 'h1')))
  check('and the host minted the one-shot grant from its own record',
    grants.rulesFor(ledger.id, 'h1').length === 1, JSON.stringify(grants.rulesFor(ledger.id, 'h1')))

  // "always allow": the command writes the rule and the note carries its label.
  await gate(exec('rm -rf two', { callId: 'h2' }), next)
  const remembered = rememberCall(ledger.id, 'h2')
  check('remembering writes the rule', remembered.ok === true, JSON.stringify(remembered))
  await approval({ agent: { session: sessionOf(ledger.id) }, callId: 'h2' }, () => Promise.resolve('allowed-once'))
  const alwaysRecord = humanRecordOf(ledger, 'h2')
  check('one call, one always-allow record', recordsIn(ledger, 'h2').filter(entry => entry.origin === 'human').length === 1,
    JSON.stringify(recordsIn(ledger, 'h2')))
  check('and it names the rules the button wrote',
    alwaysRecord?.action === 'always-allow' && alwaysRecord?.rules?.length === 1
    && alwaysRecord.rules[0].path === `${WORKSPACE}/two`, JSON.stringify(alwaysRecord))

  // A rejection settles through the built-in card: no route, no note.
  await gate(exec('rm -rf three', { callId: 'h3' }), next)
  const rejected = await approval({ agent: { session: sessionOf(ledger.id) }, callId: 'h3' }, () => Promise.resolve('rejected'))
  check('a rejection passes through unchanged', rejected === 'rejected', String(rejected))
  const rejectedRecord = humanRecordOf(ledger, 'h3')
  check('and is recorded as a human refusal',
    rejectedRecord?.action === 'deny' && rejectedRecord?.decision === 'forbidden', JSON.stringify(recordsIn(ledger, 'h3')))
  check('with the prompt that preceded it still in the log',
    recordsIn(ledger, 'h3').some(entry => entry.origin === 'baseline' && entry.decision === 'prompt'), JSON.stringify(recordsIn(ledger, 'h3')))
  check('with the pending record dropped', pendings.get(ledger.id, 'h3') === null)
  check('and the note store left empty', decisions.size() === 0, String(decisions.size()))

  for (const [outcome, action] of [['cancelled', 'cancelled'], ['unavailable', 'unavailable']]) {
    await gate(exec(`rm -rf ${outcome}`, { callId: `h-${outcome}` }), next)
    await approval({ agent: { session: sessionOf(ledger.id) }, callId: `h-${outcome}` }, () => Promise.resolve(outcome))
    const record = humanRecordOf(ledger, `h-${outcome}`)
    check(`an ${outcome} approval is recorded`, record?.action === action, JSON.stringify(recordsIn(ledger, `h-${outcome}`)))
  }

  // A foreign approval this plugin never judged leaves no line at all.
  const before = auditOf(ledger).length
  await approval({ agent: { session: sessionOf('s9') }, callId: 'foreign' }, () => Promise.resolve('allowed-once'))
  check('a foreign approval records nothing', auditOf(ledger).length === before, String(auditOf(ledger).length))

  // A listener that answers with its own decision object is not a human outcome.
  await gate(exec('rm -rf four', { callId: 'h4' }), next)
  await approval({ agent: { session: sessionOf(ledger.id) }, callId: 'h4' }, () => Promise.resolve({ kind: 'allow' }))
  check('an unrecognized outcome records no human decision', humanRecordOf(ledger, 'h4') === undefined, JSON.stringify(recordsIn(ledger, 'h4')))
  check('and leaves the card able to address it', pendings.get(ledger.id, 'h4') !== null)

  // The settle listener is the last moment a note is still attributable.
  await gate(exec('rm -rf five', { callId: 'h5' }), next)
  rememberCall(ledger.id, 'h5')
  const settle = host.createSettleListener({ grants, logger, pendings, decisions, config: where })
  await settle(exec('rm -rf five', { callId: 'h5' }), { kind: 'accepted' }, next)
  const settledRecord = humanRecordOf(ledger, 'h5')
  check('a note no approval consumed is recorded when the call settles',
    settledRecord?.action === 'always-allow', JSON.stringify(recordsIn(ledger, 'h5')))

  // Auditing off means no line, whichever layer decided.
  const silent = join(root, 'silent.ndjson')
  const offConfig = { ...where, audit: false }
  const offDecision = store.createDecisionLog()
  const offPendings = store.createPendingStore()
  const offGrants = store.createGrantStore()
  const offEngine = host.createEngine({ config: offConfig, home: HOME, grants: offGrants, pendings: offPendings, ctx })
  const offGate = host.createGate({ engine: offEngine, pendings: offPendings, logger, config: offConfig })
  const offApproval = host.createApprovalListener({ engine: offEngine, pendings: offPendings, logger, config: offConfig, decisions: offDecision })
  await offGate(exec('rm -rf six', { callId: 'h6' }), next)
  await offApproval({ agent: { session: sessionOf(ledger.id) }, callId: 'h6' }, () => Promise.resolve('rejected'))
  check('audit: false writes nothing, wherever the decision came from', auditOf(silent).length === 0, JSON.stringify(auditOf(silent)))
}

console.log('decision log')
{
  freshLedger()
  const decisions = store.createDecisionLog({ limit: 2 })
  check('a note without a call id is refused', decisions.note(ledger.id, undefined, { action: 'allow-once' }) === false)
  decisions.note(ledger.id, 'a', { action: 'allow-once' })
  check('a note is readable before it is taken', decisions.peek(ledger.id, 'a')?.action === 'allow-once')
  check('taking it clears it', decisions.take(ledger.id, 'a')?.action === 'allow-once' && decisions.peek(ledger.id, 'a') === null)
  decisions.note(ledger.id, 'b', { action: 'allow-once' })
  decisions.note(ledger.id, 'c', { action: 'deny' })
  decisions.note(ledger.id, 'd', { action: 'deny' })
  check('the oldest note is dropped past the cap', decisions.size() === 2 && decisions.peek(ledger.id, 'b') === null)
  check('and another session is unaffected', decisions.peek('s2', 'd') === null)
}

console.log('a tool operation the rules answer')
{
  freshLedger()
    const where = { ...config, rulesFile: join(root, 'tool-rules.json') }
  const pendings = store.createPendingStore()
  const decisions = store.createDecisionLog()
  const grants = store.createGrantStore()
  const engine = host.createEngine({ config: where, home: HOME, grants, pendings, ctx })
  const approval = host.createApprovalListener({ engine, pendings, grants, logger, config: where, decisions })
  const rememberCall = host.createRememberCall({ pendings, config: where, logger, decisions })
  // The call itself lives in the real Session's log: the gate records into that Session, and
  // a stub would swallow the record.
  const toolCall = (args, callId) => {
    ledger.append('tool/call', { turn: 1, step: 1, callId, name: 'plugin_manager', arguments: JSON.stringify(args) })
    return { agent: { session: ledger }, toolName: 'plugin_manager', callId }
  }

  store.addToolRule(where.rulesFile, { tool: 'plugin_manager', action: 'list_plugins' })
  let cardAsked = 0
  const answered = await approval(toolCall({ action: 'list_plugins' }, 'a1'), () => {
    cardAsked += 1
    return Promise.resolve('allowed-once')
  })
  check('a stored tool rule answers the call without reaching the card',
    answered === 'allowed-once' && cardAsked === 0, `asked=${String(cardAsked)}`)
  const ruleRecord = recordsIn(ledger, 'a1')[0]
  check('the ledger keeps the rule as its origin, with the operation it allowed',
    ruleRecord?.origin === 'rule' && ruleRecord?.decision === 'allow'
    && ruleRecord?.subject === 'plugin_manager list_plugins', JSON.stringify(ruleRecord))
  check('and names the rule itself, with no path it could have granted',
    ruleRecord?.matchedRules?.[0]?.label === 'plugin_manager list_plugins'
    && ruleRecord?.matchedRules?.[0]?.path === undefined, JSON.stringify(ruleRecord?.matchedRules))
  check('a rule-answered tool call is never recorded as a human answer',
    humanRecordOf(ledger, 'a1') === undefined, JSON.stringify(recordsIn(ledger, 'a1')))

  await approval(toolCall({ action: 'set_plugin', target: 'other-plugin', enabled: true }, 'a2'), () => Promise.resolve('allowed-once'))
  const onceRecord = humanRecordOf(ledger, 'a2')
  check('a card-answered tool call is recorded as the human decision it was',
    onceRecord?.action === 'allow-once' && onceRecord?.tool === 'plugin_manager', JSON.stringify(recordsIn(ledger, 'a2')))
  check('and the tool call mints no filesystem capability',
    grants.rulesFor(ledger.id, 'a2').length === 0 && grants.holder('s1', 'a9') === null)

  let remembered = null
  await approval(toolCall({ action: 'install_bundle', target: 'pkg@1.0.0' }, 'a3'), () => {
    remembered = rememberCall(ledger.id, 'a3')
    return Promise.resolve('allowed-once')
  })
  check('the card\'s always-allow stores the tool rule it named',
    remembered?.ok === true && store.readToolRules(where.rulesFile).some(rule => rule.target === 'pkg@1.0.0'),
    JSON.stringify(remembered))
  const alwaysRecord = humanRecordOf(ledger, 'a3')
  check('and records one always-allow naming that rule',
    alwaysRecord?.action === 'always-allow'
    && alwaysRecord?.rules?.[0]?.label === 'plugin_manager install_bundle pkg@1.0.0', JSON.stringify(recordsIn(ledger, 'a3')))

  // A call the plugin refuses to answer at all still reaches the card, and the
  // record says so instead of inventing a rule.
  const blocked = await approval(toolCall({ action: 'set_version_exemption', target: 'pkg@1.0.0', acceptRisk: true }, 'a4'), () => Promise.resolve('allowed-once'))
  check('a blocked tool call reaches the card and records the human answer',
    blocked === 'allowed-once' && humanRecordOf(ledger, 'a4')?.action === 'allow-once'
    && !store.readToolRules(where.rulesFile).some(rule => rule.action === 'set_version_exemption'),
    JSON.stringify(recordsIn(ledger, 'a4')))
}

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
