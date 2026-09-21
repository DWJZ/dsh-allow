/**
 * dsh-allow — host half.
 *
 * A filesystem permission layer over shell tool calls, evaluated before anything
 * executes:
 *
 *   model writes a command
 *     → tools/pre-execute gate: parse, derive the filesystem effects, resolve
 *       each (path, operation) against the rules
 *     → allow: continue to the sandbox, which keeps fencing the process
 *       prompt: raise the approval card (deny / always allow / allow once)
 *       forbidden: refuse outright — the platform protects that path
 *
 * The card consults this process through three loopback routes, because the
 * browser knows only the session id and call id: `/pending` describes what is
 * missing, `/remember` writes a persistent rule, and `/once` grants the
 * capability for this session only. Nothing here is remembered as command text.
 */
import { homedir } from 'node:os'
import { canonicalPath, describeRule, protectedRefusal } from './fspolicy.js'
import { evaluateCommandLine } from './decide.js'
import { createEnforcer } from './enforce.js'
import { createReviewer } from './reviewer.js'
import {
  addRule, appendAudit, clearRules, countHit, createDecisionLog, createGrantStore, createPendingStore,
  readAuditTail, readRules, removeRule, resolveConfig, resolveHome,
} from './store.js'

/** Stable Cordis plugin name. */
export const name = 'dsh-allow'

/** Tools whose call carries a shell command line. */
const SHELL_TOOLS = new Set(['bash', 'pwsh'])

/** Marks a policy-layer approval reason, so the card claims it. */
export const POLICY_REASON_PREFIX = 'dsh-allow: '

/** How many trailing session events one tool-call lookup scans. */
const MAX_SCAN_EVENTS = 2000

/** Default answer size of the audit route. */
const AUDIT_PAGE = 200

/** Largest answer the audit route will build, however the caller asks. */
const AUDIT_PAGE_MAX = 500

/**
 * Which layer answered one call: a stored rule, the platform baseline, the auto
 * reviewer, or the user. `policy` is the plugin refusing on its own.
 * @param decision - the decision the policy layer reached.
 * @param usedRules - the rules that granted part of the command line.
 * @returns the origin recorded in the audit log.
 */
export function originOf(decision, usedRules = []) {
  if (decision === 'forbidden') return 'policy'
  return usedRules.some(rule => rule?.baseline !== true) ? 'rule' : 'baseline'
}

/**
 * Project the rules that answered one command line into audit-sized records.
 * @param usedRules - the granting rules.
 * @returns one record per rule, without its compiled spelling.
 */
export function matchedRulesOf(usedRules = []) {
  return usedRules.map(rule => ({
    id: rule.id,
    path: rule.path,
    recursive: rule.recursive === true,
    source: rule.source ?? 'user',
    access: rule.access ?? {},
  }))
}

/**
 * The command line one shell tool call carries, or null for other calls.
 * @param exec - the pending tool execution.
 * @returns the raw command, or null.
 */
export function commandOf(exec) {
  if (!SHELL_TOOLS.has(exec?.name)) return null
  const args = exec?.arguments
  if (args === null || typeof args !== 'object') return null
  return typeof args.command === 'string' && args.command.trim() !== '' ? args.command : null
}

/**
 * The working directory one call runs in.
 * @param exec - the pending tool execution.
 * @param fallback - value used when neither the call nor its session names one.
 * @returns the effective cwd.
 */
export function cwdOf(exec, fallback = process.cwd()) {
  const args = exec?.arguments
  if (args !== null && typeof args === 'object' && typeof args.workdir === 'string' && args.workdir !== '') {
    return args.workdir
  }
  const sessionCwd = exec?.agent?.session?.header?.cwd
  return typeof sessionCwd === 'string' && sessionCwd !== '' ? sessionCwd : fallback
}

/**
 * Read the arguments of one logged tool call.
 * @param session - the session that logged the call.
 * @param callId - the call id.
 * @returns the parsed arguments, or null when unavailable.
 */
export function toolCallArguments(session, callId) {
  if (session === undefined || session === null || typeof callId !== 'string') return null
  const end = Number(session.seq)
  if (!Number.isFinite(end)) return null
  const floor = Math.max(0, end - MAX_SCAN_EVENTS)
  for (let seq = end - 1; seq >= floor; seq -= 1) {
    const event = session.eventAt(seq)
    if (event?.type !== 'tool/call' || event.data?.callId !== callId) continue
    try {
      const parsed = JSON.parse(event.data.arguments)
      return typeof parsed === 'object' && parsed !== null ? parsed : null
    }
    catch {
      // A malformed arguments blob carries no command to judge.
      return null
    }
  }
  return null
}

/**
 * Build the decision engine: it resolves the session's sandbox policy, judges
 * one command, and records what it saw.
 * @param options - configuration, harness home, session grants, the pending
 *   store, and the Cordis context (used to read `sandboxPolicy`).
 * @returns the engine.
 */
export function createEngine({ config, home, grants, pendings, ctx = null, enforcement = null }) {
  /**
   * The session's sandbox policy, or null when nothing publishes one. A missing
   * policy means nothing enforces the process, so the engine fails closed.
   */
  const policyOf = (exec) => {
    const service = ctx?.get?.('sandboxPolicy')
    if (service === undefined || service === null) return null
    try {
      return service.resolve({ session: exec?.agent?.session })
    }
    catch {
      // A policy that refuses to resolve is a policy the engine cannot trust.
      return null
    }
  }

  /** What the kernel currently fences, for the opaque-code branch. */
  const fenceState = () => (enforcement === null ? null : enforcement.status())

  /**
   * Judge one command line and record the outcome.
   *
   * The audit record is built here even when `deferAudit` suppresses the write,
   * so the gate that consults the auto reviewer can record the decision it
   * actually took — one record per call, whichever layer answered it.
   * @param request - the call, the command, its cwd, whether to stay silent, and
   *   whether the caller writes the audit record itself.
   * @returns the decision, the context it was made in, and the audit record.
   */
  const decide = ({ exec, command, cwd, silent = false, deferAudit = false }) => {
    const policy = policyOf(exec)
    const workspaceRoot = policy?.workspaceRoot
      ?? (typeof exec?.agent?.session?.header?.cwd === 'string' ? exec.agent.session.header.cwd : cwd)
    const rules = readRules(config.rulesFile)
    const sessionId = exec?.agent?.session?.id
    const decision = evaluateCommandLine({
      command,
      cwd,
      home,
      workspaceRoot,
      harnessHome: config.harnessHome,
      mode: policy?.mode ?? null,
      rules: [...config.grants, ...rules],
      protectedFiles: config.protectedFiles,
      enforcement: fenceState(),
      sessionRules: grants.rulesFor(sessionId, exec?.callId),
    })
    if (!silent) {
      for (const rule of decision.usedRules) {
        if (rule.source === 'user') countHit(config.rulesFile, rule.id)
      }
    }
    const audit = {
      tool: exec?.name ?? 'unknown',
      cwd,
      command,
      decision: decision.decision,
      origin: originOf(decision.decision, decision.usedRules),
      reason: decision.reason,
      mode: policy?.mode ?? null,
      workspaceRoot,
      sessionId: typeof sessionId === 'string' ? sessionId : null,
      callId: typeof exec?.callId === 'string' ? exec.callId : null,
      effects: decision.effects.map(effect => ({ operation: effect.operation, path: effect.path })),
      missing: decision.missing.map(entry => ({ operation: entry.operation, path: entry.path })),
      unknown: decision.unknown.map(entry => entry.reason),
      matchedRules: matchedRulesOf(decision.usedRules),
    }
    if (config.audit && !silent && !deferAudit) appendAudit(config.auditFile, audit)
    return { decision, policy, workspaceRoot, audit }
  }

  return { decide, policyOf }
}

/**
 * Record one decision in the pending store, when the call can address it.
 * @param pendings - the pending store.
 * @param exec - the pending call.
 * @param context - the decision and the workspace it was made in.
 * @param command - the raw command.
 * @param cwd - the effective cwd.
 * @returns whether a record was written.
 */
function remember(pendings, exec, context, command, cwd) {
  const sessionId = exec?.agent?.session?.id
  const callId = exec?.callId
  if (typeof callId !== 'string') return false
  const { decision, workspaceRoot, policy } = context
  pendings.remember(sessionId, callId, {
    sessionId,
    command,
    cwd,
    workspaceRoot,
    mode: policy?.mode ?? null,
    decision: decision.decision,
    reason: decision.reason,
    analyzable: decision.analyzable,
    missing: decision.missing.map(entry => ({ operation: entry.operation, path: entry.path })),
    unknown: decision.unknown.map(entry => entry.reason),
    suggestions: decision.suggestions,
  })
  return true
}

/** Tools whose call names one file to read or change. */
const FILE_TOOLS = Object.freeze({
  write: 'change',
  edit: 'write',
  str_replace_editor: 'write',
})

/**
 * The file one non-shell tool call would change, or null.
 * @param exec - the pending tool execution.
 * @returns the absolute-ish path and the operation, or null.
 */
export function fileTargetOf(exec) {
  const operation = FILE_TOOLS[exec?.name]
  if (operation === undefined) return null
  const args = exec?.arguments
  if (args === null || typeof args !== 'object') return null
  const path = typeof args.path === 'string' ? args.path : (typeof args.file_path === 'string' ? args.file_path : null)
  return path === null || path === '' ? null : { operation, path }
}

/**
 * The `tools/pre-execute` gate.
 *
 * Shell calls go through the whole filesystem policy. File tools only get the
 * protection this policy owns outright — the permission store itself — because
 * the harness's own fence already bounds where they may write; without this,
 * the agent could rewrite its own rules with a file tool.
 *
 * A confinement knows its session but not its call, so while one call holds an
 * "allow once" grant every other call in that session waits for it to settle:
 * that is what keeps a second call from running under the first one's grant.
 * A permission request the policy could not settle goes to the optional auto
 * reviewer first: `ALLOW` becomes the same one-shot grant the card's "allow
 * once" writes and the call proceeds, everything else leaves the card in front
 * of the user.
 * @param options - the engine, the pending store, the configuration, the session
 *   grants, the reviewer, and the logger.
 * @returns the waterfall listener.
 */
export function createGate({ engine, pendings, logger, config = null, grants = null, reviewer = null }) {
  return async (exec, next) => {
    if (grants !== null) await waitForGrantHolder(grants, exec, logger)
    const command = commandOf(exec)
    if (command === null) {
      const target = fileTargetOf(exec)
      if (target === null) return next()
      const path = canonicalPath(target.path, { cwd: cwdOf(exec), home: homedir() })
      const refusal = protectedRefusal(path, target.operation === 'change' ? 'write' : target.operation, config?.protectedFiles ?? [])
      if (refusal === null) return next()
      logger.warn(`dsh-allow: denied a ${String(exec?.name)} of ${path} — ${refusal}`)
      if (config?.audit === true) {
        appendAudit(config.auditFile, {
          tool: exec?.name ?? 'unknown',
          cwd: cwdOf(exec),
          command: null,
          decision: 'forbidden',
          origin: 'policy',
          action: 'deny',
          reason: refusal,
          sessionId: exec?.agent?.session?.id ?? null,
          callId: typeof exec?.callId === 'string' ? exec.callId : null,
          matchedRules: [],
        })
      }
      return {
        kind: 'deny',
        reason: `dsh-allow refused this call: ${refusal}. The permission store is not something the agent may change; ask the user to run /allow instead.`,
      }
    }
    const cwd = cwdOf(exec)
    const reviewing = reviewer !== null && reviewer.enabled === true
    const context = engine.decide({ exec, command, cwd, deferAudit: reviewing })
    const { decision } = context
    if (decision.decision === 'allow') {
      if (reviewing) appendAudit(auditTarget(config), context.audit)
      return next()
    }
    if (decision.decision === 'prompt' && reviewing) {
      const review = await reviewer.review({
        exec,
        command,
        cwd,
        workspace: context.workspaceRoot,
        missing: decision.missing,
      })
      const record = {
        ...context.audit,
        review: {
          verdict: review.verdict,
          reason: review.reason,
          latencyMs: review.latencyMs,
          route: review.route,
        },
      }
      if (review.verdict === 'ALLOW' && decision.suggestions.length > 0 && grants !== null) {
        // The same one-shot grant the card would write: bound to this call,
        // carried into the profile by its command, spent when the call settles.
        grants.grant(exec?.agent?.session?.id, exec?.callId, command, decision.suggestions)
        appendAudit(auditTarget(config), {
          ...record,
          decision: 'allow',
          origin: 'auto-review',
          reason: `auto review allowed this call once: ${review.reason}`,
        })
        logger.info(`dsh-allow: auto review allowed this call once — ${review.reason}`)
        return next()
      }
      appendAudit(auditTarget(config), {
        ...record,
        decision: 'prompt',
        reason: `auto review deferred to the user: ${review.reason}`,
      })
    } else if (reviewing) {
      // The reviewer answers prompts only; a decision it was never asked about
      // still owes the one audit record this layer deferred.
      appendAudit(auditTarget(config), context.audit)
    }
    remember(pendings, exec, context, command, cwd)
    if (decision.decision === 'forbidden') {
      logger.warn(`dsh-allow: denied ${JSON.stringify(command.slice(0, 120))} — ${decision.reason}`)
      return {
        kind: 'deny',
        reason: `dsh-allow refused this command: ${decision.reason}. Do not retry it, and do not look for another way to perform the same operation.`,
      }
    }
    logger.info(`dsh-allow: asking about ${JSON.stringify(command.slice(0, 120))} — ${decision.reason}`)
    // The prefix is the card's marker: it tells the client this prompt belongs
    // to the policy layer, so the card can offer its grant buttons.
    return { kind: 'ask', reason: `${POLICY_REASON_PREFIX}${decision.reason}` }
  }
}

/**
 * Wait while another call in this session holds an "allow once" grant.
 *
 * A confinement is told its session, not its call, so the provider's profile
 * can only match a grant by the command it is about to run. Two calls of the
 * same session overlapped would therefore be one command away from sharing a
 * grant. Serializing them costs a wait that ends when the holder settles (or
 * when the grant expires) and removes the overlap entirely.
 * @param grants - the session-grant store.
 * @param exec - the call about to be judged.
 * @param logger - the plugin logger.
 * @returns a promise that settles when no other call holds a grant.
 */
export async function waitForGrantHolder(grants, exec, logger) {
  const sessionId = exec?.agent?.session?.id
  const callId = exec?.callId
  for (let guard = 0; guard < 8; guard += 1) {
    const holder = grants.holder(sessionId, callId)
    if (holder === null) return
    logger.info(`dsh-allow: waiting for call ${holder} to spend its one-shot grant before judging ${String(callId)}`)
    await grants.released(sessionId, holder)
  }
}

/**
 * The audit file a listener should write to, or null when auditing is off.
 * @param config - resolved plugin configuration, or null.
 * @returns the absolute audit-file path, or null.
 */
function auditTarget(config) {
  if (config === null || config === undefined || config.audit === false) return null
  return config.auditFile ?? null
}

/** The recorded action one approval outcome stands for. */
const OUTCOME_ACTIONS = {
  'allowed-once': 'allow-once',
  rejected: 'deny',
  cancelled: 'cancelled',
  unavailable: 'unavailable',
}

/**
 * What one human action decided, and how the audit log reads it.
 * @param action - the recorded action.
 * @param note - the card's record, or null when it is gone.
 * @returns the decision and its one-line reason.
 */
function describeHumanAction(action, note) {
  const labels = (note?.rules ?? []).map(rule => rule?.label ?? describeRule(rule))
  switch (action) {
    case 'always-allow':
      return {
        decision: 'allow',
        reason: labels.length === 0
          ? 'the user allowed this call and stored a rule'
          : `the user allowed this call and stored ${labels.map(label => `"${label}"`).join(', ')}`,
      }
    case 'allow-once':
      return { decision: 'allow', reason: 'the user allowed this call once' }
    case 'cancelled':
      return { decision: 'forbidden', reason: 'the approval request was cancelled before it was answered' }
    case 'unavailable':
      return { decision: 'forbidden', reason: 'no answerer was available to decide this call' }
    default:
      return { decision: 'forbidden', reason: 'the user rejected this call' }
  }
}

/**
 * Record the one audit line a human decision produces, and drop the state that
 * carried it: the pending record (written by the gate or the escalation
 * listener) and the note the card left (written by `/once` or `/remember`).
 *
 * The callback's action wins over the outcome, because the card reports both —
 * it calls the grant route and then settles the approval as `allowed-once`
 * either way. With neither a pending record nor a note there is nothing this
 * plugin judged, so a foreign approval leaves no line.
 * @param options - configuration, the pending store, and the decision log.
 * @param decision - the session, the call, the outcome, and the tool name.
 * @returns the recorded action, or null when nothing was recorded.
 */
export function settleHumanDecision({ config = null, pendings, decisions = null }, { sessionId, callId, outcome, tool = 'bash' }) {
  if (typeof callId !== 'string') return null
  const note = decisions === null ? null : decisions.peek(sessionId, callId)
  const action = note?.action ?? OUTCOME_ACTIONS[outcome]
  // An outcome this plugin does not answer — a foreign approval, or a waterfall
  // listener that returned its own decision object — leaves both the note and
  // the card's pending record where they are.
  if (action === undefined) return null
  if (decisions !== null) decisions.take(sessionId, callId)
  const pending = pendings.get(sessionId, callId)
  if (pending !== null) pendings.forget(sessionId, callId)
  const record = note ?? pending
  const { decision, reason } = describeHumanAction(action, record)
  appendAudit(auditTarget(config), {
    tool: record?.tool ?? tool,
    cwd: record?.cwd ?? null,
    command: record?.command ?? null,
    decision,
    origin: 'human',
    action,
    reason,
    mode: record?.mode ?? null,
    sessionId: sessionId ?? null,
    callId,
    missing: record?.missing ?? [],
    ...(action === 'always-allow' ? { rules: note?.rules ?? [] } : {}),
  })
  return action
}

/**
 * The settle listener: "allow once" is spent by the call it was given to, and a
 * human decision the approval listener never saw is recorded here instead.
 * @param options - the session-grant store, the pending store, the human-decision
 *   log, the configuration, and the logger.
 * @returns the waterfall listener.
 */
export function createSettleListener({ grants, logger, pendings = null, decisions = null, config = null }) {
  return async (exec, result, next) => {
    const dropped = grants.consume(exec?.agent?.session?.id, exec?.callId)
    if (dropped > 0) logger.info(`dsh-allow: released ${String(dropped)} one-shot grant(s) after call ${String(exec?.callId)}`)
    // A call that ran was allowed by something; when the card answered through a
    // path that never reached the approval listener, this is the last moment
    // that decision is still attributable.
    if (pendings !== null && decisions !== null && decisions.peek(exec?.agent?.session?.id, exec?.callId) !== null) {
      settleHumanDecision(
        { config, pendings, decisions },
        { sessionId: exec?.agent?.session?.id, callId: exec?.callId, outcome: 'allowed-once', tool: exec?.name ?? 'bash' },
      )
    }
    return next()
  }
}

/**
 * The approval listener: an escalation that skipped the gate gets a pending
 * record of its own and reaches the card.
 *
 * A `sandbox_permissions` escalation widens the process fence itself — an
 * approval here is what lets a command run outside the mode the session is in,
 * which is more than the filesystem policy it may also be asking about. It is
 * therefore never answered here: a fully granted command runs without an
 * escalation, and every escalation is a human decision.
 *
 * Every outcome this listener sees is also the moment one human decision
 * becomes knowable — the waterfall's return value is the answer the card sent,
 * and nothing else in this process observes it.
 * @param options - the engine, the pending store, the human-decision log, the
 *   configuration, and the logger.
 * @returns the waterfall listener.
 */
export function createApprovalListener({ engine, pendings, logger, config = null, decisions = null }) {
  const settle = (sessionId, callId, outcome) => settleHumanDecision(
    { config, pendings, decisions },
    { sessionId, callId, outcome, tool: 'bash' },
  )
  return async (request, next) => {
    const sessionId = request?.agent?.session?.id
    const callId = request?.callId
    if (typeof callId !== 'string') return next()
    // The gate already recorded its own prompt for this call, so this listener
    // owns only the outcome. The card's grant routes drop the pending record
    // before they settle the approval, so the note is the second half of the
    // same identity: a call this plugin judged is one it must account for.
    const ours = pendings.get(sessionId, callId) !== null
      || (decisions !== null && decisions.peek(sessionId, callId) !== null)
    if (ours) {
      const outcome = await next()
      settle(sessionId, callId, outcome)
      return outcome
    }
    const args = toolCallArguments(request?.agent?.session, callId)
    const command = typeof args?.command === 'string' && args.command.trim() !== '' ? args.command : null
    if (command === null) return next()
    const sessionCwd = request?.agent?.session?.header?.cwd
    const cwd = typeof args?.workdir === 'string' && args.workdir !== ''
      ? args.workdir
      : (typeof sessionCwd === 'string' && sessionCwd !== '' ? sessionCwd : process.cwd())
    const exec = { name: 'bash', callId, agent: request.agent }
    const context = engine.decide({ exec, command, cwd, silent: true })
    const { decision } = context
    if (decision.decision === 'forbidden') {
      logger.warn(`dsh-allow: rejected the escalation for ${JSON.stringify(command.slice(0, 80))} — ${decision.reason}`)
      return 'rejected'
    }
    logger.info(`dsh-allow: sending the escalation for ${JSON.stringify(command.slice(0, 80))} to the card — a wider process fence is not the policy's to grant`)
    remember(pendings, { callId, agent: request.agent }, context, command, cwd)
    const outcome = await next()
    settle(sessionId, callId, outcome)
    return outcome
  }
}

/**
 * Answer one route with JSON.
 * @param res - the response to own.
 * @param statusCode - HTTP status.
 * @param payload - JSON body.
 */
function sendJson(res, statusCode, payload) {
  const body = JSON.stringify(payload)
  res.writeHead(statusCode, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(body),
  })
  res.end(body)
}

/** Whether a request arrived from this host on loopback. */
function isLoopback(req) {
  const address = req.socket.remoteAddress
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

/**
 * Whether a state-changing request came from this Web host itself.
 * @param req - incoming request.
 * @returns true only for a direct same-origin loopback request.
 */
function sameOriginLoopback(req) {
  if (!isLoopback(req)) return false
  if (req.headers.forwarded !== undefined
    || req.headers['x-forwarded-for'] !== undefined
    || req.headers['x-real-ip'] !== undefined) return false
  const host = req.headers.host
  const origin = req.headers.origin
  if (typeof host !== 'string' || typeof origin !== 'string') return false
  try {
    const parsed = new URL(origin)
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.host === host
  }
  catch {
    // URL() rejects a malformed Origin; an unparseable authority authorizes nothing.
    return false
  }
}

/**
 * Read one JSON request body.
 * @param req - incoming request.
 * @param limit - largest accepted body in bytes.
 * @returns the parsed body.
 */
async function readJsonBody(req, limit = 64 * 1024) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > limit) throw new Error('request body too large')
    chunks.push(chunk)
  }
  if (chunks.length === 0) return {}
  return JSON.parse(Buffer.concat(chunks).toString('utf8'))
}

/** The card's view of one pending decision. */
function pendingPayload(record) {
  return {
    ok: true,
    rememberable: record.decision !== 'forbidden' && (record.suggestions ?? []).length > 0,
    command: record.command,
    cwd: record.cwd,
    reason: record.reason,
    mode: record.mode,
    decision: record.decision,
    missing: (record.missing ?? []).map(entry => ({
      operation: entry.operation,
      path: entry.path ?? '(computed at run time)',
      label: `${entry.operation} ${entry.path ?? entry.command ?? ''}`.trim(),
    })),
    unknown: record.unknown ?? [],
    suggestions: (record.suggestions ?? []).map(suggestion => ({
      label: suggestion.label,
      path: suggestion.path,
      recursive: suggestion.recursive === true,
      access: suggestion.access,
    })),
  }
}

/**
 * The card's read route.
 * @param options - the pending store.
 * @returns a Web-host route handler.
 */
export function createPendingHandler({ pendings }) {
  return (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' })
      res.end()
      return
    }
    if (!isLoopback(req)) {
      sendJson(res, 403, { ok: false, error: 'loopback only' })
      return
    }
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const record = pendings.get(url.searchParams.get('sessionId'), url.searchParams.get('callId'))
    if (record === null) {
      sendJson(res, 404, { ok: false })
      return
    }
    sendJson(res, 200, pendingPayload(record))
  }
}

/**
 * The card's "always allow" route: it writes the persistent rules the user is
 * looking at, and answers with their labels.
 *
 * The route notes what the user clicked instead of writing the audit line
 * itself: the card settles the approval right after, and that is the moment one
 * decision — and one record — is complete.
 * @param options - pending store, the human-decision log, configuration, and logger.
 * @returns a Web-host route handler.
 */
export function createRememberHandler({ pendings, config, logger, decisions = null }) {
  return async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' })
      res.end()
      return
    }
    if (!sameOriginLoopback(req)) {
      sendJson(res, 403, { ok: false, error: 'same-origin loopback only' })
      return
    }
    try {
      const body = await readJsonBody(req)
      const record = pendings.get(body?.sessionId, body?.callId)
      if (record === null) {
        sendJson(res, 404, { ok: false, error: 'this approval is no longer pending' })
        return
      }
      const suggestions = record.suggestions ?? []
      if (suggestions.length === 0 || record.decision === 'forbidden') {
        sendJson(res, 409, { ok: false, error: 'this command cannot be remembered' })
        return
      }
      // One button, and exactly the narrowest rules it named: no folder is
      // opened behind the user's back.
      const stored = suggestions.map(suggestion => addRule(config.rulesFile, {
        path: suggestion.path,
        recursive: suggestion.recursive,
        access: suggestion.access,
      }))
      const labels = stored.map(describeRule)
      if (decisions !== null) {
        decisions.note(body?.sessionId, body?.callId, {
          action: 'always-allow',
          tool: 'bash',
          command: record.command,
          cwd: record.cwd,
          mode: record.mode,
          missing: record.missing ?? [],
          rules: stored.map((rule, index) => ({ ...rule, label: labels[index] })),
        })
      }
      pendings.forget(body?.sessionId, body?.callId)
      logger.info(`dsh-allow: remembered ${labels.map(label => `"${label}"`).join(', ')}`)
      sendJson(res, 200, {
        ok: true,
        label: labels.join(' + '),
        labels,
        rules: stored.map(rule => ({ path: rule.path, recursive: rule.recursive, access: rule.access })),
      })
    }
    catch (error) {
      sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
    }
  }
}

/**
 * The card's "allow once" route: it grants the missing capabilities to this
 * session only, for a bounded time, and never touches the rules file.
 * @param options - pending store, the session grant store, the human-decision
 *   log, and logger.
 * @returns a Web-host route handler.
 */
export function createOnceHandler({ pendings, grants, logger, decisions = null }) {
  return async (req, res) => {
    if (req.method !== 'POST') {
      res.writeHead(405, { allow: 'POST' })
      res.end()
      return
    }
    if (!sameOriginLoopback(req)) {
      sendJson(res, 403, { ok: false, error: 'same-origin loopback only' })
      return
    }
    try {
      const body = await readJsonBody(req)
      const record = pendings.get(body?.sessionId, body?.callId)
      if (record === null) {
        sendJson(res, 404, { ok: false, error: 'this approval is no longer pending' })
        return
      }
      const suggestions = record.suggestions ?? []
      const granted = grants.grant(record.sessionId ?? body?.sessionId, body?.callId, record.command, suggestions)
      if (decisions !== null) {
        decisions.note(body?.sessionId, body?.callId, {
          action: 'allow-once',
          tool: 'bash',
          command: record.command,
          cwd: record.cwd,
          mode: record.mode,
          missing: record.missing ?? [],
        })
      }
      pendings.forget(body?.sessionId, body?.callId)
      logger.info(`dsh-allow: granted ${String(granted.length)} capability rule(s) to call ${String(body?.callId)}`)
      sendJson(res, 200, { ok: true, granted: granted.map(describeRule) })
    }
    catch (error) {
      sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
    }
  }
}

/**
 * The audit route's view of one recorded decision.
 * @param record - one parsed audit-log record.
 * @returns the fields the approval tab renders, with the absent ones explicit.
 */
function auditPayload(record) {
  return {
    at: record.at ?? null,
    tool: record.tool ?? 'unknown',
    command: record.command ?? null,
    cwd: record.cwd ?? null,
    decision: record.decision ?? null,
    origin: record.origin ?? 'legacy',
    action: record.action ?? null,
    reason: record.reason ?? null,
    mode: record.mode ?? null,
    sessionId: record.sessionId ?? null,
    callId: record.callId ?? null,
    effects: record.effects ?? [],
    missing: record.missing ?? [],
    unknown: record.unknown ?? [],
    matchedRules: record.matchedRules ?? [],
    ...(record.review === undefined ? {} : { review: record.review }),
    ...(record.rules === undefined ? {} : { rules: record.rules }),
  }
}

/**
 * The approval tab's read route: the newest decisions of one session, read from
 * the end of the audit log.
 *
 * Read-only and loopback-only, like the card's own routes: it answers what the
 * policy already decided and grants nothing.
 * @param options - configuration and the logger.
 * @returns a Web-host route handler.
 */
export function createAuditHandler({ config, logger }) {
  return (req, res) => {
    if (req.method !== 'GET' && req.method !== 'HEAD') {
      res.writeHead(405, { allow: 'GET, HEAD' })
      res.end()
      return
    }
    if (!isLoopback(req)) {
      sendJson(res, 403, { ok: false, error: 'loopback only' })
      return
    }
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    const sessionId = url.searchParams.get('sessionId')
    const requested = Number(url.searchParams.get('limit'))
    const limit = Number.isFinite(requested) && requested > 0
      ? Math.min(Math.floor(requested), AUDIT_PAGE_MAX)
      : AUDIT_PAGE
    const answer = readAuditTail(config.auditFile, {
      sessionId,
      limit,
      includeBaseline: url.searchParams.get('baseline') === '1',
    })
    logger.info(`dsh-allow: the approval tab read ${String(answer.entries.length)} record(s) for ${sessionId ?? 'every session'}`)
    sendJson(res, 200, {
      ok: true,
      sessionId,
      limit,
      entries: answer.entries.map(auditPayload),
      scannedBytes: answer.scannedBytes,
      truncated: answer.truncated,
    })
  }
}

/**
 * Render the stored rules.
 * @param file - rules-file path.
 * @returns the command's answer text.
 */
export function renderRules(file) {
  const rules = readRules(file)
  const lines = []
  if (rules.length === 0) lines.push('还没有记住任何文件权限。审批卡片上选「总是允许…」就会写入一条。')
  else {
    lines.push(`已记住 ${String(rules.length)} 条文件权限：`)
    for (const [index, rule] of rules.entries()) {
      const hits = Number(rule.hits) || 0
      lines.push(`${String(index + 1)}. ${describeRule(rule)}${hits > 0 ? `（已用 ${String(hits)} 次）` : ''}`)
    }
  }
  lines.push('用 /allow remove <编号> 删除，/allow clear 清空，/allow status 看强制层现状。')
  return lines.join('\n')
}

/**
 * Render what the policy grants by default and what the kernel actually fences.
 * @param options - the workspace root, the resolved sandbox mode, and the
 *   enforcer's status.
 * @returns the command's answer text.
 */
export function renderStatus({ workspaceRoot, mode, enforcement = null }) {
  const status = enforcement ?? { state: 'off', reason: '未安装', capabilities: {} }
  const capabilityLine = ['read', 'write', 'create', 'delete', 'execute']
    .map(operation => `${operation}=${status.capabilities?.[operation] === true ? '内核强制' : '仅命令层'}`)
    .join('  ')
  return [
    `沙箱模式：${mode ?? '未知（无 sandboxPolicy，遇到看不清效果的命令会直接询问）'}`,
    `工作区：${workspaceRoot ?? '未知'}`,
    `进程沙箱：${status.state}（${status.reason}）`,
    `能力：${capabilityLine}`,
    '',
    '默认权限（工作区）：read/write/create/execute 允许，delete 拒绝；临时目录全允许；',
    '工作区外只允许系统路径的 read+execute（/bin /usr/bin /System /usr/lib 等）与 Homebrew 前缀的 read；',
    'harness home（~/.dsh）只读，权限库与审计日志对任何规则都不可写。',
    '',
    '说明：',
    '· 命令层闸门按命令行推导出的效果判定；内核强制是把同一套 FsPolicy 编译成 Seatbelt profile，',
    '  因此 python -c、node -e、子进程都受同一份策略约束。',
    '· state=full 表示五种能力都在内核层；partial 表示 write/create/delete 在内核层，read/execute 只在命令层；',
    '  off 表示没有可用的 Seatbelt 后端（此时看不清效果的命令会直接询问，不会静默放行）。',
  ].join('\n')
}

/**
 * Answer `/allow`.
 * @param options - rules file, workspace root, and the resolved sandbox mode.
 * @param rawInput - text after the command name.
 * @returns the command result.
 */
export function runAllowCommand({ file, workspaceRoot, mode, enforcement = null }, rawInput) {
  const input = rawInput.trim()
  if (input === '' || input === 'list') return { kind: 'success', text: renderRules(file) }
  const [verb, ...rest] = input.split(/\s+/u)
  if (verb === 'status') return { kind: 'success', text: renderStatus({ workspaceRoot, mode, enforcement }) }
  if (verb === 'clear') return { kind: 'success', text: `已清空 ${String(clearRules(file))} 条文件权限。` }
  if (verb === 'remove') {
    const removed = removeRule(file, Number(rest[0]))
    return removed === null
      ? { kind: 'error', text: `用法：/allow remove <编号>（1-${String(readRules(file).length)}）` }
      : { kind: 'success', text: `已删除：${describeRule(removed)}` }
  }
  if (verb === 'add') {
    const [operations, path, scope] = rest
    if (operations === undefined || path === undefined) {
      return { kind: 'error', text: '用法：/allow add <read|write|create|delete|execute>[,…] <路径> [file|folder]，例如 /allow add delete,write build folder' }
    }
    const access = {}
    for (const operation of operations.split(',')) {
      if (!['read', 'write', 'create', 'delete', 'execute'].includes(operation)) {
        return { kind: 'error', text: `未知权限「${operation}」，可用：read write create delete execute` }
      }
      access[operation] = true
    }
    try {
      const stored = addRule(file, {
        path: canonicalPath(path, { cwd: workspaceRoot ?? process.cwd(), home: homedir() }),
        recursive: scope !== 'file',
        access,
      })
      return { kind: 'success', text: `已记住：${describeRule(stored)}` }
    }
    catch (error) {
      return { kind: 'error', text: error instanceof Error ? error.message : String(error) }
    }
  }
  return { kind: 'error', text: '用法：/allow [list|status|add <权限…> <路径> [file|folder]|remove <编号>|clear]' }
}

/**
 * Wire the gate, the approval listener, the card routes, and `/allow`.
 * @param ctx - Cordis context of this plugin's fiber.
 * @param pluginConfig - plugin configuration from cordis.yml.
 */
export function apply(ctx, pluginConfig) {
  const home = homedir()
  const harnessHome = resolveHome()
  const config = { ...resolveConfig(pluginConfig, harnessHome), harnessHome, home }
  const pendings = createPendingStore()
  const grants = createGrantStore({ ttlMs: config.sessionGrantTtlMs })
  const decisions = createDecisionLog()
  // The process fence is refined before anything can be judged against it, so
  // the first decision already knows what the kernel enforces.
  const enforcement = createEnforcer({ config, grants, logger: ctx.logger })
  ctx.effect(() => {
    enforcement.install(ctx)
    return () => { enforcement.uninstall() }
  }, 'dsh-allow: process fence')
  const engine = createEngine({ config, home, grants, pendings, ctx, enforcement })
  const reviewer = createReviewer({
    config,
    logger: ctx.logger,
    llmOf: () => ctx.get('llm'),
  })
  const gate = createGate({ engine, pendings, logger: ctx.logger, config, grants, reviewer })
  // Ahead of every other pre-execute listener: a protected path must be refused
  // before any other policy can allow it.
  ctx.on('tools/pre-execute', (exec, next) => gate(exec, next), { prepend: true })
  const approvalListener = createApprovalListener({ engine, pendings, logger: ctx.logger, config, decisions })
  ctx.on('approval/request', (request, next) => approvalListener(request, next), { prepend: true })
  const settleListener = createSettleListener({ grants, logger: ctx.logger, pendings, decisions, config })
  ctx.on('tools/post-execute', (exec, result, next) => settleListener(exec, result, next), { prepend: true })
  const pendingHandler = createPendingHandler({ pendings })
  const rememberHandler = createRememberHandler({ pendings, config, logger: ctx.logger, decisions })
  const onceHandler = createOnceHandler({ pendings, grants, logger: ctx.logger, decisions })
  const auditHandler = createAuditHandler({ config, logger: ctx.logger })
  ctx.inject(['webServer'], (webCtx) => {
    webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path: '/dsh-allow/pending',
      handler: pendingHandler,
    }), 'dsh-allow: pending route')
    webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path: '/dsh-allow/remember',
      handler: rememberHandler,
    }), 'dsh-allow: remember route')
    webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path: '/dsh-allow/once',
      handler: onceHandler,
    }), 'dsh-allow: once route')
    webCtx.effect(() => webCtx.webServer.register({
      kind: 'exact',
      path: '/dsh-allow/audit',
      handler: auditHandler,
    }), 'dsh-allow: audit route')
  })
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.effect(() => commandCtx.commands.register({
      name: 'allow',
      description: 'List or change the filesystem permissions that no longer ask for approval',
      input: { hint: '[list|status|add <operations> <path> [file|folder]|remove <number>|clear]' },
      handler: invocation => runAllowCommand({
        file: config.rulesFile,
        workspaceRoot: engine.policyOf({ agent: invocation.agent })?.workspaceRoot,
        mode: engine.policyOf({ agent: invocation.agent })?.mode,
        enforcement: enforcement.status(),
      }, invocation.rawInput),
    }), 'dsh-allow: /allow command')
  })
}
