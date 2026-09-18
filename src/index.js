/**
 * dsh-allow — host half.
 *
 * A deterministic approval layer over shell tool calls, evaluated before
 * anything executes:
 *
 *   model writes a command
 *     → tools/pre-execute gate: parse, classify, match stored rules
 *     → allow: continue to the sandbox (which remains the write fence)
 *       prompt: raise the approval card (allow once / always allow / deny)
 *       forbidden: deny outright, no escalation possible
 *
 * The gate consults the policy engine in `./policy.js`; the card consults this
 * process through two loopback routes, because the browser knows only the tool
 * name and call id. `always allow` stores the narrow structured rule the engine
 * suggested, never the raw command line.
 */
import { homedir } from 'node:os'
import { basename } from 'node:path'
import { describeRule, evaluateCommandLine } from './policy.js'
import {
  addRule, appendAudit, clearRules, countHit, createPendingStore, readRules, removeRule, resolveConfig, resolveHome,
} from './store.js'

/** Stable Cordis plugin name. */
export const name = 'dsh-allow'

/** Tools whose call carries a shell command line. */
const SHELL_TOOLS = new Set(['bash', 'pwsh'])

/** Marks a policy-layer approval reason, so the card claims it. */
export const POLICY_REASON_PREFIX = 'dsh-allow: '

/** How many trailing session events one tool-call lookup scans. */
const MAX_SCAN_EVENTS = 2000

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
 * Record one decision in the pending store, when the call can address it.
 * @param pendings - the pending store.
 * @param exec - the pending call.
 * @param decision - the engine's decision.
 * @param command - the raw command.
 * @param cwd - the effective cwd.
 * @returns whether a record was written.
 */
function remember(pendings, exec, decision, command, cwd) {
  const sessionId = exec?.agent?.session?.id
  const callId = exec?.callId
  if (typeof callId !== 'string') return false
  pendings.remember(sessionId, callId, {
    command,
    cwd,
    decision: decision.decision,
    reason: decision.reason,
    risk: decision.risk,
    analyzable: decision.analyzable,
    label: decision.suggestion === null ? null : describeRule(decision.suggestion),
    labels: decision.suggestions.map(describeRule),
    suggestions: decision.suggestions,
    partial: decision.partial === true,
    exact: decision.suggestions.length > 0 && decision.suggestions.every(rule => rule.exact === true),
    triggers: decision.triggers.map(trigger => trigger.command),
  })
  return true
}

/**
 * Evaluate one command line against the stored rules and audit the outcome.
 * @param options - configuration, home, the call, command, and cwd.
 * @returns the engine's decision.
 */
export function decide({ config, home, exec, command, cwd, silent = false }) {
  const rules = readRules(config.rulesFile)
  const decision = evaluateCommandLine({
    command, cwd, home, rules, defaultDecision: config.defaultDecision, allowForbiddenSource: config.allowForbiddenSource,
  })
  // A silent re-judgement (the escalation listener) must not count a use.
  if (!silent) {
    for (const rule of decision.matchedRules) {
      if (rule.decision === 'allow') countHit(config.rulesFile, rule.id)
    }
  }
  if (config.audit && !silent) {
    appendAudit(config.auditFile, {
      tool: exec?.name ?? 'unknown',
      cwd,
      command,
      commands: decision.commands,
      decision: decision.decision,
      reason: decision.reason,
      risk: decision.risk,
      analyzable: decision.analyzable,
      matchedRules: decision.matchedRules.map(rule => ({
        id: rule.id, decision: rule.decision, executable: rule.executable, argvPrefix: rule.argvPrefix,
      })),
    })
  }
  return decision
}

/**
 * The `tools/pre-execute` gate.
 * @param options - configuration, home, logger, and the pending store.
 * @returns the waterfall listener.
 */
export function createGate({ config, home, logger, pendings }) {
  return async (exec, next) => {
    const command = commandOf(exec)
    if (command === null) return next()
    const cwd = cwdOf(exec)
    const decision = decide({ config, home, exec, command, cwd })
    if (decision.decision === 'allow') return next()
    remember(pendings, exec, decision, command, cwd)
    const headline = decision.triggers[0]?.command ?? command
    if (decision.decision === 'forbidden') {
      logger.warn(`dsh-allow: denied ${JSON.stringify(headline)} — ${decision.reason}`)
      return {
        kind: 'deny',
        reason: `dsh-allow refused this command: ${decision.reason}. Do not retry it, and do not look for another way to perform the same operation.`,
      }
    }
    logger.info(`dsh-allow: asking about ${JSON.stringify(headline)} — ${decision.reason}`)
    // The prefix is the card's marker: it tells the client this prompt belongs
    // to the policy layer, so the card can offer its rule button.
    return { kind: 'ask', reason: `${POLICY_REASON_PREFIX}${decision.reason} (${headline})` }
  }
}

/**
 * The approval listener: give an escalation that skipped the gate a pending
 * record of its own, then let the card answer it.
 * @param options - configuration, home, and the pending store.
 * @returns the waterfall listener.
 */
export function createApprovalListener({ config, home, pendings, logger }) {
  return async (request, next) => {
    const sessionId = request?.agent?.session?.id
    const callId = request?.callId
    if (typeof callId !== 'string') return next()
    // The gate already recorded its own prompt for this call.
    if (pendings.get(sessionId, callId) !== null) return next()
    const args = toolCallArguments(request?.agent?.session, callId)
    const command = typeof args?.command === 'string' && args.command.trim() !== '' ? args.command : null
    if (command === null) return next()
    const sessionCwd = request?.agent?.session?.header?.cwd
    const cwd = typeof args?.workdir === 'string' && args.workdir !== ''
      ? args.workdir
      : (typeof sessionCwd === 'string' && sessionCwd !== '' ? sessionCwd : process.cwd())
    const decision = decide({ config, home, exec: { name: 'bash', callId }, command, cwd, silent: true })
    if (decision.decision === 'forbidden') {
      logger.warn(`dsh-allow: rejected the escalation for ${JSON.stringify(command.slice(0, 80))} — ${decision.reason}`)
      return 'rejected'
    }
    if (decision.covered && config.autoApproveEscalations !== false) {
      logger.info(`dsh-allow: approved the escalation for ${JSON.stringify(command.slice(0, 80))} — every command in it is remembered`)
      return 'allowed-once'
    }
    remember(pendings, { callId, agent: request.agent }, decision, command, cwd)
    return next()
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
    sendJson(res, 200, {
      ok: true,
      rememberable: (record.suggestions ?? []).length > 0 && record.decision !== 'forbidden',
      label: record.label,
      labels: record.labels ?? [],
      command: record.command,
      cwd: record.cwd,
      reason: record.reason,
      risk: record.risk,
      decision: record.decision,
      triggers: record.triggers,
      partial: record.partial === true,
      exact: record.exact === true,
    })
  }
}

/**
 * The card's "always allow" route.
 * @param options - pending store, configuration, and logger.
 * @returns a Web-host route handler.
 */
export function createRememberHandler({ pendings, config, logger }) {
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
      const stored = suggestions.map(suggestion => addRule(config.rulesFile, suggestion))
      const labels = stored.map(describeRule)
      logger.info(`dsh-allow: remembered ${labels.map(label => `"${label}"`).join(', ')}`)
      sendJson(res, 200, {
        ok: true,
        label: labels.join(' + '),
        labels,
        rules: stored.map(rule => ({ decision: rule.decision, executable: rule.executable, argvPrefix: rule.argvPrefix })),
      })
    }
    catch (error) {
      sendJson(res, 400, { ok: false, error: error instanceof Error ? error.message : String(error) })
    }
  }
}

/**
 * Render the stored rules.
 * @param file - rules-file path.
 * @returns the command's answer text.
 */
export function renderRules(file) {
  const rules = readRules(file)
  if (rules.length === 0) return '还没有记住任何规则。审批卡片上选「总是允许…」就会写入一条。'
  const lines = [`已记住 ${String(rules.length)} 条规则：`]
  for (const [index, rule] of rules.entries()) {
    const hits = Number(rule.hits) || 0
    lines.push(`${String(index + 1)}. ${rule.decision} · ${describeRule(rule)}${hits > 0 ? `（已用 ${String(hits)} 次）` : ''}`)
  }
  lines.push('用 /allow remove <编号> 删除，/allow clear 清空。')
  return lines.join('\n')
}

/**
 * Answer `/allow`.
 * @param file - rules-file path.
 * @param rawInput - text after the command name.
 * @returns the command result.
 */
export function runAllowCommand(file, rawInput) {
  const input = rawInput.trim()
  if (input === '' || input === 'list') return { kind: 'success', text: renderRules(file) }
  const [verb, ...rest] = input.split(/\s+/u)
  if (verb === 'clear') return { kind: 'success', text: `已清空 ${String(clearRules(file))} 条规则。` }
  if (verb === 'remove') {
    const removed = removeRule(file, Number(rest[0]))
    return removed === null
      ? { kind: 'error', text: `用法：/allow remove <编号>（1-${String(readRules(file).length)}）` }
      : { kind: 'success', text: `已删除规则「${describeRule(removed)}」。` }
  }
  if (verb === 'add') {
    const [decision, executable, ...argvPrefix] = rest
    if (!['allow', 'prompt', 'forbidden'].includes(decision) || executable === undefined) {
      return { kind: 'error', text: '用法：/allow add <allow|prompt|forbidden> <程序> [参数前缀…]，例如 /allow add allow git status' }
    }
    try {
      const stored = addRule(file, { decision, executable: basename(executable), argvPrefix })
      return { kind: 'success', text: `已记住：${stored.decision} · ${describeRule(stored)}` }
    }
    catch (error) {
      return { kind: 'error', text: error instanceof Error ? error.message : String(error) }
    }
  }
  return { kind: 'error', text: '用法：/allow [list|add <决策> <程序> [参数…]|remove <编号>|clear]' }
}

/**
 * Wire the gate, the approval listener, the card routes, and `/allow`.
 * @param ctx - Cordis context of this plugin's fiber.
 * @param pluginConfig - plugin configuration from cordis.yml.
 */
export function apply(ctx, pluginConfig) {
  const config = resolveConfig(pluginConfig, resolveHome())
  const home = homedir()
  const pendings = createPendingStore()
  const gate = createGate({ config, home, logger: ctx.logger, pendings })
  // Ahead of every other pre-execute listener: a forbidden command must be
  // denied before any other policy can allow it.
  ctx.on('tools/pre-execute', (exec, next) => gate(exec, next), { prepend: true })
  const approvalListener = createApprovalListener({ config, home, pendings, logger: ctx.logger })
  ctx.on('approval/request', (request, next) => approvalListener(request, next), { prepend: true })
  const pendingHandler = createPendingHandler({ pendings })
  const rememberHandler = createRememberHandler({ pendings, config, logger: ctx.logger })
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
  })
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.effect(() => commandCtx.commands.register({
      name: 'allow',
      description: 'List or change the shell commands that no longer ask for approval',
      input: { hint: '[list|add <decision> <program> [args…]|remove <number>|clear]' },
      handler: invocation => runAllowCommand(config.rulesFile, invocation.rawInput),
    }), 'dsh-allow: /allow command')
  })
}
