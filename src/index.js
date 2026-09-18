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
import {
  addRule, appendAudit, clearRules, countHit, createGrantStore, createPendingStore, readRules,
  removeRule, resolveConfig, resolveHome,
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
   * @param request - the call, the command, its cwd, and whether to stay silent.
   * @returns the decision plus the context it was made in.
   */
  const decide = ({ exec, command, cwd, silent = false }) => {
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
    if (config.audit && !silent) {
      appendAudit(config.auditFile, {
        tool: exec?.name ?? 'unknown',
        cwd,
        command,
        decision: decision.decision,
        reason: decision.reason,
        mode: policy?.mode ?? null,
        workspaceRoot,
        effects: decision.effects.map(effect => ({ operation: effect.operation, path: effect.path })),
        missing: decision.missing.map(entry => ({ operation: entry.operation, path: entry.path })),
        unknown: decision.unknown.map(entry => entry.reason),
      })
    }
    return { decision, policy, workspaceRoot }
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
 * @param options - the engine, the pending store, the configuration, the session
 *   grants, and the logger.
 * @returns the waterfall listener.
 */
export function createGate({ engine, pendings, logger, config = null, grants = null }) {
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
      return {
        kind: 'deny',
        reason: `dsh-allow refused this call: ${refusal}. The permission store is not something the agent may change; ask the user to run /allow instead.`,
      }
    }
    const cwd = cwdOf(exec)
    const context = engine.decide({ exec, command, cwd })
    const { decision } = context
    if (decision.decision === 'allow') return next()
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
 * The settle listener: "allow once" is spent by the call it was given to.
 * @param options - the session-grant store and the logger.
 * @returns the waterfall listener.
 */
export function createSettleListener({ grants, logger }) {
  return async (exec, result, next) => {
    const dropped = grants.consume(exec?.agent?.session?.id, exec?.callId)
    if (dropped > 0) logger.info(`dsh-allow: released ${String(dropped)} one-shot grant(s) after call ${String(exec?.callId)}`)
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
 * @param options - the engine, the pending store, and the logger.
 * @returns the waterfall listener.
 */
export function createApprovalListener({ engine, pendings, logger }) {
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
    const exec = { name: 'bash', callId, agent: request.agent }
    const context = engine.decide({ exec, command, cwd, silent: true })
    const { decision } = context
    if (decision.decision === 'forbidden') {
      logger.warn(`dsh-allow: rejected the escalation for ${JSON.stringify(command.slice(0, 80))} — ${decision.reason}`)
      return 'rejected'
    }
    logger.info(`dsh-allow: sending the escalation for ${JSON.stringify(command.slice(0, 80))} to the card — a wider process fence is not the policy's to grant`)
    remember(pendings, { callId, agent: request.agent }, context, command, cwd)
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
      // One button, and exactly the narrowest rules it named: no folder is
      // opened behind the user's back.
      const stored = suggestions.map(suggestion => addRule(config.rulesFile, {
        path: suggestion.path,
        recursive: suggestion.recursive,
        access: suggestion.access,
      }))
      const labels = stored.map(describeRule)
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
 * @param options - pending store, the session grant store, and logger.
 * @returns a Web-host route handler.
 */
export function createOnceHandler({ pendings, grants, logger }) {
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
  // The process fence is refined before anything can be judged against it, so
  // the first decision already knows what the kernel enforces.
  const enforcement = createEnforcer({ config, grants, logger: ctx.logger })
  ctx.effect(() => {
    enforcement.install(ctx)
    return () => { enforcement.uninstall() }
  }, 'dsh-allow: process fence')
  const engine = createEngine({ config, home, grants, pendings, ctx, enforcement })
  const gate = createGate({ engine, pendings, logger: ctx.logger, config, grants })
  // Ahead of every other pre-execute listener: a protected path must be refused
  // before any other policy can allow it.
  ctx.on('tools/pre-execute', (exec, next) => gate(exec, next), { prepend: true })
  const approvalListener = createApprovalListener({ engine, pendings, logger: ctx.logger })
  ctx.on('approval/request', (request, next) => approvalListener(request, next), { prepend: true })
  const settleListener = createSettleListener({ grants, logger: ctx.logger })
  ctx.on('tools/post-execute', (exec, result, next) => settleListener(exec, result, next), { prepend: true })
  const pendingHandler = createPendingHandler({ pendings })
  const rememberHandler = createRememberHandler({ pendings, config, logger: ctx.logger })
  const onceHandler = createOnceHandler({ pendings, grants, logger: ctx.logger })
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
