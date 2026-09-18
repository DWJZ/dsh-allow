/**
 * dsh-allow — host half.
 *
 * Remembers sandbox-escalation approvals, so a command the user already
 * allowed stops asking. It hooks the `approval/request` waterfall ahead of the
 * interactive answerer:
 *
 * - A request whose logged tool call asks for `sandbox_permissions` (the
 *   sandbox-escalation shape) is matched against the stored rules.
 * - A hit allows the call without asking anyone.
 * - A miss asks the user with three answers: allow once, always allow this
 *   command prefix, or reject. "Always" stores a rule first, then allows.
 * - Every other approval request is delegated unchanged.
 *
 * A rule is scoped by tool, requested sandbox mode, and the command's leading
 * words, so allowing `pnpm dsh plugin` never allows `rm`. Rules live in
 * `$DSH_HOME/dsh-allow.json` and are managed with `/allow`.
 */
import { mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** Stable Cordis plugin name. */
export const name = 'dsh-allow'

/** Default rules-file name below the harness home. */
const RULES_FILE_NAME = 'dsh-allow.json'

/** How many trailing session events one lookup scans for the tool call. */
const MAX_SCAN_EVENTS = 2000

/** Longest command prefix a rule may store. */
const MAX_PREFIX_WORDS = 4

/** Answer labels the plugin owns (built per question so "always" can name the rule). */
const ALLOW_ONCE = '允许一次'
const REJECT = '拒绝'

/**
 * Resolve the harness home: `$DSH_HOME` when set, otherwise `~/.dsh`.
 * @param env - environment to read.
 * @returns the absolute harness home.
 */
export function resolveHome(env = process.env) {
  const configured = env.DSH_HOME
  if (typeof configured === 'string' && configured.trim() !== '') return configured.trim()
  return join(homedir(), '.dsh')
}

/**
 * Reduce a shell command to the stable leading words a rule can match.
 *
 * Leading `cd … &&` chains and `VAR=value` assignments are dropped, then words
 * are kept until the first flag, path, assignment, or shell operator. The
 * result is what the dialog shows the user, so it stays short and readable.
 * @param command - the raw shell command.
 * @returns the prefix, or an empty string when nothing usable remains.
 */
export function commandPrefix(command) {
  if (typeof command !== 'string') return ''
  let text = command.trim()
  for (;;) {
    const cd = /^cd\s+(?:'[^']*'|"[^"]*"|\S+)\s*&&\s*/u.exec(text)
    if (cd === null) break
    text = text.slice(cd[0].length)
  }
  const words = text.split(/\s+/u).filter((word) => word !== '')
  let start = 0
  while (start < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/u.test(words[start])) start += 1
  const kept = []
  for (let index = start; index < words.length && kept.length < MAX_PREFIX_WORDS; index += 1) {
    const word = words[index]
    if (word.startsWith('-') || word.includes('/') || word.includes('=') || /[;&|<>()]/u.test(word)) break
    kept.push(word)
  }
  return kept.join(' ')
}

/**
 * Read the stored rules.
 * @param file - absolute rules-file path.
 * @returns the rules, empty when the file is absent or unusable.
 */
export function readRules(file) {
  let parsed
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'))
  }
  catch {
    // Missing or unparseable file reads as "no rules"; a broken file must not
    // block approvals, which is the state a first run and a hand-edit share.
    return []
  }
  const rules = parsed?.rules
  if (!Array.isArray(rules)) return []
  return rules.filter((rule) => typeof rule?.id === 'string'
    && typeof rule?.tool === 'string'
    && typeof rule?.mode === 'string'
    && typeof rule?.prefix === 'string')
}

/**
 * Persist the rules, replacing the file atomically.
 * @param file - absolute rules-file path.
 * @param rules - the complete rule list.
 */
export function writeRules(file, rules) {
  mkdirSync(dirname(file), { recursive: true })
  const temporary = `${file}.tmp`
  writeFileSync(temporary, `${JSON.stringify({ version: 1, rules }, null, 2)}\n`, 'utf8')
  renameSync(temporary, file)
}

/**
 * Find the rule that covers one escalation.
 * @param rules - stored rules.
 * @param query - tool, requested mode, and command prefix of the request.
 * @returns the matching rule, or null.
 */
export function matchRule(rules, query) {
  return rules.find((rule) => rule.tool === query.tool
    && rule.mode === query.mode
    && rule.prefix === query.prefix) ?? null
}

/**
 * Read one logged tool call's parsed arguments.
 * @param session - the session that logged the call.
 * @param callId - the approval request's call id.
 * @param maxScan - how many trailing events to scan.
 * @returns the parsed arguments object, or null when unavailable.
 */
export function toolCallArguments(session, callId, maxScan = MAX_SCAN_EVENTS) {
  if (session === undefined || session === null || typeof callId !== 'string') return null
  const end = Number(session.seq)
  if (!Number.isFinite(end)) return null
  const floor = Math.max(0, end - maxScan)
  for (let seq = end - 1; seq >= floor; seq -= 1) {
    const event = session.eventAt(seq)
    if (event?.type !== 'tool/call' || event.data?.callId !== callId) continue
    try {
      const parsed = JSON.parse(event.data.arguments)
      return typeof parsed === 'object' && parsed !== null ? parsed : null
    }
    catch {
      // A malformed arguments blob is not an escalation this plugin recognizes.
      return null
    }
  }
  return null
}

/**
 * Recognize the sandbox-escalation shape in one tool call's arguments.
 * @param args - parsed tool-call arguments.
 * @returns the requested mode, command, and justification, or null.
 */
export function escalationOf(args) {
  if (args === null || typeof args !== 'object') return null
  const mode = args.sandbox_permissions
  if (typeof mode !== 'string' || mode === '') return null
  const command = typeof args.command === 'string' ? args.command : ''
  if (command.trim() === '') return null
  return {
    mode,
    command,
    justification: typeof args.justification === 'string' ? args.justification : '',
  }
}

/**
 * Build the three-answer question for one escalation.
 * @param escalation - the requested mode, command, and justification.
 * @param prefix - the command prefix a "always allow" answer would store.
 * @returns the question item and the label that means "remember this".
 */
export function buildQuestion(escalation, prefix) {
  const always = `总是允许「${prefix}」开头的命令`
  return {
    always,
    question: {
      id: 'dsh-allow',
      header: '权限请求',
      question: `这条命令请求把沙箱权限提升到 ${escalation.mode}，是否允许？`,
      detail: `${escalation.command}${escalation.justification === '' ? '' : `\n\n原因：${escalation.justification}`}`,
      options: [
        { label: ALLOW_ONCE, description: '只放行这一次，下次仍然询问。' },
        { label: always, description: `记住这条规则，以后以「${prefix}」开头、请求相同模式的命令直接放行。` },
        { label: REJECT, description: '拒绝，本次调用不会执行。' },
      ],
    },
  }
}

/**
 * Pick the single selection of one answer, by question id.
 * @param answer - the answer returned by the question service.
 * @param id - question id to read.
 * @returns the selected label, or an empty string.
 */
export function selectionOf(answer, id) {
  const item = answer?.answers?.find((entry) => entry?.id === id)
  const selected = item?.selected
  return Array.isArray(selected) && typeof selected[0] === 'string' ? selected[0] : ''
}

/**
 * Add one rule, replacing an identical rule and keeping ids stable.
 * @param file - absolute rules-file path.
 * @param rule - tool, mode, and prefix to remember.
 * @returns the stored rule.
 */
export function addRule(file, rule) {
  const rules = readRules(file)
  const existing = matchRule(rules, rule)
  if (existing !== null) return existing
  const stored = { id: `r${String(Date.now())}`, hits: 0, ...rule }
  writeRules(file, [...rules, stored])
  return stored
}

/**
 * Count one rule's use, best effort: a failed bookkeeping write must never
 * change the approval outcome.
 * @param file - absolute rules-file path.
 * @param id - rule id to count.
 */
function countHit(file, id) {
  try {
    const rules = readRules(file)
    const next = rules.map((rule) => (rule.id === id ? { ...rule, hits: (Number(rule.hits) || 0) + 1 } : rule))
    writeRules(file, next)
  }
  catch {
    // Bookkeeping only; the grant already happened.
  }
}

/**
 * Create the approval listener.
 * @param options - rules file, logger, and the question service lookup.
 * @returns the waterfall listener.
 */
export function createApprovalListener({ file, logger, questionsFor }) {
  return async (request, next) => {
    const parsed = escalationOf(toolCallArguments(request?.agent?.session, request?.callId))
    if (parsed === null) return next()
    const prefix = commandPrefix(parsed.command)
    if (prefix === '') return next()
    const query = { tool: request.toolName, mode: parsed.mode, prefix }
    const hit = matchRule(readRules(file), query)
    if (hit !== null) {
      logger.info(`dsh-allow: allowed "${query.tool}" ${query.prefix} (rule ${hit.id}, ${query.mode}) without asking`)
      countHit(file, hit.id)
      return 'allowed-once'
    }
    const questions = questionsFor()
    if (questions === undefined) return next()
    const { always, question } = buildQuestion(parsed, prefix)
    let answer
    try {
      answer = await questions.ask({
        agent: request.agent,
        questions: [question],
        ...request.signal === undefined ? {} : { signal: request.signal },
      })
    }
    catch (error) {
      // An aborted ask is a cancellation; anything else (no answerer, a
      // delegated caller) falls through to the interactive answerer.
      return error?.code === 'ASK_ABORTED' ? 'cancelled' : next()
    }
    const selected = selectionOf(answer, question.id)
    if (selected === always) {
      const stored = addRule(file, query)
      logger.info(`dsh-allow: remembered "${query.tool}" ${prefix} (${query.mode}) as rule ${stored.id}`)
      return 'allowed-once'
    }
    if (selected === ALLOW_ONCE) return 'allowed-once'
    return 'rejected'
  }
}

/**
 * Render the stored rules for `/allow`.
 * @param file - absolute rules-file path.
 * @returns the command's answer text.
 */
export function renderRules(file) {
  const rules = readRules(file)
  if (rules.length === 0) {
    return '还没有记住任何命令。下次权限弹窗里选「总是允许…」，规则就会出现在这里。'
  }
  const lines = [`已记住 ${String(rules.length)} 条允许规则：`]
  for (const [index, rule] of rules.entries()) {
    const hits = Number(rule.hits) || 0
    lines.push(`${String(index + 1)}. ${rule.tool} · ${rule.mode} · 「${rule.prefix}」${hits > 0 ? `（已用 ${String(hits)} 次）` : ''}`)
  }
  lines.push('用 /allow remove <编号> 删除一条，/allow clear 清空。')
  return lines.join('\n')
}

/**
 * Answer `/allow`.
 * @param file - absolute rules-file path.
 * @param rawInput - text after the command name.
 * @returns the command result.
 */
export function runAllowCommand(file, rawInput) {
  const input = rawInput.trim()
  if (input === '') return { kind: 'success', text: renderRules(file) }
  const [verb, ...rest] = input.split(/\s+/u)
  if (verb === 'list') return { kind: 'success', text: renderRules(file) }
  if (verb === 'clear') {
    const count = readRules(file).length
    try {
      unlinkSync(file)
    }
    catch {
      // An absent file already means "no rules".
    }
    return { kind: 'success', text: `已清空 ${String(count)} 条规则。` }
  }
  if (verb === 'remove') {
    const rules = readRules(file)
    const index = Number(rest[0])
    if (!Number.isSafeInteger(index) || index < 1 || index > rules.length) {
      return { kind: 'error', text: `用法：/allow remove <编号>（1-${String(rules.length)}）` }
    }
    const removed = rules[index - 1]
    writeRules(file, rules.filter((_, position) => position !== index - 1))
    return { kind: 'success', text: `已删除规则「${removed.tool} · ${removed.prefix}」。` }
  }
  if (verb === 'add') {
    const [tool, mode, ...prefixWords] = rest
    const prefix = prefixWords.join(' ')
    if (tool === undefined || mode === undefined || prefix === '') {
      return { kind: 'error', text: '用法：/allow add <tool> <模式> <命令前缀>，例如 /allow add bash danger-full-access pnpm dsh plugin' }
    }
    const stored = addRule(file, { tool, mode, prefix })
    return { kind: 'success', text: `已记住：${stored.tool} · ${stored.mode} · 「${stored.prefix}」` }
  }
  return { kind: 'error', text: '用法：/allow [list|add <tool> <模式> <前缀>|remove <编号>|clear]' }
}

/**
 * Normalize the plugin configuration.
 * @param config - raw config object from cordis.yml, possibly absent.
 * @param home - resolved harness home.
 * @returns the rules-file path.
 */
export function resolveConfig(config, home) {
  const configured = config?.rulesFile
  if (configured !== undefined && (typeof configured !== 'string' || configured === '')) {
    throw new TypeError(`dsh-allow: config rulesFile must be a non-empty string, got ${JSON.stringify(configured)}`)
  }
  return { file: configured ?? join(home, RULES_FILE_NAME) }
}

/**
 * Wire the approval listener and the `/allow` command.
 * @param ctx - Cordis context of this plugin's fiber.
 * @param config - validated plugin configuration from cordis.yml.
 */
export function apply(ctx, config) {
  const { file } = resolveConfig(config, resolveHome())
  const listener = createApprovalListener({
    file,
    logger: ctx.logger,
    questionsFor: () => ctx.get('userQuestions'),
  })
  // Ahead of the interactive answerer: a remembered rule must settle the ask
  // before the browser is troubled with it.
  ctx.on('approval/request', (request, next) => listener(request, next), { prepend: true })
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.effect(() => commandCtx.commands.register({
      name: 'allow',
      description: 'List or change the commands that no longer ask for approval',
      input: { hint: '[list|add <tool> <mode> <prefix>|remove <number>|clear]' },
      handler: (invocation) => runAllowCommand(file, invocation.rawInput),
    }), 'dsh-allow: /allow command')
  })
}
