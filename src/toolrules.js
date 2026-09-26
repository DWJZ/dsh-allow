/**
 * Tool-operation rules: what one management tool call may do without asking.
 *
 * A filesystem rule answers "may this process touch this path, this way". A tool
 * rule answers a different question — "may this tool perform this operation at
 * all" — for the calls that ask for a wider process fence instead of naming a
 * path. `plugin_manager` is the one tool built that way: every action escalates
 * to `danger-full-access`, because a profile change installs and runs Host code
 * outside the workspace fence, so the filesystem policy has nothing to say about
 * it and the user was asked on every single call.
 *
 * What a rule may answer stays narrow:
 *
 *   - a read-only action is named by its action alone;
 *   - a mutating action also needs its exact target, so allowing one plugin
 *     never allows the next one;
 *   - an action whose own contract requires a fresh human answer is never
 *     answered by a rule, and neither is any call carrying a risk
 *     acknowledgement or a build-script approval.
 *
 * Nothing here is inferred from a call's text beyond what the tool declared: an
 * action this table does not name is a call no rule may answer.
 *
 * @module dsh-allow/toolrules
 */

/**
 * The tool-operation vocabulary this plugin judges, as
 * `tool → action → scope`, where the scope is:
 *
 *   - `action` — a read-only action a rule may name by action alone;
 *   - `target` — a mutating action a rule may name only with its exact target;
 *   - `never` — an action no rule may answer, however it is written.
 */
export const TOOL_ACTIONS = Object.freeze({
  plugin_manager: Object.freeze({
    list_plugins: 'action',
    list_bundles: 'action',
    list_version_exemptions: 'action',
    set_plugin: 'target',
    set_bundle: 'target',
    install_bundle: 'target',
    remove_bundle: 'target',
    // The tool's own contract: warn the user about the exact plugin/runtime
    // pair and obtain explicit permission before granting the exemption.
    set_version_exemption: 'never',
  }),
})

/** The tools this plugin can judge, in a stable order. */
export const TOOL_NAMES = Object.freeze(Object.keys(TOOL_ACTIONS))

/** Rule sources a stored or configured tool rule may carry. */
const TOOL_RULE_SOURCES = Object.freeze(['user', 'session'])

/**
 * Whether this plugin judges one tool's calls at all.
 * @param tool - tool name.
 * @returns true when the vocabulary names that tool.
 */
export function isJudgedTool(tool) {
  return typeof tool === 'string' && TOOL_ACTIONS[tool] !== undefined
}

/**
 * The scope one action of one tool has.
 * @param tool - tool name.
 * @param action - the action the call named.
 * @returns `action`, `target`, `never`, or null for an unknown pair.
 */
export function actionScope(tool, action) {
  if (typeof tool !== 'string' || typeof action !== 'string') return null
  return TOOL_ACTIONS[tool]?.[action] ?? null
}

/**
 * The human label of one tool rule — the tool, the action, and the target when
 * the action has one. Language-neutral, like {@link describeRule}.
 * @param rule - stored, configured, or suggested rule.
 * @returns the label.
 */
export function describeToolRule(rule) {
  const parts = [rule?.tool, rule?.action]
  if (typeof rule?.target === 'string' && rule.target !== '') parts.push(rule.target)
  return parts.filter(part => typeof part === 'string' && part !== '').join(' ')
}

/**
 * Build one rule of this kind from its fields.
 * @param fields - tool, action, target, and the optional source, id, and note.
 * @returns the rule.
 */
export function makeToolRule(fields) {
  const target = typeof fields.target === 'string' && fields.target.trim() !== '' ? fields.target.trim() : undefined
  const source = TOOL_RULE_SOURCES.includes(fields.source) ? fields.source : 'user'
  const tool = fields.tool
  const action = fields.action
  return {
    id: typeof fields.id === 'string' && fields.id !== ''
      ? fields.id
      : `${source}:${String(tool)}:${String(action)}${target === undefined ? '' : `:${target}`}`,
    tool,
    action,
    ...(target === undefined ? {} : { target }),
    source,
    ...(fields.note === undefined ? {} : { note: fields.note }),
  }
}

/**
 * Whether one rule may be stored or configured at all.
 *
 * The check is the policy, not a formality: it is what keeps "allow this one
 * plugin" from being written as "allow every plugin", and what keeps an action
 * that owes the user a fresh answer out of the store.
 * @param fields - tool, action, and target as the caller wrote them.
 * @returns whether it may be used, with the reason when it may not.
 */
export function validateToolRule(fields) {
  const tool = fields?.tool
  const action = fields?.action
  if (typeof tool !== 'string' || tool === '') return { ok: false, reason: '这条规则没有写明工具' }
  if (TOOL_ACTIONS[tool] === undefined) {
    return { ok: false, reason: `「${tool}」不在本插件的判定范围里，可用：${TOOL_NAMES.join(' ')}` }
  }
  if (typeof action !== 'string' || action === '') return { ok: false, reason: '这条规则没有写明动作' }
  const scope = TOOL_ACTIONS[tool][action]
  if (scope === undefined) {
    return {
      ok: false,
      reason: `「${tool}」没有「${action}」这个动作，可用：${Object.keys(TOOL_ACTIONS[tool]).join(' ')}`,
    }
  }
  const target = typeof fields.target === 'string' && fields.target.trim() !== '' ? fields.target.trim() : undefined
  if (scope === 'never') {
    return { ok: false, reason: `「${tool} ${action}」必须每次由用户对确切对象明确同意，不能写成规则` }
  }
  if (scope === 'target' && target === undefined) {
    return { ok: false, reason: `「${tool} ${action}」需要写明目标，规则不能对整个动作放行` }
  }
  if (scope === 'action' && target !== undefined) {
    return { ok: false, reason: `「${tool} ${action}」是只读动作，规则不需要目标` }
  }
  return { ok: true }
}

/**
 * Normalize one rule read from disk or from the configuration.
 * @param raw - the stored record.
 * @param source - the source to force.
 * @returns the usable rule, or null.
 */
export function normalizeStoredToolRule(raw, source) {
  if (raw === null || typeof raw !== 'object') return null
  if (!validateToolRule(raw).ok) return null
  const rule = makeToolRule({ ...raw, source })
  rule.hits = Number(raw.hits) || 0
  if (typeof raw.createdAt === 'string') rule.createdAt = raw.createdAt
  return rule
}

/**
 * Whether a rule still names a pair this plugin judges. A record written by an
 * older or a hand-edited file is dropped rather than widened.
 * @param rule - the candidate rule.
 * @returns true when it may be matched.
 */
export function isUsableToolRule(rule) {
  if (rule === null || rule === undefined) return false
  const scope = actionScope(rule.tool, rule.action)
  if (scope === null || scope === 'never') return false
  const named = typeof rule.target === 'string' && rule.target !== ''
  return scope === 'target' ? named : !named
}

/**
 * Read one call into the request a rule is matched against.
 *
 * A call that carries a risk acknowledgement or a build-script approval is
 * reported as blocked, not as rememberable: both answer a question the user is
 * asked directly, and a rule that answered them would decide it in the user's
 * place. The same holds for an action whose contract demands a fresh answer, and
 * for a mutating call that named no target at all.
 * @param tool - the tool the call names.
 * @param args - the call's arguments, as the session log holds them.
 * @returns the request, or null when this plugin does not judge that tool.
 */
export function toolRequestOf(tool, args) {
  if (!isJudgedTool(tool)) return null
  const action = typeof args?.action === 'string' && args.action !== '' ? args.action : null
  // An action this table does not name is a call no rule may answer, and neither
  // is a call whose arguments cannot be read at all.
  if (action === null || TOOL_ACTIONS[tool][action] === undefined) return null
  const scope = TOOL_ACTIONS[tool][action]
  const request = { tool, action, target: null, rememberable: false, blocked: null }
  if (scope === 'never') {
    return { ...request, blocked: `${tool} ${action} 需要每次由用户对确切对象明确同意` }
  }
  if (args.acceptRisk === true) {
    return { ...request, blocked: `${tool} ${action} 带着风险确认，必须由用户自己承担` }
  }
  if (Array.isArray(args.approvedBuilds) && args.approvedBuilds.length > 0) {
    return { ...request, blocked: `${tool} ${action} 带着安装脚本授权，必须由用户自己授予` }
  }
  if (scope === 'action') return { ...request, rememberable: true }
  const target = typeof args.target === 'string' && args.target.trim() !== '' ? args.target.trim() : null
  if (target === null) return { ...request, blocked: `${tool} ${action} 没有写明目标，规则无法收窄到一次调用` }
  return { ...request, target, rememberable: true }
}

/**
 * The rule that answers one request, if any.
 * @param rules - the stored and configured tool rules.
 * @param request - the request, as {@link toolRequestOf} read it.
 * @returns the matching rule, or null.
 */
export function matchToolRule(rules, request) {
  if (request === null || request === undefined || request.blocked !== null) return null
  const target = request.target === null || request.target === undefined ? undefined : request.target
  return (rules ?? []).find(rule => isUsableToolRule(rule)
    && rule.tool === request.tool
    && rule.action === request.action
    && rule.target === target) ?? null
}

/**
 * Project the tool rule that answered one call into an audit-sized record, next
 * to the `path` field a filesystem rule's record carries.
 * @param rule - the granting rule.
 * @returns the record.
 */
export function matchedToolRuleOf(rule) {
  return {
    id: rule.id,
    tool: rule.tool,
    action: rule.action,
    ...(rule.target === undefined ? {} : { target: rule.target }),
    source: rule.source ?? 'user',
    label: describeToolRule(rule),
  }
}
