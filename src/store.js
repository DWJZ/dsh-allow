/**
 * Persistent filesystem rules, per-session grants, the pending-approval
 * scratch space, and the decision audit log.
 *
 * A stored rule is a path plus the capabilities granted there — never a command
 * line — so `rm build` and `rm src` cannot share one unless the user opened the
 * folder they share on purpose. The audit log is NDJSON and never records
 * environment values or credential-shaped text.
 */
import { appendFileSync, existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { OPERATIONS, canonicalPath, describeRule, makeRule, normalizeStoredRule } from './fspolicy.js'

/** Default file name for stored rules below the harness home. */
const RULES_FILE_NAME = 'dsh-allow.json'

/** Rule file a workspace may carry for itself. */
export const WORKSPACE_RULES_FILE_NAME = '.dsh-allow.json'

/** Default file name for the audit log below the harness home. */
const AUDIT_FILE_NAME = 'dsh-allow-audit.ndjson'

/** How many escalations may wait for a card at once. */
const PENDING_LIMIT = 100

/** How long a pending approval stays addressable, in milliseconds. */
const PENDING_TTL_MS = 15 * 60 * 1000

/** How long an "allow once" grant survives, in milliseconds. */
const SESSION_GRANT_TTL_MS = 10 * 60 * 1000

/** Separator between a session id and a call id inside one pending key. */
const PENDING_SEPARATOR = '\u0000'

/** The rule-file format this version writes. */
const RULES_VERSION = 3

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
 * Resolve one configured grant into a rule.
 * @param entry - `{path, recursive, access}` from the plugin configuration.
 * @param home - harness home, used for `~` in configured paths.
 * @returns the rule.
 */
function configGrantRule(entry, home) {
  if (entry === null || typeof entry !== 'object' || typeof entry.path !== 'string') {
    throw new TypeError(`dsh-allow: config grants entries need a path, got ${JSON.stringify(entry)}`)
  }
  const access = {}
  for (const operation of OPERATIONS) if (entry.access?.[operation] === true) access[operation] = true
  if (Object.keys(access).length === 0) {
    throw new TypeError(`dsh-allow: config grant for ${entry.path} grants no operation`)
  }
  return makeRule({
    path: canonicalPath(entry.path, { cwd: process.cwd(), home }),
    recursive: entry.recursive !== false,
    access,
    source: 'user',
    note: 'configured grant',
  })
}

/**
 * Resolve the rules and audit paths for one harness home.
 * @param config - raw plugin configuration.
 * @param home - resolved harness home.
 * @returns absolute paths, the configured grants, and the deployment flags.
 */
export function resolveConfig(config, home) {
  const text = (value, field, fallback) => {
    if (value === undefined) return fallback
    if (typeof value !== 'string' || value === '') {
      throw new TypeError(`dsh-allow: config ${field} must be a non-empty string, got ${JSON.stringify(value)}`)
    }
    return value
  }
  const sessionGrantTtlMs = config?.sessionGrantTtlMs ?? SESSION_GRANT_TTL_MS
  if (typeof sessionGrantTtlMs !== 'number' || !Number.isFinite(sessionGrantTtlMs) || sessionGrantTtlMs <= 0) {
    throw new TypeError(`dsh-allow: config sessionGrantTtlMs must be a positive number, got ${JSON.stringify(sessionGrantTtlMs)}`)
  }
  const grants = config?.grants === undefined ? [] : config.grants
  if (!Array.isArray(grants)) {
    throw new TypeError('dsh-allow: config grants must be a list of {path, access, recursive} entries')
  }
  return {
    rulesFile: text(config?.rulesFile, 'rulesFile', join(home, RULES_FILE_NAME)),
    auditFile: text(config?.auditFile, 'auditFile', join(home, AUDIT_FILE_NAME)),
    audit: config?.audit !== false,
    sessionGrantTtlMs,
    grants: grants.map(entry => configGrantRule(entry, home)),
    // An approval for one call also answers the sandbox's escalation question:
    // that is what "stop asking for this path" means once the run needs a wider
    // mode. Turn it off to keep every widening manual.
    autoApproveEscalations: config?.autoApproveEscalations !== false,
  }
}

/**
 * Read one JSON file.
 * @param file - absolute path.
 * @returns the parsed value, or null.
 */
function readJson(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
  }
  catch {
    // Missing or hand-broken file means "nothing configured"; approvals must
    // still work, so this is not an error the caller has to handle.
    return null
  }
}

/**
 * Read the stored rules. A file from an older rule model reads as empty: its
 * command-shaped rules say nothing about filesystem capabilities, and the
 * writer keeps a backup of it rather than rewriting it in place.
 * @param file - absolute rules-file path.
 * @returns the rules.
 */
export function readRules(file) {
  const parsed = readJson(file)
  if (!Array.isArray(parsed?.rules)) return []
  if (parsed.version !== undefined && parsed.version !== RULES_VERSION) return []
  return parsed.rules.map(rule => normalizeStoredRule(rule, 'user')).filter(rule => rule !== null)
}

/**
 * Read the rules one workspace carries for itself.
 * @param workspaceRoot - the session workspace root.
 * @returns the workspace rules.
 */
export function readWorkspaceRules(workspaceRoot) {
  if (typeof workspaceRoot !== 'string' || workspaceRoot === '') return []
  const parsed = readJson(resolve(workspaceRoot, WORKSPACE_RULES_FILE_NAME))
  if (!Array.isArray(parsed?.rules)) return []
  return parsed.rules.map(rule => normalizeStoredRule(rule, 'workspace')).filter(rule => rule !== null)
}

/**
 * Replace the whole rule set atomically, keeping one backup of a file written
 * by an earlier rule model.
 * @param file - absolute rules-file path.
 * @param rules - the complete list.
 */
export function writeRules(file, rules) {
  mkdirSync(dirname(file), { recursive: true })
  const previous = readJson(file)
  if (previous !== null && previous.version !== undefined && previous.version !== RULES_VERSION
    && !existsSync(`${file}.v${String(previous.version)}.bak`)) {
    renameSync(file, `${file}.v${String(previous.version)}.bak`)
  }
  const temporary = `${file}.tmp`
  writeFileSync(temporary, `${JSON.stringify({ version: RULES_VERSION, rules }, null, 2)}\n`, 'utf8')
  renameSync(temporary, file)
}

/**
 * Refuse the one rule that would open the whole machine to writers.
 * @param rule - the rule about to be stored.
 * @returns whether it may be stored, with the reason when it may not.
 */
export function validateRule(rule) {
  const operations = OPERATIONS.filter(operation => rule.access?.[operation] === true)
  if (operations.length === 0) return { ok: false, reason: '这条规则没有授予任何权限' }
  if (rule.path === '/' && rule.recursive === true
    && operations.some(operation => operation !== 'read' && operation !== 'execute')) {
    return { ok: false, reason: '拒绝写入「整个磁盘可写」的规则；请把范围收窄到具体目录' }
  }
  return { ok: true }
}

/**
 * Store one rule, replacing an identical one.
 * @param file - absolute rules-file path.
 * @param fields - path, access, and recursive flag.
 * @returns the stored rule.
 */
export function addRule(file, fields) {
  const rule = makeRule({ ...fields, source: 'user' })
  const check = validateRule(rule)
  if (!check.ok) throw new TypeError(`dsh-allow: ${check.reason}`)
  const rules = readRules(file)
  const same = rules.find(existing => existing.path === rule.path
    && existing.recursive === rule.recursive
    && OPERATIONS.every(operation => existing.access[operation] === rule.access[operation]))
  if (same !== undefined) return same
  const stored = {
    id: `f${String(Date.now())}${String(rules.length)}`,
    path: rule.path,
    recursive: rule.recursive,
    access: rule.access,
    hits: 0,
    createdAt: new Date().toISOString(),
    ...(rule.note === undefined ? {} : { note: rule.note }),
  }
  writeRules(file, [...readRulesRaw(file), stored])
  return normalizeStoredRule(stored, 'user')
}

/**
 * Read the stored records without normalization, so a rewrite keeps every field.
 * @param file - absolute rules-file path.
 * @returns the raw records.
 */
function readRulesRaw(file) {
  const parsed = readJson(file)
  if (!Array.isArray(parsed?.rules)) return []
  if (parsed.version !== undefined && parsed.version !== RULES_VERSION) return []
  return parsed.rules
}

/**
 * Remove one rule by 1-based position.
 * @param file - absolute rules-file path.
 * @param position - 1-based index.
 * @returns the removed rule, or null when the position is out of range.
 */
export function removeRule(file, position) {
  const rules = readRulesRaw(file)
  if (!Number.isSafeInteger(position) || position < 1 || position > rules.length) return null
  const [removed] = rules.splice(position - 1, 1)
  writeRules(file, rules)
  return removed === undefined ? null : normalizeStoredRule(removed, 'user')
}

/**
 * Clear every stored rule.
 * @param file - absolute rules-file path.
 * @returns how many rules were removed.
 */
export function clearRules(file) {
  const count = readRulesRaw(file).length
  try {
    unlinkSync(file)
  }
  catch {
    // An absent file already means "no rules".
  }
  return count
}

/**
 * Count one rule's use; bookkeeping failures never change a decision.
 * @param file - absolute rules-file path.
 * @param id - rule id.
 */
export function countHit(file, id) {
  try {
    const rules = readRulesRaw(file)
    writeRules(file, rules.map(rule => (rule.id === id ? { ...rule, hits: (Number(rule.hits) || 0) + 1 } : rule)))
  }
  catch {
    // Bookkeeping only.
  }
}

/**
 * Create the "allow once" store: capability grants that live in this process
 * only, for a bounded time, and are never written to the rules file.
 * @param options - lifetime and clock.
 * @returns grant/read/release operations.
 */
export function createGrantStore({ ttlMs = SESSION_GRANT_TTL_MS, now = Date.now } = {}) {
  const entries = new Map()
  const prune = () => {
    for (const [key, entry] of entries) if (now() - entry.at > ttlMs) entries.delete(key)
  }
  return {
    /**
     * Grant capabilities for one session until the grant expires.
     * @param sessionId - owning session id.
     * @param rules - the rules to remember, in `makeRule` fields.
     * @returns the granted rules.
     */
    grant(sessionId, rules) {
      if (typeof sessionId !== 'string') return []
      prune()
      const current = entries.get(sessionId)?.rules ?? []
      const stored = rules.map((fields, index) => makeRule({
        ...fields,
        source: 'session',
        id: `s${String(now())}${String(index)}`,
      }))
      entries.set(sessionId, { rules: [...current, ...stored], at: now() })
      return stored
    },
    /**
     * The session's live grants.
     * @param sessionId - owning session id.
     * @returns the rules.
     */
    rulesFor(sessionId) {
      if (typeof sessionId !== 'string') return []
      prune()
      return entries.get(sessionId)?.rules ?? []
    },
    /**
     * Drop one session's grants.
     * @param sessionId - owning session id.
     */
    release(sessionId) {
      if (typeof sessionId === 'string') entries.delete(sessionId)
    },
  }
}

/** Redact credential-shaped text before it reaches the audit log. */
const SECRET_PATTERNS = [
  /(?:api[_-]?key|token|secret|password|passwd|authorization)\s*[=:]\s*(?:Bearer\s+|Basic\s+)?\S+/giu,
  /Bearer\s+\S+/gu,
  /-----BEGIN[^-]+-----[\s\S]*?-----END[^-]+-----/gu,
]

/**
 * Strip credential-shaped text from one audit string.
 * @param text - raw text.
 * @returns the redacted text.
 */
export function redact(text) {
  return SECRET_PATTERNS.reduce((current, pattern) => current.replace(pattern, '[redacted]'), text)
}

/**
 * Append one policy decision to the audit log.
 * @param file - absolute audit-file path, or null to disable.
 * @param entry - the decision record.
 */
export function appendAudit(file, entry) {
  if (file === null) return
  try {
    mkdirSync(dirname(file), { recursive: true })
    // Redact the serialized record, so arguments and reasons are covered too.
    const line = JSON.stringify({ at: new Date().toISOString(), ...entry })
    appendFileSync(file, `${redact(line)}\n`, 'utf8')
  }
  catch {
    // Auditing is best effort; a full disk must not block approvals.
  }
}

/** The key one pending approval is stored under. */
export function pendingKey(sessionId, callId) {
  if (typeof sessionId !== 'string' || typeof callId !== 'string') return null
  return `${sessionId}${PENDING_SEPARATOR}${callId}`
}

/**
 * Create the pending-approval store: what a card on screen needs to know.
 * @param options - lifetime, capacity, and clock.
 * @returns remember/get/forget operations.
 */
export function createPendingStore({ ttlMs = PENDING_TTL_MS, limit = PENDING_LIMIT, now = Date.now } = {}) {
  const entries = new Map()
  const prune = () => {
    for (const [key, entry] of entries) if (now() - entry.at > ttlMs) entries.delete(key)
  }
  return {
    /**
     * Record one approval that is now on screen.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     * @param record - decision, missing capabilities, cwd, command, suggestions.
     */
    remember(sessionId, callId, record) {
      const key = pendingKey(sessionId, callId)
      if (key === null) return
      prune()
      entries.set(key, { ...record, at: now() })
      while (entries.size > limit) {
        const oldest = entries.keys().next().value
        if (oldest === undefined) break
        entries.delete(oldest)
      }
    },
    /**
     * Read one pending approval.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     * @returns the record, or null.
     */
    get(sessionId, callId) {
      const key = pendingKey(sessionId, callId)
      if (key === null) return null
      prune()
      return entries.get(key) ?? null
    },
    /**
     * Drop one pending approval once it was answered.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     */
    forget(sessionId, callId) {
      const key = pendingKey(sessionId, callId)
      if (key !== null) entries.delete(key)
    },
  }
}

/**
 * Render one rule for the command line.
 * @param rule - stored or suggested rule.
 * @returns the human label.
 */
export function renderRule(rule) {
  return describeRule(rule)
}
