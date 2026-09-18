/**
 * Persistent structured rules, the pending-approval scratch space, and the
 * decision audit log.
 *
 * A rule is an executable plus a literal argv prefix — never a raw substring —
 * so `git status` and `git reset --hard` cannot share one. The audit log is
 * NDJSON and never records environment values or credential-shaped text.
 */
import { appendFileSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'

/** Default file name for stored rules below the harness home. */
const RULES_FILE_NAME = 'dsh-allow.json'

/** Default file name for the audit log below the harness home. */
const AUDIT_FILE_NAME = 'dsh-allow-audit.ndjson'

/** How many escalations may wait for a card at once. */
const PENDING_LIMIT = 100

/** How long a pending approval stays addressable, in milliseconds. */
const PENDING_TTL_MS = 15 * 60 * 1000

/** Separator between a session id and a call id inside one pending key. */
const PENDING_SEPARATOR = '\u0000'

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
 * Resolve the rules and audit paths for one harness home.
 * @param config - raw plugin configuration.
 * @param home - resolved harness home.
 * @returns absolute paths plus the default decision.
 */
export function resolveConfig(config, home) {
  const text = (value, field, fallback) => {
    if (value === undefined) return fallback
    if (typeof value !== 'string' || value === '') {
      throw new TypeError(`dsh-allow: config ${field} must be a non-empty string, got ${JSON.stringify(value)}`)
    }
    return value
  }
  const defaultDecision = config?.defaultDecision ?? 'allow'
  if (!['allow', 'prompt'].includes(defaultDecision)) {
    throw new TypeError(`dsh-allow: config defaultDecision must be "allow" or "prompt", got ${JSON.stringify(defaultDecision)}`)
  }
  return {
    rulesFile: text(config?.rulesFile, 'rulesFile', join(home, RULES_FILE_NAME)),
    auditFile: text(config?.auditFile, 'auditFile', join(home, AUDIT_FILE_NAME)),
    audit: config?.audit !== false,
    defaultDecision,
    // A remembered command also answers the sandbox's escalation question:
    // that is what "stop asking for this command" means for a path outside
    // the workspace. Turn it off to keep every widening manual.
    autoApproveEscalations: config?.autoApproveEscalations !== false,
  }
}

/**
 * Read the stored rules.
 * @param file - absolute rules-file path.
 * @returns the rules; an unreadable file reads as none.
 */
export function readRules(file) {
  let parsed
  try {
    parsed = JSON.parse(readFileSync(file, 'utf8'))
  }
  catch {
    // Missing or hand-broken file means "no rules"; approvals must still work.
    return []
  }
  const rules = parsed?.rules
  if (!Array.isArray(rules)) return []
  return rules.filter(rule => typeof rule?.id === 'string'
    && ['allow', 'prompt', 'forbidden'].includes(rule?.decision)
    && typeof rule?.executable === 'string')
}

/**
 * Replace the whole rule set atomically.
 * @param file - absolute rules-file path.
 * @param rules - the complete list.
 */
export function writeRules(file, rules) {
  mkdirSync(dirname(file), { recursive: true })
  const temporary = `${file}.tmp`
  writeFileSync(temporary, `${JSON.stringify({ version: 2, rules }, null, 2)}\n`, 'utf8')
  renameSync(temporary, file)
}

/**
 * Store one rule, replacing an identical one.
 * @param file - absolute rules-file path.
 * @param fields - decision, executable, and argv prefix.
 * @returns the stored rule.
 */
export function addRule(file, fields) {
  const rules = readRules(file)
  const same = rules.find(rule => rule.decision === fields.decision
    && rule.executable === fields.executable
    && (rule.argvPrefix ?? []).join('\u0000') === (fields.argvPrefix ?? []).join('\u0000'))
  if (same !== undefined) return same
  const stored = {
    id: `r${String(Date.now())}${String(rules.length)}`,
    decision: fields.decision,
    executable: fields.executable,
    argvPrefix: [...(fields.argvPrefix ?? [])],
    hits: 0,
    createdAt: new Date().toISOString(),
    ...(fields.note === undefined ? {} : { note: fields.note }),
  }
  writeRules(file, [...rules, stored])
  return stored
}

/**
 * Remove one rule by 1-based position.
 * @param file - absolute rules-file path.
 * @param position - 1-based index.
 * @returns the removed rule, or null when the position is out of range.
 */
export function removeRule(file, position) {
  const rules = readRules(file)
  if (!Number.isSafeInteger(position) || position < 1 || position > rules.length) return null
  const [removed] = rules.splice(position - 1, 1)
  writeRules(file, rules)
  return removed ?? null
}

/**
 * Clear every stored rule.
 * @param file - absolute rules-file path.
 * @returns how many rules were removed.
 */
export function clearRules(file) {
  const count = readRules(file).length
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
    const rules = readRules(file)
    writeRules(file, rules.map(rule => (rule.id === id ? { ...rule, hits: (Number(rule.hits) || 0) + 1 } : rule)))
  }
  catch {
    // Bookkeeping only.
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
     * @param record - decision, reason, cwd, command, and suggested rule.
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
