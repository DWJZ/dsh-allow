/**
 * Persistent filesystem rules, per-session grants, the pending-approval
 * scratch space, and the decision audit log.
 *
 * A stored rule is a path plus the capabilities granted there — never a command
 * line — so `rm build` and `rm src` cannot share one unless the user opened the
 * folder they share on purpose. The audit log is NDJSON and never records
 * environment values or credential-shaped text.
 */
import {
  appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, readSync, renameSync,
  statSync, unlinkSync, writeFileSync,
} from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { OPERATIONS, canonicalPath, describeRule, makeRule, normalizeStoredRule } from './fspolicy.js'

/** Default file name for stored rules below the harness home. */
const RULES_FILE_NAME = 'dsh-allow.json'

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

/** How much of the audit log one tail read consumes before it stops, in bytes. */
const AUDIT_CHUNK_BYTES = 256 * 1024

/** Largest window a tail read scans from the end of the audit log, in bytes. */
const AUDIT_MAX_BYTES = 4 * 1024 * 1024

/** How many tail answers are cached; an unchanged file is then read once. */
const AUDIT_CACHE_LIMIT = 8

/** How many unanswered human notes may wait before the oldest is dropped. */
const DECISION_NOTE_LIMIT = 100

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
  const enforce = config?.enforce ?? 'auto'
  if (!['auto', 'full', 'guarded', 'process', 'writes', 'off'].includes(enforce)) {
    throw new TypeError(`dsh-allow: config enforce must be "auto", "full", "guarded", "process", "writes" or "off", got ${JSON.stringify(enforce)}`)
  }
  const autoReviewRaw = config?.autoReview ?? {}
  if (typeof autoReviewRaw !== 'object' || autoReviewRaw === null) {
    throw new TypeError('dsh-allow: config autoReview must be an object')
  }
  const timeoutMs = autoReviewRaw.timeoutMs ?? 10000
  if (typeof timeoutMs !== 'number' || !Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new TypeError(`dsh-allow: config autoReview.timeoutMs must be a positive number, got ${JSON.stringify(timeoutMs)}`)
  }
  const routeField = (value, field) => {
    if (value === undefined || value === 'inherit') return undefined
    if (typeof value !== 'string' || value === '') {
      throw new TypeError(`dsh-allow: config autoReview.${field} must be a non-empty string or "inherit", got ${JSON.stringify(value)}`)
    }
    return value
  }
  const reviewProvider = routeField(autoReviewRaw.provider, 'provider')
  const reviewModel = routeField(autoReviewRaw.model, 'model')
  if ((reviewProvider === undefined) !== (reviewModel === undefined)) {
    throw new TypeError('dsh-allow: config autoReview.provider and autoReview.model are configured together')
  }
  const rulesFile = text(config?.rulesFile, 'rulesFile', join(home, RULES_FILE_NAME))
  const auditFile = text(config?.auditFile, 'auditFile', join(home, AUDIT_FILE_NAME))
  return {
    rulesFile,
    auditFile,
    audit: config?.audit !== false,
    sessionGrantTtlMs,
    grants: grants.map(entry => configGrantRule(entry, home)),
    // How much of the filesystem policy is compiled into the process sandbox.
    // `auto` takes the strongest fence a probe proves this host can hold:
    // writes and execution always, user-data reads when macOS survives it.
    enforce,
    // The optional reviewer only ever answers "allow once" for one call; it is
    // off unless a deployment asks for it, and it never writes a rule.
    autoReview: {
      enabled: autoReviewRaw.enabled === true,
      timeoutMs,
      ...(reviewProvider === undefined ? {} : { provider: reviewProvider, model: reviewModel }),
    },
    // Nothing the agent runs may change the rules that judge it. The paths are
    // canonical so they match the paths a decision compares, whatever spelling
    // the configuration used.
    protectedFiles: [rulesFile, auditFile, join(home, 'dsh-allow.json'), join(home, 'dsh-allow-audit.ndjson')]
      .map(file => canonicalPath(file, { cwd: process.cwd(), home })),
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
 * only, are bound to the one call the user approved, are handed to the sandbox
 * for that call, and are dropped as soon as the call settles.
 *
 * A confinement knows its session but not its call, so the store also answers
 * the two questions that keep a grant from leaking sideways: which call is
 * holding a grant in this session, and which command that call is running. The
 * profile builder matches the command, and the gate makes a second call in the
 * same session wait for the holder to settle.
 * @param options - lifetime and clock.
 * @returns grant/read/hold/consume operations.
 */
export function createGrantStore({ ttlMs = SESSION_GRANT_TTL_MS, now = Date.now } = {}) {
  const entries = new Map()
  const waiters = new Map()
  const prune = () => {
    for (const [key, entry] of entries) {
      if (now() - entry.at > ttlMs) {
        entries.delete(key)
        release(key)
      }
    }
  }
  /** Wake everyone waiting for one call's grant to be spent. */
  function release(key) {
    const waiting = waiters.get(key)
    if (waiting === undefined) return
    waiters.delete(key)
    for (const resolve of waiting) resolve()
  }
  return {
    /**
     * Grant capabilities for one approved call.
     * @param sessionId - owning session id.
     * @param callId - the call the approval belongs to.
     * @param command - the command line the user approved.
     * @param rules - the rules to remember, in `makeRule` fields.
     * @returns the granted rules.
     */
    grant(sessionId, callId, command, rules) {
      if (typeof sessionId !== 'string' || typeof callId !== 'string') return []
      prune()
      const stored = rules.map((fields, index) => makeRule({
        ...fields,
        source: 'session',
        id: `s${String(now())}${String(index)}`,
      }))
      const key = `${sessionId}\u0000${callId}`
      const current = entries.get(key)?.rules ?? []
      entries.set(key, { rules: [...current, ...stored], command, at: now() })
      return stored
    },
    /**
     * The grants that belong to one call.
     * @param sessionId - owning session id.
     * @param callId - the call being judged.
     * @returns the rules.
     */
    rulesFor(sessionId, callId) {
      if (typeof sessionId !== 'string' || typeof callId !== 'string') return []
      prune()
      return entries.get(`${sessionId}\u0000${callId}`)?.rules ?? []
    },
    /**
     * The grants that belong to one command line in one session: what a
     * confinement may carry, because the command it is about to run is the one
     * the user approved for that call.
     * @param sessionId - owning session id.
     * @param command - the command the confinement is about to run.
     * @returns the rules.
     */
    forCommand(sessionId, command) {
      if (typeof sessionId !== 'string' || typeof command !== 'string') return []
      prune()
      const prefix = `${sessionId}\u0000`
      const rules = []
      for (const [key, entry] of entries) {
        if (key.startsWith(prefix) && entry.command === command) rules.push(...entry.rules)
      }
      return rules
    },
    /**
     * The call holding a one-shot grant in this session, when it is not the one
     * asking: the caller must wait for it, or its profile would carry it too.
     * @param sessionId - owning session id.
     * @param callId - the call asking.
     * @returns the holding call id, or null.
     */
    holder(sessionId, callId) {
      if (typeof sessionId !== 'string') return null
      prune()
      const prefix = `${sessionId}\u0000`
      for (const key of entries.keys()) {
        if (!key.startsWith(prefix)) continue
        const holderCall = key.slice(prefix.length)
        if (holderCall !== callId) return holderCall
      }
      return null
    },
    /**
     * Wait until one call's grant is spent or expires.
     * @param sessionId - owning session id.
     * @param callId - the call being waited for.
     * @returns a promise that settles when the grant is gone.
     */
    released(sessionId, callId) {
      if (typeof sessionId !== 'string' || typeof callId !== 'string') return Promise.resolve()
      prune()
      const key = `${sessionId}\u0000${callId}`
      const entry = entries.get(key)
      if (entry === undefined) return Promise.resolve()
      return new Promise((resolve) => {
        const waiting = waiters.get(key) ?? new Set()
        waiting.add(resolve)
        waiters.set(key, waiting)
        // A waiter must not outlive the grant it is waiting for: when the TTL
        // runs out the grant is gone anyway, so the wait ends there.
        const remaining = Math.max(0, ttlMs - (now() - entry.at))
        const timer = setTimeout(() => {
          entries.delete(key)
          release(key)
        }, remaining)
        timer.unref?.()
      })
    },
    /**
     * Drop the grants of one call once it has run.
     * @param sessionId - owning session id.
     * @param callId - the call that settled.
     * @returns how many rules were dropped.
     */
    consume(sessionId, callId) {
      if (typeof sessionId !== 'string' || typeof callId !== 'string') return 0
      const key = `${sessionId}\u0000${callId}`
      const dropped = entries.get(key)?.rules.length ?? 0
      entries.delete(key)
      release(key)
      return dropped
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

/**
 * Parse one audit-log line.
 * @param line - raw line text.
 * @returns the record, or null for a blank, truncated, or non-object line.
 */
function parseAuditLine(line) {
  const trimmed = line.trim()
  if (trimmed === '' || trimmed[0] !== '{') return null
  try {
    const parsed = JSON.parse(trimmed)
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed) ? parsed : null
  }
  catch {
    // A line the reader caught mid-write, or one a chunk boundary split, carries
    // nothing this reader can attribute to a decision.
    return null
  }
}

/**
 * Whether one audit record belongs in the answer.
 * @param entry - parsed audit record.
 * @param sessionId - session to keep, or null for every session.
 * @param includeBaseline - whether platform-baseline allows are included.
 * @returns true when the record is kept.
 */
function auditMatches(entry, sessionId, includeBaseline) {
  if (sessionId !== null && entry.sessionId !== sessionId) return false
  if (!includeBaseline && entry.origin === 'baseline') return false
  return true
}

/** Answers from the last reads, so a poll that follows no write reads no file. */
const auditTailCache = new Map()

/** Remember one tail answer under a bounded cache. */
function cacheAuditTail(key, answer) {
  auditTailCache.delete(key)
  auditTailCache.set(key, answer)
  while (auditTailCache.size > AUDIT_CACHE_LIMIT) {
    const oldest = auditTailCache.keys().next().value
    if (oldest === undefined) break
    auditTailCache.delete(oldest)
  }
  return answer
}

/**
 * Read the newest audit records from the end of the log, without loading it.
 *
 * The window grows backwards in fixed chunks until the answer is full or the
 * byte cap is reached, so a busy session answers from the last chunk while a
 * quiet one pays for the history it asked about. A file that did not change
 * since the previous identical request is answered from cache.
 *
 * A line a chunk boundary split is dropped rather than repaired: the reader
 * cannot tell a partial line from a malformed one, and a decision it cannot
 * parse is a decision it must not report.
 * @param file - absolute audit-file path.
 * @param options - session filter, answer size, and baseline inclusion.
 * @returns the newest matching records (oldest first), the bytes read, and
 *   whether older matching records remain outside the window.
 */
export function readAuditTail(file, { sessionId = null, limit = 200, includeBaseline = false } = {}) {
  const empty = { entries: [], scannedBytes: 0, truncated: false }
  if (typeof file !== 'string' || file === '' || limit <= 0) return empty
  let stat
  try {
    stat = statSync(file)
  }
  catch {
    // No audit log yet: a session that decided nothing has nothing to show.
    return empty
  }
  if (!stat.isFile() || stat.size === 0) return empty
  const cacheKey = [file, stat.size, stat.mtimeMs, sessionId ?? '', limit, includeBaseline ? 1 : 0].join('\u0000')
  const cached = auditTailCache.get(cacheKey)
  if (cached !== undefined) return cached

  let descriptor
  try {
    descriptor = openSync(file, 'r')
  }
  catch {
    return empty
  }
  const entries = []
  let position = stat.size
  let scannedBytes = 0
  let carry = ''
  try {
    while (position > 0 && entries.length < limit && scannedBytes < AUDIT_MAX_BYTES) {
      const length = Math.min(AUDIT_CHUNK_BYTES, position, AUDIT_MAX_BYTES - scannedBytes)
      const buffer = Buffer.allocUnsafe(length)
      const read = readSync(descriptor, buffer, 0, length, position - length)
      if (read <= 0) break
      position -= read
      scannedBytes += read
      const lines = (buffer.subarray(0, read).toString('utf8') + carry).split('\n')
      // The first line is only whole once the chunk before it has been read.
      carry = position > 0 ? (lines.shift() ?? '') : ''
      for (let index = lines.length - 1; index >= 0 && entries.length < limit; index -= 1) {
        const entry = parseAuditLine(lines[index])
        if (entry !== null && auditMatches(entry, sessionId, includeBaseline)) entries.push(entry)
      }
    }
  }
  finally {
    closeSync(descriptor)
  }
  entries.reverse()
  return cacheAuditTail(cacheKey, { entries, scannedBytes, truncated: position > 0 })
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
 * Create the human-decision scratch space: what the user clicked, before the
 * approval service reports the outcome it produced.
 *
 * A card answers in two steps — it calls `/dsh-allow/remember` or
 * `/dsh-allow/once`, then settles the pending approval — and the pending record
 * is gone by the second. The note is keyed separately so both halves of one
 * decision still produce exactly one audit record.
 * @param options - how many unanswered notes may wait.
 * @returns note/take/peek operations.
 */
export function createDecisionLog({ limit = DECISION_NOTE_LIMIT } = {}) {
  const notes = new Map()
  return {
    /**
     * Record what the user clicked for one call.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     * @param entry - the action, and whatever the card was looking at.
     * @returns whether a note was written.
     */
    note(sessionId, callId, entry) {
      const key = pendingKey(sessionId, callId)
      if (key === null) return false
      notes.delete(key)
      notes.set(key, entry)
      while (notes.size > limit) {
        const oldest = notes.keys().next().value
        if (oldest === undefined) break
        notes.delete(oldest)
      }
      return true
    },
    /**
     * Read and clear one call's note.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     * @returns the note, or null.
     */
    take(sessionId, callId) {
      const key = pendingKey(sessionId, callId)
      if (key === null) return null
      const entry = notes.get(key) ?? null
      notes.delete(key)
      return entry
    },
    /**
     * Read one call's note without clearing it.
     * @param sessionId - owning session id.
     * @param callId - tool call id.
     * @returns the note, or null.
     */
    peek(sessionId, callId) {
      const key = pendingKey(sessionId, callId)
      return key === null ? null : notes.get(key) ?? null
    },
    /**
     * How many notes are waiting.
     * @returns the note count.
     */
    size() {
      return notes.size
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
