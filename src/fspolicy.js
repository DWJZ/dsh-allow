/**
 * The filesystem permission model: capabilities, canonical paths, rule
 * precedence, and the platform baseline.
 *
 * A permission question is always one `(path, operation)` pair, and the answer
 * comes from the rule set alone — never from the name of the program that asked.
 * Rules only GRANT; "not granted" is the default, so a path nobody spoke about
 * is closed, and a rule written for one file never opens its folder.
 *
 * Precedence, highest first (each level is consulted in turn; the lowest level
 * that states the operation wins):
 *
 *   0. protected system paths — refused for every writer, user rules included
 *   1. explicit rules (`source: user` or `session`)
 *   2. rules from the workspace's own `.dsh-allow.json`
 *   3. the platform baseline (workspace, temp areas, system read/execute)
 *   4. the global default: not granted
 *
 * Inside one level the more specific path wins, and a rule that names the
 * operation beats one that only names other operations. Paths are compared as
 * canonical absolute paths component by component — `..`, `.`, symlinked
 * ancestors and relative spellings are resolved first, so `/tmp/x` and
 * `/private/tmp/x` are one path and a rule can never be escaped with `../`.
 *
 * @module dsh-allow/fspolicy
 */
import { realpathSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, normalize } from 'node:path'

/** The five filesystem capabilities this policy speaks about. */
export const OPERATIONS = Object.freeze(['read', 'write', 'create', 'delete', 'execute'])

/** Precedence levels; the global default is one past the last level. */
export const LEVELS = Object.freeze({ user: 1, workspace: 2, baseline: 3 })

/** The level of the implicit "nobody granted this" answer. */
export const DEFAULT_LEVEL = 4

/** Rule sources accepted from disk and from the UI. */
export const RULE_SOURCES = Object.freeze(['user', 'workspace', 'system', 'session'])

/** How many leading components a `never`-protected path resists. */
const PROTECTED = Object.freeze([
  { path: '/System', operations: ['write', 'create', 'delete'] },
  { path: '/bin', operations: ['write', 'create', 'delete'] },
  { path: '/sbin', operations: ['write', 'create', 'delete'] },
  { path: '/usr', operations: ['write', 'create', 'delete'] },
  { path: '/AppleInternal', operations: ['write', 'create', 'delete'] },
  { path: '/private/var/db', operations: ['write', 'create', 'delete'] },
  { path: '/dev', operations: ['write', 'create', 'delete'] },
])

/** Paths under a protected root that are ordinary writable files anyway. */
const PROTECTED_EXCEPTIONS = Object.freeze([
  '/usr/local',
  '/dev/null',
  '/dev/stdout',
  '/dev/stderr',
  '/dev/fd',
  '/dev/tty',
  '/dev/zero',
  '/dev/random',
  '/dev/urandom',
])

/** System paths macOS itself must read and start. */
const SYSTEM_READ_EXECUTE = Object.freeze([
  '/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/lib', '/usr/libexec',
  '/System', '/Library/Apple', '/Library/Developer',
])

/** System paths that are readable but hold no program to start. */
const SYSTEM_READ = Object.freeze([
  '/etc', '/private/etc', '/var', '/private/var', '/usr', '/usr/share',
  '/Library', '/opt/homebrew', '/dev', '/Applications',
])

/** Every capability, for the baseline rules that grant all of them. */
const ALL_ACCESS = Object.freeze({ read: true, write: true, create: true, delete: true, execute: true })

/**
 * Whether `target` is `ancestor` itself or lies underneath it, compared by path
 * components so `/w/build-2` is never treated as being inside `/w/build`.
 * @param ancestor - the containing path.
 * @param target - the path to test.
 * @returns true when the target lies within the ancestor.
 */
export function pathWithin(ancestor, target) {
  if (ancestor === target) return true
  if (ancestor === '/') return target.startsWith('/')
  return target.startsWith(ancestor.endsWith('/') ? ancestor : `${ancestor}/`)
}

/**
 * Resolve one path the way the policy compares it: `~` expanded, relative to
 * `cwd`, `.`/`..` collapsed, and every existing ancestor replaced by its real
 * path so symlinks cannot spell one location two ways.
 * @param target - path text as written.
 * @param options - the effective working directory and home directory.
 * @returns an absolute canonical path.
 */
export function canonicalPath(target, { cwd = '/', home = '/' } = {}) {
  let text = String(target ?? '')
  if (text === '~') text = home
  else if (text.startsWith('~/')) text = `${home}/${text.slice(2)}`
  if (!text.startsWith('/')) text = `${cwd}/${text}`
  const lexical = normalize(text)
  let head = lexical
  const tail = []
  for (;;) {
    try {
      const real = realpathSync.native(head)
      return tail.length === 0 ? real : normalize(`${real}/${[...tail].reverse().join('/')}`)
    }
    catch {
      // The path (or a prefix of it) does not exist yet: keep walking up to the
      // deepest ancestor that does, and re-append the missing tail verbatim.
    }
    const parent = dirname(head)
    if (parent === head) return lexical
    tail.push(basename(head))
    head = parent
  }
}

/**
 * Whether a platform rule refuses this operation for every writer.
 * @param path - canonical absolute path.
 * @param operation - the capability being asked for.
 * @returns the refusal reason, or null when the path is not platform-protected.
 */
export function protectedRefusal(path, operation) {
  if (operation !== 'write' && operation !== 'create' && operation !== 'delete') return null
  if (PROTECTED_EXCEPTIONS.some(exception => pathWithin(exception, path))) return null
  for (const entry of PROTECTED) {
    if (!entry.operations.includes(operation)) continue
    if (pathWithin(entry.path, path)) return `the platform reserves ${entry.path}`
  }
  return null
}

/**
 * Build one well-formed rule.
 * @param fields - path, access map, optional recursive flag, source, and label.
 * @returns the rule with defaults filled in.
 */
export function makeRule(fields) {
  const path = canonicalPath(fields.path, { cwd: '/', home: '/' })
  const access = {}
  for (const operation of OPERATIONS) {
    if (fields.access?.[operation] === true) access[operation] = true
  }
  return {
    id: fields.id ?? `${fields.source ?? 'user'}:${path}${fields.recursive === false ? '' : '/**'}`,
    path,
    recursive: fields.recursive !== false,
    access,
    source: RULE_SOURCES.includes(fields.source) ? fields.source : 'user',
    ...(fields.baseline === true ? { baseline: true } : {}),
    ...(fields.note === undefined ? {} : { note: fields.note }),
  }
}

/**
 * The precedence level one rule belongs to.
 * @param rule - the rule to rank.
 * @returns the level number (lower is more authoritative).
 */
export function levelOf(rule) {
  if (rule.baseline === true) return LEVELS.baseline
  return rule.source === 'workspace' ? LEVELS.workspace : LEVELS.user
}

/**
 * Whether one rule speaks about one canonical path.
 * @param rule - the rule.
 * @param path - canonical absolute path.
 * @returns true when the rule covers the path.
 */
export function ruleCovers(rule, path) {
  return rule.recursive === true ? pathWithin(rule.path, path) : rule.path === path
}

/**
 * Whether a rule is well-formed enough to take part in a decision.
 * @param rule - the candidate rule.
 * @returns true when the rule can be matched.
 */
export function isUsableRule(rule) {
  return typeof rule?.path === 'string' && rule.path.startsWith('/')
    && rule.access !== null && typeof rule.access === 'object'
}

/**
 * Resolve one capability for one path.
 *
 * Both the spelling the caller used and the path behind its symlinks are
 * matched, so a rule written for `/opt/homebrew/bin/gh` and a rule written for
 * the Cellar binary it points at each authorize the same program — without
 * either of them authorizing the rest of `/opt/homebrew`.
 * @param request - the canonical path, its real path, the operation, and rules.
 * @returns whether the capability is granted, and by which rule.
 */
export function resolveOperation({ path, realPath = path, operation, rules }) {
  const spellings = path === realPath ? [path] : [path, realPath]
  const levels = [...new Set(rules.map(levelOf))].sort((left, right) => left - right)
  for (const level of levels) {
    const matching = rules.filter(rule => levelOf(rule) === level
      && spellings.some(spelling => ruleCovers(rule, spelling)))
    if (matching.length === 0) continue
    const granted = matching
      .filter(rule => rule.access?.[operation] === true)
      .sort((left, right) => right.path.length - left.path.length)[0]
    if (granted !== undefined) return { granted: true, rule: granted, level }
  }
  return { granted: false, rule: null, level: DEFAULT_LEVEL }
}

/**
 * The rules the platform contributes on its own: the workspace, the temp areas,
 * the harness home, and the system paths macOS needs. The workspace grants
 * everything except `delete`; the temp areas and the harness home grant all
 * five; system paths grant read and execute, and Homebrew's prefix grants read
 * only — every Homebrew binary is authorized one file at a time.
 * @param options - workspace root, harness home, and the session's sandbox mode.
 * @returns baseline rules, in no particular order.
 */
export function baselineRules({ workspaceRoot, harnessHome, home, mode = 'workspace-write' } = {}) {
  const rules = []
  const readOnly = mode === 'read-only'
  if (typeof workspaceRoot === 'string' && workspaceRoot !== '') {
    rules.push(makeRule({
      path: workspaceRoot,
      recursive: true,
      source: 'system',
      baseline: true,
      access: readOnly ? { read: true, execute: true } : { read: true, write: true, create: true, execute: true },
      note: 'the session workspace',
    }))
  }
  for (const temp of [tmpdir(), '/tmp']) {
    rules.push(makeRule({
      path: temp,
      recursive: true,
      source: 'system',
      baseline: true,
      access: readOnly ? { read: true, execute: true } : ALL_ACCESS,
      note: 'a platform temp area',
    }))
  }
  if (typeof harnessHome === 'string' && harnessHome !== '') {
    rules.push(makeRule({
      path: harnessHome,
      recursive: true,
      source: 'system',
      baseline: true,
      access: readOnly ? { read: true } : { read: true, write: true, create: true, delete: true },
      note: 'the harness home',
    }))
  }
  for (const path of SYSTEM_READ_EXECUTE) {
    rules.push(makeRule({
      path, recursive: true, source: 'system', baseline: true,
      access: { read: true, execute: true }, note: 'a system path',
    }))
  }
  for (const path of SYSTEM_READ) {
    rules.push(makeRule({
      path, recursive: true, source: 'system', baseline: true,
      access: { read: true }, note: 'a system path',
    }))
  }
  // `$HOME` itself is deliberately absent: everything outside the workspace but
  // the read-only system paths stays closed until the user opens it.
  void home
  return rules
}

/**
 * Describe one rule the way the card and `/allow list` render it.
 * @param rule - the rule to describe.
 * @returns a short human label.
 */
export function describeRule(rule) {
  const operations = OPERATIONS.filter(operation => rule.access?.[operation] === true)
  const scope = rule.recursive === true ? `${rule.path}${rule.path === '/' ? '' : '/'}**` : rule.path
  const prefix = rule.source === 'session' ? 'once：' : ''
  return `${prefix}${operations.join('+')} · ${scope}`
}

/**
 * Normalize one rule read from disk, dropping what cannot be used.
 * @param rule - the stored record.
 * @param source - the source to force (user rules and workspace rules).
 * @returns the usable rule, or null.
 */
export function normalizeStoredRule(rule, source) {
  if (typeof rule?.path !== 'string' || rule.path === '') return null
  const normalized = makeRule({
    ...rule,
    path: rule.path,
    source,
    recursive: rule.recursive !== false,
  })
  if (Object.keys(normalized.access).length === 0) return null
  if (typeof rule.id === 'string' && rule.id !== '') normalized.id = rule.id
  normalized.hits = Number(rule.hits) || 0
  if (typeof rule.createdAt === 'string') normalized.createdAt = rule.createdAt
  if (typeof rule.note === 'string') normalized.note = rule.note
  return normalized
}

/**
 * Whether a directory exists at one canonical path.
 * @param path - canonical absolute path.
 * @returns true when the path names an existing directory.
 */
export function isDirectory(path) {
  try {
    return statSync(path).isDirectory()
  }
  catch {
    // Not there yet: a rule for it covers the file that is about to be created.
    return false
  }
}

/**
 * The grants worth offering for one missing capability: the narrowest one that
 * covers what the user just saw, and the folder around it.
 * @param missing - the missing `{operation, path}` entries.
 * @param options - the effective working directory.
 * @returns one suggestion per scope, narrowest first.
 */
export function suggestGrants(missing, { cwd }) {
  const narrow = new Map()
  const folder = new Map()
  for (const entry of missing) {
    if (typeof entry.path !== 'string') {
      // The operation is known but the path is not (a variable, a here-document
      // program): the narrowest scope the user can name is the working directory.
      const key = `${cwd}\u0000true`
      const current = narrow.get(key) ?? { path: cwd, recursive: true, access: {} }
      current.access[entry.operation] = true
      narrow.set(key, current)
      continue
    }
    const recurse = isDirectory(entry.path)
    const key = `${entry.path}\u0000${String(recurse)}`
    const exact = narrow.get(key) ?? { path: entry.path, recursive: recurse, access: {} }
    exact.access[entry.operation] = true
    narrow.set(key, exact)
    const parent = dirname(entry.path)
    if (parent !== entry.path) {
      const folderKey = `${parent}\u0000true`
      const current = folder.get(folderKey) ?? { path: parent, recursive: true, access: {} }
      current.access[entry.operation] = true
      folder.set(folderKey, current)
    }
  }
  const suggestions = []
  for (const entry of narrow.values()) {
    suggestions.push({ scope: 'file', ...entry, label: describeRule({ ...entry, source: 'user' }) })
  }
  const exact = new Set(suggestions.map(suggestion => `${suggestion.path}\u0000${String(suggestion.recursive)}`))
  for (const entry of folder.values()) {
    const key = `${entry.path}\u0000true`
    if (exact.has(key)) continue
    suggestions.push({ scope: 'folder', ...entry, label: describeRule({ ...entry, source: 'user' }) })
  }
  void cwd
  return suggestions.slice(0, 2)
}
