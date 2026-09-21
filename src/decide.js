/**
 * The decision: one command line plus the live rule set, and the answer is
 * `allow`, `prompt`, or `forbidden`.
 *
 * Nothing here reads a model or a network. The command is parsed, the paths it
 * touches are derived, each `(path, operation)` pair is resolved against the
 * rules, and the strictest outcome wins: one missing capability asks about the
 * whole line, and one platform-protected write refuses it.
 *
 * Lines whose effects cannot be read at all — an inline `python -c`, an
 * `eval`, a program computed at run time — are not judged by their text. They
 * are deferred to the OS sandbox, which bounds the process itself; only when no
 * sandbox mode is enforcing does deferring stop being safe, and then the line
 * asks.
 *
 * @module dsh-allow/decide
 */
import { effectsOf } from './effects.js'
import {
  baselineRules, canonicalPath, isUsableRule, protectedRefusal, resolveOperation, suggestGrants,
} from './fspolicy.js'
import { parseCommandLine } from './parse.js'

/** Sandbox modes that actually fence a process; the plugin may defer to these. */
const ENFORCING_MODES = new Set(['read-only', 'workspace-write'])

/**
 * Evaluate one complete command line.
 * @param request - the raw command, its directory, the rules, the sandbox mode,
 *   the files the permission store owns, and what the kernel currently fences.
 * @returns the decision, the effects behind it, and what could be remembered.
 */
export function evaluateCommandLine(request) {
  const {
    command, cwd = '/', home = '/', workspaceRoot, harnessHome,
    mode = 'workspace-write', rules = [], sessionRules = [], grants = [],
    protectedFiles = [], enforcement = null,
  } = request
  const parsed = parseCommandLine(command, { home })
  if (!parsed.analyzable && parsed.syntaxError === true) {
    return {
      decision: 'forbidden',
      reason: 'the shell grammar cannot parse this line, so it can never run as written',
      effects: [],
      missing: [],
      unknown: [],
      suggestions: [],
      commands: [],
      // The unparseable branch answers before any rule is consulted, so callers
      // reading `usedRules` see the same empty list every other refusal carries.
      usedRules: [],
      analyzable: false,
    }
  }
  const allRules = [
    ...rules.filter(isUsableRule),
    ...grants.filter(isUsableRule),
    ...baselineRules({ workspaceRoot, harnessHome, home, mode }),
    ...sessionRules.filter(isUsableRule),
  ]
  const derived = parsed.analyzable
    ? effectsOf(parsed, { cwd, home })
    : { effects: [], unknown: [{ operation: null, path: null, command, reason: parsed.reason }], commands: [] }

  const missing = []
  const usedRules = new Map()
  for (const effect of derived.effects) {
    const refusal = protectedRefusal(effect.path, effect.operation, protectedFiles)
    if (refusal !== null) {
      return {
        decision: 'forbidden',
        reason: `${refusal}, so ${effect.operation} is refused for every writer`,
        effects: derived.effects,
        missing: [],
        unknown: derived.unknown,
        suggestions: [],
        commands: derived.commands,
        usedRules: [],
        analyzable: parsed.analyzable,
      }
    }
    const resolved = resolveOperation({
      path: effect.path,
      realPath: effect.realPath,
      operation: effect.operation,
      rules: allRules,
    })
    if (resolved.granted) usedRules.set(resolved.rule.id, resolved.rule)
    else missing.push({ ...effect, rule: null })
  }

  // An unknown path for a known operation is not deferrable: the policy can see
  // that a delete is happening without being able to check where, so it asks —
  // unless the operation is already granted for the working directory, in which
  // case the sandbox bounds the run-time path to what the user opened.
  const workingDirectory = canonicalPath(cwd, { cwd, home })
  const blocked = []
  for (const entry of derived.unknown) {
    if (entry.operation === null) continue
    const resolved = resolveOperation({
      path: workingDirectory, realPath: workingDirectory, operation: entry.operation, rules: allRules,
    })
    if (resolved.granted) usedRules.set(resolved.rule.id, resolved.rule)
    else blocked.push(entry)
  }
  // Only a wholly opaque program — inline code, an unreadable shell program —
  // is left to the sandbox, and only when that sandbox can actually be trusted
  // for it: either the kernel fences all five capabilities, or this line's
  // directory already grants all five, so there is nothing left to withhold.
  const opaque = derived.unknown.filter(entry => entry.operation === null)
  const grantedHere = operation => resolveOperation({
    path: workingDirectory, realPath: workingDirectory, operation, rules: allRules,
  }).granted
  const openHere = ['read', 'write', 'create', 'delete', 'execute'].every(grantedHere)
  const fenced = enforcement === null
    ? Object.fromEntries(['read', 'write', 'create', 'delete', 'execute'].map(operation => [operation, false]))
    : enforcement.capabilities
  const fencedEverywhere = ['read', 'write', 'create', 'delete', 'execute'].every(operation => fenced[operation] === true)
  const opener = openHere ? 'this directory grants every capability' : 'the sandbox fences every capability'
  const deferred = opaque.length > 0 && ENFORCING_MODES.has(mode) && (fencedEverywhere || openHere)
  if (missing.length === 0 && blocked.length === 0 && (opaque.length === 0 || deferred)) {
    return {
      decision: 'allow',
      reason: opaque.length === 0
        ? 'every filesystem capability this line needs is granted'
        : `the line's effects cannot be read from its text, and ${opener}`,
      effects: derived.effects,
      missing: [],
      unknown: derived.unknown,
      suggestions: [],
      commands: derived.commands,
      usedRules: [...usedRules.values()],
      analyzable: parsed.analyzable,
    }
  }

  const unreachable = opaque.length > 0 && !deferred
  const suggestions = suggestGrants(
    missing.length > 0 || blocked.length > 0
      ? [...missing, ...blocked.map(entry => ({ operation: entry.operation, path: undefined }))]
      : ['read', 'write', 'create', 'delete', 'execute'].map(operation => ({ operation })),
    { cwd },
  )
  const what = missing.length > 0
    ? missing.map(entry => `${entry.operation}(${entry.path})`).join(', ')
    : derived.unknown.map(entry => `${String(entry.operation ?? 'the line')}: ${entry.reason}`).join('; ')
  const why = missing.length > 0 || blocked.length > 0
    ? `filesystem permission required: ${what}`
    : fencedEverywhere
      ? `the effects of this line cannot be determined (${what}) and no sandbox mode is enforcing them`
      : `the effects of this line cannot be determined (${what}), and the sandbox cannot fence every capability: grant them for this directory to let opaque programs run`
  return {
    decision: 'prompt',
    reason: why,
    effects: derived.effects,
    missing: [...missing, ...blocked.map(entry => ({
      operation: entry.operation, path: undefined, command: entry.command, computed: true,
    }))],
    unknown: derived.unknown,
    suggestions,
    commands: derived.commands,
    usedRules: [...usedRules.values()],
    analyzable: parsed.analyzable,
    unreachable,
  }
}
