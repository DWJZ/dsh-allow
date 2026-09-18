/**
 * The macOS backend: how this policy's five capabilities compile to an
 * `sandbox-exec` (Seatbelt/SBPL) profile.
 *
 * The mapping was measured against the kernel, not assumed:
 *
 *   read    -> file-read*
 *   write   -> file-write-data, file-write-xattr, file-write-mode,
 *              file-write-flags, file-write-owner, file-write-times
 *   create  -> file-write-create
 *   delete  -> file-write-unlink   (unlink, rmdir, and rename-away)
 *   execute -> process-exec
 *
 * `delete` is therefore genuinely separable from `write`: a profile that grants
 * `file-write-data`/`file-write-create` under a subtree and withholds
 * `file-write-unlink` lets a process rewrite and create files there while
 * `rm`, `rmdir` and `rename` all fail with EPERM. Seatbelt filters match the
 * path the kernel resolved, so every rule path must be canonical — a grant
 * spelled `/tmp/x` matches nothing when the kernel sees `/private/tmp/x`.
 *
 * DSH's own `sandbox-local` profile currently grants `file-write*` under the
 * workspace, which includes unlink; this module is the reference for the
 * capability split and is exercised by `test/sandbox.integration.mjs`.
 *
 * @module dsh-allow/macos
 */
import { OPERATIONS } from './fspolicy.js'

/** The SBPL operations behind each capability. */
export const SEATBELT_OPERATIONS = Object.freeze({
  // Contents, not metadata: a fenced read still has to let the kernel look up
  // every path component, which is what `file-read-metadata` is allowed for.
  read: Object.freeze(['file-read-data']),
  write: Object.freeze([
    'file-write-data', 'file-write-xattr', 'file-write-mode',
    'file-write-flags', 'file-write-owner', 'file-write-times',
  ]),
  create: Object.freeze(['file-write-create']),
  delete: Object.freeze(['file-write-unlink']),
  execute: Object.freeze(['process-exec']),
})

/** Devices a confined process may always use as sinks, whatever the rules say. */
export const ALWAYS_WRITABLE_DEVICES = Object.freeze(['/dev/null', '/dev/stdout', '/dev/stderr'])

/** Quote one path as an SBPL string literal. */
function sbplString(path) {
  return `"${path.replaceAll('\\', String.raw`\\`).replaceAll('"', String.raw`\"`)}"`
}

/** The path filters for one rule: every spelling it was granted under. */
function filtersFor(rule) {
  const paths = rule.spelling === undefined ? [rule.path] : [rule.path, rule.spelling]
  return paths.map(path => (rule.recursive === true ? `(subpath ${sbplString(path)})` : `(literal ${sbplString(path)})`))
}

/**
 * Compile one rule set into an SBPL profile.
 *
 * The profile starts from the platform default and then fences each capability
 * separately, so a rule that grants `write` and `create` but not `delete`
 * produces exactly that: no unlink for anyone in the subtree, including child
 * processes, which inherit the profile. Clauses are order-sensitive in SBPL —
 * the last match wins — so refusals that must survive every grant are written
 * last.
 *
 * Reads are fenced in one of two ways. `includeRead` withholds every file's
 * contents and re-allows them rule by rule, which macOS itself does not
 * survive; `readDenyRoots` is the usable form: the platform keeps reading what
 * it needs, the user-data areas named there stop being readable, and the rules
 * re-open the workspace, the temp areas and everything the user approved.
 * @param options - the rules, the read fence, the execute fence, the user-data
 *   areas to withhold, and files no grant may make writable.
 * @returns the profile text for `sandbox-exec -p`.
 */
export function seatbeltProfile({
  rules, includeRead = false, includeExecute = true, deniedPaths = [], readDenyRoots = [],
}) {
  const clauses = ['(version 1)', '(allow default)', '(deny file-write*)']
  for (const device of ALWAYS_WRITABLE_DEVICES) {
    clauses.push(`(allow file-write* (literal ${sbplString(device)}))`)
  }
  if (includeRead) {
    // Path lookup itself needs metadata; file CONTENTS are what the fence
    // withholds, so a process can still resolve a path it may not open.
    clauses.push('(deny file-read-data)', '(allow file-read-metadata)')
  }
  for (const root of readDenyRoots) {
    if (typeof root !== 'string' || root === '') continue
    // Before the rule allows, so a grant for a path inside one of these areas
    // re-opens exactly that path and nothing else.
    clauses.push(`(deny file-read-data (subpath ${sbplString(root)}))`)
  }
  for (const rule of rules) {
    const allowed = new Set()
    for (const operation of OPERATIONS) {
      if (rule.access?.[operation] === true) for (const name of SEATBELT_OPERATIONS[operation]) allowed.add(name)
    }
    if (allowed.size === 0) continue
    clauses.push(`(allow ${[...allowed].join(' ')} ${filtersFor(rule).join(' ')})`)
  }
  if (includeExecute) {
    // `execute` is a capability too: with the fence in place, only the rules
    // that grant it may start a program.
    clauses.push('(deny process-exec)')
    for (const rule of rules) {
      if (rule.access?.execute !== true) continue
      clauses.push(`(allow process-exec ${filtersFor(rule).join(' ')})`)
    }
  }
  for (const path of deniedPaths) {
    if (typeof path !== 'string' || path === '') continue
    // Named operations, not `file-write*`: a wildcard denial loses to a
    // specific `(allow file-write-data …)`, which is exactly what a rule for
    // the surrounding folder contributed.
    const operations = [...SEATBELT_OPERATIONS.write, ...SEATBELT_OPERATIONS.create, ...SEATBELT_OPERATIONS.delete]
    for (const operation of operations) {
      clauses.push(`(deny ${operation} (literal ${sbplString(path)}))`)
      clauses.push(`(deny ${operation} (subpath ${sbplString(path)}))`)
    }
  }
  return clauses.join(' ')
}

/**
 * The `sandbox-exec` argv that runs one command under a compiled profile.
 * @param profile - profile text from {@link seatbeltProfile}.
 * @param argv - the command to run.
 * @returns argv for {@link import('node:child_process').spawnSync}.
 */
export function seatbeltArgs(profile, argv) {
  return ['/usr/bin/sandbox-exec', '-p', profile, '--', ...argv]
}

/**
 * The capabilities this backend cannot separate, for honest reporting.
 * @returns one line per limitation.
 */
export function backendLimitations() {
  return [
    'read: the contents fence denies file-read-data and keeps file-read-metadata allowed so paths still resolve; macOS itself reads outside the rules (dyld caches, XPC, preferences), so a fenced read is probed before it is trusted.',
    'create without write: file-write-create lets a process make an empty file; filling it also needs file-write-data, so a create-only rule produces empty files only.',
    'rename counts as delete of the source plus create of the target, so it needs both grants.',
    'the filter matches the resolved path: rule paths must be canonical.',
  ]
}
