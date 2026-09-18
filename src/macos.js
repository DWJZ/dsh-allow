/**
 * The macOS backend: how this policy's five capabilities compile to an
 * `sandbox-exec` (Seatbelt/SBPL) profile.
 *
 * The mapping was measured against the kernel, not assumed:
 *
 *   read    -> file-read*
 *   write   -> file-write-data, file-write-attributes, file-write-mode,
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
  read: Object.freeze(['file-read*']),
  write: Object.freeze([
    'file-write-data', 'file-write-attributes', 'file-write-mode',
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

/** The path filter for one rule: a subtree for `recursive`, one file otherwise. */
function filterFor(rule) {
  return rule.recursive === true ? `(subpath ${sbplString(rule.path)})` : `(literal ${sbplString(rule.path)})`
}

/**
 * Compile one rule set into an SBPL profile.
 *
 * The profile starts from the platform default and then fences each capability
 * separately, so a rule that grants `write` and `create` but not `delete`
 * produces exactly that: no unlink for anyone in the subtree, including child
 * processes, which inherit the profile.
 * @param options - the rules, and whether to fence reads and executions too.
 * @returns the profile text for `sandbox-exec -p`.
 */
export function seatbeltProfile({ rules, includeRead = false, includeExecute = true }) {
  const clauses = ['(version 1)', '(allow default)', '(deny file-write*)']
  for (const device of ALWAYS_WRITABLE_DEVICES) {
    clauses.push(`(allow file-write* (literal ${sbplString(device)}))`)
  }
  for (const rule of rules) {
    const allowed = new Set()
    for (const operation of OPERATIONS) {
      if (rule.access?.[operation] === true) for (const name of SEATBELT_OPERATIONS[operation]) allowed.add(name)
    }
    if (allowed.size === 0) continue
    clauses.push(`(allow ${[...allowed].join(' ')} ${filterFor(rule)})`)
  }
  if (includeExecute) {
    // `execute` is a capability too: with the fence in place, only the rules
    // that grant it may start a program.
    clauses.push('(deny process-exec)')
    for (const rule of rules) {
      if (rule.access?.execute !== true) continue
      clauses.push(`(allow process-exec ${filterFor(rule)})`)
    }
  }
  if (includeRead) {
    clauses.push('(deny file-read*)')
    for (const rule of rules) {
      if (rule.access?.read !== true) continue
      clauses.push(`(allow file-read* ${filterFor(rule)})`)
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
    'read: Seatbelt can deny file-read*, but macOS needs a large read baseline; a deny-everything-then-allow profile is only usable with the full system rule set.',
    'create without write: file-write-create lets a process make an empty file; filling it also needs file-write-data, so a create-only rule produces empty files only.',
    'rename counts as delete of the source plus create of the target, so it needs both grants.',
    'the filter matches the resolved path: rule paths must be canonical.',
  ]
}
