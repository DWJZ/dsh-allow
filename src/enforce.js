/**
 * Runtime enforcement: the effective filesystem policy, compiled into the
 * profile the confined child actually runs under.
 *
 * The plugin's decision layer answers "may this command start?". This module
 * answers the question the kernel has to answer for everything that command
 * then does, including the children it starts and the code the command line
 * never showed:
 *
 *   effective FsPolicy  →  Seatbelt profile  →  the confined process tree
 *
 * DSH's `ctx.sandbox` provider owns process confinement, and it accepts one
 * provider per name, so this module refines the provider that is already
 * registered instead of replacing it: it wraps that instance's `confine` and,
 * on macOS, returns the caller's argv wrapped in the profile compiled here.
 * Everything it does not handle — every non-darwin platform, an unavailable
 * runner, a policy it cannot compile — delegates to the original `confine`
 * unchanged.
 *
 * How much of the policy reaches the kernel is probed once per (mode, root,
 * capability set) and reported:
 *
 *   full     write, create, delete, read and execute are all fenced
 *   writes   write, create and delete are fenced; read and execute are not
 *   off      nothing of this policy is fenced; the decision layer then refuses
 *            to let opaque code run on the assumption that it is
 *
 * The write fence is what separates `delete` from `write`: a profile that
 * grants `file-write-data` and `file-write-create` while withholding
 * `file-write-unlink` lets a process rewrite and create files and still fails
 * `rm`, `rmdir`, `rename` and `python -c 'os.remove(…)'` with EPERM.
 *
 * @module dsh-allow/enforce
 */
import { spawnSync } from 'node:child_process'
import { existsSync } from 'node:fs'
import { OPERATIONS, baselineRules } from './fspolicy.js'
import { seatbeltProfile } from './macos.js'
import { readRules } from './store.js'

/** The macOS profile runner. */
const SANDBOX_EXEC = '/usr/bin/sandbox-exec'

/** stderr a Seatbelt denial produces, for the shell tool's denial classification. */
const SEATBELT_DENIALS = Object.freeze(['operation not permitted'])

/** A profile the kernel refuses is a runner failure, not a command failure. */
const SEATBELT_RUNNER_RULES = Object.freeze([{ fatalSignatures: ['sandbox-exec: '] }])

/**
 * The user-data areas whose file CONTENTS the usable read fence withholds. The
 * platform keeps reading everything it needs (nothing here is part of a macOS
 * runtime path, except a user-installed toolchain, which the baseline re-opens),
 * and a rule for a path inside one of them re-opens exactly that path.
 */
export const SENSITIVE_READ_ROOTS = Object.freeze(['/Users', '/Volumes'])

/**
 * The fence levels a compiled profile can carry, strongest first.
 *
 * - `full` withholds every read and re-allows rule by rule. macOS aborts under
 *   it, so it is probe-gated and rarely installable.
 * - `guarded` withholds the user-data areas and re-allows rule by rule: the
 *   read fence that a normal macOS runtime survives.
 * - `process` fences execution and writes only.
 * - `writes` fences writes only.
 */
const CAPABILITY_SETS = Object.freeze({
  full: Object.freeze({ read: 'all', execute: true }),
  guarded: Object.freeze({ read: 'sensitive', execute: true }),
  process: Object.freeze({ read: 'none', execute: true }),
  writes: Object.freeze({ read: 'none', execute: false }),
})

/** The fence levels, strongest first. */
const CAPABILITY_ORDER = Object.freeze(['full', 'guarded', 'process', 'writes'])

/** The command a confinement is about to run, when it is a shell invocation. */
export function commandOfArgv(argv) {
  if (!Array.isArray(argv) || argv.length < 3) return null
  const program = String(argv[0] ?? '').split('/').pop()
  if (program !== 'bash' && program !== 'sh' && program !== 'zsh') return null
  const flagIndex = argv.findIndex((token, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/u.test(String(token)))
  if (flagIndex === -1) return null
  return typeof argv[flagIndex + 1] === 'string' ? argv[flagIndex + 1] : null
}

/**
 * The profile one policy compiles to.
 * @param request - the mode, the workspace root, the rules, and the fence level.
 * @returns the SBPL profile text.
 */
export function compileProfile({ mode, workspaceRoot, rules, protectedFiles = [], capabilities = 'full' }) {
  const fence = CAPABILITY_SETS[capabilities] ?? CAPABILITY_SETS.full
  const readOnly = mode === 'read-only'
  const fenced = rules.map(rule => {
    if (!readOnly) return rule
    // A read-only session is the outer fence: no rule may hand out a write.
    const access = {}
    for (const operation of OPERATIONS) {
      if ((operation === 'read' || operation === 'execute') && rule.access?.[operation] === true) access[operation] = true
    }
    return { ...rule, access }
  })
  return seatbeltProfile({
    rules: fenced,
    includeRead: fence.read === 'all',
    includeExecute: fence.execute,
    readDenyRoots: fence.read === 'sensitive' ? SENSITIVE_READ_ROOTS : [],
    // The permission store is refused after every grant, so a rule that covers
    // its directory still cannot make it writable.
    deniedPaths: protectedFiles,
  })
}

/**
 * Whether a profile can be applied and still start a shell that reads the
 * workspace. Probes run from this (unsandboxed) process, so they answer for
 * the kernel rather than for the caller's own confinement.
 *
 * The runner's presence is read through the injected `exists` rather than the
 * host, so a test on a platform without Seatbelt can still drive every probe
 * outcome.
 * @param profile - the compiled profile to try.
 * @param options - the workspace root, the process spawner, and the runner's
 *   presence check.
 * @returns true when the profile applies and the probe command succeeds under it.
 */
export function probeProfile(profile, { workspaceRoot, spawn = spawnSync, exists = existsSync }) {
  if (!exists(SANDBOX_EXEC)) return false
  const probes = [
    ['/bin/sh', '-c', 'exit 0'],
    ['/usr/bin/env'],
    ['/bin/ls', workspaceRoot],
  ]
  for (const argv of probes) {
    let probe
    try {
      probe = spawn(SANDBOX_EXEC, ['-p', profile, '--', ...argv], { stdio: 'ignore', timeout: 5000 })
    }
    catch {
      // A missing or unusable runner: nothing to probe.
      return false
    }
    if (probe.status !== 0) return false
  }
  return true
}

/**
 * Build the enforcer for one deployment.
 *
 * @param options - configuration, the session-grant store, the logger, the
 *   platform, spawner and runner-presence check (injectable for tests), and the
 *   pass-through reader that supplies the caller's own `next()`-style spawn for
 *   probes.
 * @returns install/uninstall, the per-policy profile, and the reported status.
 */
export function createEnforcer({
  config, grants, logger, platform = process.platform, spawn = spawnSync, exists = existsSync,
}) {
  const verdicts = new Map()
  let installed = false
  let original = null
  let provider = null
  const report = { state: 'off', reason: 'not installed', capabilities: {} }

  /**
   * The fence level one policy can carry: the strongest set the kernel accepts
   * for this mode and root, probed once and remembered.
   */
  const fenceFor = (policy, rules) => {
    if (config.enforce === 'off') return { capabilities: 'off', reason: 'disabled by configuration' }
    if (platform !== 'darwin') return { capabilities: 'off', reason: `no Seatbelt backend on ${platform}` }
    if (!exists(SANDBOX_EXEC)) return { capabilities: 'off', reason: `${SANDBOX_EXEC} is not installed` }
    // `enforce: all` is the one setting that does not accept a weaker fence: it
    // is how a deployment says "the read fence or nothing".
    const requested = config.enforce === 'auto'
      ? CAPABILITY_ORDER
      : (CAPABILITY_ORDER.includes(config.enforce) ? [config.enforce] : CAPABILITY_ORDER)
    const key = `${policy.mode}\u0000${policy.workspaceRoot}`
    const cached = verdicts.get(key)
    if (cached !== undefined) return cached
    let verdict = { capabilities: 'off', reason: 'no capability set applied' }
    for (const capabilities of requested) {
      const profile = compileProfile({
        mode: policy.mode,
        workspaceRoot: policy.workspaceRoot,
        rules,
        protectedFiles: config.protectedFiles,
        capabilities,
      })
      if (probeProfile(profile, { workspaceRoot: policy.workspaceRoot, spawn, exists })) {
        const fence = CAPABILITY_SETS[capabilities]
        verdict = {
          capabilities,
          reason: `${['write', 'create', 'delete'].join(', ')} are fenced`
            + (fence.execute ? '; execute is fenced' : '; execute is not')
            + (fence.read === 'all'
              ? '; every read is fenced'
              : (fence.read === 'sensitive'
                ? `; reads under ${SENSITIVE_READ_ROOTS.join(' and ')} are fenced`
                : '; read is not')),
        }
        break
      }
    }
    if (config.enforce === 'full' && verdict.capabilities !== 'full') {
      verdict = {
        capabilities: 'off',
        reason: `the kernel refused the full read fence (${verdict.reason}), and enforce: full accepts no weaker fence`,
      }
    }
    verdicts.set(key, verdict)
    return verdict
  }

  /**
   * The effective rules for one confinement: the platform baseline for its mode
   * and root, the stored rules, and the one-shot grant that belongs to the
   * command this confinement is about to run.
   */
  const rulesFor = (policy, command) => [
    ...readRules(config.rulesFile),
    ...config.grants,
    ...baselineRules({
      workspaceRoot: policy.workspaceRoot,
      harnessHome: config.harnessHome,
      home: config.home,
      mode: policy.mode,
    }),
    ...grants.forCommand(policy.sessionId, command),
  ]

  /**
   * The confined argv for one call, or null when this deployment cannot refine
   * the policy for it.
   */
  const refine = (argv, policy) => {
    if (policy === null || typeof policy !== 'object') return null
    if (policy.mode === 'danger-full-access') return null
    if (typeof policy.workspaceRoot !== 'string' || policy.workspaceRoot === '') return null
    const rules = rulesFor(policy, commandOfArgv(argv))
    const fence = fenceFor(policy, rules)
    const set = CAPABILITY_SETS[fence.capabilities] ?? { read: 'none', execute: false }
    report.state = fence.capabilities === 'off'
      ? 'off'
      : (fence.capabilities === 'full' ? 'full' : 'partial')
    report.level = fence.capabilities
    report.reason = fence.reason
    report.capabilities = Object.fromEntries(OPERATIONS.map(operation => [
      operation,
      fence.capabilities !== 'off'
        && (operation !== 'read' && operation !== 'execute'
          ? true
          : (operation === 'read' ? set.read !== 'none' : set.execute)),
    ]))
    if (fence.capabilities === 'off') return null
    return compileProfile({
      mode: policy.mode,
      workspaceRoot: policy.workspaceRoot,
      rules,
      protectedFiles: config.protectedFiles,
      capabilities: fence.capabilities,
    })
  }

  return {
    /**
     * Wrap the registered sandbox provider's `confine`.
     * @param ctx - the plugin's Cordis context.
     * @returns whether a provider was found and wrapped.
     */
    install(ctx) {
      if (installed) return true
      const found = ctx?.get?.('sandbox')
      if (found === undefined || found === null || typeof found.confine !== 'function') {
        report.state = 'off'
        report.reason = 'no sandbox provider is registered'
        logger.warn('dsh-allow: no sandbox provider to refine; the process fence stays as the harness set it')
        return false
      }
      provider = found
      original = found.confine
      found.confine = (argv, policy) => {
        let profile = null
        try {
          profile = refine(argv, policy)
        }
        catch (error) {
          // A policy this module cannot compile must not become a wider fence.
          report.state = 'off'
          report.reason = `profile compilation failed: ${error instanceof Error ? error.message : String(error)}`
          logger.warn(`dsh-allow: ${report.reason}; refusing to widen the fence`)
        }
        if (profile === null) return original.call(provider, argv, policy)
        return {
          argv: [SANDBOX_EXEC, '-p', profile, '--', ...argv],
          enforcement: report.state === 'full' ? 'full' : 'partial',
          denialSignatures: SEATBELT_DENIALS,
          runnerFailureRules: SEATBELT_RUNNER_RULES,
        }
      }
      installed = true
      return true
    },
    /** Restore the provider's own `confine`. */
    uninstall() {
      if (installed && provider !== null && original !== null) provider.confine = original
      installed = false
      provider = null
      original = null
    },
    /**
     * The profile one confinement compiles to, for `/allow status` and tests.
     * @param argv - the command the caller is about to spawn.
     * @param policy - the resolved sandbox policy.
     * @returns the profile text, or null when nothing is enforced for it.
     */
    profileFor(argv, policy) {
      return refine(argv, policy)
    },
    /**
     * What the kernel is currently enforcing.
     * @returns the state, the per-capability flags, and the reason.
     */
    status() {
      return { ...report, installed }
    },
  }
}
