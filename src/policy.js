/**
 * Deterministic approval policy over parsed shell commands.
 *
 * The engine never guesses: a command line that the parser cannot reduce to
 * simple commands is `prompt` at best, and a stored allow rule can only ever
 * cover a simple command whose arguments are all literal. Decisions aggregate
 * with `forbidden > prompt > allow` across every command in the line, so a
 * pipeline or `&&` chain is exactly as safe as its most dangerous member.
 *
 * Nothing here calls a model: the decision is a pure function of the parsed
 * command, the working directory, and the stored rules.
 */
import { basename } from 'node:path'
import { parseCommandLine } from './parse.js'

/** Strictness order used to aggregate decisions. */
const RANK = { allow: 0, prompt: 1, forbidden: 2 }

/**
 * Programs whose arguments can BE a program. A rule for one of these is only
 * ever safe when it pins the program text (a script path) or the exact code
 * string — never the interpreter alone.
 */
const CODE_PROGRAMS = {
  sh: { shell: true }, bash: { shell: true }, zsh: { shell: true }, dash: { shell: true },
  ksh: { shell: true }, ash: { shell: true }, fish: { shell: true },
  pwsh: { shell: true }, powershell: { shell: true },
  python: { inline: ['-c'] }, python3: { inline: ['-c'] }, pypy: { inline: ['-c'] }, pypy3: { inline: ['-c'] },
  node: { inline: ['-e', '-p', '--eval', '--print'] },
  perl: { inline: ['-e'] }, ruby: { inline: ['-e'] }, lua: { inline: ['-e'] },
  php: { inline: ['-r'] }, osascript: { inline: ['-e'] }, deno: { inline: ['eval'] },
  eval: { inline: [] }, exec: { inline: [] }, source: { inline: [] }, '.': { inline: [] },
  // Programs that run code selected by their arguments: a rule for one of them
  // must pin the operation, never the program alone. `git -c alias.p='!cmd' p`
  // and `sudo rm -rf /` are capabilities, not program names.
  git: { inline: [] }, npm: { inline: [] }, pnpm: { inline: [] }, yarn: { inline: [] },
  bun: { inline: [] }, make: { inline: [] }, docker: { inline: [] }, podman: { inline: [] },
  kubectl: { inline: [] }, ssh: { inline: [] }, sudo: { inline: [] }, su: { inline: [] },
  doas: { inline: [] }, env: { inline: [] }, xargs: { inline: [] }, nohup: { inline: [] },
  timeout: { inline: [] }, nice: { inline: [] }, command: { inline: [] },
}

/** Shell flags that make the next argument a program (`-c`, `-lc`, `-ic`, …). */
const SHELL_INLINE_FLAG = /^-[A-Za-z]*c[A-Za-z]*$/u

/**
 * Whether one argv token asks a program to run code from its arguments.
 * @param executable - the program name.
 * @param token - the argv token.
 * @returns whether the token is that program's inline-code flag.
 */
function isInlineFlag(executable, token) {
  const spec = CODE_PROGRAMS[executable]
  if (spec === undefined) return false
  if (spec.shell === true) return SHELL_INLINE_FLAG.test(token)
  return spec.inline.includes(token)
}

/**
 * Decide whether one persistent rule may be stored.
 *
 * This is the single authority for "broad rule that hands out a code-execution
 * capability". It is called by the rule builder and again by the store, so a UI
 * bug, a future caller, or an imported config cannot write `bash -c` or
 * `python -c` as an always-allow rule.
 * @param rule - the rule about to be stored.
 * @returns whether it is storable, with the reason when it is not.
 */
export function validatePersistentRule(rule) {
  if (rule?.decision !== 'allow') return { ok: true }
  // An exact-source rule pins the whole command line: whatever it runs, it runs
  // the same thing every time, which is the same guarantee as an exact argv pin.
  if (typeof rule.source === 'string' && rule.source.trim() !== '') return { ok: true }
  const executable = basename(String(rule.executable ?? ''))
  if (CODE_PROGRAMS[executable] === undefined) return { ok: true }
  const prefix = Array.isArray(rule.argvPrefix) ? rule.argvPrefix : []
  if (prefix.length === 0) {
    return { ok: false, reason: `允许「${executable}」本身就等于允许它执行任意代码` }
  }
  for (const [index, token] of prefix.entries()) {
    if (isInlineFlag(executable, token)) {
      return index + 1 < prefix.length
        ? { ok: true }
        : { ok: false, reason: `「${executable} ${token}」没有把内联代码固定到具体文本` }
    }
    if (token === '-') return { ok: false, reason: `「${executable} -」从 stdin 读程序，无法固定` }
    if (!String(token).startsWith('-')) return { ok: true }
  }
  return { ok: false, reason: `「${executable} ${prefix.join(' ')}」没有固定将要运行的程序` }
}

/**
 * The prefix that pins one code-bearing invocation: leading flags up to and
 * including the first non-flag token (a script path), or the whole argv when
 * the code lives in an argument (inline code).
 * @param executable - the program name.
 * @param args - argv without the program.
 * @returns the prefix, or null when the invocation cannot be pinned.
 */
function codePrefix(executable, args) {
  for (const [index, token] of args.entries()) {
    if (isInlineFlag(executable, token)) return args.slice(0, index + 2)
    if (!String(token).startsWith('-') && token !== '-') {
      return PARAMETER_SENSITIVE.has(executable) && executable !== 'git'
        ? args.slice(0, index + PARAMETER_PREFIX_LENGTH)
        : args.slice(0, index + 1)
    }
  }
  return null
}

/**
 * Programs whose effect depends on their arguments: the suggested rule keeps a
 * couple of them, so `rm -rf build` is remembered as `rm -rf build`-ish rather
 * than as a bare `rm`, without pinning the whole invocation.
 */
const PARAMETER_SENSITIVE = new Set([
  'rm', 'rmdir', 'mv', 'dd', 'shred', 'truncate', 'unlink', 'chmod', 'chown', 'chgrp',
  'kill', 'killall', 'pkill', 'systemctl', 'service', 'launchctl', 'mount', 'umount',
  'diskutil', 'fdisk', 'parted', 'docker', 'podman', 'kubectl', 'sudo', 'su', 'doas',
  'ssh', 'scp', 'rsync', 'curl', 'wget', 'tee', 'truncate',
])

/** How many leading arguments a parameter-sensitive rule keeps. */
const PARAMETER_PREFIX_LENGTH = 2

/** Programs whose first non-flag argument names a subcommand. */
const SUBCOMMAND_PROGRAMS = new Set([
  'git', 'gh', 'pnpm', 'npm', 'yarn', 'bun', 'cargo', 'go', 'docker', 'podman',
  'kubectl', 'brew', 'systemctl', 'apt', 'apt-get', 'dnf', 'yum', 'pacman', 'pip', 'pip3',
])

/** Interpreters whose inline-code flag makes the argument itself a program. */
const INLINE_CODE_FLAGS = {
  python: '-c', python3: '-c', node: '-e', deno: 'eval', ruby: '-e', perl: '-e',
  php: '-r', osascript: '-e', pwsh: '-c', powershell: '-c',
}

/** Shell programs that read a program from stdin when run without `-c`. */
const SHELL_PROGRAMS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish'])

/** Environment names that change executable resolution or inject code. */
const DANGEROUS_ENV = /^(?:PATH|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_[A-Z_]+|PYTHONPATH|PYTHONSTARTUP|NODE_OPTIONS|BASH_ENV|ENV|IFS|GIT_SSH_COMMAND|GIT_EXTERNAL_DIFF)$/u

/** Absolute roots whose modification is a system-level change. */
const SYSTEM_ROOTS = ['/etc', '/usr', '/bin', '/sbin', '/var', '/opt', '/System', '/Library', '/boot', '/dev']

/** Home-relative paths holding credentials or shell startup state. */
const SENSITIVE_HOME = ['.ssh', '.aws', '.gnupg', '.config', '.bashrc', '.zshrc', '.bash_profile', '.profile', '.netrc', '.gitconfig']

/**
 * Resolve one literal path the way the policy needs it: `~` expanded, relative
 * to the effective cwd, with `.`/`..` collapsed textually.
 * @param target - literal path text.
 * @param cwd - effective working directory.
 * @param home - home directory.
 * @returns the normalized absolute path.
 */
export function normalizePath(target, cwd, home) {
  let text = target
  if (text === '~') text = home
  else if (text.startsWith('~/')) text = `${home}/${text.slice(2)}`
  const absolute = text.startsWith('/') ? text : `${cwd}/${text}`
  const parts = []
  for (const part of absolute.split('/')) {
    if (part === '' || part === '.') continue
    if (part === '..') { parts.pop(); continue }
    parts.push(part)
  }
  return `/${parts.join('/')}`
}

/**
 * Whether one path names a system or credential location.
 * @param path - normalized absolute path.
 * @param home - home directory.
 * @returns the risk label, or null when the path is unremarkable.
 */
export function pathRisk(path, home) {
  if (path === '/' ) return 'root'
  if (SYSTEM_ROOTS.some(root => path === root || path.startsWith(`${root}/`))) return 'system'
  for (const entry of SENSITIVE_HOME) {
    if (path === `${home}/${entry}` || path.startsWith(`${home}/${entry}/`)) return 'credentials'
  }
  return null
}

/**
 * The flags an `rm` invocation carries, and the paths it would remove.
 * @param args - argv without the program.
 * @param cwd - effective working directory.
 * @param home - home directory.
 * @returns recursive/force flags and normalized targets.
 */
function rmShape(args, cwd, home) {
  let recursive = false
  let force = false
  const targets = []
  for (const argument of args) {
    if (argument.startsWith('--')) {
      if (argument === '--recursive') recursive = true
      if (argument === '--force') force = true
      if (argument === '--no-preserve-root') force = true
      continue
    }
    if (/^-[A-Za-z]+$/u.test(argument)) {
      if (/[rR]/u.test(argument)) recursive = true
      if (/f/u.test(argument)) force = true
      continue
    }
    targets.push({ raw: argument, path: normalizePath(argument, cwd, home) })
  }
  return { recursive, force, targets }
}

/**
 * The built-in classification of one simple command.
 *
 * Entries are evaluated in order; the first that returns a decision wins. Only
 * high-confidence, statically visible cases are `forbidden`; everything else
 * that deserves attention is `prompt`.
 * @param command - one parsed simple command.
 * @param context - cwd, home, and the tool name.
 * @returns a decision with its reason and risk label, or null when unremarkable.
 */
export function classifyBuiltin(command, context) {
  const { cwd, home } = context
  const program = basename(command.argv[0] ?? '')
  const args = command.argv.slice(1)

  // Environment manipulation, in the assignment prefix or through export.
  const assignments = program === 'export' || program === 'unset' ? args.map(argument => argument.split('=')[0]) : command.env
  for (const name of assignments) {
    if (DANGEROUS_ENV.test(name)) {
      return { decision: 'prompt', risk: 'environment', reason: `${name} changes how later programs resolve or start` }
    }
  }

  // Redirection targets: writing system or credential files is a filesystem change.
  for (const redirection of command.redirections) {
    if (!['>', '>>', '&>', '&>>'].includes(redirection.op)) continue
    if (redirection.dynamic) {
      return { decision: 'prompt', risk: 'filesystem-write', reason: 'a redirection target is built at runtime' }
    }
    const path = normalizePath(redirection.target, cwd, home)
    if (/^\/dev\/(?:disk|sd|nvme|hd|rdisk)/u.test(path)) {
      return { decision: 'prompt', risk: 'device-write', reason: `writing to the raw device ${path}` }
    }
    if (pathRisk(path, home) !== null) {
      return { decision: 'prompt', risk: 'filesystem-write', reason: `writing to ${path}` }
    }
  }

  if (command.opaque === true) {
    return { decision: 'prompt', risk: 'code-execution', reason: 'the shell program could not be parsed, so its effect is unknown' }
  }

  if (command.background) {
    return { decision: 'prompt', risk: 'background', reason: 'the process outlives this agent call' }
  }

  if (program === 'rm') {
    const { recursive, force, targets } = rmShape(args, cwd, home)
    for (const target of targets) {
      // `$HOME` is a literal spelling of the home directory, not an unknown.
      const path = /^\$\{?HOME\}?$/u.test(target.raw) ? home : target.path
      const what = path === '/' ? 'the filesystem root' : path === home ? 'the home directory' : null
      if (what !== null) {
        return { decision: 'prompt', risk: 'catastrophic', reason: recursive && force ? `recursively deleting ${what}` : `deleting ${what}` }
      }
      // A glob that expands to everything under a root is the same disaster.
      if (recursive && force && target.raw.startsWith('/') && /[*?]/u.test(target.raw)) {
        return { decision: 'prompt', risk: 'catastrophic', reason: `recursively deleting every path matching ${target.raw}` }
      }
    }
    return { decision: 'prompt', risk: 'destructive', reason: 'rm deletes files' }
  }

  if (program === 'dd') {
    const device = args.find(argument => /^of=\/dev\//u.test(argument))
    if (device !== undefined) return { decision: 'prompt', risk: 'device-write', reason: `writing an image to ${device.slice(3)}` }
    return { decision: 'prompt', risk: 'destructive', reason: 'dd writes raw data' }
  }

  if (/^mkfs(\.|$)/u.test(program) || program === 'fdisk' || program === 'parted' || program === 'shred') {
    return { decision: 'prompt', risk: 'catastrophic', reason: `${program} rewrites a filesystem or its device` }
  }

  if (['sudo', 'su', 'doas', 'pkexec'].includes(program)) {
    return { decision: 'prompt', risk: 'privilege', reason: `${program} runs with elevated privileges` }
  }

  if (['chmod', 'chown', 'chgrp'].includes(program)) {
    const recursive = args.some(argument => /^-[A-Za-z]*[Rr]/u.test(argument))
    const wide = args.some(argument => /^(?:777|a\+rwx|-R\s+777)/u.test(argument))
    return {
      decision: 'prompt',
      risk: 'permissions',
      reason: recursive || wide ? `${program} changes permissions recursively or world-writable` : `${program} changes file ownership or permissions`,
    }
  }

  if (['kill', 'killall', 'pkill', 'killall5'].includes(program)) {
    return { decision: 'prompt', risk: 'process', reason: `${program} terminates other processes` }
  }

  if (['systemctl', 'service', 'launchctl', 'shutdown', 'reboot', 'halt'].includes(program)) {
    return { decision: 'prompt', risk: 'service', reason: `${program} changes system services` }
  }

  if (['mount', 'umount', 'diskutil'].includes(program)) {
    return { decision: 'prompt', risk: 'filesystem', reason: `${program} changes mounted filesystems` }
  }

  if (['eval', 'exec', 'source'].includes(program) || program === '.') {
    return { decision: 'prompt', risk: 'code-execution', reason: `${program} runs code built at runtime` }
  }

  const inlineFlag = INLINE_CODE_FLAGS[program]
  if (inlineFlag !== undefined) {
    if (args.includes(inlineFlag)) {
      return { decision: 'prompt', risk: 'code-execution', reason: `${program} ${inlineFlag} runs an inline program` }
    }
    // No program file at all: the program arrives on stdin (a here-document or
    // a pipe), which is exactly as unreadable as `-c`.
    if (args.length === 0 || args[0] === '-') {
      return { decision: 'prompt', risk: 'code-execution', reason: `${program} reads its program from stdin` }
    }
  }

  if (SHELL_PROGRAMS.has(program) && !args.some(argument => /^-[A-Za-z]*c/u.test(argument))) {
    return { decision: 'prompt', risk: 'code-execution', reason: `${program} without -c reads its program from stdin` }
  }

  if (['curl', 'wget', 'nc', 'netcat', 'telnet', 'ssh', 'scp', 'sftp', 'rsync'].includes(program)) {
    const writes = program === 'curl' || program === 'wget'
      ? args.some(argument => /^-{1,2}(?:o|O|output-document)\b/u.test(argument) || /^-O$/u.test(argument))
      : true
    if (writes) return { decision: 'prompt', risk: 'network', reason: `${program} transfers data with the network or writes a file` }
    return null
  }

  if (['docker', 'podman', 'nerdctl'].includes(program)) {
    return { decision: 'prompt', risk: 'container', reason: `${program} runs or changes containers, which can mount the host` }
  }

  if (['git'].includes(program)) {
    const subcommand = args[0]
    if (subcommand === 'reset' && args.includes('--hard')) {
      return { decision: 'prompt', risk: 'destructive', reason: 'git reset --hard discards working-tree changes' }
    }
    if (subcommand === 'clean' && args.some(argument => /^-[A-Za-z]*[fdx]/u.test(argument))) {
      return { decision: 'prompt', risk: 'destructive', reason: 'git clean removes untracked or ignored files' }
    }
    if (subcommand === 'push' && args.some(argument => /^--force(?:-with-lease)?$/u.test(argument) || argument === '-f')) {
      return { decision: 'prompt', risk: 'destructive', reason: 'git push --force rewrites remote history' }
    }
    if (subcommand === 'checkout' && args.includes('--')) {
      return { decision: 'prompt', risk: 'destructive', reason: 'git checkout -- discards working-tree changes' }
    }
  }

  if (['npm', 'pnpm', 'yarn', 'bun'].includes(program)) {
    if (args.includes('publish')) return { decision: 'prompt', risk: 'publish', reason: `${program} publish uploads a package` }
    if (args.includes('--foreground-scripts')) return { decision: 'prompt', risk: 'code-execution', reason: `${program} runs dependency lifecycle scripts` }
  }

  if (['mv', 'truncate', 'rmdir', 'unlink'].includes(program)) {
    return { decision: 'prompt', risk: 'destructive', reason: `${program} removes or replaces paths` }
  }

  if (command.dynamicArgv.some(flag => flag === true)) {
    return { decision: 'prompt', risk: 'dynamic-arguments', reason: 'an argument is expanded at run time, so its effect cannot be read from the line' }
  }

  return null
}

/**
 * Whether one stored rule covers one simple command.
 *
 * A rule names an executable plus a literal argv prefix. It may not cover a
 * command whose arguments are expanded at run time, and a `prompt`/`forbidden`
 * rule matches by prefix alone (it only ever adds strictness).
 * @param rule - the stored rule.
 * @param command - the parsed simple command.
 * @returns whether the rule matches.
 */
export function ruleMatches(rule, command) {
  // Source-pinned rules match only their own text, never a program name.
  if (typeof rule.source === 'string') return false
  if (basename(command.argv[0] ?? '') !== rule.executable) return false
  // Defense in depth: even a rule this engine was handed directly may not grant
  // a code-execution capability, so an invalid allow rule matches nothing.
  if (rule.decision === 'allow' && !validatePersistentRule(rule).ok) return false
  const args = command.argv.slice(1)
  const dynamic = command.dynamicArgv.slice(1)
  // Only an unresolved expansion blocks a rule; a command substitution whose
  // own commands the policy approved is part of the same judgement.
  if (rule.decision === 'allow' && dynamic.some(flag => flag === true)) return false
  const prefix = rule.argvPrefix ?? []
  if (args.length < prefix.length) return false
  return prefix.every((word, index) => args[index] === word)
}

/**
 * Suggest the narrowest useful persistent rule for one command.
 *
 * The executable always; the leading subcommand word for programs whose first
 * argument names an operation (`git status`, `pnpm install`). Flags, paths, and
 * expanded arguments are never part of a suggestion, so a rule never claims
 * more than the operation the user just approved.
 * @param command - the parsed simple command.
 * @returns the rule fields to store.
 */
export function suggestRule(command) {
  const executable = basename(command.argv[0] ?? '')
  const args = command.argv.slice(1)
  const dynamic = command.dynamicArgv.slice(1)
  const literal = !dynamic.some(flag => flag === true)
  if (command.opaque === true || CODE_PROGRAMS[executable] !== undefined) {
    // Never the interpreter alone, and never a truncated code argument: pin the
    // invocation to the script it runs or the exact text the user is looking at.
    if (!literal) return null
    const pinned = codePrefix(executable, args)
    if (pinned === null) return null
    const inline = args.some(token => isInlineFlag(executable, token))
    const exact = {
      decision: 'allow',
      executable,
      argvPrefix: pinned,
      exact: inline,
    }
    return validatePersistentRule(exact).ok ? exact : null
  }
  const argvPrefix = []
  const parameterSensitive = PARAMETER_SENSITIVE.has(executable) || /^mkfs/u.test(executable)
  if (literal && parameterSensitive) {
    argvPrefix.push(...args.slice(0, PARAMETER_PREFIX_LENGTH))
  }
  else if (SUBCOMMAND_PROGRAMS.has(executable) && args.length > 0 && literal
    && !args[0].startsWith('-') && !args[0].includes('/')) {
    argvPrefix.push(args[0])
  }
  const suggestion = { decision: 'allow', executable, argvPrefix }
  return validatePersistentRule(suggestion).ok ? suggestion : null
}

/**
 * Describe a rule the way the approval card should render it.
 * @param rule - stored or suggested rule fields.
 * @returns the human label.
 */
export function describeRule(rule) {
  if (typeof rule.source === 'string') {
    const text = rule.source.replace(/\s+/gu, ' ')
    return text.length > 48 ? `${text.slice(0, 47)}…` : text
  }
  return [rule.executable, ...(rule.argvPrefix ?? [])].join(' ')
}

/**
 * Normalize one command line for exact-source comparison: the text must be the
 * same command, so only surrounding whitespace is ignored.
 * @param text - raw command line.
 * @returns the comparable text.
 */
export function normalizeSource(text) {
  return String(text ?? '').trim()
}

/**
 * The program word an exact-source suggestion names on a card.
 * @param command - the raw command line.
 * @returns the first whitespace-separated word, or the whole text.
 */
function firstWord(command) {
  const match = /^\s*(\S+)/u.exec(String(command ?? ''))
  return match?.[1] ?? ''
}

/**
 * Evaluate one complete command line.
 * @param request - raw command, effective cwd, home, and the stored rules.
 * @returns the aggregate decision with reasons, triggers, and a suggestion.
 */
export function evaluateCommandLine(request) {
  const { command, cwd, home, rules = [], defaultDecision = 'allow', allowForbiddenSource = false } = request
  const parsed = parseCommandLine(command, { home })
  if (!parsed.analyzable) {
    // The line cannot be reduced to commands, but it can still be pinned to its
    // own text: the same text runs the same program every time.
    const source = normalizeSource(command)
    const remembered = rules.find(rule => rule.decision === 'allow'
      && typeof rule.source === 'string'
      && normalizeSource(rule.source) === source)
    if (remembered !== undefined) {
      return {
        decision: 'allow',
        reason: 'an exact-source rule matches this command line',
        risk: 'none',
        matchedRules: [remembered],
        triggers: [],
        commands: [],
        suggestion: null,
        suggestions: [],
        partial: false,
        covered: true,
        analyzable: false,
      }
    }
    const pinned = { decision: 'allow', executable: firstWord(command), argvPrefix: [], source, exact: true }
    const suggestion = validatePersistentRule(pinned).ok ? pinned : null
    return {
      decision: 'prompt',
      reason: `cannot be analysed statically (${parsed.reason}); only this exact command can be remembered`,
      risk: 'unanalysable',
      matchedRules: [],
      triggers: [],
      commands: [],
      suggestion,
      suggestions: suggestion === null ? [] : [suggestion],
      partial: suggestion === null,
      covered: false,
      analyzable: false,
    }
  }
  const triggers = []
  const matchedRules = []
  const suggestions = []
  let suggestionBlocked = false
  let forbiddenSeen = false
  let covered = true
  let decision = 'allow'
  let reason = 'no policy rule applies'
  const consider = (candidate, why, rule = null) => {
    if (rule !== null) matchedRules.push(rule)
    if (RANK[candidate] > RANK[decision]) {
      decision = candidate
      reason = why
    }
  }
  let suggestion = null
  for (const simple of parsed.commands) {
    // A wrapper whose program was parsed contributes its inner commands; only
    // an opaque wrapper is a command in its own right.
    if (simple.nested === true && simple.opaque !== true) continue
    const builtin = classifyBuiltin(simple, { cwd, home })
    const matched = rules.filter(rule => ruleMatches(rule, simple))
    if (builtin !== null && builtin.decision !== 'allow') triggers.push({ command: simple.source, ...builtin })
    const forbidden = builtin?.decision === 'forbidden' || matched.some(rule => rule.decision === 'forbidden')
    const allowed = matched.some(rule => rule.decision === 'allow')
    if (forbidden) forbiddenSeen = true
    if (forbidden) {
      suggestionBlocked = true
      covered = false
    }
    else if (!allowed) {
      covered = false
    }
    if (!forbidden) {
      const candidate = suggestRule(simple)
      if (candidate === null) suggestionBlocked = true
      else if (!suggestions.some(rule => rule.executable === candidate.executable
        && rule.argvPrefix.join('\u0000') === candidate.argvPrefix.join('\u0000'))) {
        suggestions.push(candidate)
      }
    }
    if (forbidden) {
      const source = builtin?.decision === 'forbidden' ? builtin : matched.find(rule => rule.decision === 'forbidden')
      consider('forbidden', source.reason ?? `forbidden by rule ${source.id ?? ''}`.trim(), source.id === undefined ? null : source)
      continue
    }
    if (allowed) {
      consider('allow', 'a stored rule covers this command', null)
      for (const rule of matched) if (rule.decision === 'allow') matchedRules.push(rule)
      continue
    }
    if (builtin !== null || matched.some(rule => rule.decision === 'prompt')) {
      const prompt = builtin ?? matched.find(rule => rule.decision === 'prompt')
      consider('prompt', prompt.reason ?? 'matched a prompt rule', prompt.id === undefined ? null : prompt)
      continue
    }
    // Unremarkable: the sandbox remains the enforcement layer for this command.
    consider(defaultDecision === 'allow' ? 'allow' : defaultDecision, 'deferred to the sandbox', null)
  }
  // A denied line is never stored as per-command capabilities: remembering the
  // rest of it would pre-approve a command that can never run. When the
  // deployment allows it, the whole line may still be pinned to its own text,
  // which is one exact command rather than a capability.
  if (forbiddenSeen) suggestions.length = 0
  if (forbiddenSeen && allowForbiddenSource && decision === 'forbidden') {
    const source = normalizeSource(command)
    const pinned = { decision: 'allow', executable: firstWord(command), argvPrefix: [], source, exact: true }
    if (validatePersistentRule(pinned).ok) {
      suggestions.push(pinned)
      suggestionBlocked = false
    }
  }
  const sourceRule = rules.find(rule => rule.decision === 'allow'
    && typeof rule.source === 'string'
    && normalizeSource(rule.source) === normalizeSource(command))
  if (sourceRule !== undefined && (!forbiddenSeen || allowForbiddenSource)) {
    decision = 'allow'
    reason = 'an exact-source rule matches this command line'
    covered = true
    suggestions.length = 0
    matchedRules.push(sourceRule)
  }
  else if (decision === 'prompt' && (suggestions.length === 0 || suggestionBlocked
    || triggers.some(trigger => trigger.risk === 'filesystem-write' || trigger.risk === 'device-write')) && !forbiddenSeen) {
    // Something in this line cannot be pinned per command (a stdin program, a
    // dynamic argument, syntax the parser does not model). The parsable parts
    // keep their minimal rules and the whole line is added as an exact pin, so
    // there is no command the user cannot silence.
    const source = normalizeSource(command)
    const pinned = { decision: 'allow', executable: firstWord(command), argvPrefix: [], source, exact: true }
    if (validatePersistentRule(pinned).ok) {
      suggestions.push(pinned)
      suggestionBlocked = false
    }
  }
  const rememberable = suggestions.length > 0
  return {
    decision,
    reason,
    risk: decision === 'allow' ? 'none' : (triggers[0]?.risk ?? 'unknown'),
    matchedRules,
    triggers,
    commands: parsed.commands.map(simple => simple.argv),
    suggestion: rememberable ? (suggestions[0] ?? null) : null,
    suggestions: rememberable ? suggestions : [],
    // Some member can never be remembered (inline code, a substituted program),
    // so this line keeps asking even after its other commands are stored.
    partial: suggestionBlocked,
    covered,
    analyzable: true,
  }
}
