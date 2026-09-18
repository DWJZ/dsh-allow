/**
 * Filesystem effects of one parsed command line.
 *
 * This module answers a single question per command: which `(path, operation)`
 * pairs will it touch? The answer comes from what the program does with its
 * arguments, never from how dangerous its name sounds — `rm` is a `delete` of
 * its operands and `echo` is nothing at all, and neither gets special handling
 * beyond that reading. Anything the line does not state (an inline program, a
 * variable where a path belongs) is reported as unknown instead of guessed.
 *
 * @module dsh-allow/effects
 */
import { accessSync, constants, statSync } from 'node:fs'
import { basename, join } from 'node:path'
import { canonicalPath } from './fspolicy.js'

/** Redirections that write or create their target. */
const WRITE_REDIRECTIONS = new Set(['>', '>>', '&>', '&>>', '>|'])

/** Redirections that read their target. */
const READ_REDIRECTIONS = new Set(['<'])

/** Devices whose writes are sinks, not file changes. */
const DEVICE_TARGET = /^\/dev\/(?:null|stdout|stderr|tty|zero|random|urandom|fd\/\d+)$/u

/** How one operation reads the positional arguments of a program. */
const ARGS = 'args'
const SOURCES = 'sources'
const LAST = 'last'
const CHANGE = 'change'
const DD_INPUT = 'if'
const DD_OUTPUT = 'of'
const OUTPUT_FILE = 'output'

/**
 * What each program does with the paths it is given. A program missing from
 * this table contributes only its own execution: its file effects are either
 * none or invisible from the command line, and the sandbox remains the fence.
 */
const PROGRAM_EFFECTS = {
  rm: { delete: ARGS },
  rmdir: { delete: ARGS },
  unlink: { delete: ARGS },
  shred: { delete: ARGS },
  srm: { delete: ARGS },
  mkdir: { create: ARGS },
  mknod: { create: ARGS },
  mkfifo: { create: ARGS },
  touch: { change: ARGS },
  truncate: { write: ARGS },
  chmod: { write: { skip: 1 } },
  chown: { write: { skip: 1 } },
  chgrp: { write: { skip: 1 } },
  chflags: { write: { skip: 1 } },
  setfile: { write: { skip: 1 } },
  cat: { read: ARGS },
  head: { read: ARGS },
  tail: { read: ARGS },
  less: { read: ARGS },
  more: { read: ARGS },
  wc: { read: ARGS },
  stat: { read: ARGS },
  file: { read: ARGS },
  du: { read: ARGS },
  df: { read: ARGS },
  xxd: { read: ARGS },
  strings: { read: ARGS },
  tree: { read: ARGS },
  readlink: { read: ARGS },
  realpath: { read: ARGS },
  cmp: { read: ARGS },
  diff: { read: ARGS },
  jq: { read: ARGS },
  sort: { read: ARGS },
  uniq: { read: ARGS },
  cut: { read: ARGS },
  tr: { read: ARGS },
  base64: { read: ARGS },
  md5: { read: ARGS },
  md5sum: { read: ARGS },
  shasum: { read: ARGS },
  sha1sum: { read: ARGS },
  sha256sum: { read: ARGS },
  ls: { read: ARGS },
  find: { read: ARGS },
  grep: { read: { skip: 1 } },
  rg: { read: { skip: 1 } },
  awk: { read: { skip: 1 } },
  sed: { read: { skip: 1 }, writeWhen: '-i' },
  cp: { read: SOURCES, change: LAST },
  install: { read: SOURCES, create: LAST },
  mv: { delete: SOURCES, change: LAST },
  ln: { create: LAST },
  tee: { change: ARGS },
  rsync: { read: SOURCES, change: LAST },
  scp: { read: { skip: 1 }, change: LAST },
  curl: { change: OUTPUT_FILE },
  wget: { change: OUTPUT_FILE },
  dd: { read: DD_INPUT, change: DD_OUTPUT },
  gzip: { read: ARGS, change: ARGS },
  gunzip: { read: ARGS, change: ARGS },
  unzip: { read: ARGS },
  tar: { read: ARGS },
  zip: { read: SOURCES, change: LAST },
}

/** Programs that hand their first positional argument to another interpreter. */
const INTERPRETERS = new Set([
  'sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish',
  'python', 'python3', 'pypy', 'pypy3', 'node', 'deno', 'bun', 'tsx', 'ts-node',
  'ruby', 'perl', 'php', 'lua', 'osascript', 'pwsh', 'powershell', 'Rscript',
])

/** Interpreter flags whose value is code or a module name, not a path. */
const INLINE_FLAGS = new Set(['-c', '-e', '-p', '-r', '-m', '--eval', '--print', 'eval', '-lc', '-ic', '-ec'])

/** Programs that only decide how another program is started. */
const WRAPPERS = new Set(['sudo', 'doas', 'env', 'nice', 'nohup', 'timeout', 'command', 'exec', 'ionice', 'stdbuf', 'setsid'])

/** Wrapper options that consume the following token. */
const WRAPPER_OPTION_VALUES = {
  sudo: ['-u', '-g', '-p', '-C', '-h', '-r', '-t', '-U', '-u#', '-g#'],
  doas: ['-u', '-C'],
  nice: ['-n', '--adjustment'],
  timeout: ['-s', '--signal', '-k', '--kill-after'],
  env: ['-u', '--unset', '-C', '--chdir', '-S', '--split-string'],
  ionice: ['-c', '-n', '-p'],
  stdbuf: ['-i', '-o', '-e'],
}

/** Archive programs whose extraction target names come from the archive. */
const EXTRACTORS = new Set(['tar', 'unzip', 'gunzip'])

/**
 * Whether one argv entry was expanded at run time.
 * @param flag - the parser's per-token marker.
 * @returns true when the token's value is not known statically.
 */
function dynamic(flag) {
  return flag === true
}

/**
 * The positional tokens of an argv slice, with their original indices.
 * @param tokens - argv without the program name.
 * @param flags - the parser's per-token markers.
 * @returns `{index, text}` for every token that is not an option.
 */
function positionals(tokens, flags) {
  const found = []
  for (const [index, text] of tokens.entries()) {
    if (typeof text !== 'string' || text === '') continue
    if (text.startsWith('-') && text !== '-') continue
    found.push({ index, text, dynamic: dynamic(flags[index]) })
  }
  return found
}

/**
 * Resolve the program a command will start.
 * @param program - the program token as written.
 * @param options - effective cwd, home, and environment.
 * @returns the spelling used on the command line and the path behind it, or null.
 */
function resolveProgram(program, { cwd, home, env }) {
  if (typeof program !== 'string' || program === '') return null
  if (program.includes('/')) {
    const path = canonicalPath(program, { cwd, home })
    return { path, realPath: canonicalPath(path, { cwd, home }) }
  }
  const path = String(env?.PATH ?? '').split(':').filter(directory => directory !== '')
  for (const directory of path) {
    const candidate = join(directory, program)
    try {
      accessSync(candidate, constants.X_OK)
      if (!statSync(candidate).isFile()) continue
    }
    catch {
      // Not here: keep looking along PATH.
      continue
    }
    return { path: candidate, realPath: canonicalPath(candidate, { cwd, home }) }
  }
  return null
}

/**
 * Follow the wrappers that only decide how another program is started, so
 * `sudo rm -rf build` is judged as the delete it performs.
 * @param argv - the full argv of one command.
 * @returns the argv of the program the wrapper ends up starting.
 */
function unwrap(argv) {
  let current = argv
  for (let guard = 0; guard < 8; guard += 1) {
    const program = basename(current[0] ?? '')
    if (!WRAPPERS.has(program)) return current
    const tokens = current.slice(1)
    const valued = WRAPPER_OPTION_VALUES[program] ?? []
    let index = 0
    while (index < tokens.length) {
      const token = tokens[index]
      if (program === 'env' && /^[A-Za-z_][A-Za-z0-9_]*=/u.test(token)) {
        index += 1
        continue
      }
      if (valued.includes(token)) {
        index += 2
        continue
      }
      if (typeof token === 'string' && token.startsWith('-')) {
        index += 1
        continue
      }
      break
    }
    // `timeout 30 cmd`: the first positional is the duration, not the program.
    if (program === 'timeout' && index < tokens.length) index += 1
    if (index >= tokens.length) return current
    current = tokens.slice(index)
  }
  return current
}

/** Collect the effects one command line contributes. */
export function effectsOf(parsed, { cwd = '/', home = '/', env = process.env } = {}) {
  const effects = []
  const unknown = []
  const commands = []
  const seen = new Set()

  const add = (operation, rawPath, command) => {
    if (typeof rawPath !== 'string' || rawPath === '') return
    const path = canonicalPath(rawPath, { cwd, home })
    if (DEVICE_TARGET.test(path)) return
    const realPath = canonicalPath(path, { cwd, home })
    const key = `${operation}\u0000${path}\u0000${realPath}`
    if (seen.has(key)) return
    seen.add(key)
    effects.push({ operation, path, realPath, command })
  }

  const addExecute = (command) => {
    const resolved = resolveProgram(command.argv[0], { cwd, home, env })
    if (resolved === null) return
    const key = `execute\u0000${resolved.path}\u0000${resolved.realPath}`
    if (seen.has(key)) return
    seen.add(key)
    effects.push({ operation: 'execute', path: resolved.path, realPath: resolved.realPath, command: command.source })
  }

  const addChange = (target, command) => {
    let exists = false
    try {
      exists = statSync(canonicalPath(target, { cwd, home })).isFile()
    }
    catch {
      // A path that is not there yet is a creation.
    }
    add(exists ? 'write' : 'create', target, command)
  }

  for (const command of parsed.commands) {
    commands.push(command.argv)
    addExecute(command)
    if (command.opaque === true) {
      // A shell program the parser could not read, or a function definition:
      // the line says nothing about what it touches.
      unknown.push({
        operation: null,
        path: null,
        command: command.source,
        reason: command.opaqueReason ?? 'the program could not be parsed',
      })
      continue
    }
    if (command.nested === true) continue

    const inner = unwrap(command.argv)
    if (inner !== command.argv && inner.length > 0) {
      // The wrapper's own execution is already recorded; judge the program it starts.
      addExecute({ argv: inner, source: command.source })
    }
    const argv = inner
    const program = basename(argv[0] ?? '')
    const tokens = argv.slice(1)
    // Wrapper arguments carry no expansion markers of their own; an unwrapped
    // command keeps only the tokens the parser marked.
    const tail = (inner === command.argv ? command.dynamicArgv.slice(1) : []).slice(0, tokens.length)

    if (program === 'xargs') {
      unknown.push({ operation: null, path: null, command: command.source, reason: 'xargs builds its command line at run time' })
      continue
    }

    const spec = PROGRAM_EFFECTS[program]
    if (spec !== undefined) {
      const positional = positionals(tokens, tail)
      const shapePaths = (shape) => {
        const skip = typeof shape === 'object' ? shape.skip ?? 0 : 0
        const usable = positional.slice(skip)
        if (shape === SOURCES) return usable.slice(0, -1)
        if (shape === LAST) return usable.slice(-1)
        return usable
      }
      for (const [operation, shape] of Object.entries(spec)) {
        if (operation === 'writeWhen') continue
        if (shape === DD_INPUT) {
          const token = tokens.find(text => /^if=/u.test(text))
          if (token !== undefined) add('read', token.slice(3), command.source)
          continue
        }
        if (shape === DD_OUTPUT) {
          const token = tokens.find(text => /^of=/u.test(text))
          if (token !== undefined) addChange(token.slice(3), command.source)
          continue
        }
        if (shape === OUTPUT_FILE) {
          const index = tokens.findIndex(text => ['-o', '-O', '--output-document', '--output'].includes(text))
          if (index !== -1 && tokens[index + 1] !== undefined) addChange(tokens[index + 1], command.source)
          continue
        }
        for (const entry of shapePaths(shape)) {
          if (entry.dynamic === true) {
            unknown.push({
              operation,
              path: null,
              command: command.source,
              reason: `a path given to ${program} is expanded at run time`,
            })
            continue
          }
          if (operation === CHANGE) addChange(entry.text, command.source)
          else add(operation, entry.text, command.source)
        }
      }
      if (spec.writeWhen !== undefined && tokens.includes(spec.writeWhen)) {
        for (const entry of positionals(tokens, tail).slice(1)) add('write', entry.text, command.source)
      }
      if (EXTRACTORS.has(program) && tokens.some(token => /^-[A-Za-z]*[xX]/u.test(token))) {
        unknown.push({
          operation: 'create',
          path: null,
          command: command.source,
          reason: 'the archive decides which files it writes',
        })
      }
    }
    else if (INTERPRETERS.has(program)) {
      let inline = false
      for (const [index, token] of tokens.entries()) {
        if (INLINE_FLAGS.has(token)) { inline = true; break }
        if (typeof token !== 'string' || token.startsWith('-')) continue
        if (tail[index] === true) {
          unknown.push({ operation: 'read', path: null, command: command.source, reason: `the program file for ${program} is expanded at run time` })
        }
        else add('read', token, command.source)
        break
      }
      if (inline) {
        unknown.push({
          operation: null,
          path: null,
          command: command.source,
          reason: `${program} runs a program given on the command line`,
        })
      }
    }

    for (const redirection of command.redirections ?? []) {
      const operation = WRITE_REDIRECTIONS.has(redirection.op)
        ? 'change'
        : (READ_REDIRECTIONS.has(redirection.op) ? 'read' : null)
      if (operation === null) continue
      if (redirection.dynamic === true) {
        unknown.push({
          operation: operation === 'read' ? 'read' : 'write',
          path: null,
          command: command.source,
          reason: 'a redirection target is built at run time',
        })
        continue
      }
      if (DEVICE_TARGET.test(redirection.target)) continue
      if (operation === 'read') add('read', redirection.target, command.source)
      else addChange(redirection.target, command.source)
    }
  }
  return { effects, unknown, commands }
}
