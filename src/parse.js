/**
 * Restricted shell parser for the approval policy.
 *
 * The job is NOT to model bash. It is to answer one question reliably: which
 * programs would this line run, and what are their literal arguments? Anything
 * the parser cannot prove becomes `analyzable: false`, which the policy layer
 * treats as high risk — a line whose executables are unknown never inherits a
 * stored allow rule.
 *
 * Supported: quoting (`'…'`, `"…"`, backslash), the sequencing operators
 * `&&`, `||`, `;`, `|`, `&`, newlines, redirections, leading `VAR=value`
 * assignments, and one level of brace-free subshell detection.
 *
 * Deliberately unsupported (⇒ `analyzable: false`): subshells and groups,
 * control keywords, here-documents, command/process/arithmetic substitution,
 * globs, brace expansion, and parameter expansion inside a word.
 */

/** Operators that separate simple commands, longest match first. */
const OPERATORS = ['&&', '||', '|&', ';;', ';', '|', '&', '\n']

/** Keywords that make a segment a shell construct rather than a simple command. */
const CONTROL_KEYWORDS = new Set([
  'if', 'then', 'elif', 'else', 'fi', 'for', 'while', 'until', 'do', 'done',
  'case', 'esac', 'function', 'select', 'time', '{', '}', '(', ')', '[[', ']]', '!',
])

/** Programs whose `-c` argument is another shell program. */
const SHELL_PROGRAMS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish'])

/** Longest recursive shell `-c` nesting this parser will follow. */
export const MAX_WRAPPER_DEPTH = 4

/**
 * Split a command line into operator-separated raw segments.
 * @param source - the raw command line.
 * @returns segments in order, each with the operator that followed it.
 */
export function splitSegments(source) {
  const segments = []
  let text = ''
  let quote = null
  let index = 0
  const flush = (operator) => {
    segments.push({ text, operator })
    text = ''
  }
  while (index < source.length) {
    const character = source[index]
    if (quote === "'") {
      text += character
      if (character === "'") quote = null
      index += 1
      continue
    }
    if (quote === '"') {
      if (character === '\\') {
        text += character + (source[index + 1] ?? '')
        index += 2
        continue
      }
      text += character
      if (character === '"') quote = null
      index += 1
      continue
    }
    if (character === '\\') {
      text += character + (source[index + 1] ?? '')
      index += 2
      continue
    }
    if (character === "'" || character === '"') {
      quote = character
      text += character
      index += 1
      continue
    }
    const operator = OPERATORS.find(candidate => source.startsWith(candidate, index))
    if (operator !== undefined) {
      flush(operator)
      index += operator.length
      continue
    }
    text += character
    index += 1
  }
  flush(null)
  return segments
}

/**
 * Split one segment into words, tracking quoting and expansion.
 * @param text - segment text with no sequencing operators left.
 * @param home - home directory used to expand a leading `~`.
 * @returns words with their dynamic flag, or a parse failure.
 */
function tokenize(text, home) {
  const words = []
  let value = ''
  let dynamic = false
  let quote = null
  let started = false
  let index = 0
  const push = () => {
    if (!started) return
    words.push({ value, dynamic })
    value = ''
    dynamic = false
    started = false
  }
  while (index < text.length) {
    const character = text[index]
    if (quote === "'") {
      started = true
      if (character === "'") { quote = null; index += 1; continue }
      value += character
      index += 1
      continue
    }
    if (quote === '"') {
      started = true
      if (character === '\\') {
        const next = text[index + 1] ?? ''
        if ('$`"\\'.includes(next)) { value += next; index += 2; continue }
        value += character
        index += 1
        continue
      }
      if (character === '"') { quote = null; index += 1; continue }
      if (character === '$' || character === '`') dynamic = true
      value += character
      index += 1
      continue
    }
    if (character === '\\') {
      started = true
      value += text[index + 1] ?? ''
      index += 2
      continue
    }
    if (character === "'" || character === '"') {
      started = true
      quote = character
      index += 1
      continue
    }
    if (/\s/u.test(character)) {
      push()
      index += 1
      continue
    }
    if (character === '$' || character === '`') dynamic = true
    if (character === '*' || character === '?' || character === '[' || character === '{') dynamic = true
    started = true
    value += character
    index += 1
  }
  if (quote !== null) return null
  push()
  if (words.length > 0 && words[0].value.startsWith('~')) {
    words[0] = { value: `${home}${words[0].value.slice(1)}`, dynamic: words[0].dynamic }
  }
  return words
}

/** Redirection operators, longest match first. */
const REDIRECTIONS = ['&>>', '&>', '>>', '<<<', '<<', '>&', '<&', '>', '<']

/**
 * Parse one segment into a simple command.
 * @param segment - raw segment text.
 * @param home - home directory used for `~` expansion.
 * @returns the parsed command, or a reason it cannot be analysed.
 */
function parseSegment(segment, home) {
  const words = tokenize(segment, home)
  if (words === null) return { ok: false, reason: 'unterminated quote' }
  if (words.length === 0) return { ok: false, reason: 'empty segment' }
  const env = []
  const argv = []
  const redirections = []
  let background = segment.trimEnd().endsWith('&')
  let index = 0
  for (; index < words.length; index += 1) {
    const word = words[index]
    if (argv.length === 0 && !word.dynamic && /^[A-Za-z_][A-Za-z0-9_]*=/u.test(word.value)) {
      env.push(word.value.slice(0, word.value.indexOf('=')))
      continue
    }
    const redirection = REDIRECTIONS.find(candidate => word.value.startsWith(candidate))
    if (redirection !== undefined) {
      const target = word.value.slice(redirection.length)
      if (target === '') {
        const next = words[index + 1]
        if (next === undefined) return { ok: false, reason: 'redirection without a target' }
        redirections.push({ op: redirection, target: next.value, dynamic: next.dynamic })
        index += 1
        continue
      }
      redirections.push({ op: redirection, target, dynamic: word.dynamic })
      continue
    }
    if (word.value === '&&' || word.value === '||' || word.value === ';' || word.value === '|') {
      return { ok: false, reason: `operator ${word.value} inside a segment` }
    }
    argv.push(word)
  }
  if (argv.length === 0) return { ok: false, reason: 'no executable' }
  for (const word of argv) {
    // Subshells and groups change what runs; do not guess their contents.
    if (/[()]/u.test(word.value) || word.value === '{' || word.value === '}') {
      return { ok: false, reason: 'subshell or group syntax' }
    }
  }
  const program = argv[0]
  if (!program.dynamic && CONTROL_KEYWORDS.has(program.value)) {
    return { ok: false, reason: `shell construct "${program.value}"` }
  }
  return {
    ok: true,
    command: {
      argv: argv.map(word => word.value),
      dynamicArgv: argv.map(word => word.dynamic),
      env,
      redirections,
      background,
      source: segment.trim(),
    },
  }
}

/**
 * Recognise `<shell> -c '…'` / `-lc` and return the inner program.
 * @param command - one parsed simple command.
 * @returns the inner source, or null when this is not a shell wrapper.
 */
export function shellWrapperSource(command) {
  const program = command.argv[0]
  if (typeof program !== 'string') return null
  const name = program.split(/[\\/]/u).pop() ?? program
  if (!SHELL_PROGRAMS.has(name)) return null
  for (let index = 1; index < command.argv.length; index += 1) {
    const argument = command.argv[index]
    if (/^-[A-Za-z]*c[A-Za-z]*$/u.test(argument)) {
      const source = command.argv[index + 1]
      return typeof source === 'string' ? source : null
    }
    if (/^-[A-Za-z]+$/u.test(argument)) continue
    return null
  }
  return null
}

/** Programs whose first argument is another shell program when it is literal. */
const EVAL_PROGRAMS = new Set(['eval', 'source', '.'])

/**
 * Recognise `eval '…'`, `source file`, `. file` and return the inner source.
 * A dynamic argument yields null so the segment is treated as unanalysable by
 * the caller (the policy turns that into `prompt`).
 * @param command - one parsed simple command.
 * @returns the inner source, `false` when the argument is dynamic, or null.
 */
export function evalSource(command) {
  const program = command.argv[0]
  if (typeof program !== 'string') return null
  if (!EVAL_PROGRAMS.has(program)) return null
  const argument = command.argv[1]
  if (argument === undefined) return false
  if (command.dynamicArgv[1] === true) return false
  return argument
}

/**
 * Parse a complete command line.
 * @param source - the raw shell command.
 * @param options - home directory for `~`, and the wrapper recursion budget.
 * @returns the parsed line: commands, operators, and whether it is analysable.
 */
export function parseCommandLine(source, { home = '/', depth = 0 } = {}) {
  if (typeof source !== 'string' || source.trim() === '') {
    return { analyzable: false, reason: 'empty command', commands: [], operators: [] }
  }
  if (depth > MAX_WRAPPER_DEPTH) {
    return { analyzable: false, reason: 'shell wrapper nesting too deep', commands: [], operators: [] }
  }
  const segments = splitSegments(source)
  const commands = []
  const operators = []
  for (const segment of segments) {
    if (segment.operator !== null) operators.push(segment.operator)
    if (segment.text.trim() === '') continue
    const parsed = parseSegment(segment.text, home)
    if (!parsed.ok) {
      return { analyzable: false, reason: parsed.reason, commands: [], operators }
    }
    const command = parsed.command
    const evaluated = evalSource(command)
    if (evaluated === false) {
      return { analyzable: false, reason: 'eval of a runtime string', commands: [], operators }
    }
    if (evaluated !== null) {
      const inner = parseCommandLine(evaluated, { home, depth: depth + 1 })
      if (!inner.analyzable) {
        return { analyzable: false, reason: `eval program: ${inner.reason}`, commands: [], operators }
      }
      commands.push(...inner.commands, { ...command, nested: true, nestedSource: evaluated })
      continue
    }
    const wrapped = shellWrapperSource(command)
    if (wrapped !== null) {
      const inner = parseCommandLine(wrapped, { home, depth: depth + 1 })
      if (!inner.analyzable) {
        return { analyzable: false, reason: `shell wrapper program: ${inner.reason}`, commands: [], operators }
      }
      commands.push(...inner.commands, { ...command, nested: true, nestedSource: wrapped })
      continue
    }
    if (command.dynamicArgv[0] === true) {
      return { analyzable: false, reason: 'dynamic executable', commands: [], operators }
    }
    commands.push(command)
  }
  if (commands.length === 0) {
    return { analyzable: false, reason: 'no analysable command', commands: [], operators }
  }
  return { analyzable: true, commands, operators }
}
