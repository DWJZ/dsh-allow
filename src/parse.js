/**
 * Shell parsing for the approval policy, built on tree-sitter + tree-sitter-bash.
 *
 * The grammar decides the structure — statements, pipelines, lists, control
 * structures, substitutions, redirections, here-documents — and this module
 * only reads that tree: it reports the simple commands a line would run, their
 * literal arguments, which words are expanded at run time, and whether the line
 * can be judged at all. A line the grammar cannot parse, or one whose program
 * name is itself computed, is reported unanalysable so the policy never guesses.
 */
import Parser from 'tree-sitter'
import Bash from 'tree-sitter-bash'

/** One shared parser: `parse` is synchronous and does not retain the last tree. */
const parser = new Parser()
parser.setLanguage(Bash)

/** How deep shell `-c` wrappers are followed. */
export const MAX_WRAPPER_DEPTH = 4

/** Programs whose `-c` argument is another shell program. */
const SHELL_PROGRAMS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'ash', 'fish'])

/** Node types that make a word's value depend on run time. */
const DYNAMIC_PARTS = new Set([
  'simple_expansion', 'expansion', 'arithmetic_expansion', 'process_substitution',
])

/** Node types that contain statements this parser must follow. */
const STATEMENT_CONTAINERS = new Set([
  'program', 'list', 'pipeline', 'redirected_statement', 'subshell', 'compound_statement',
  'do_group', 'if_statement', 'elif_clause', 'else_clause', 'while_statement', 'for_statement',
  'case_statement', 'case_item', 'negated_command', 'c_style_for_statement', 'select_statement',
])

/** Redirection operators tree-sitter exposes as unnamed children. */
const REDIRECTION_TOKENS = new Set(['>', '>>', '<', '>&', '<&', '&>', '&>>', '>|', '<>', '<<', '<<-', '<<<'])

/**
 * Strip the surrounding quotes from one string node.
 * @param type - the node type (`string` or `raw_string`).
 * @param text - the node's source text.
 * @returns the inner text.
 */
function unquote(type, text) {
  const inner = text.slice(1, -1)
  return type === 'raw_string' ? inner : inner.replace(/\\(["'$`\\])/gu, '$1')
}

/**
 * Read one word-like node.
 *
 * @param node - a tree-sitter node used as an argument or program name.
 * @param collect - receives the statements of any command substitution found.
 * @returns the literal text and whether it is expanded at run time.
 */
function readWord(node, collect) {
  const named = node.namedChildren ?? []
  const substitutions = named.filter(child => child.type === 'command_substitution')
  if (substitutions.length > 0) {
    let resolved = true
    for (const substitution of substitutions) {
      if (!collect(substitution)) resolved = false
    }
    const text = node.type === 'string' || node.type === 'raw_string' ? unquote(node.type, node.text) : node.text
    return { text, dynamic: resolved ? 'resolved' : true }
  }
  if (node.type === 'string' || node.type === 'raw_string') {
    return { text: unquote(node.type, node.text), dynamic: named.some(child => DYNAMIC_PARTS.has(child.type)) }
  }
  if (DYNAMIC_PARTS.has(node.type)) return { text: node.text, dynamic: true }
  if (named.length === 0) return { text: node.text, dynamic: false }
  return { text: node.text, dynamic: named.some(child => DYNAMIC_PARTS.has(child.type) || child.type === 'command_substitution') }
}

/**
 * Read one redirect node.
 * @param node - a `file_redirect`, `heredoc_redirect`, or `herestring_redirect`.
 * @returns the operator, the target text, and whether the target is expanded.
 */
function readRedirect(node) {
  const operator = (node.children ?? []).find(child => child.isNamed === false && REDIRECTION_TOKENS.has(child.text))?.text
    ?? (node.type === 'heredoc_redirect' ? '<<' : '>')
  const target = node.namedChildren.find(child => child.type === 'word' || child.type === 'string'
    || child.type === 'raw_string' || DYNAMIC_PARTS.has(child.type) || child.type === 'command_substitution')
  if (target === undefined) return { op: operator, target: '', dynamic: false }
  const word = readWord(target, () => true)
  return { op: operator, target: word.text, dynamic: word.dynamic === true || word.dynamic === 'resolved' }
}

/**
 * Parse a complete command line.
 *
 * @param source - the raw shell command.
 * @param options - `home` for `~` expansion and the wrapper recursion budget.
 * @returns the simple commands in source order, the operators between them, and
 *   whether the line could be analysed at all.
 */
export function parseCommandLine(source, { home = '/', depth = 0 } = {}) {
  if (typeof source !== 'string' || source.trim() === '') {
    return { analyzable: false, reason: 'empty command', commands: [], operators: [] }
  }
  if (depth > MAX_WRAPPER_DEPTH) {
    return { analyzable: false, reason: 'shell wrapper nesting too deep', commands: [], operators: [] }
  }
  const tree = parser.parse(source)
  if (tree.rootNode.hasError) {
    // The grammar rejected the line: the shell would too, so the policy denies
    // it outright instead of asking anyone to approve a command that cannot run.
    return { analyzable: false, syntaxError: true, reason: 'shell syntax error', commands: [], operators: [] }
  }
  const commands = []
  const operators = []
  let dynamicProgram = null

  /** Collect the statements one command substitution runs: they run first. */
  const collectSubstitution = (node) => {
    for (const child of node.namedChildren ?? []) walk(child)
    return true
  }

  /** Turn one `command` node into a policy-visible command. */
  const readCommand = (node, background) => {
    const nameNode = node.childForFieldName?.('name') ?? null
    const name = nameNode === null ? { text: '', dynamic: false } : readWord(nameNode, collectSubstitution)
    if (nameNode !== null && (name.dynamic === true || name.dynamic === 'resolved')) {
      // `$(printf rm) -rf /` — an executable computed at run time is not judged.
      dynamicProgram = nameNode.text
      return
    }
    const argv = [name.text]
    const dynamicArgv = [name.dynamic]
    const env = []
    const redirections = []
    for (const child of node.namedChildren ?? []) {
      if (child.type === 'command_name') continue
      if (child.type === 'variable_assignment' && argv.length === 1) {
        const assignmentName = child.childForFieldName?.('name')
        if (assignmentName !== null) env.push(assignmentName.text)
        continue
      }
      if (child.type === 'file_redirect' || child.type === 'heredoc_redirect' || child.type === 'herestring_redirect') {
        redirections.push(readRedirect(child))
        continue
      }
      const word = readWord(child, collectSubstitution)
      argv.push(word.text)
      dynamicArgv.push(word.dynamic)
    }
    // A shell wrapper's inner program is a program too: follow it when literal.
    const program = argv[0].split(/[\\/]/u).pop() ?? argv[0]
    if (SHELL_PROGRAMS.has(program)) {
      const flagIndex = argv.findIndex((token, index) => index > 0 && /^-[A-Za-z]*c[A-Za-z]*$/u.test(token))
      const inner = flagIndex === -1 ? null : argv[flagIndex + 1]
      if (typeof inner === 'string' && dynamicArgv[flagIndex + 1] === false) {
        const nested = parseCommandLine(inner, { home, depth: depth + 1 })
        if (nested.analyzable) commands.push(...nested.commands)
        commands.push({
          argv,
          dynamicArgv,
          env,
          redirections,
          background,
          source: node.text,
          nested: true,
          nestedSource: inner,
          ...nested.analyzable ? {} : { opaque: true, opaqueReason: nested.reason },
        })
        return
      }
    }
    commands.push({ argv, dynamicArgv, env, redirections, background, source: node.text })
  }

  /** Walk one statement-bearing node. */
  const walk = (node, background = false) => {
    if (node === null || node === undefined) return
    if (node.type === 'command') {
      readCommand(node, background)
      return
    }
    if (node.type === 'redirected_statement') {
      // `cmd > file`: the redirects belong to whatever the body runs.
      const redirects = (node.children ?? [])
        .filter(child => child.isNamed === true && (child.type === 'file_redirect' || child.type === 'heredoc_redirect' || child.type === 'herestring_redirect'))
        .map(readRedirect)
      const body = node.childForFieldName?.('body')
      const before = commands.length
      walk(body ?? node, background)
      for (let index = before; index < commands.length; index += 1) {
        commands[index].redirections = [...commands[index].redirections, ...redirects]
      }
      return
    }
    if (node.type === 'declaration_command') {
      const words = node.text.trim().split(/\s+/u)
      commands.push({
        argv: words,
        dynamicArgv: words.map(() => false),
        env: [],
        redirections: [],
        background,
        source: node.text,
      })
      return
    }
    if (node.type === 'test_command' || node.type === 'arithmetic') return
    if (node.type === 'function_definition') {
      commands.push({
        argv: [node.text],
        dynamicArgv: [true],
        env: [],
        redirections: [],
        background,
        source: node.text,
        opaque: true,
        opaqueReason: 'function definition',
      })
      return
    }
    if (!STATEMENT_CONTAINERS.has(node.type)) {
      for (const child of node.namedChildren ?? []) walk(child, background)
      return
    }
    let markFrom = commands.length
    for (const child of node.children ?? []) {
      if (child.isNamed === false) {
        if (child.text === '&&' || child.text === '||' || child.text === '|' || child.text === '|&'
          || child.text === ';' || child.text === '&') operators.push(child.text)
        // `&` backgrounds the statement before it, which may be a whole pipeline.
        if (child.text === '&') {
          for (let index = markFrom; index < commands.length; index += 1) commands[index].background = true
        }
        continue
      }
      markFrom = commands.length
      walk(child, background)
    }
  }

  walk(tree.rootNode)
  if (dynamicProgram !== null) {
    return { analyzable: false, reason: `dynamic executable (${dynamicProgram})`, commands: [], operators }
  }
  if (commands.length === 0) {
    return { analyzable: false, reason: 'no command to judge', commands: [], operators }
  }
  return { analyzable: true, commands, operators }
}
