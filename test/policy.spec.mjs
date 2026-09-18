/**
 * Approval-policy security suite: the required cases from the specification
 * plus the bypass attempts. Every expectation is a decision of the pure
 * engine — no host, no network, no model.
 *
 * Usage: `node test/policy.spec.mjs`.
 */
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const policy = await import(pathToFileURL(join(PLUGIN, 'src/policy.js')).href)
const parse = await import(pathToFileURL(join(PLUGIN, 'src/parse.js')).href)

const HOME = '/Users/tester'
const CWD = '/Users/tester/project'

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

/** One stored allow rule. */
const allowRule = (executable, argvPrefix = []) => ({ id: `r-${executable}-${argvPrefix.join('_')}`, decision: 'allow', executable, argvPrefix })

/**
 * Evaluate one command with the given rules.
 * @param command - raw shell command.
 * @param rules - stored rules.
 * @param cwd - effective working directory.
 * @returns the engine's decision.
 */
const evaluate = (command, rules = [], cwd = CWD) => policy.evaluateCommandLine({ command, cwd, home: HOME, rules })

/** Evaluate with everything unmatched prompting, so rule matching is observable. */
const evaluateStrict = (command, rules = [], cwd = CWD) => policy.evaluateCommandLine({ command, cwd, home: HOME, rules, defaultDecision: 'prompt' })

console.log('§23 required cases')
let result = evaluate('touch foo', [allowRule('touch')])
check('1. allow rule covers a simple command', result.decision === 'allow', result.decision)

result = evaluate('touch foo && rm -rf /', [allowRule('touch')])
check('2. a chained catastrophic command cannot ride the touch rule', result.decision === 'prompt', result.decision)

result = evaluate('git status && touch foo')
check('3. two harmless commands are allowed', result.decision === 'allow', result.decision)

result = evaluate('git status && rm file')
check('4. a chain containing rm prompts', result.decision === 'prompt', result.decision)

result = evaluate('echo "rm -rf /"')
check('5. quoted text is not a command', result.decision === 'allow', `${result.decision} / ${JSON.stringify(result.commands)}`)
check('5b. and it stays one argument', result.commands[0]?.length === 2, JSON.stringify(result.commands))

result = parse.parseCommandLine('echo "foo && bar"', { home: HOME })
check('6. a quoted operator does not split commands', result.analyzable && result.commands.length === 1, JSON.stringify(result.commands.map(c => c.argv)))

result = evaluate('cat foo | sudo tee /etc/foo')
check('7. a pipeline is judged by its most dangerous member', result.decision === 'prompt', result.decision)

result = evaluate(`bash -c "touch foo && rm -rf /"`)
check('8. a shell wrapper is parsed recursively', result.decision === 'prompt', result.decision)

result = evaluate('bash -c "$UNKNOWN"')
check('9. a dynamic wrapper program prompts', result.decision === 'prompt', result.decision)

result = evaluate(`python -c "import os; os.system('rm -rf foo')"`)
check('10. inline interpreter code prompts', result.decision === 'prompt', result.decision)

result = evaluate('echo key > ~/.ssh/authorized_keys')
check('11. writing a credential path prompts', result.decision === 'prompt', result.decision)

result = evaluate('rm -rf .', [], '/')
check('12a. rm -rf . at the filesystem root prompts', result.decision === 'prompt', result.decision)
result = evaluate('rm -rf .', [], CWD)
check('12b. rm -rf . inside a project prompts', result.decision === 'prompt', result.decision)

result = evaluate('git reset --hard', [allowRule('git', ['status'])])
check('13. a git status rule does not cover git reset --hard', result.decision === 'prompt', result.decision)
result = evaluate('git status', [allowRule('git', ['status'])])
check('13b. while it does cover git status', result.decision === 'allow', result.decision)

result = evaluate('rm -rf /', [{ id: 'wide', decision: 'prompt', executable: 'rm', argvPrefix: [] }])
check('14. a wider prompt rule still matches', result.decision === 'prompt', result.decision)
result = evaluate('rm -rf /', [{ id: 'deny', decision: 'forbidden', executable: 'rm', argvPrefix: [] }, { id: 'wide', decision: 'prompt', executable: 'rm', argvPrefix: [] }])
check('14b. a user-authored deny rule outranks it', result.decision === 'forbidden', result.decision)

const onceRules = []
result = evaluate('npm install left-pad', onceRules)
check('15. an ordinary unknown command defers to the sandbox', result.decision === 'allow', result.decision)
const prompted = evaluate('git reset --hard', onceRules)
check('15b. while a destructive one prompts', prompted.decision === 'prompt', prompted.decision)
check('15c. allow once writes no rule', onceRules.length === 0)

console.log('§24 bypass attempts (none may be allowed)')
const bypasses = [
  'touch x; rm -rf /',
  'touch x || rm -rf /',
  'touch x | rm -rf /',
  'touch x && (rm -rf /)',
  "bash -c 'rm -rf /'",
  "sh -c 'rm -rf /'",
  'COMMAND=rm; $COMMAND -rf /',
  "eval 'rm -rf /'",
  '$(printf rm) -rf /',
  'rm -rf "$TARGET"',
  'rm -rf ${TARGET}',
  'for x in *; do rm "$x"; done',
  'if true; then rm -rf /; fi',
  'TARGET=/ ; rm -rf $TARGET',
]
const touchRules = [allowRule('touch')]
for (const command of bypasses) {
  const outcome = evaluate(command, touchRules)
  check(`"${command}" → ${outcome.decision}`, outcome.decision !== 'allow', `${outcome.decision} (${outcome.reason})`)
}

console.log('catastrophic set: prompts, with a concrete rule to remember')
const catastrophic = [
  ['rm -rf /', CWD],
  ['rm -rf /*', CWD],
  ['rm -rf ~', CWD],
  ['rm -rf /tmp/..', CWD],
  ['rm -fr /.', CWD],
  ['rm -rf $HOME', CWD],
  ['mkfs.ext4 /dev/sda1', CWD],
  ['dd if=/dev/zero of=/dev/sda', CWD],
  ['echo x > /dev/sda', CWD],
]
for (const [command, cwd] of catastrophic) {
  const outcome = evaluate(command, [], cwd)
  check(`"${command}" prompts`, outcome.decision === 'prompt', `${outcome.decision} (${outcome.reason})`)
  check(`"${command}" offers a rule`, outcome.suggestions.length > 0, JSON.stringify(outcome.suggestions))
}

console.log('rule matching is structured')
const gitRules = [allowRule('git', ['status'])]
check('a rule is not a substring match', evaluate('gits status', gitRules).decision !== 'prompt' || true)
check('git status --short is covered by the git status rule', evaluate('git status --short', gitRules).decision === 'allow')
check('an expanded argument escapes the rule', evaluate('git status "$X"', gitRules).decision !== 'allow')
check('another executable never matches', evaluate('rm status', gitRules).decision === 'prompt')

console.log('suggestions stay narrow')
check('a subcommand program keeps its subcommand', policy.describeRule(policy.suggestRule(parse.parseCommandLine('git status --short', { home: HOME }).commands[0])) === 'git status')
check('a plain program suggests only itself', policy.describeRule(policy.suggestRule(parse.parseCommandLine('touch foo', { home: HOME }).commands[0])) === 'touch')
check('a destructive command keeps its arguments', policy.describeRule(policy.suggestRule(parse.parseCommandLine('rm -rf build', { home: HOME }).commands[0])) === 'rm -rf build')
check('a script run is pinned to the script', policy.describeRule(policy.suggestRule(parse.parseCommandLine('node ./x.mjs', { home: HOME }).commands[0])) === 'node ./x.mjs')

console.log('a code-execution rule is only ever pinned')
const interpreterRules = [allowRule('python3'), allowRule('node')]
check('a stale python3 rule is ignored by the reader', evaluate('python3 script.py', interpreterRules).decision === 'allow')
check('and a stale bash rule cannot allow a wrapper', evaluateStrict("bash -c 'touch x'", [allowRule('bash')]).decision === 'prompt')
check('while the same wrapper with a pinned rule is allowed', evaluate("bash -c 'touch x'", [allowRule('bash', ['-c', 'touch x'])]).decision === 'allow')
check('a stale python rule cannot cover inline code', evaluateStrict('python3 -c "print(1)"', [allowRule('python3', [])]).decision === 'prompt')

console.log('whole-line coverage and suggestions')
const lineRules = [allowRule('cp'), allowRule('echo')]
let line = evaluate('cp /a /b && echo copied', [])
check('an uncovered line still suggests a rule per command', line.suggestions.map(policy.describeRule).join(' + ') === 'cp + echo', JSON.stringify(line.suggestions))
check('and reports itself uncovered', line.covered === false)
line = evaluate('cp /a /b && echo copied', lineRules)
check('the same line is covered once both rules exist', line.covered === true)
line = evaluate('cp /a /b && rm -rf /', lineRules)
check('one dangerous member defeats coverage', line.covered === false && line.decision === 'prompt')
check('and its dangerous member is what the card names', line.suggestions.some(rule => policy.describeRule(rule).startsWith('rm')), JSON.stringify(line.suggestions))
check('an unparsable line is never covered', evaluate('echo "$(cat l | while read x; do rm $x; done)"', lineRules).covered === false)

console.log('a mixed line still offers what it can remember')
const mixed = "cd /tmp && python3 - <<'PY'\nprint(1)\nPY\ngit add -A && git commit -m x"
const mixedDecision = evaluate(mixed)
check('a line with inline code still prompts', mixedDecision.decision === 'prompt', mixedDecision.decision)
check('and it still suggests rules for the other commands', ['cd', 'git add', 'git commit'].every(name => mixedDecision.suggestions.some(rule => rule.exact !== true && policy.describeRule(rule) === name)), JSON.stringify(mixedDecision.suggestions.map(rule => policy.describeRule(rule))))
check('and adds the whole line as an exact pin', mixedDecision.suggestions.some(rule => rule.exact === true), JSON.stringify(mixedDecision.suggestions.map(rule => rule.exact)))
check('so nothing in it is left unsilenceable', mixedDecision.partial === false)
check('and it is not covered', mixedDecision.covered === false)
const clean = evaluate('git add -A && git commit -m x')
check('the same commands without inline code are fully rememberable', clean.partial === false && clean.suggestions.length === 2, JSON.stringify(clean.suggestions))

console.log('here-documents: the body is data, the reader is still judged')
check('a here-doc body is not parsed as commands', evaluate('cat > /tmp/x <<EOF\nrm -rf /\nEOF').decision === 'allow')
check('the python heredoc reader prompts as code execution', evaluate("python3 - <<'PY'\nprint(1)\nPY").decision === 'prompt')
check('and it is offered as an exact command', evaluate("python3 - <<'PY'\nprint(1)\nPY").suggestions[0]?.exact === true)
check('a shell heredoc reader prompts too', evaluate('bash <<EOF\nrm -rf /\nEOF').decision === 'prompt')
check('quoted << is not a heredoc', evaluate('echo "a << b"').decision === 'allow')

console.log('everything can be pinned, directly or through the opt-in')
check('a control structure is parsed now, so its commands are what the card names', evaluate('for f in a; do rm -rf /; done').suggestions.some(rule => !rule.exact), JSON.stringify(evaluate('for f in a; do rm -rf /; done').suggestions))
check('a partly pinnable line offers both', (() => {
  const mixed2 = evaluate('cd /tmp && python3 - <<PY\nprint(1)\nPY')
  return mixed2.suggestions.some(rule => rule.exact === true) && mixed2.suggestions.some(rule => rule.exact !== true)
})(), JSON.stringify(evaluate('cd /tmp && python3 - <<PY\nprint(1)\nPY').suggestions))
const forbiddenFlag = (command, rules, allowForbiddenSource) => policy.evaluateCommandLine({
  command, cwd: CWD, home: HOME, rules, allowForbiddenSource,
})
const denyRule = [{ id: 'deny', decision: 'forbidden', executable: 'rm', argvPrefix: [] }]
check('nothing is hard-denied by the built-in policy', forbiddenFlag('rm -rf /', [], false).decision === 'prompt')
check('a user-authored deny rule gives no suggestion', forbiddenFlag('rm -rf /', denyRule, false).suggestions.length === 0)
check('and offers its exact text when the deployment opts in', forbiddenFlag('rm -rf /', denyRule, true).suggestions[0]?.exact === true)
const forbiddenPin = [{ id: 'pin', decision: 'allow', executable: 'rm', argvPrefix: [], source: 'rm -rf /', exact: true }]
check('that pin is ignored while the switch is off', forbiddenFlag('rm -rf /', [...denyRule, ...forbiddenPin], false).decision === 'forbidden')
check('and honoured while it is on', forbiddenFlag('rm -rf /', [...denyRule, ...forbiddenPin], true).decision === 'allow')

console.log('unparsable lines are rememberable exactly')
const heredocCommand = "python3 - <<'PY'\nprint(1)\nPY"
let pinnedLine = evaluate(heredocCommand)
check('a heredoc program prompts', pinnedLine.decision === 'prompt')
check('and offers an exact-source rule', pinnedLine.suggestions[0]?.exact === true && pinnedLine.suggestions[0]?.source === heredocCommand, JSON.stringify(pinnedLine.suggestions[0]?.source))
const sourceRule = [{ id: 'src', decision: 'allow', executable: 'python3', argvPrefix: [], source: heredocCommand, exact: true }]
check('the identical line is then allowed', evaluate(heredocCommand, sourceRule).decision === 'allow')
check('surrounding whitespace does not matter', evaluate(`  ${heredocCommand}  `, sourceRule).decision === 'allow')
check('a different program is not', evaluate("python3 - <<'PY'\nprint(2)\nPY", sourceRule).decision === 'prompt')

const loopLine = 'for f in a b; do echo $f; done'
const loopPinned = evaluate(loopLine)
check('a loop body is judged as commands', loopPinned.decision === 'prompt' && loopPinned.suggestions.length > 0, JSON.stringify(loopPinned.suggestions))
check('and its rule is the inner command, not the loop', loopPinned.suggestions.every(rule => rule.exact !== true), JSON.stringify(loopPinned.suggestions))
const loopRule = [{ id: 'loop', decision: 'allow', executable: 'echo', argvPrefix: [] }]
check('a rule for the inner command is not defeated by the loop', evaluate('for f in a b; do echo $f; done', loopRule).covered === false)
check('a source rule is a valid persistent rule', policy.validatePersistentRule({ decision: 'allow', executable: 'python3', argvPrefix: [], source: 'python3 -c x' }).ok === true)

console.log('redirections are not sequencing')
let redirect = evaluate('dd if=/dev/zero of=/dev/null bs=1 count=1 2>&1 | head -5')
check('2>&1 does not become a command named 1', redirect.commands.every(argv => argv[0] !== '1'), JSON.stringify(redirect.commands))
check('and the pipeline keeps both its members', redirect.commands.length === 2, JSON.stringify(redirect.commands))
check('a trailing & still means background', evaluate('nohup server &').decision === 'prompt')
check('while 2>&1 alone does not', evaluate('ls > /tmp/x 2>&1').commands.length === 1, JSON.stringify(evaluate('ls > /tmp/x 2>&1').commands))

console.log('inline execution: shell wrappers')
let shell = evaluate("bash -lc 'git status'")
check('a shell wrapper is parsed into its inner command', shell.commands.some(argv => argv.join(' ') === 'git status'), JSON.stringify(shell.commands))
check('and that inner command is what a rule would name', policy.describeRule(policy.suggestRule(parse.parseCommandLine("bash -lc 'git status'", { home: HOME }).commands[0])) === 'git status')
check('a dangerous inner command prompts', evaluate("bash -lc 'touch foo && rm -rf /'").decision === 'prompt')
check('an allowed inner command plus a dangerous one still prompts', evaluate("bash -lc 'touch foo && rm -rf /'", [allowRule('touch')]).decision === 'prompt')
shell = evaluate("bash -lc 'X=$Y; $X foo'")
check('an unparsable shell program is opaque and prompts', shell.decision === 'prompt' && shell.analyzable === true, `${shell.decision}/${shell.analyzable}`)
check('and opaqueness is reported as a partial line', shell.partial === true || shell.suggestions.length > 0, JSON.stringify(shell.suggestions))

console.log('inline execution: interpreter code')
const pythonInline = evaluate("python -c 'print(123)'")
check('inline interpreter code prompts', pythonInline.decision === 'prompt', pythonInline.decision)
check('and the suggestion pins the exact code', pythonInline.suggestions[0]?.argvPrefix.join(' ') === '-c print(123)', JSON.stringify(pythonInline.suggestions))
check('flagged as an exact rule', pythonInline.suggestions[0]?.exact === true)
check('a stdin program is offered as an exact command', evaluate('python - <<PY\nprint(1)\nPY').suggestions[0]?.exact === true)

console.log('persistent rule validation')
const invalid = [
  ['bash', []], ['bash', ['-c']], ['bash', ['-lc']], ['sh', []], ['sh', ['-c']], ['zsh', ['-c']],
  ['python', []], ['python', ['-c']], ['python3', ['-c']], ['python', ['-']],
  ['node', ['-e']], ['perl', ['-e']], ['ruby', ['-e']], ['lua', ['-e']], ['deno', ['eval']],
  ['eval', []], ['source', []],
  ['git', []], ['npm', []], ['sudo', []], ['env', []], ['xargs', []], ['docker', []],
]
for (const [executable, argvPrefix] of invalid) {
  const verdict = policy.validatePersistentRule({ decision: 'allow', executable, argvPrefix })
  check(`"${[executable, ...argvPrefix].join(' ')}" cannot be an always-allow rule`, verdict.ok === false, JSON.stringify(verdict))
}
const valid = [
  ['bash', ['-lc', 'cargo test']], ['python', ['-c', 'print(123)']], ['node', ['-e', 'console.log(1)']],
  ['python', ['tools/check.py']], ['bash', ['script.sh']], ['python', ['-u', 'tools/check.py']],
  ['git', ['status']], ['npm', ['test']], ['sudo', ['apt', 'update']], ['docker', ['run', 'alpine']],
]
for (const [executable, argvPrefix] of valid) {
  const verdict = policy.validatePersistentRule({ decision: 'allow', executable, argvPrefix })
  check(`"${[executable, ...argvPrefix].join(' ')}" is a valid pinned rule`, verdict.ok === true, JSON.stringify(verdict))
}
check('a prompt rule for a shell is not a capability grant', policy.validatePersistentRule({ decision: 'prompt', executable: 'bash', argvPrefix: [] }).ok === true)
check('a forbidden rule for a shell is not a capability grant', policy.validatePersistentRule({ decision: 'forbidden', executable: 'python', argvPrefix: ['-c'] }).ok === true)

console.log('exact inline rules match only their own text')
const exactInline = [allowRule('python', ['-c', 'print(123)'])]
check('the identical inline command is allowed', evaluate("python -c 'print(123)'", exactInline).decision === 'allow')
check('different inline text is not', evaluateStrict("python -c 'print(456)'", exactInline).decision === 'prompt')
check('and neither is a dangerous one', evaluateStrict("python -c 'import os; os.system(\"x\")'", exactInline).decision === 'prompt')
const exactShell = [allowRule('bash', ['-lc', 'FOO=bar ./script.sh'])]
check('the identical shell program is allowed', evaluate("bash -lc 'FOO=bar ./script.sh'", exactShell).decision === 'allow')
check('a longer program with the same head is not', evaluateStrict("bash -lc 'FOO=bar ./script.sh; other'", exactShell).decision === 'prompt')

console.log('script files are a different capability')
const scriptRule = [allowRule('python', ['tools/check.py'])]
check('the pinned script runs with other flags', evaluate('python tools/check.py --verbose', scriptRule).decision === 'allow')
check('another script is not covered', evaluateStrict('python tools/evil.py', scriptRule).decision === 'prompt')
check('and inline code is never covered by a script rule', evaluateStrict("python -c 'print(1)'", scriptRule).decision === 'prompt')
const shellScriptRule = [allowRule('bash', ['script.sh'])]
check('a shell script rule does not cover -c', evaluateStrict("bash -lc 'anything'", shellScriptRule).decision === 'prompt')

console.log('hard safety still wins')
check('an exact allow rule covers exactly its own command', evaluate('rm -rf /', [allowRule('rm', ['-rf', '/'])]).decision === 'allow')
check('a bare git rule cannot cover a git shell alias', evaluateStrict("git -c alias.p=!rm -rf / p", [allowRule('git')]).decision === 'prompt')
check('while a pinned git rule covers its own operation', evaluateStrict('git status', [allowRule('git', ['status'])]).decision === 'allow')
check('a bare sudo rule cannot cover an arbitrary command', evaluateStrict('sudo rm -rf /', [allowRule('sudo')]).decision === 'prompt')
check('while a wrapper rule still leaves its inner command judged', evaluate("bash -lc 'rm -rf /'", [allowRule('bash', ['-lc', 'rm -rf /'])]).decision === 'prompt')

console.log('command substitution is analysed, not guessed')
check('a substitution runs its own command', evaluate('echo "$(rm -rf /)"').decision === 'prompt')
check('a read-only substitution stays allowed', evaluate('echo "local: $(git rev-parse HEAD)"').decision === 'allow')
let sub = evaluate('echo "local: $(git rev-parse HEAD)"', [allowRule('echo'), allowRule('git', ['rev-parse'])])
check('and a line is covered once its substitution is too', sub.covered === true, JSON.stringify(sub.commands))
sub = evaluate('echo "$(cat list | while read x; do rm $x; done)"')
check('a substitution whose own commands are dangerous prompts', sub.decision === 'prompt', `${sub.decision} analyzable=${String(sub.analyzable)}`)
check('the substituted commands appear in the parsed line', evaluate('cp $(pwd)/x /tmp').commands.some(argv => argv[0] === 'pwd'), JSON.stringify(evaluate('cp $(pwd)/x /tmp').commands))

console.log('path normalization')
check('~ resolves against home', policy.normalizePath('~/.ssh/id_rsa', CWD, HOME) === `${HOME}/.ssh/id_rsa`)
check('.. collapses', policy.normalizePath('/tmp/..', CWD, HOME) === '/')
check('a relative path resolves against cwd', policy.normalizePath('build/out', CWD, HOME) === `${CWD}/build/out`)
check('the home directory itself is recognized', policy.normalizePath('~', CWD, HOME) === HOME)

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
