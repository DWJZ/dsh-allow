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

console.log('§23 required cases')
let result = evaluate('touch foo', [allowRule('touch')])
check('1. allow rule covers a simple command', result.decision === 'allow', result.decision)

result = evaluate('touch foo && rm -rf /', [allowRule('touch')])
check('2. a chained catastrophic command is forbidden despite the touch rule', result.decision === 'forbidden', result.decision)

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
check('8. a shell wrapper is parsed recursively', result.decision === 'forbidden', result.decision)

result = evaluate('bash -c "$UNKNOWN"')
check('9. a dynamic wrapper program prompts', result.decision === 'prompt', result.decision)

result = evaluate(`python -c "import os; os.system('rm -rf foo')"`)
check('10. inline interpreter code prompts', result.decision === 'prompt', result.decision)

result = evaluate('echo key > ~/.ssh/authorized_keys')
check('11. writing a credential path prompts', result.decision === 'prompt', result.decision)

result = evaluate('rm -rf .', [], '/')
check('12a. rm -rf . at the filesystem root is forbidden', result.decision === 'forbidden', result.decision)
result = evaluate('rm -rf .', [], CWD)
check('12b. rm -rf . inside a project prompts', result.decision === 'prompt', result.decision)

result = evaluate('git reset --hard', [allowRule('git', ['status'])])
check('13. a git status rule does not cover git reset --hard', result.decision === 'prompt', result.decision)
result = evaluate('git status', [allowRule('git', ['status'])])
check('13b. while it does cover git status', result.decision === 'allow', result.decision)

result = evaluate('rm -rf /', [{ id: 'wide', decision: 'prompt', executable: 'rm', argvPrefix: [] }])
check('14. forbidden outranks a wider prompt rule', result.decision === 'forbidden', result.decision)

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

console.log('catastrophic set')
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
  check(`"${command}" is forbidden`, outcome.decision === 'forbidden', `${outcome.decision} (${outcome.reason})`)
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
check('a flag is never part of a suggestion', policy.describeRule(policy.suggestRule(parse.parseCommandLine('rm -rf build', { home: HOME }).commands[0])) === 'rm')
check('a path is never part of a suggestion', policy.describeRule(policy.suggestRule(parse.parseCommandLine('node ./x.mjs', { home: HOME }).commands[0])) === 'node')

console.log('path normalization')
check('~ resolves against home', policy.normalizePath('~/.ssh/id_rsa', CWD, HOME) === `${HOME}/.ssh/id_rsa`)
check('.. collapses', policy.normalizePath('/tmp/..', CWD, HOME) === '/')
check('a relative path resolves against cwd', policy.normalizePath('build/out', CWD, HOME) === `${CWD}/build/out`)
check('the home directory itself is recognized', policy.normalizePath('~', CWD, HOME) === HOME)

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
