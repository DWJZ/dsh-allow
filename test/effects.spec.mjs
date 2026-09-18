/**
 * Effect derivation suite: what one parsed command line does to the filesystem,
 * read from the program and its arguments rather than from its name.
 *
 * Usage: `node test/effects.spec.mjs`.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const effects = await import(pathToFileURL(join(PLUGIN, 'src/effects.js')).href)
const parser = await import(pathToFileURL(join(PLUGIN, 'src/parse.js')).href)
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-effects-'))
const CWD = join(root, 'proj')
const HOME = '/Users/tester'
mkdirSync(CWD, { recursive: true })
writeFileSync(join(CWD, 'existing.txt'), 'seed\n')
mkdirSync(join(CWD, 'src'), { recursive: true })
const canon = (path) => fspolicy.canonicalPath(path, { cwd: CWD, home: HOME })

/** Derive the effects of one command line. */
function derive(command) {
  const parsed = parser.parseCommandLine(command, { home: HOME })
  if (!parsed.analyzable) return { effects: [], unknown: [], commands: [], parsed }
  const derived = effects.effectsOf(parsed, { cwd: CWD, home: HOME, env: { PATH: '/usr/bin:/bin' } })
  return { ...derived, parsed }
}

/** The paths one operation was derived for. */
const pathsFor = (result, operation) => result.effects
  .filter(effect => effect.operation === operation)
  .map(effect => effect.path)

console.log('mutations')
let result = derive('rm -rf build')
check('rm is a delete of its operand', pathsFor(result, 'delete').includes(canon('build')), JSON.stringify(pathsFor(result, 'delete')))
check('and nothing else', pathsFor(result, 'write').length === 0 && pathsFor(result, 'create').length === 0)

result = derive('rm "$DIR"')
check('a variable path is unknown, not guessed', pathsFor(result, 'delete').length === 0)
check('and it says which operation was unknown',
  result.unknown.some(entry => entry.operation === 'delete' && entry.reason.includes('expanded at run time')), JSON.stringify(result.unknown))

result = derive('mkdir -p a/b')
check('mkdir creates the directory it names', pathsFor(result, 'create').includes(canon('a/b')))

result = derive('touch new.txt')
check('touch on a missing path is a create', pathsFor(result, 'create').includes(canon('new.txt')))

result = derive('touch existing.txt')
check('touch on an existing path is a write', pathsFor(result, 'write').includes(canon('existing.txt')))

result = derive('chmod 600 existing.txt')
check('chmod writes metadata on its operand', pathsFor(result, 'write').includes(canon('existing.txt')))
check('and not on its mode argument', !pathsFor(result, 'write').includes(canon('600')), JSON.stringify(pathsFor(result, 'write')))

result = derive('sed -i s/a/b/ existing.txt')
check('sed -i reads and writes its file',
  pathsFor(result, 'read').includes(canon('existing.txt')) && pathsFor(result, 'write').includes(canon('existing.txt')))

result = derive('dd if=in.img of=out.img')
check('dd reads if= and creates of=', pathsFor(result, 'read').includes(canon('in.img')) && pathsFor(result, 'create').includes(canon('out.img')))

result = derive('curl -o out.json https://example.invalid')
check('curl -o creates the output file', pathsFor(result, 'create').includes(canon('out.json')))
check('and does not treat the url as a path', !pathsFor(result, 'create').includes(canon('https://example.invalid')))

console.log('copies and moves')
result = derive('cp src/a.txt b.txt')
check('cp reads its source', pathsFor(result, 'read').includes(canon('src/a.txt')))
check('cp creates its target', pathsFor(result, 'create').includes(canon('b.txt')))

result = derive('mv src/a.txt b.txt')
check('mv deletes its source', pathsFor(result, 'delete').includes(canon('src/a.txt')))
check('mv creates its target', pathsFor(result, 'create').includes(canon('b.txt')))

console.log('reads')
result = derive('cat README.md')
check('cat reads its operand', pathsFor(result, 'read').includes(canon('README.md')))

result = derive('grep -rn pattern src')
check('grep reads its path argument', pathsFor(result, 'read').includes(canon('src')))
check('and never the pattern', !pathsFor(result, 'read').includes(canon('pattern')), JSON.stringify(pathsFor(result, 'read')))

result = derive('find . -name x')
check('find reads the directory it walks', pathsFor(result, 'read').includes(canon('.')))

console.log('redirections')
result = derive('echo hi > out.txt')
check('a redirection creates its target', pathsFor(result, 'create').includes(canon('out.txt')))
check('and the program itself is only executed',
  pathsFor(result, 'execute').length === 1 && basename(pathsFor(result, 'execute')[0]) === 'echo')

result = derive('echo hi > /dev/null')
check('the null device is not a file change', pathsFor(result, 'create').length === 0 && pathsFor(result, 'write').length === 0)

result = derive('echo hi > /dev/stdout')
check('the standard streams are not file changes', pathsFor(result, 'create').length === 0)

result = derive('cat < in.txt')
check('an input redirection reads its target', pathsFor(result, 'read').includes(canon('in.txt')))

result = derive('echo x > "$OUT"')
check('a computed redirection target is unknown',
  result.unknown.some(entry => entry.operation === 'write'), JSON.stringify(result.unknown))

result = derive('ls 2>&1')
check('a descriptor duplication invents no command', pathsFor(result, 'execute').every(path => basename(path) === 'ls'), JSON.stringify(pathsFor(result, 'execute')))

console.log('wrappers and interpreters')
result = derive('sudo rm -rf build')
check('sudo is followed to the program it starts', pathsFor(result, 'delete').includes(canon('build')))

result = derive('env FOO=1 rm -rf build')
check('env assignments do not hide the program', pathsFor(result, 'delete').includes(canon('build')))

result = derive('python3 foo.py')
check('an interpreter script is read', pathsFor(result, 'read').includes(canon('foo.py')))

result = derive("python3 -c 'print(1)'")
check('inline code contributes no path effects', pathsFor(result, 'read').length === 0)
check('and is reported as an unreadable program',
  result.unknown.some(entry => entry.reason.includes('runs a program given on the command line')), JSON.stringify(result.unknown))

result = derive("bash -c 'rm -rf build'")
check('bash -c is parsed, not guessed', pathsFor(result, 'delete').includes(canon('build')))
check('and is not reported as unknown', result.unknown.length === 0, JSON.stringify(result.unknown))

result = derive('xargs rm')
check('xargs is unknown', result.unknown.length === 1 && result.unknown[0].reason.includes('xargs'), JSON.stringify(result.unknown))

result = derive('f() { rm -rf build; }; f')
check('a function body is judged as the line\'s effects', pathsFor(result, 'delete').includes(canon('build')), JSON.stringify(result.effects))

result = derive('f() { :; }')
check('an empty-bodied definition is not a command', result.effects.length === 0, JSON.stringify(result.effects))

result = derive('tar -xf archive.tar')
check('extraction reads the archive', pathsFor(result, 'read').includes(canon('archive.tar')))
check('and admits the archive decides what it writes',
  result.unknown.some(entry => entry.operation === 'create'), JSON.stringify(result.unknown))

result = derive("python3 <<'EOF'\nprint(open('x').read())\nEOF")
check('a here-document body is data, not a command', pathsFor(result, 'read').every(path => !path.includes('x')), JSON.stringify(pathsFor(result, 'read')))

console.log('executables')
result = derive('/bin/ls -la')
check('an absolute program is an execute effect', pathsFor(result, 'execute').some(path => basename(path) === 'ls'))
check('and carries the real path behind it', result.effects.some(effect => effect.operation === 'execute' && effect.realPath.startsWith('/')))

result = derive('definitely-not-on-path-xyz --version')
check('a program that cannot be found contributes no execute effect', pathsFor(result, 'execute').length === 0)

console.log('programs outside the table')
result = derive('git status')
check('git contributes only its execution', result.effects.every(effect => effect.operation === 'execute'), JSON.stringify(result.effects))

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
