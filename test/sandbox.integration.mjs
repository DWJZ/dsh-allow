/**
 * Real macOS sandbox integration: the profiles `src/enforce.js` compiles are
 * applied by the kernel through `sandbox-exec`, and every capability the policy
 * claims is checked against what actually happens — including from Python, from
 * a child shell, and from a grandchild.
 *
 * Nothing here mocks the enforcement layer. It needs a host that can start
 * `sandbox-exec`; inside another Seatbelt sandbox that call is refused
 * (`sandbox_apply: Operation not permitted`), in which case the suite reports a
 * loud skip instead of passing quietly. Run it from a plain terminal:
 *
 *   npm run test:sandbox
 *
 * Usage: `node test/sandbox.integration.mjs`.
 */
import { spawnSync } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)
const enforce = await import(pathToFileURL(join(PLUGIN, 'src/enforce.js')).href)
const macos = await import(pathToFileURL(join(PLUGIN, 'src/macos.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const SANDBOX_EXEC = '/usr/bin/sandbox-exec'

/** Whether this host can apply a Seatbelt profile at all. */
function sandboxUsable() {
  if (!existsSync(SANDBOX_EXEC)) return false
  const probe = spawnSync(SANDBOX_EXEC, ['-p', '(version 1)(allow default)', '--', '/usr/bin/true'], { encoding: 'utf8' })
  return probe.status === 0
}

if (!sandboxUsable()) {
  console.log('  SKIP the macOS sandbox integration suite: sandbox-exec cannot apply a profile here.')
  console.log('       (nested Seatbelt: run this test outside the DSH sandbox to exercise the kernel.)')
  process.exit(0)
}

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-sandbox-'))
// The workspace deliberately lives OUTSIDE the temp area: a platform temp root
// grants every capability, which would answer for the workspace instead of the
// workspace rules under test.
const WORKSPACE = join(PLUGIN, 'test', '.sandbox-workspace')
const outside = join(PLUGIN, 'test', '.sandbox-outside')
// The runtime cases run real macOS programs, so the home the baseline names has
// to be the real one.
const HOME = process.env.HOME ?? '/Users/tester'
const NODE = process.execPath
for (const directory of [WORKSPACE, outside]) rmSync(directory, { recursive: true, force: true })
mkdirSync(join(WORKSPACE, 'sub'), { recursive: true })
mkdirSync(outside, { recursive: true })
writeFileSync(join(WORKSPACE, 'keep.txt'), 'seed\n')
writeFileSync(join(outside, 'outside.txt'), 'seed\n')

/** Run one command under a profile. */
let last = null
const under = (profile, argv) => {
  last = spawnSync(SANDBOX_EXEC, ['-p', profile, '--', ...argv], { encoding: 'utf8' })
  return last
}
/** Why the last confined run behaved the way it did, for a failing check. */
const why = () => (last === null ? '' : `status=${String(last.status)} ${last.stderr || last.stdout}`)

/** The baseline the runtime uses, plus whatever a case adds. */
const baseline = extra => [
  ...fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' }),
  ...extra,
]
const compile = (rules, options = {}) => enforce.compileProfile({
  mode: options.mode ?? 'workspace-write',
  workspaceRoot: WORKSPACE,
  rules,
  protectedFiles: options.protectedFiles ?? [],
  capabilities: options.capabilities ?? 'all',
})

const writeProfile = compile(baseline([]), { capabilities: 'writes' })

console.log('profile rendering')
const rendered = macos.seatbeltProfile({
  rules: [fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { write: true, create: true } })],
  includeExecute: false,
})
check('write and create compile to their own operations',
  rendered.includes('file-write-data') && rendered.includes('file-write-create'), rendered)
check('a rule without delete grants no unlink', !rendered.includes('(allow file-write-unlink'), rendered)
const withDelete = macos.seatbeltProfile({
  rules: [fspolicy.makeRule({ path: join(WORKSPACE, 'open'), recursive: true, access: { delete: true } })],
  includeExecute: false,
})
check('a delete-granting rule adds unlink', withDelete.includes('file-write-unlink'), withDelete)
check('the null device stays writable', rendered.includes('/dev/null'))
const protectedProfile = compile(
  baseline([fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { write: true, delete: true } })]),
  { protectedFiles: [join(WORKSPACE, 'dsh-allow.json')] },
)
check('a protected path is refused after every grant',
  protectedProfile.trimEnd().endsWith(`(deny file-write-unlink (subpath "${join(WORKSPACE, 'dsh-allow.json')}"))`)
  && protectedProfile.includes(`(deny file-write-data (literal "${join(WORKSPACE, 'dsh-allow.json')}"))`),
  protectedProfile.slice(-200))

console.log('A: the permission store is not the agent\'s to change')
const storeFile = join(WORKSPACE, 'dsh-allow.json')
const storeProfile = compile(
  baseline([fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { write: true, create: true, delete: true } })]),
  { protectedFiles: [storeFile], capabilities: 'process' },
)
let result = under(storeProfile, ['/bin/sh', '-c', `echo '{}' > ${storeFile}`])
check('A1: a shell cannot write the rules file', result.status !== 0 && !existsSync(storeFile), result.stderr)
result = under(storeProfile, ['/usr/bin/python3', '-c', `open(${JSON.stringify(storeFile)}, 'w').write('{}')`])
check('A2: python cannot either', result.status !== 0 && !existsSync(storeFile), result.stderr)
writeFileSync(storeFile, '{}\n')
result = under(storeProfile, ['/bin/rm', storeFile])
check('A3: and cannot delete it', result.status !== 0 && existsSync(storeFile), result.stderr)
check('A4: while the rest of the workspace stays writable',
  under(storeProfile, ['/bin/sh', '-c', `echo x > ${join(WORKSPACE, 'other.txt')}`]).status === 0, why())

console.log('workspace read/write/create')
result = under(writeProfile, ['/bin/cat', join(WORKSPACE, 'keep.txt')])
check('B0: reading the workspace succeeds', result.status === 0 && result.stdout.includes('seed'), result.stderr)
result = under(writeProfile, ['/bin/sh', '-c', `echo more >> ${join(WORKSPACE, 'keep.txt')}`])
check('B1: writing an existing file succeeds', result.status === 0, result.stderr)
result = under(writeProfile, ['/bin/sh', '-c', `echo new > ${join(WORKSPACE, 'created.txt')}`])
check('C1: creating a new file succeeds', result.status === 0 && existsSync(join(WORKSPACE, 'created.txt')), result.stderr)
result = under(writeProfile, ['/bin/mkdir', join(WORKSPACE, 'fresh-dir')])
check('C2: creating a directory succeeds', result.status === 0 && existsSync(join(WORKSPACE, 'fresh-dir')), result.stderr)

console.log('B/C: delete is withheld inside the workspace')
result = under(writeProfile, ['/bin/rm', join(WORKSPACE, 'keep.txt')])
check('B2: deleting a workspace file is denied', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)
check('B3: and the kernel said why', /Operation not permitted|Permission denied/u.test(result.stderr), result.stderr)
result = under(writeProfile, ['/bin/rmdir', join(WORKSPACE, 'fresh-dir')])
check('B4: removing a directory is denied', result.status !== 0 && existsSync(join(WORKSPACE, 'fresh-dir')), result.stderr)
result = under(writeProfile, ['/bin/mv', join(WORKSPACE, 'created.txt'), join(WORKSPACE, 'renamed.txt')])
check('B5: renaming is denied too (it unlinks the source)', result.status !== 0 && existsSync(join(WORKSPACE, 'created.txt')), result.stderr)
result = under(writeProfile, ['/usr/bin/python3', '-c', `import os; os.remove(${JSON.stringify(join(WORKSPACE, 'keep.txt'))})`])
check('C3: python os.remove is denied by the kernel', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)
result = under(writeProfile, ['/usr/bin/python3', '-c', `open(${JSON.stringify(join(WORKSPACE, 'from-python.txt'))}, 'w').write('x')`])
check('C4: while python may still create and write', result.status === 0 && existsSync(join(WORKSPACE, 'from-python.txt')), result.stderr)
result = under(writeProfile, [NODE, '-e', `require('node:fs').writeFileSync(${JSON.stringify(join(WORKSPACE, 'from-node.txt'))}, 'x')`])
check('C5: node may write and create as well', result.status === 0 && existsSync(join(WORKSPACE, 'from-node.txt')), result.stderr)
result = under(writeProfile, [NODE, '-e', `require('node:fs').rmSync(${JSON.stringify(join(WORKSPACE, 'keep.txt'))})`])
check('C6: and node cannot delete either', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)

console.log('granting delete makes it work again')
const deleteGranted = baseline([fspolicy.makeRule({ path: WORKSPACE, recursive: true, source: 'user', access: { delete: true } })])
result = under(compile(deleteGranted, { capabilities: 'writes' }), ['/bin/rm', join(WORKSPACE, 'created.txt')])
check('B6: a delete grant is enough to unlink', result.status === 0 && !existsSync(join(WORKSPACE, 'created.txt')), result.stderr)

console.log('D/E: write and create can be withheld on their own')
const readExecuteOnly = compile([
  fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { read: true, execute: true } }),
  ...fspolicy.baselineRules({ harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' }),
], { capabilities: 'process' })
check('D1: the workspace is still readable', under(readExecuteOnly, ['/bin/cat', join(WORKSPACE, 'keep.txt')]).status === 0, why())
result = under(readExecuteOnly, ['/usr/bin/python3', '-c', `open(${JSON.stringify(join(WORKSPACE, 'keep.txt'))}, 'a').write('x')`])
check('D2: python cannot write an existing file', result.status !== 0, result.stderr)
result = under(readExecuteOnly, ['/usr/bin/python3', '-c', `open(${JSON.stringify(join(WORKSPACE, 'brand-new.txt'))}, 'w').write('x')`])
check('E1: python cannot create a new file', result.status !== 0 && !existsSync(join(WORKSPACE, 'brand-new.txt')), result.stderr)
result = under(readExecuteOnly, ['/bin/mkdir', join(WORKSPACE, 'nope')])
check('E2: and neither can mkdir', result.status !== 0 && !existsSync(join(WORKSPACE, 'nope')), result.stderr)

console.log('F: the read fence is expressible, and macOS trips over it')
const readFenced = compile([
  fspolicy.makeRule({ path: outside, recursive: true, access: { read: true } }),
  ...fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' }),
], { capabilities: 'full' })
// Measured: a profile that withholds reads the platform baseline does not name
// makes /bin/sh abort before it runs anything, which is why `enforce: auto`
// stops at `process` on this host and reports the read fence as unfenced.
check('F1: the shell cannot start under the policy read fence',
  under(readFenced, ['/bin/sh', '-c', 'exit 0']).status !== 0, why())
check('F2: the enforcer probe rejects it for the same reason',
  enforce.probeProfile(readFenced, { workspaceRoot: WORKSPACE }) === false)
const wideRead = compile([
  fspolicy.makeRule({ path: '/', recursive: true, access: { read: true, execute: true } }),
], { capabilities: 'full' })
check('F3: with reads granted the same fence starts a shell',
  under(wideRead, ['/bin/sh', '-c', 'exit 0']).status === 0, why())
check('F4: and the probe accepts that one',
  enforce.probeProfile(wideRead, { workspaceRoot: WORKSPACE }) === true)

console.log('R: read is a capability too (the guarded fence)')
const guarded = compile(baseline([]), { capabilities: 'guarded' })
const hostSecret = join(outside, 'outside.txt')
result = under(guarded, ['/bin/cat', join(WORKSPACE, 'keep.txt')])
check('R1: A — the workspace stays readable by cat', result.status === 0 && result.stdout.includes('seed'), why())
result = under(guarded, ['/usr/bin/python3', '-c', `print(open(${JSON.stringify(join(WORKSPACE, 'keep.txt'))}).read().strip())`])
check('R2: A — and by python', result.status === 0 && result.stdout.includes('seed'), why())
result = under(guarded, ['/bin/cat', hostSecret])
check('R3: B — a file outside the grants is refused by cat', result.status !== 0, why())
result = under(guarded, ['/usr/bin/python3', '-c', `print(open(${JSON.stringify(hostSecret)}).read())`])
check('R4: B — and by python, whatever the command line says', result.status !== 0, why())
result = under(guarded, [NODE, '-e', `process.stdout.write(require('node:fs').readFileSync(${JSON.stringify(hostSecret)}, 'utf8'))`])
check('R5: C — and by node', result.status !== 0, why())
result = under(guarded, ['/bin/bash', '-c', `cat ${hostSecret}`])
check('R6: C — and by bash', result.status !== 0, why())
result = under(guarded, ['/bin/sh', '-c', `/bin/sh -c 'cat ${hostSecret}'`])
check('R7: E — a child shell inherits the read refusal', result.status !== 0, why())
result = under(guarded, ['/usr/bin/python3', '-c', `import subprocess; subprocess.run(['/bin/cat', ${JSON.stringify(hostSecret)}])`])
check('R8: E — and so does a python -> cat grandchild', result.status !== 0, why())
const readGranted = compile(baseline([
  fspolicy.makeRule({ path: outside, recursive: true, source: 'user', access: { read: true } }),
]), { capabilities: 'guarded' })
result = under(readGranted, ['/usr/bin/python3', '-c', `print(open(${JSON.stringify(hostSecret)}).read().strip())`])
check('R9: D — a read grant re-opens exactly that folder', result.status === 0 && result.stdout.includes('seed'), why())
check('R10: D — while a sibling folder stays closed',
  under(readGranted, ['/bin/cat', join(root, 'secret.txt')]).status !== 0, why())
check('R11: the permission store stays refused under the guarded fence',
  under(compile(baseline([fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { write: true, delete: true } })]),
    { capabilities: 'guarded', protectedFiles: [join(WORKSPACE, 'dsh-allow.json')] }),
  ['/bin/sh', '-c', `echo '{}' > ${join(WORKSPACE, 'dsh-allow.json')}`]).status !== 0)

console.log('F: the read fence leaves the runtime alone')
const ghPath = String(spawnSync('/usr/bin/which', ['gh'], { encoding: 'utf8' }).stdout).trim()
const runtimePrograms = [
  fspolicy.makeRule({ path: NODE, recursive: false, source: 'user', access: { read: true, execute: true } }),
  ...(ghPath === '' ? [] : [
    fspolicy.makeRule({ path: ghPath, recursive: false, source: 'user', access: { read: true, execute: true } }),
    fspolicy.makeRule({ path: `${HOME}/.config/gh`, recursive: true, source: 'user', access: { read: true } }),
  ]),
]
const runtimeRules = baseline(runtimePrograms)
const runtimeProfile = compile(runtimeRules, { capabilities: 'guarded' })
result = under(runtimeProfile, ['/bin/sh', '-c', 'echo ok'])
check('F1: /bin/sh runs', result.status === 0 && result.stdout.includes('ok'), why())
result = under(runtimeProfile, ['/usr/bin/python3', '-c', 'print("ok")'])
check('F2: python runs', result.status === 0 && result.stdout.includes('ok'), why())
result = under(runtimeProfile, [NODE, '-e', 'console.log("ok")'])
check('F3: node runs', result.status === 0 && result.stdout.includes('ok'), why())
result = under(runtimeProfile, ['/usr/bin/git', '--version'])
check('F4: git runs', result.status === 0 && result.stdout.includes('git version'), why())
if (ghPath !== '') {
  result = under(runtimeProfile, [ghPath, '--version'])
  check('F5: gh runs once its binary is granted', result.status === 0 && result.stdout.includes('gh version'), why())
}
else {
  console.log('  skip gh --version (not installed)')
}

console.log('H: children and grandchildren inherit the fence')
result = under(writeProfile, ['/bin/sh', '-c', `/bin/sh -c '/bin/rm ${join(WORKSPACE, 'keep.txt')}'`])
check('H1: a child shell cannot delete either', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)
under(writeProfile, ['/usr/bin/python3', '-c',
  `import subprocess; subprocess.run(['/bin/sh', '-c', 'echo x > ${join(WORKSPACE, 'grandchild.txt')}']); subprocess.run(['/bin/rm', '${join(WORKSPACE, 'keep.txt')}'])`])
check('H2: a python -> sh grandchild may still write', existsSync(join(WORKSPACE, 'grandchild.txt')), why())
check('H3: and still cannot delete', existsSync(join(WORKSPACE, 'keep.txt')), why())
check('H4: a node -> sh child inherits the same grant',
  under(writeProfile, [NODE, '-e',
    `require('node:child_process').execFileSync('/bin/sh', ['-c', 'echo y >> ${join(WORKSPACE, 'from-node.txt')}'])`]).status === 0, why())
result = under(writeProfile, [NODE, '-e',
  `require('node:child_process').execFileSync('/bin/rm', ['${join(WORKSPACE, 'keep.txt')}'])`])
check('H5: and the same refusal', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)

console.log('G: execute is a capability')
const realBinary = join(WORKSPACE, 'real-tool.sh')
writeFileSync(realBinary, '#!/bin/sh\necho real-tool-ran\n')
chmodSync(realBinary, 0o755)
const outsideBinary = join(outside, 'other-tool.sh')
writeFileSync(outsideBinary, '#!/bin/sh\necho other-ran\n')
chmodSync(outsideBinary, 0o755)
const linkedBinary = join(outside, 'linked-tool')
symlinkSync(realBinary, linkedBinary)
const plainFence = compile(baseline([]), { capabilities: 'process' })
check('G0: the workspace baseline already authorizes its own programs',
  under(plainFence, [realBinary]).status === 0, why())
const executeProfile = compile(baseline([
  fspolicy.makeRule({ path: linkedBinary, recursive: false, source: 'user', access: { execute: true, read: true } }),
]), { capabilities: 'process' })
check('G1: an ungranted binary outside the workspace is denied execute',
  under(executeProfile, [outsideBinary]).status !== 0, why())
const symlinkRun = under(executeProfile, [linkedBinary])
check('G2: a grant for a symlink authorizes the binary it points at',
  symlinkRun.status === 0 && symlinkRun.stdout.includes('real-tool-ran'), why())
check('G3: while the folder around the symlink stays closed',
  under(executeProfile, [outsideBinary]).status !== 0, why())

console.log('I: a profile the kernel refuses runs nothing')
const mustNotExist = join(WORKSPACE, 'must-not-exist.txt')
result = under('(version 1)(allow default)(this-is-not-an-operation)', ['/bin/sh', '-c', `echo x > ${mustNotExist}`])
check('I1: a malformed profile fails before the command', result.status !== 0 && !existsSync(mustNotExist), result.stderr)
check('I2: and the runner failure is identifiable', /sandbox-exec:/u.test(result.stderr), result.stderr)
check('I3: a rule set with no applicable operation still fences writes',
  under(compile([]), ['/bin/sh', '-c', `echo x > ${join(WORKSPACE, 'no-rules.txt')}`]).status !== 0, why())

console.log('outside the workspace')
result = under(writeProfile, ['/bin/sh', '-c', `echo x > ${join(outside, 'nope.txt')}`])
check('W1: writing outside the workspace is denied', result.status !== 0 && !existsSync(join(outside, 'nope.txt')), result.stderr)
const outsideGranted = baseline([fspolicy.makeRule({ path: outside, recursive: true, source: 'user', access: { write: true, create: true } })])
const outsideProfile = compile(outsideGranted, { capabilities: 'writes' })
result = under(outsideProfile, ['/bin/sh', '-c', `echo x > ${join(outside, 'allowed.txt')}`])
check('W2: a grant for that folder makes the write succeed', result.status === 0 && existsSync(join(outside, 'allowed.txt')), result.stderr)
result = under(outsideProfile, ['/bin/rm', join(outside, 'outside.txt')])
check('W3: and the same grant still withholds delete', result.status !== 0 && existsSync(join(outside, 'outside.txt')), result.stderr)

console.log('what the kernel cannot separate')
const createOnly = compile([fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { create: true } })], { capabilities: 'writes' })
check('create alone may create and fill a new file',
  under(createOnly, ['/bin/sh', '-c', `echo data > ${join(WORKSPACE, 'created-only.txt')}`]).status === 0
  && existsSync(join(WORKSPACE, 'created-only.txt')), why())
check('but it may not change an existing one',
  under(createOnly, ['/bin/sh', '-c', `echo more >> ${join(WORKSPACE, 'keep.txt')}`]).status !== 0, why())
check('the backend states its own limits', macos.backendLimitations().some(line => line.startsWith('read:')))

rmSync(WORKSPACE, { recursive: true, force: true })
rmSync(root, { recursive: true, force: true })
rmSync(outside, { recursive: true, force: true })
check('the fixture wrote nothing into the repository', !existsSync(outside))
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
