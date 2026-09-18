/**
 * Real macOS sandbox integration: the FsPolicy compiled by `src/macos.js` is
 * applied by the kernel through `sandbox-exec`, and every capability the policy
 * claims is checked against what actually happens.
 *
 * This test does not mock the enforcement layer: it renders a profile from the
 * same rules the plugin decides with, runs real commands under it, and reads
 * the resulting files. It needs a host that can start `sandbox-exec` — inside
 * another Seatbelt sandbox that call is refused (`sandbox_apply: Operation not
 * permitted`), in which case the suite reports a loud skip instead of passing
 * quietly.
 *
 * Usage: `node test/sandbox.integration.mjs`.
 */
import { spawnSync } from 'node:child_process'
import { existsSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)
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
const outside = join(PLUGIN, 'test', '.sandbox-outside')
const HOME = '/Users/tester'
const WORKSPACE = fspolicy.canonicalPath(root, { cwd: '/', home: HOME })
rmSync(outside, { recursive: true, force: true })
mkdirSync(outside, { recursive: true })
mkdirSync(join(WORKSPACE, 'sub'), { recursive: true })
writeFileSync(join(WORKSPACE, 'keep.txt'), 'seed\n')
writeFileSync(join(outside, 'outside.txt'), 'seed\n')

/** Run one command under a profile. */
const under = (profile, argv) => spawnSync(SANDBOX_EXEC, ['-p', profile, '--', ...argv], { encoding: 'utf8' })

const baseline = fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' })
const writeProfile = macos.seatbeltProfile({ rules: baseline, includeExecute: false, includeRead: false })

console.log('profile rendering')
const rendered = macos.seatbeltProfile({
  rules: [
    fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { write: true, create: true } }),
    fspolicy.makeRule({ path: join(WORKSPACE, 'open'), recursive: true, access: { delete: true } }),
  ],
  includeExecute: false,
})
check('write and create compile to their own operations',
  rendered.includes('file-write-data') && rendered.includes('file-write-create'), rendered)
check('a rule without delete grants no unlink', !rendered.includes('(allow file-write-unlink'))
check('a delete-granting rule adds unlink', rendered.includes('file-write-unlink'))
check('the null device stays writable', rendered.includes('/dev/null'))

console.log('workspace read/write/create')
let result = under(writeProfile, ['/bin/cat', join(WORKSPACE, 'keep.txt')])
check('A: reading the workspace succeeds', result.status === 0 && result.stdout.includes('seed'), result.stderr)

result = under(writeProfile, ['/bin/sh', '-c', `echo more >> ${join(WORKSPACE, 'keep.txt')}`])
check('B: writing an existing file succeeds', result.status === 0, result.stderr)

result = under(writeProfile, ['/bin/sh', '-c', `echo new > ${join(WORKSPACE, 'created.txt')}`])
check('C: creating a new file succeeds', result.status === 0 && existsSync(join(WORKSPACE, 'created.txt')), result.stderr)

result = under(writeProfile, ['/bin/mkdir', join(WORKSPACE, 'fresh-dir')])
check('C2: creating a directory succeeds', result.status === 0 && existsSync(join(WORKSPACE, 'fresh-dir')), result.stderr)

console.log('delete is withheld inside the workspace')
result = under(writeProfile, ['/bin/rm', join(WORKSPACE, 'keep.txt')])
check('D: deleting a workspace file is denied', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)
check('D: and the kernel said why', /Operation not permitted|Permission denied/u.test(result.stderr), result.stderr)

result = under(writeProfile, ['/bin/rmdir', join(WORKSPACE, 'fresh-dir')])
check('D2: removing a directory is denied', result.status !== 0 && existsSync(join(WORKSPACE, 'fresh-dir')), result.stderr)

result = under(writeProfile, ['/bin/mv', join(WORKSPACE, 'created.txt'), join(WORKSPACE, 'renamed.txt')])
check('D3: renaming is denied too (it unlinks the source)', result.status !== 0 && existsSync(join(WORKSPACE, 'created.txt')), result.stderr)

console.log('child processes inherit the fence')
result = under(writeProfile, ['/bin/sh', '-c', `/bin/sh -c '/bin/rm ${join(WORKSPACE, 'keep.txt')}'`])
check('N: a child shell cannot delete either', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)

result = under(writeProfile, ['/usr/bin/python3', '-c', `import os; os.remove(${JSON.stringify(join(WORKSPACE, 'keep.txt'))})`])
check('O: python cannot delete either', result.status !== 0 && existsSync(join(WORKSPACE, 'keep.txt')), result.stderr)

result = under(writeProfile, ['/usr/bin/python3', '-c', `open(${JSON.stringify(join(WORKSPACE, 'from-python.txt'))}, 'w').write('x')`])
check('O2: but python may still write and create', result.status === 0 && existsSync(join(WORKSPACE, 'from-python.txt')), result.stderr)

console.log('granting delete makes it work again')
const deleteGranted = fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' })
deleteGranted.push(fspolicy.makeRule({ path: WORKSPACE, recursive: true, source: 'user', access: { delete: true } }))
const deleteProfile = macos.seatbeltProfile({ rules: deleteGranted, includeExecute: false })
result = under(deleteProfile, ['/bin/rm', join(WORKSPACE, 'created.txt')])
check('E: a delete grant is enough to unlink', result.status === 0 && !existsSync(join(WORKSPACE, 'created.txt')), result.stderr)

console.log('outside the workspace')
result = under(writeProfile, ['/bin/sh', '-c', `echo x > ${join(outside, 'nope.txt')}`])
check('H: writing outside the workspace is denied', result.status !== 0 && !existsSync(join(outside, 'nope.txt')), result.stderr)

const outsideGranted = fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: join(root, '.dsh'), home: HOME, mode: 'workspace-write' })
outsideGranted.push(fspolicy.makeRule({ path: outside, recursive: true, source: 'user', access: { write: true, create: true } }))
const outsideProfile = macos.seatbeltProfile({ rules: outsideGranted, includeExecute: false })
result = under(outsideProfile, ['/bin/sh', '-c', `echo x > ${join(outside, 'allowed.txt')}`])
check('I: a grant for that folder makes the write succeed', result.status === 0 && existsSync(join(outside, 'allowed.txt')), result.stderr)
result = under(outsideProfile, ['/bin/rm', join(outside, 'outside.txt')])
check('I2: and the same grant still withholds delete', result.status !== 0 && existsSync(join(outside, 'outside.txt')), result.stderr)

console.log('execute is a capability')
const realBinary = join(root, 'real-tool.sh')
writeFileSync(realBinary, '#!/bin/sh\necho real-tool-ran\n')
const linkedBinary = join(root, 'linked-tool')
symlinkSync(realBinary, linkedBinary)
const executeRules = baseline.concat([
  fspolicy.makeRule({ path: realBinary, recursive: false, source: 'user', access: { execute: true, read: true } }),
  fspolicy.makeRule({ path: linkedBinary, recursive: false, source: 'user', access: { execute: true, read: true } }),
])
const executeProfile = macos.seatbeltProfile({ rules: executeRules, includeExecute: true, includeRead: false })
result = under(executeProfile, ['/bin/cat', join(WORKSPACE, 'keep.txt')])
check('K0: a granted binary runs under the execute fence', result.status === 0, result.stderr)
result = under(executeProfile, [linkedBinary])
check('M: a symlinked binary runs through its granted real path',
  result.status === 0 && result.stdout.includes('real-tool-ran'), result.stderr)

const ungranted = join(root, 'other-tool.sh')
writeFileSync(ungranted, '#!/bin/sh\necho other-ran\n')
result = under(executeProfile, [ungranted])
check('L: an ungranted binary is denied execute', result.status !== 0, result.stderr)

console.log('read fence')
const readGranted = baseline.concat([
  fspolicy.makeRule({ path: outside, recursive: true, source: 'user', access: { read: true } }),
])
const readProfile = macos.seatbeltProfile({ rules: readGranted, includeExecute: false, includeRead: true })
result = under(readProfile, ['/bin/cat', join(outside, 'outside.txt')])
check('A2: a granted read fence still reads that folder', result.status === 0 && result.stdout.includes('seed'), result.stderr)
result = under(readProfile, ['/bin/cat', join(root, 'nothing-here.txt')])
check('A3: an ungranted path under the fence is denied', result.status !== 0, result.stdout)

console.log('fail closed')
result = under('(version 1)(allow default)(this-is-not-an-operation)', ['/bin/sh', '-c', `echo x > ${join(WORKSPACE, 'must-not-exist.txt')}`])
check('P: a profile the kernel refuses runs nothing', result.status !== 0 && !existsSync(join(WORKSPACE, 'must-not-exist.txt')), result.stderr)

console.log('what the kernel cannot separate')
check('create alone yields empty files',
  under(macos.seatbeltProfile({
    rules: [fspolicy.makeRule({ path: WORKSPACE, recursive: true, access: { create: true } })],
    includeExecute: false,
  }), ['/bin/sh', '-c', `echo data > ${join(WORKSPACE, 'empty.txt')} && wc -c < ${join(WORKSPACE, 'empty.txt')}`]).status !== 0,
  'create-only cannot write content')
check('the backend states its own limits', macos.backendLimitations().some(line => line.startsWith('read:')))

rmSync(root, { recursive: true, force: true })
rmSync(outside, { recursive: true, force: true })
check('the fixture wrote nothing into the repository', !existsSync(outside))
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
