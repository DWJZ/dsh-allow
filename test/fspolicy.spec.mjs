/**
 * Filesystem permission model suite: path canonicalization, rule precedence,
 * specificity, the platform refusals, and the baseline.
 *
 * Usage: `node test/fspolicy.spec.mjs`.
 */
import { mkdirSync, mkdtempSync, rmSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve, dirname } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const fs = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-fspolicy-'))
const HOME = '/Users/tester'
const CWD = '/Users/tester/project'
/** Query paths reach the resolver canonical, the way derived effects do. */
const canon = (path) => fs.canonicalPath(path, { cwd: '/', home: HOME })

console.log('path containment')
check('a path is inside itself', fs.pathWithin('/w', '/w'))
check('a child is inside', fs.pathWithin('/w', '/w/a/b'))
check('a sibling prefix is not inside', !fs.pathWithin('/w/build', '/w/build-2'))
check('the root contains everything absolute', fs.pathWithin('/', '/anywhere'))
check('a parent is not inside its child', !fs.pathWithin('/w/a', '/w'))

console.log('canonical paths')
check('a relative path resolves against the cwd', fs.canonicalPath('a/b', { cwd: CWD, home: HOME }) === `${CWD}/a/b`)
check('dot segments collapse', fs.canonicalPath('a/../b', { cwd: CWD, home: HOME }) === `${CWD}/b`)
check('parent segments collapse', fs.canonicalPath('../../x', { cwd: CWD, home: HOME }) === '/Users/x')
check('a bare tilde is the home directory', fs.canonicalPath('~', { cwd: CWD, home: HOME }) === HOME)
check('a tilde prefix expands', fs.canonicalPath('~/notes', { cwd: CWD, home: HOME }) === `${HOME}/notes`)
const realDir = join(root, 'real')
mkdirSync(realDir, { recursive: true })
const linkPath = join(root, 'link')
symlinkSync(realDir, linkPath)
check('a symlinked directory resolves to its target',
  fs.canonicalPath(linkPath, { cwd: '/', home: HOME }) === fs.canonicalPath(realDir, { cwd: '/', home: HOME }))
check('a missing tail keeps its spelling',
  fs.canonicalPath(join(linkPath, 'new.txt'), { cwd: '/', home: HOME }) === join(fs.canonicalPath(realDir, { cwd: '/', home: HOME }), 'new.txt'))

console.log('platform refusals')
check('writing a system directory is refused', fs.protectedRefusal('/usr/bin/x', 'write') !== null)
check('deleting under /System is refused', fs.protectedRefusal('/System/Library/x', 'delete') !== null)
check('reading a system path is not refused', fs.protectedRefusal('/usr/bin/ls', 'read') === null)
check('executing a system path is not refused', fs.protectedRefusal('/usr/bin/ls', 'execute') === null)
check('/usr/local stays writable', fs.protectedRefusal('/usr/local/bin/tool', 'write') === null)
check('the null device stays writable', fs.protectedRefusal('/dev/null', 'write') === null)
check('a disk device is refused', fs.protectedRefusal('/dev/disk2', 'write') !== null)
check('the home directory is not platform-protected', fs.protectedRefusal(`${HOME}/notes.txt`, 'write') === null)

console.log('rule shape')
const workspace = fs.makeRule({ path: '/w', recursive: true, source: 'system', baseline: true, access: { read: true, write: true, delete: false, execute: true } })
check('false capabilities are dropped, not stored', workspace.access.delete === undefined && workspace.access.read === true, JSON.stringify(workspace.access))
check('a rule path is canonical', fs.makeRule({ path: '/w/a/../b', access: { read: true } }).path === '/w/b')
check('a rule defaults to recursive', fs.makeRule({ path: '/w', access: { read: true } }).recursive === true)
check('levels rank user over workspace over baseline',
  fs.levelOf(fs.makeRule({ path: '/w', access: { read: true } })) === fs.LEVELS.user
  && fs.levelOf(fs.makeRule({ path: '/w', source: 'workspace', access: { read: true } })) === fs.LEVELS.workspace
  && fs.levelOf(workspace) === fs.LEVELS.baseline)

console.log('resolution')
const user = (path, access, recursive = true) => fs.makeRule({ path, access, recursive })
check('an ungranted operation is not granted',
  fs.resolveOperation({ path: '/w/x', operation: 'delete', rules: [] }).granted === false)
check('a rule grants only what it lists',
  fs.resolveOperation({ path: '/w/x', operation: 'write', rules: [user('/w', { read: true })] }).granted === false)
check('a recursive rule covers descendants',
  fs.resolveOperation({ path: '/w/a/b', operation: 'read', rules: [user('/w', { read: true })] }).granted === true)
check('a non-recursive rule covers only its own path',
  fs.resolveOperation({ path: '/w/a', operation: 'read', rules: [user('/w', { read: true }, false)] }).granted === false)
check('the more specific rule wins inside a level',
  fs.resolveOperation({
    path: '/w/build/out.o', operation: 'delete',
    rules: [user('/w', { delete: true }), user('/w/build', { delete: true })],
  }).rule.path === '/w/build')
check('a more specific rule that is silent falls through to the broader one',
  fs.resolveOperation({
    path: '/w/build/out.o', operation: 'read',
    rules: [user('/w', { read: true }), user('/w/build', { write: true })],
  }).granted === true)
const brew = canon('/opt/homebrew/bin/gh')
check('a user rule outranks the baseline',
  fs.resolveOperation({
    path: brew, realPath: canon(brew), operation: 'execute',
    rules: [user(brew, { execute: true }, false)],
  }).granted === true)
check('the baseline still answers where the user rule is silent',
  fs.resolveOperation({
    path: '/bin/ls', operation: 'execute',
    rules: [user('/bin', { read: true }), ...fs.baselineRules({ workspaceRoot: '/w' })],
  }).granted === true)
check('an exact-file rule does not open its folder',
  fs.resolveOperation({
    path: '/w/build/other.o', operation: 'delete',
    rules: [user('/w/build/out.o', { delete: true }, false)],
  }).granted === false)
const cellar = join(root, 'Cellar', 'gh', 'bin', 'gh')
check('the real path behind a symlink is matched too',
  fs.resolveOperation({
    path: canon(linkPath), realPath: canon(realDir), operation: 'read',
    rules: [user(canon(realDir), { read: true })],
  }).granted === true)
check('a rule for the spelling matches a symlinked target',
  fs.resolveOperation({
    path: canon(linkPath), realPath: canon(realDir), operation: 'read',
    rules: [user(canon(linkPath), { read: true })],
  }).granted === true)
void cellar

console.log('baseline')
// A workspace outside the temp area, so the temp grants cannot answer for it.
const fakeWorkspace = '/Users/tester/project'
const baseline = fs.baselineRules({ workspaceRoot: fakeWorkspace, harnessHome: join(root, '.dsh'), home: HOME })
const withBaseline = (path, operation) => fs.resolveOperation({ path: canon(path), operation, rules: baseline }).granted
check('the workspace grants read', withBaseline(`${fakeWorkspace}/a.txt`, 'read'))
check('the workspace grants write', withBaseline(`${fakeWorkspace}/a.txt`, 'write'))
check('the workspace grants create', withBaseline(`${fakeWorkspace}/new.txt`, 'create'))
check('the workspace grants execute', withBaseline(`${fakeWorkspace}/script.sh`, 'execute'))
check('the workspace withholds delete', !withBaseline(`${fakeWorkspace}/a.txt`, 'delete'))
check('temp areas grant delete', withBaseline(`${fs.canonicalPath(tmpdir())}/a.txt`, 'delete'))
check('the harness home grants delete', withBaseline(`${join(root, '.dsh')}/old.json`, 'delete'))
check('system binaries grant execute', withBaseline('/usr/bin/env', 'execute'))
check('system binaries grant read', withBaseline('/usr/bin/env', 'read'))
check('homebrew grants read', withBaseline('/opt/homebrew/bin/gh', 'read'))
check('homebrew does not grant execute', !withBaseline('/opt/homebrew/bin/gh', 'execute'))
check('an unrelated home path stays closed', !withBaseline(`${HOME}/notes.txt`, 'read'))
check('a traversal out of the workspace stays closed', !withBaseline(`${fakeWorkspace}/../elsewhere/secret.txt`, 'read'))
const readOnly = fs.baselineRules({ workspaceRoot: root, harnessHome: join(root, '.dsh'), home: HOME, mode: 'read-only' })
const readOnlyGrant = (path, operation) => fs.resolveOperation({ path: canon(path), operation, rules: readOnly }).granted
check('read-only withholds write', !readOnlyGrant(`${root}/a.txt`, 'write'))
check('read-only withholds delete', !readOnlyGrant(tmpdir() + '/a.txt', 'delete'))
check('read-only still grants read', readOnlyGrant(`${root}/a.txt`, 'read'))

console.log('labels and suggestions')
check('a rule label names the operations and the scope',
  fs.describeRule(user('/w/build', { delete: true })) === 'delete · /w/build/**')
check('an exact rule label omits the glob',
  fs.describeRule(user('/w/build/out.o', { write: true }, false)) === 'write · /w/build/out.o')
const suggestions = fs.suggestGrants([{ operation: 'delete', path: join(root, 'build') }], { cwd: root })
check('a narrow grant and its folder are offered', suggestions.length === 2, JSON.stringify(suggestions))
check('the narrow grant names the path itself', suggestions[0].path === join(root, 'build') && suggestions[0].scope === 'file')
check('the folder grant is recursive', suggestions[1].recursive === true && suggestions[1].scope === 'folder')
const unknownSuggestions = fs.suggestGrants([{ operation: 'read' }], { cwd: root })
check('an unknown path falls back to the working directory',
  unknownSuggestions.length === 1 && unknownSuggestions[0].path === root && unknownSuggestions[0].recursive === true)

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
