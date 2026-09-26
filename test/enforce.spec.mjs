/**
 * Enforcement suite: the profile one policy compiles to, what the probe does
 * with a kernel that refuses part of it, how the registered provider is
 * refined, and what happens when nothing can be enforced.
 *
 * The kernel itself is exercised by `test/sandbox.integration.mjs`; here the
 * spawner is injected so every branch is reachable.
 *
 * Usage: `node test/enforce.spec.mjs`.
 */
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const enforce = await import(pathToFileURL(join(PLUGIN, 'src/enforce.js')).href)
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)
const store = await import(pathToFileURL(join(PLUGIN, 'src/store.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const root = mkdtempSync(join(tmpdir(), 'dsh-allow-enforce-'))
const HOME = '/Users/tester'
const WORKSPACE = fspolicy.canonicalPath(join(root, 'project'), { cwd: '/', home: HOME })
const rulesFile = join(root, 'rules.json')
writeFileSync(rulesFile, `${JSON.stringify({ version: 3, rules: [] })}\n`)
const config = {
  ...store.resolveConfig({ rulesFile }, root),
  harnessHome: root,
  home: HOME,
}
const logger = { info: () => {}, warn: () => {}, error: () => {} }

const rule = (path, access, recursive = true) => fspolicy.makeRule({ path, access, recursive })

console.log('profile compilation')
const workspaceRules = fspolicy.baselineRules({ workspaceRoot: WORKSPACE, harnessHome: root, home: HOME, mode: 'workspace-write' })
let profile = enforce.compileProfile({ mode: 'workspace-write', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'full' })
check('write and create are granted in the workspace',
  profile.includes('file-write-data') && profile.includes('file-write-create'), profile)
check('delete is withheld in the workspace', !profile.includes('(allow file-write-unlink'), profile)
check('the write fence is always present', profile.includes('(deny file-write*)'))
check('the full read fence is present when asked for',
  profile.includes('(deny file-read-data)') && profile.includes('(allow file-read-metadata)'))
check('and it withholds nothing less than everything', !profile.includes('(deny file-read-data (subpath'))
check('the execute fence is present', profile.includes('(deny process-exec)'))
check('system binaries stay executable', profile.includes('(allow process-exec (subpath "/usr/bin"))') || profile.includes('(allow process-exec (subpath "/bin"))'), profile)

profile = enforce.compileProfile({ mode: 'workspace-write', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'writes' })
check('a writes-only profile fences writes without fencing reads',
  profile.includes('(deny file-write*)') && !profile.includes('(deny file-read-data)') && !profile.includes('(deny process-exec)'), profile)

profile = enforce.compileProfile({
  mode: 'workspace-write',
  workspaceRoot: WORKSPACE,
  rules: [...workspaceRules, rule(join(WORKSPACE, 'build'), { delete: true })],
  capabilities: 'full',
})
check('a delete grant becomes an unlink allowance',
  profile.includes(`(allow file-write-unlink (subpath "${join(WORKSPACE, 'build')}"))`), profile)

profile = enforce.compileProfile({ mode: 'workspace-write', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'guarded' })
check('the guarded fence withholds user data',
  profile.includes('(deny file-read-data (subpath "/Users"))') && profile.includes('(deny file-read-data (subpath "/Volumes"))'), profile)
check('and re-opens the workspace after it',
  profile.indexOf('(allow file-read-data file-write-data') > profile.indexOf('(deny file-read-data (subpath'), profile)
check('and re-opens the harness home',
  profile.includes(`(subpath "${fspolicy.canonicalPath(root, { cwd: '/', home: HOME })}")`), profile)
check('and a user toolchain below the home', profile.includes(`(subpath "${HOME}/.nvm")`), profile)
check('the guarded fence still fences execution', profile.includes('(deny process-exec)'), profile)
check('and does not fence every read', !profile.includes('(deny file-read-data) (allow file-read-metadata)'), profile)

profile = enforce.compileProfile({ mode: 'read-only', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'writes' })
check('a read-only mode ignores write grants on the workspace', !profile.includes(`(allow file-write-data (subpath "${WORKSPACE}"))`), profile)

profile = enforce.compileProfile({
  mode: 'workspace-write',
  workspaceRoot: WORKSPACE,
  rules: [...workspaceRules, rule(root, { write: true, create: true, delete: true })],
  protectedFiles: [join(root, 'dsh-allow.json')],
  capabilities: 'writes',
})
const storeIndex = profile.indexOf('(deny file-write-data (literal')
check('the permission store is refused after every grant',
  storeIndex > 0 && storeIndex > profile.lastIndexOf('(allow file-write-data'), profile)
check('and its whole subtree is refused too', profile.includes('(deny file-write-unlink (subpath'))
check('every write operation is named, not a wildcard',
  ['file-write-data', 'file-write-create', 'file-write-unlink'].every(operation => profile.includes(`(deny ${operation} (literal`)))

console.log('probing')
const okSpawn = () => ({ status: 0 })
/** This suite drives the runner through injected seams, so it runs anywhere. */
const runnerPresent = { exists: () => true }
/** A kernel that can fence writes but refuses a profile that fences reads. */
const readRefusing = (_program, args) => ({ status: String(args?.[1] ?? '').includes('(deny file-read-data) (allow file-read-metadata)') ? 1 : 0 })
check('an applying profile passes the probe',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: okSpawn, ...runnerPresent }) === true)
check('a refusing profile fails the probe',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: () => ({ status: 1 }), ...runnerPresent }) === false)
check('a host without the runner cannot probe',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: okSpawn, exists: () => false }) === false)
check('a spawner that throws fails closed',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: () => { throw new Error('nope') }, ...runnerPresent }) === false)

console.log('installing on the registered provider')
/** A stand-in for the harness's sandbox provider. */
function fakeProvider() {
  return {
    calls: [],
    async confine(argv, policy, signal) {
      this.calls.push({ argv, policy, signal })
      return { argv: ['original', ...argv], enforcement: 'full', denialSignatures: ['read-only file system'], runnerFailureRules: [] }
    },
  }
}
const provider = fakeProvider()
const grants = store.createGrantStore()
const ctx = { get: name => (name === 'sandbox' ? provider : undefined) }
const enforcer = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: okSpawn, ...runnerPresent })
check('install wraps the provider', enforcer.install(ctx) === true)
const policy = { mode: 'workspace-write', workspaceRoot: WORKSPACE }
const pending = provider.confine(['bash', '-c', 'rm -rf build'], policy)
check('the wrapped confine returns a promise, as the provider contract requires', typeof pending?.then === 'function')
const confined = await pending
check('the caller gets the Seatbelt argv', confined.argv[0] === '/usr/bin/sandbox-exec' && confined.argv[1] === '-p', JSON.stringify(confined.argv.slice(0, 2)))
check('and its own command', confined.argv.slice(-3).join(' ') === 'bash -c rm -rf build', JSON.stringify(confined.argv.slice(-3)))
check('with the denial dialect the shell tool classifies', confined.denialSignatures.includes('operation not permitted'))
check('and a runner-failure rule for a profile the kernel refuses',
  confined.runnerFailureRules[0]?.fatalSignatures?.[0] === 'sandbox-exec: ')
check('the status reports full enforcement', enforcer.status().state === 'full', JSON.stringify(enforcer.status()))

const delegated = new AbortController()
await provider.confine(['bash', '-c', 'true'], { ...policy, mode: 'danger-full-access' }, delegated.signal)
check('the delegated branch forwards the caller signal', provider.calls.at(-1)?.signal === delegated.signal)
const aborted = new AbortController()
aborted.abort()
let abortedThrew = false
try {
  await provider.confine(['bash', '-c', 'true'], policy, aborted.signal)
}
catch {
  abortedThrew = true
}
check('an already-aborted call fails before the fence is compiled', abortedThrew)

console.log('what a session grant does to the profile')
const sessionPolicy = { mode: 'workspace-write', workspaceRoot: WORKSPACE, sessionId: 's1' }
const bash = command => ['bash', '-c', command]
const unlinkFor = text => text.includes(`(allow file-write-unlink (literal "${join(WORKSPACE, 'build')}"))`)
check('a plain call has no unlink allowance for that path',
  !unlinkFor(enforcer.profileFor(bash('rm -rf build'), sessionPolicy)))
grants.grant('s1', 'c1', 'rm -rf build', [{ path: join(WORKSPACE, 'build'), recursive: false, access: { delete: true } }])
check('the granted call carries it into the profile',
  unlinkFor(enforcer.profileFor(bash('rm -rf build'), sessionPolicy)))
check('but only for the command the user approved',
  !unlinkFor(enforcer.profileFor(bash('rm -rf other'), sessionPolicy)))
check('and the decision layer sees the same call',
  grants.rulesFor('s1', 'c1').length === 1)
check('while another call does not', grants.rulesFor('s1', 'c2').length === 0)
check('and the holder is visible to the gate', grants.holder('s1', 'c2') === 'c1' && grants.holder('s1', 'c1') === null)
grants.consume('s1', 'c1')
check('and the next call does not', !unlinkFor(enforcer.profileFor(bash('rm -rf build'), sessionPolicy)))
check('a command the builder cannot read carries no grant',
  !unlinkFor(enforcer.profileFor(['/bin/sh', '-c', 'rm -rf build'], sessionPolicy)))

console.log('delegating what it cannot refine')
const other = fakeProvider()
enforcer.uninstall()
const restored = await provider.confine(['x'], policy)
check('uninstall restores the provider method',
  restored.argv[0] === 'original', JSON.stringify(restored.argv))
const nonDarwin = enforce.createEnforcer({ config, grants, logger, platform: 'linux', spawn: okSpawn, ...runnerPresent })
nonDarwin.install({ get: () => other })
check('a non-darwin host delegates to the original',
  (await other.confine(['bash', '-c', 'ls'], policy)).argv[0] === 'original')
check('and reports that nothing is enforced', nonDarwin.status().state === 'off', JSON.stringify(nonDarwin.status()))

const offProvider = fakeProvider()
const offEnforcer = enforce.createEnforcer({ config: { ...config, enforce: 'off' }, grants, logger, platform: 'darwin', spawn: okSpawn, ...runnerPresent })
offEnforcer.install({ get: () => offProvider })
check('enforce: off delegates too', (await offProvider.confine(['bash', '-c', 'ls'], policy)).argv[0] === 'original')
check('and says why', offEnforcer.status().reason.includes('disabled'), offEnforcer.status().reason)

console.log('a kernel that refuses the full read fence')
const partialProvider = fakeProvider()
const partial = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: readRefusing, ...runnerPresent })
partial.install({ get: () => partialProvider })
const partialConfined = await partialProvider.confine(['bash', '-c', 'echo hi'], policy)
check('the call still runs under a profile', partialConfined.argv[0] === '/usr/bin/sandbox-exec')
check('one with the guarded read fence instead',
  partialConfined.argv[2].includes('(deny file-read-data (subpath "/Users"))')
  && !partialConfined.argv[2].includes('(deny file-read-data) (allow file-read-metadata)'), partialConfined.argv[2].slice(0, 160))
check('and the write fence survives', partialConfined.argv[2].includes('(deny file-write*)'))
check('the status says partial', partial.status().state === 'partial', JSON.stringify(partial.status()))
check('with the guarded level named', partial.status().level === 'guarded', JSON.stringify(partial.status()))
check('and user-data reads still fenced while execute is fenced too',
  partial.status().capabilities.read === true && partial.status().capabilities.execute === true
  && partial.status().capabilities.delete === true,
  JSON.stringify(partial.status().capabilities))
check('enforcement is partial for the shell tool', partialConfined.enforcement === 'partial')

console.log('a provider that cannot be refined')
const bare = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: okSpawn, ...runnerPresent })
check('a provider without confine is reported, not patched',
  bare.install({ get: () => ({}) }) === false && bare.status().state === 'off')
check('and no provider at all fails closed', bare.install({ get: () => undefined }) === false)

console.log('a host without the Seatbelt runner')
const unbacked = fakeProvider()
const noRunner = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: okSpawn, exists: () => false })
check('the enforcer still installs', noRunner.install({ get: () => unbacked }) === true)
check('but delegates every confinement to the provider',
  (await unbacked.confine(['bash', '-c', 'ls'], policy)).argv[0] === 'original')
check('and reports why nothing is enforced',
  noRunner.status().state === 'off' && noRunner.status().reason.includes('is not installed'),
  JSON.stringify(noRunner.status()))

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
