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
let profile = enforce.compileProfile({ mode: 'workspace-write', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'all' })
check('write and create are granted in the workspace',
  profile.includes('file-write-data') && profile.includes('file-write-create'), profile)
check('delete is withheld in the workspace', !profile.includes('(allow file-write-unlink'), profile)
check('the write fence is always present', profile.includes('(deny file-write*)'))
check('the read fence is present when asked for',
  profile.includes('(deny file-read-data)') && profile.includes('(allow file-read-metadata)'))
check('the execute fence is present', profile.includes('(deny process-exec)'))
check('system binaries stay executable', profile.includes('(allow process-exec (subpath "/usr/bin"))') || profile.includes('(allow process-exec (subpath "/bin"))'), profile)

profile = enforce.compileProfile({ mode: 'workspace-write', workspaceRoot: WORKSPACE, rules: workspaceRules, capabilities: 'writes' })
check('a writes-only profile fences writes without fencing reads',
  profile.includes('(deny file-write*)') && !profile.includes('(deny file-read-data)') && !profile.includes('(deny process-exec)'), profile)

profile = enforce.compileProfile({
  mode: 'workspace-write',
  workspaceRoot: WORKSPACE,
  rules: [...workspaceRules, rule(join(WORKSPACE, 'build'), { delete: true })],
  capabilities: 'all',
})
check('a delete grant becomes an unlink allowance',
  profile.includes(`(allow file-write-unlink (subpath "${join(WORKSPACE, 'build')}"))`), profile)

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
/** A kernel that can fence writes but refuses a profile that fences reads. */
const readRefusing = (_program, args) => ({ status: String(args?.[1] ?? '').includes('(deny file-read-data)') ? 1 : 0 })
check('an applying profile passes the probe',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: okSpawn }) === true)
check('a refusing profile fails the probe',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: () => ({ status: 1 }) }) === false)
check('a spawner that throws fails closed',
  enforce.probeProfile(profile, { workspaceRoot: WORKSPACE, spawn: () => { throw new Error('nope') } }) === false)

console.log('installing on the registered provider')
/** A stand-in for the harness's sandbox provider. */
function fakeProvider() {
  return {
    calls: [],
    confine(argv, policy) {
      this.calls.push({ argv, policy })
      return { argv: ['original', ...argv], enforcement: 'full', denialSignatures: ['read-only file system'], runnerFailureRules: [] }
    },
  }
}
const provider = fakeProvider()
const grants = store.createGrantStore()
const ctx = { get: name => (name === 'sandbox' ? provider : undefined) }
const enforcer = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: okSpawn })
check('install wraps the provider', enforcer.install(ctx) === true)
const policy = { mode: 'workspace-write', workspaceRoot: WORKSPACE }
const confined = provider.confine(['bash', '-c', 'rm -rf build'], policy)
check('the caller gets the Seatbelt argv', confined.argv[0] === '/usr/bin/sandbox-exec' && confined.argv[1] === '-p', JSON.stringify(confined.argv.slice(0, 2)))
check('and its own command', confined.argv.slice(-3).join(' ') === 'bash -c rm -rf build', JSON.stringify(confined.argv.slice(-3)))
check('with the denial dialect the shell tool classifies', confined.denialSignatures.includes('operation not permitted'))
check('and a runner-failure rule for a profile the kernel refuses',
  confined.runnerFailureRules[0]?.fatalSignatures?.[0] === 'sandbox-exec: ')
check('the status reports full enforcement', enforcer.status().state === 'full', JSON.stringify(enforcer.status()))

console.log('what a session grant does to the profile')
const sessionPolicy = { mode: 'workspace-write', workspaceRoot: WORKSPACE, sessionId: 's1' }
const unlinkFor = text => text.includes(`(allow file-write-unlink (literal "${join(WORKSPACE, 'build')}"))`)
check('a plain call has no unlink allowance for that path', !unlinkFor(enforcer.profileFor(sessionPolicy)))
grants.grant('s1', 'c1', [{ path: join(WORKSPACE, 'build'), recursive: false, access: { delete: true } }])
check('the granted call carries it into the profile', unlinkFor(enforcer.profileFor(sessionPolicy)), enforcer.profileFor(sessionPolicy))
grants.consume('s1', 'c1')
check('and the next call does not', !unlinkFor(enforcer.profileFor(sessionPolicy)))

console.log('delegating what it cannot refine')
const other = fakeProvider()
enforcer.uninstall()
check('uninstall restores the provider method',
  provider.confine(['x'], policy).argv[0] === 'original', JSON.stringify(provider.confine(['x'], policy).argv))
const nonDarwin = enforce.createEnforcer({ config, grants, logger, platform: 'linux', spawn: okSpawn })
nonDarwin.install({ get: () => other })
check('a non-darwin host delegates to the original',
  other.confine(['bash', '-c', 'ls'], policy).argv[0] === 'original')
check('and reports that nothing is enforced', nonDarwin.status().state === 'off', JSON.stringify(nonDarwin.status()))

const offProvider = fakeProvider()
const offEnforcer = enforce.createEnforcer({ config: { ...config, enforce: 'off' }, grants, logger, platform: 'darwin', spawn: okSpawn })
offEnforcer.install({ get: () => offProvider })
check('enforce: off delegates too', offProvider.confine(['bash', '-c', 'ls'], policy).argv[0] === 'original')
check('and says why', offEnforcer.status().reason.includes('disabled'), offEnforcer.status().reason)

console.log('a kernel that refuses the read fence')
const partialProvider = fakeProvider()
const partial = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: readRefusing })
partial.install({ get: () => partialProvider })
const partialConfined = partialProvider.confine(['bash', '-c', 'echo hi'], policy)
check('the call still runs under a profile', partialConfined.argv[0] === '/usr/bin/sandbox-exec')
check('one without the read fence', !partialConfined.argv[2].includes('(deny file-read-data)'), partialConfined.argv[2].slice(0, 120))
check('and the write fence survives', partialConfined.argv[2].includes('(deny file-write*)'))
check('the status says partial', partial.status().state === 'partial', JSON.stringify(partial.status()))
check('with read and execute marked unfenced',
  partial.status().capabilities.read === false && partial.status().capabilities.delete === true,
  JSON.stringify(partial.status().capabilities))
check('enforcement is partial for the shell tool', partialConfined.enforcement === 'partial')

console.log('a provider that cannot be refined')
const bare = enforce.createEnforcer({ config, grants, logger, platform: 'darwin', spawn: okSpawn })
check('a provider without confine is reported, not patched',
  bare.install({ get: () => ({}) }) === false && bare.status().state === 'off')
check('and no provider at all fails closed', bare.install({ get: () => undefined }) === false)

rmSync(root, { recursive: true, force: true })
console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
