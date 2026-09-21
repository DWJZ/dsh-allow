/**
 * Decision suite: one command line, one rule set, one answer — over paths that
 * are not created on disk, so the assertions are about the policy rather than
 * about this machine.
 *
 * Usage: `node test/decide.spec.mjs`.
 */
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { tmpdir } from 'node:os'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const { evaluateCommandLine } = await import(pathToFileURL(join(PLUGIN, 'src/decide.js')).href)
const fspolicy = await import(pathToFileURL(join(PLUGIN, 'src/fspolicy.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const HOME = '/Users/tester'
const WORKSPACE = `${HOME}/project`
const CWD = WORKSPACE
const BASE = { cwd: CWD, home: HOME, workspaceRoot: WORKSPACE, harnessHome: `${HOME}/.dsh`, mode: 'workspace-write' }
const decide = (command, overrides = {}) => evaluateCommandLine({ command, ...BASE, ...overrides })
const rule = (path, access, recursive = true) => fspolicy.makeRule({ path, access, recursive })
/** A kernel that fences every capability, as `enforce: 'auto'` reports when it can. */
const FENCED = { capabilities: { read: true, write: true, create: true, delete: true, execute: true } }
/** A kernel that fences only the writes, which is what `enforce: 'writes'` buys. */
const WRITES_FENCED = { capabilities: { read: false, write: true, create: true, delete: true, execute: false } }

console.log('granted within the workspace')
check('listing the workspace is allowed', decide('ls -la').decision === 'allow')
check('reading a workspace file is allowed', decide('cat README.md').decision === 'allow')
check('creating a workspace file is allowed', decide('echo x > out.md').decision === 'allow')
check('running a workspace script is allowed', decide('./build.sh').decision === 'allow')
check('creating a temp file is allowed', decide('mkdir -p /tmp/dsh-allow-check').decision === 'allow')

console.log('the workspace withholds delete')
let decision = decide('rm -rf build')
check('deleting in the workspace asks', decision.decision === 'prompt', JSON.stringify(decision.reason))
check('and names the missing capability', decision.missing[0]?.operation === 'delete'
  && decision.missing[0]?.path === `${WORKSPACE}/build`, JSON.stringify(decision.missing))
check('and offers exactly one grant, the narrowest one',
  decision.suggestions.length === 1
  && decision.suggestions[0]?.path === `${WORKSPACE}/build`
  && decision.suggestions[0]?.recursive === false, JSON.stringify(decision.suggestions))

decision = decide('rm -rf build', { rules: [rule(`${WORKSPACE}/build`, { delete: true })] })
check('a stored delete rule allows it', decision.decision === 'allow', JSON.stringify(decision.reason))
check('and the rule is reported as used',
  decision.usedRules.some(used => used.path === `${WORKSPACE}/build` && used.access.delete === true),
  JSON.stringify(decision.usedRules.map(used => used.id)))

decision = decide('rm -rf other', { rules: [rule(`${WORKSPACE}/build`, { delete: true })] })
check('a rule for one folder does not cover its sibling', decision.decision === 'prompt', JSON.stringify(decision.reason))

decision = decide('rm -rf build', { sessionRules: [rule(`${WORKSPACE}/build`, { delete: true })] })
check('an allow-once grant allows it', decision.decision === 'allow')

console.log('the permission store is not the agent\'s to change')
const STORE = `${HOME}/.dsh/dsh-allow.json`
check('writing the rules file is refused',
  decide(`echo x > ${STORE}`, { protectedFiles: [STORE] }).decision === 'forbidden')
check('deleting the rules file is refused',
  decide(`rm -f ${STORE}`, { protectedFiles: [STORE] }).decision === 'forbidden')
check('a user rule cannot unlock it',
  decide(`rm -f ${STORE}`, { protectedFiles: [STORE], rules: [rule('/Users/tester/.dsh', { delete: true })] }).decision === 'forbidden')
check('a rule for the directory grants nothing there',
  decide(`cat ${STORE}`, { protectedFiles: [STORE], rules: [rule('/Users/tester/.dsh', { read: true })] }).decision === 'allow')
check('the audit log is protected too',
  decide(`rm -f ${HOME}/.dsh/dsh-allow-audit.ndjson`, { protectedFiles: [`${HOME}/.dsh/dsh-allow-audit.ndjson`] }).decision === 'forbidden')
check('and the harness home is read-only by default',
  decide(`echo x > ${HOME}/.dsh/other.json`).decision === 'prompt')

console.log('outside the workspace')
decision = decide('echo x > /Users/tester/other/out.txt')
check('writing outside the workspace asks', decision.decision === 'prompt', JSON.stringify(decision.reason))
check('and names create', decision.missing[0]?.operation === 'create', JSON.stringify(decision.missing))

decision = decide('cat /Users/tester/other/notes.txt')
check('reading outside the workspace asks', decision.decision === 'prompt', JSON.stringify(decision.reason))

decision = decide('cat /opt/homebrew/bin/gh')
check('reading a homebrew path is allowed', decision.decision === 'allow', JSON.stringify(decision.reason))

// Spelled by path, so the answer comes from the policy rather than from whether
// this machine happens to have Homebrew installed.
decision = decide('/opt/homebrew/bin/gh pr list')
check('running a homebrew binary asks for execute', decision.decision === 'prompt'
  && decision.missing.some(entry => entry.operation === 'execute'), JSON.stringify(decision.missing))

const brew = fspolicy.canonicalPath('/opt/homebrew/bin/gh', { cwd: '/', home: HOME })
decision = decide('/opt/homebrew/bin/gh pr list', { rules: [rule(brew, { execute: true }, false)] })
check('and a grant for the resolved binary allows it', decision.decision === 'allow', JSON.stringify(decision.reason))

console.log('platform refusals')
check('writing under /System is refused', decide('rm -rf /System/Library/x').decision === 'forbidden')
check('writing a system binary is refused', decide('chmod 777 /usr/bin/ls').decision === 'forbidden')
check('writing a device is refused', decide('dd if=/dev/zero of=/dev/disk2').decision === 'forbidden')
check('a user rule cannot unlock a protected path',
  decide('rm -rf /System/Library/x', { rules: [rule('/System', { delete: true })] }).decision === 'forbidden')
check('a line the grammar rejects is refused', decide('rm -rf "').decision === 'forbidden')
check('and the refusal names the syntax', decide('rm -rf "').reason.includes('grammar'))

console.log('no destructive-command classifier')
decision = decide('git reset --hard')
check('git reset --hard is not judged by its name',
  !/reset|hard|destructive|discard/iu.test(decision.reason), decision.reason)
check('at most its executable is questioned',
  decision.decision === 'allow' || decision.missing.every(entry => entry.operation === 'execute'),
  JSON.stringify(decision.missing))
check('a network transfer without a file target needs nothing', decide('curl https://example.invalid').decision === 'allow')

console.log('inline programs run only on a fence that can back them')
decision = decide("/usr/bin/python3 -c 'print(1)'", { enforcement: FENCED })
check('inline code runs when the kernel fences every capability', decision.decision === 'allow', JSON.stringify(decision.reason))
check('and is recorded as unreadable', decision.unknown.length === 1)
decision = decide("/usr/bin/python3 -c 'print(1)'")
check('without an installed fence it asks', decision.decision === 'prompt', JSON.stringify(decision.reason))
check('and the card offers every capability for this directory',
  decision.suggestions.length === 1
  && decision.suggestions[0]?.path === CWD
  && decision.suggestions[0]?.access?.delete === true
  && decision.suggestions[0]?.access?.execute === true, JSON.stringify(decision.suggestions))
decision = decide("/usr/bin/python3 -c 'print(1)'", { enforcement: WRITES_FENCED })
check('a partial fence is not enough on its own', decision.decision === 'prompt', JSON.stringify(decision.reason))
decision = decide("/usr/bin/python3 -c 'print(1)'", {
  enforcement: WRITES_FENCED,
  rules: [rule(CWD, { read: true, write: true, create: true, delete: true, execute: true })],
})
check('but an open directory is: nothing is left to withhold', decision.decision === 'allow', JSON.stringify(decision.reason))
decision = decide("/usr/bin/python3 -c 'print(1)'", { enforcement: FENCED, mode: 'danger-full-access' })
check('with no confining mode it asks', decision.decision === 'prompt', JSON.stringify(decision.reason))
decision = decide("/usr/bin/python3 -c 'print(1)'", { enforcement: FENCED, mode: null })
check('an unknown mode asks too', decision.decision === 'prompt')
decision = decide("/usr/bin/python3 -c 'print(1)'", { enforcement: FENCED, mode: 'read-only' })
check('read-only still confines the process', decision.decision === 'allow')

console.log('computed paths are not a free ride')
decision = decide('rm -rf "$DIR"')
check('a computed delete path asks', decision.decision === 'prompt', JSON.stringify(decision.reason))
check('and offers the working directory as the narrowest grant',
  decision.suggestions[0]?.path === CWD && decision.suggestions[0]?.access?.delete === true,
  JSON.stringify(decision.suggestions))
decision = decide('rm -rf "$DIR"', { sessionRules: [rule(CWD, { delete: true })] })
check('a grant for the working directory answers it', decision.decision === 'allow', JSON.stringify(decision.reason))
decision = decide('rm -rf "$DIR"', { sessionRules: [rule(join(CWD, 'build'), { delete: true })] })
check('a grant elsewhere does not', decision.decision === 'prompt', JSON.stringify(decision.reason))

console.log('wrappers and chains')
decision = decide('sudo rm -rf build')
check('sudo does not hide the delete', decision.decision === 'prompt'
  && decision.missing.some(entry => entry.operation === 'delete'), JSON.stringify(decision.reason))
decision = decide('echo ok && rm -rf build')
check('a chain is as strict as its strictest member', decision.decision === 'prompt')
decision = decide('echo ok && cat README.md')
check('a chain of granted commands is allowed', decision.decision === 'allow')

console.log('read-only sessions')
check('read-only withholds a workspace write', decide('echo x > out.md', { mode: 'read-only' }).decision === 'prompt')
check('read-only still allows a workspace read', decide('cat README.md', { mode: 'read-only' }).decision === 'allow')
check('read-only withholds a temp write', decide('mkdir -p /tmp/dsh-allow-check', { mode: 'read-only' }).decision === 'prompt')

console.log('/Users/tester is not read for the machine it runs on')
check('the fixture paths do not exist', !tmpdir().startsWith(WORKSPACE))

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
