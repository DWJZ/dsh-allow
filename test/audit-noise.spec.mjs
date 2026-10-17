/**
 * Automatic allows stay out of the audit trail; everything a person would read stays in.
 *
 * The rule under test is one predicate, so it is exercised directly rather than through
 * a whole gate: every branch below is one a real session produces.
 */
import { isAmbientAllow } from '../src/index.js'

let failures = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${detail === '' ? '' : ` — ${detail}`}`)
  if (!ok) failures += 1
}

const allow = (origin, matchedRules) => ({ decision: 'allow', origin, matchedRules })
const workspaceRule = { id: 'w', path: '/repo', recursive: true, source: 'workspace', access: { read: true } }
const systemRule = { id: 's', path: '/repo', recursive: true, source: 'system', access: { read: true } }
const userRule = { id: 'u', path: '/tmp', recursive: true, source: 'user', access: { read: true } }
const sessionRule = { id: 'g', path: '/tmp/x', recursive: false, source: 'session', access: { read: true, write: true } }

console.log('quiet: workspace and system allows')
check('a workspace rule allow is dropped', isAmbientAllow(allow('rule', [workspaceRule]), {}) === true)
check('a system rule allow is dropped', isAmbientAllow(allow('rule', [systemRule]), {}) === true)
check('a pure baseline allow is dropped', isAmbientAllow(allow('baseline', []), {}) === true)
check('mixed workspace+system is dropped', isAmbientAllow(allow('rule', [workspaceRule, systemRule]), {}) === true)

console.log('kept: anything a person would read')
check('a user rule allow is kept', isAmbientAllow(allow('rule', [userRule]), {}) === false)
check('a one-shot grant is kept', isAmbientAllow(allow('rule', [userRule, sessionRule]), {}) === false)
check('a human allow is kept', isAmbientAllow(allow('human', [workspaceRule]), {}) === false)
check('an auto-review allow is kept', isAmbientAllow(allow('auto-review', [workspaceRule]), {}) === false)
check('a prompt is kept', isAmbientAllow({ decision: 'prompt', origin: 'rule', matchedRules: [workspaceRule] }, {}) === false)
check('a denial is kept', isAmbientAllow({ decision: 'forbidden', origin: 'policy', matchedRules: [] }, {}) === false)

console.log('the switch renders automatic allows again')
check('showAllowedRows restores workspace allows', isAmbientAllow(allow('rule', [workspaceRule]), { showAllowedRows: true }) === false)
check('showAllowedRows restores baseline allows', isAmbientAllow(allow('baseline', []), { showAllowedRows: true }) === false)

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
