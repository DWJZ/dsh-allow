/**
 * Tool-operation rule suite: the action vocabulary, what may be stored at all,
 * what one call reads as, and which rule answers it. No host, no network.
 *
 * Usage: `node test/toolrules.spec.mjs`.
 */
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'

const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const rules = await import(pathToFileURL(join(PLUGIN, 'src/toolrules.js')).href)

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

console.log('the action vocabulary')
check('one tool is judged today', rules.TOOL_NAMES.join(',') === 'plugin_manager', rules.TOOL_NAMES.join(','))
check('a read-only action is named by its action alone', rules.actionScope('plugin_manager', 'list_plugins') === 'action')
check('a mutating action is scoped to its target', rules.actionScope('plugin_manager', 'set_plugin') === 'target')
check('the exemption action is answered by nobody', rules.actionScope('plugin_manager', 'set_version_exemption') === 'never')
check('an unknown action has no scope', rules.actionScope('plugin_manager', 'delete_everything') === null)
check('an unknown tool has no scope', rules.actionScope('rm', 'list_plugins') === null)
check('only a judged tool is looked at all', rules.isJudgedTool('plugin_manager') === true
  && rules.isJudgedTool('bash') === false && rules.isJudgedTool(undefined) === false)

console.log('labels')
check('a read-only rule reads as tool + action',
  rules.describeToolRule({ tool: 'plugin_manager', action: 'list_plugins' }) === 'plugin_manager list_plugins')
check('a mutating rule carries its target',
  rules.describeToolRule({ tool: 'plugin_manager', action: 'set_plugin', target: 'dsh-balance' }) === 'plugin_manager set_plugin dsh-balance')

console.log('what may be stored')
const refuses = (fields) => {
  const check2 = rules.validateToolRule(fields)
  return check2.ok === false ? check2.reason : null
}
check('a read-only rule is accepted', rules.validateToolRule({ tool: 'plugin_manager', action: 'list_plugins' }).ok === true)
check('a mutating rule with its target is accepted',
  rules.validateToolRule({ tool: 'plugin_manager', action: 'install_bundle', target: 'link:/w/plugin' }).ok === true)
check('an unknown tool is refused', refuses({ tool: 'bash', action: 'list_plugins' }) !== null)
check('an unknown action is refused', refuses({ tool: 'plugin_manager', action: 'drop_everything' }) !== null)
check('a missing action is refused', refuses({ tool: 'plugin_manager' }) !== null)
check('the exemption action can never be written as a rule',
  String(refuses({ tool: 'plugin_manager', action: 'set_version_exemption', target: 'pkg@1.0.0' })).includes('必须每次由用户'),
  String(refuses({ tool: 'plugin_manager', action: 'set_version_exemption', target: 'pkg@1.0.0' })))
check('a mutating rule without a target is refused',
  String(refuses({ tool: 'plugin_manager', action: 'set_plugin' })).includes('需要写明目标'),
  String(refuses({ tool: 'plugin_manager', action: 'set_plugin' })))
check('a blank target does not count as one', refuses({ tool: 'plugin_manager', action: 'set_plugin', target: '  ' }) !== null)
check('a read-only rule with a target is refused',
  String(refuses({ tool: 'plugin_manager', action: 'list_plugins', target: 'x' })).includes('不需要目标'))

console.log('a stored record')
check('a bad record is dropped', rules.normalizeStoredToolRule({ tool: 'plugin_manager', action: 'set_plugin' }, 'user') === null)
check('a good record keeps its id and hits',
  rules.normalizeStoredToolRule({ id: 't1', tool: 'plugin_manager', action: 'list_plugins', hits: 3, createdAt: 'now' }, 'user')?.hits === 3)
check('its source is the one it was read as',
  rules.normalizeStoredToolRule({ tool: 'plugin_manager', action: 'list_plugins' }, 'user')?.source === 'user')
check('a rule whose action is answered by nobody is never usable',
  rules.isUsableToolRule({ tool: 'plugin_manager', action: 'set_version_exemption', source: 'user' }) === false)
check('a rule for an action that no longer exists is never usable',
  rules.isUsableToolRule({ tool: 'plugin_manager', action: 'gone', source: 'user' }) === false)

console.log('what one call reads as')
check('another tool is not this plugin\'s to judge', rules.toolRequestOf('bash', { command: 'ls' }) === null)
check('an unreadable action is never answered',
  rules.toolRequestOf('plugin_manager', { action: 'whatever' }) === null
  && rules.toolRequestOf('plugin_manager', {}) === null)
const listAsk = rules.toolRequestOf('plugin_manager', { action: 'list_plugins', offset: 0, limit: 25 })
check('a read-only action asks for its action alone',
  listAsk?.target === null && listAsk?.rememberable === true && listAsk?.blocked === null, JSON.stringify(listAsk))
const setAsk = rules.toolRequestOf('plugin_manager', { action: 'set_plugin', target: 'dsh-balance', enabled: true })
check('a mutating action carries its exact target',
  setAsk?.target === 'dsh-balance' && setAsk?.rememberable === true, JSON.stringify(setAsk))
check('a mutating call with no target is not rememberable',
  rules.toolRequestOf('plugin_manager', { action: 'set_plugin', enabled: true })?.rememberable === false)
check('the exemption action is blocked, not rememberable',
  rules.toolRequestOf('plugin_manager', { action: 'set_version_exemption', target: 'pkg@1.0.0', enabled: true })?.blocked !== null
  && rules.toolRequestOf('plugin_manager', { action: 'set_version_exemption', target: 'pkg@1.0.0' })?.rememberable === false)
check('a risk acknowledgement makes the call unanswerable by a rule',
  rules.toolRequestOf('plugin_manager', { action: 'set_version_exemption', target: 'pkg@1.0.0', acceptRisk: true })?.blocked !== null
  && rules.toolRequestOf('plugin_manager', { action: 'install_bundle', target: 'pkg', acceptRisk: true })?.rememberable === false)
check('a build-script approval makes the call unanswerable by a rule',
  rules.toolRequestOf('plugin_manager', { action: 'install_bundle', target: 'pkg', approvedBuilds: ['esbuild'] })?.blocked !== null
  && rules.toolRequestOf('plugin_manager', { action: 'install_bundle', target: 'pkg', approvedBuilds: [] })?.blocked === null)
check('a blocked call names why', typeof rules.toolRequestOf('plugin_manager', { action: 'install_bundle', target: 'pkg', approvedBuilds: ['x'] })?.blocked === 'string')

console.log('which rule answers')
const store = [
  rules.makeToolRule({ id: 't1', tool: 'plugin_manager', action: 'list_plugins' }),
  rules.makeToolRule({ id: 't2', tool: 'plugin_manager', action: 'set_plugin', target: 'dsh-balance' }),
]
check('a read-only rule answers its action',
  rules.matchToolRule(store, listAsk)?.id === 't1')
check('and not a sibling action',
  rules.matchToolRule(store, rules.toolRequestOf('plugin_manager', { action: 'list_bundles' })) === null)
check('a mutating rule answers its own target',
  rules.matchToolRule(store, setAsk)?.id === 't2')
check('and never another target',
  rules.matchToolRule(store, rules.toolRequestOf('plugin_manager', { action: 'set_plugin', target: 'other-plugin' })) === null)
check('a hand-written rule that omits the target never matches',
  rules.matchToolRule([{ tool: 'plugin_manager', action: 'set_plugin', source: 'user' }], setAsk) === null)
check('a hand-written rule that names a target for a read-only action never matches',
  rules.matchToolRule([{ tool: 'plugin_manager', action: 'list_plugins', target: 'x', source: 'user' }], listAsk) === null)
check('a blocked call is answered by no rule at all',
  rules.matchToolRule(
    [...store, rules.makeToolRule({ tool: 'plugin_manager', action: 'install_bundle', target: 'pkg' })],
    rules.toolRequestOf('plugin_manager', { action: 'install_bundle', target: 'pkg', approvedBuilds: ['x'] }),
  ) === null)
check('an empty rule set answers nothing', rules.matchToolRule([], listAsk) === null)
check('a missing rule set answers nothing', rules.matchToolRule(undefined, listAsk) === null)

console.log('the audit projection')
const audited = rules.matchedToolRuleOf(store[1])
check('it names the tool, the action, and the target',
  audited.tool === 'plugin_manager' && audited.action === 'set_plugin' && audited.target === 'dsh-balance',
  JSON.stringify(audited))
check('and carries the label a ledger row renders',
  audited.label === 'plugin_manager set_plugin dsh-balance' && audited.source === 'user', JSON.stringify(audited))
check('a read-only rule carries no target key',
  rules.matchedToolRuleOf(store[0]).target === undefined, JSON.stringify(rules.matchedToolRuleOf(store[0])))

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)
