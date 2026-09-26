/**
 * dsh-allow browser smoke test — loads the client bundle outside a browser and
 * checks the chain registration it installs, plus a server-side render of the
 * card with a pending record already loaded.
 *
 * Usage: `node test/client.smoke.mjs`.
 * The render assertion needs React, resolved from a DSH checkout; set
 * `DSH_CHECKOUT` to that checkout's root, or it is skipped.
 */
import { readFileSync, readdirSync } from 'node:fs'
import { createRequire } from 'node:module'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const require = createRequire(import.meta.url)
const PLUGIN = resolve(dirname(fileURLToPath(import.meta.url)), '..')

let failures = 0
const check = (name, condition, detail = '') => {
  if (condition) console.log(`  ok   ${name}`)
  else {
    failures += 1
    console.log(`  FAIL ${name} ${detail}`)
  }
}

const found = findReact()

let captured = null
globalThis.window = { __ModuleLoader__: { load: (definition) => { captured = definition } } }
new Function(readFileSync(join(PLUGIN, 'client/client.js'), 'utf8'))()

check('the bundle registers one module', captured !== null && captured.id === 'dsh-allow', String(captured?.id))

/** The pending record a card renders; the host half sends exactly these fields. */
const pendingInfo = {
  ok: true,
  rememberable: true,
  command: 'rm -rf build',
  cwd: '/Users/tester/project',
  reason: 'filesystem permission required: delete(/Users/tester/project/build)',
  mode: 'workspace-write',
  decision: 'prompt',
  missing: [{ operation: 'delete', path: '/Users/tester/project/build', label: 'delete /Users/tester/project/build' }],
  unknown: [],
  suggestions: [
    { label: 'delete · /Users/tester/project/build', path: '/Users/tester/project/build', recursive: false, access: { delete: true } },
  ],
}

let hooks = 0
/** Hook values one render consumes in order; anything past the plan keeps its initial value. */
let plan = []
const stubRequire = (specifier) => {
  if (specifier === 'react') {
    if (found === null) return { createElement: () => null, useState: () => [null, () => {}], useEffect: () => {} }
    return {
      ...found.react,
      // Rendering a component directly is what a browser shows once its host
      // route answered, so the plan supplies the state it would have loaded.
      useState: (initial) => {
        const index = hooks
        hooks += 1
        return [index < plan.length ? plan[index] : initial, () => {}]
      },
      useEffect: () => {},
    }
  }
  if (specifier === '@deepseek-ai/dsh-client-ui-primitives') {
    return {
      Button: ({ children, ...rest }) => (found === null ? null : found.react.createElement('button', rest, children)),
    }
  }
  throw new Error(`unexpected require: ${specifier}`)
}

const client = captured.factory(stubRequire)
check('the factory exports apply', typeof client.apply === 'function')
check('the factory exports inject', Array.isArray(client.inject) && client.inject.includes('slots'))

console.log('approval predicate')
const pending = {
  kind: 'approval',
  key: 'approval:1',
  toolName: 'bash',
  sessionId: 's1',
  callId: 'c1',
  reason: 'escalate sandbox to danger-full-access: 需要写 profile',
  answer: () => Promise.resolve(),
}
check('a sandbox escalation is taken over', client.escalationOf(pending) === pending)
check('another approval is left to the built-in card', client.escalationOf({ ...pending, reason: 'hook requires approval' }) === null)
const policyPrompt = { ...pending, reason: 'dsh-allow: filesystem permission required: delete(/w/build)' }
check('a policy prompt is claimed by this card', client.escalationOf(policyPrompt) === policyPrompt)
check('a non-approval interaction is ignored', client.escalationOf({ kind: 'question' }) === null)
check('an absent interaction is ignored', client.escalationOf(undefined) === null)

console.log('display helpers')
check('an over-long display string is ellipsised', client.shorten('x'.repeat(80), 20).length === 20 && client.shorten('x'.repeat(80), 20).endsWith('\u2026'))
check('a short string is untouched', client.shorten('short', 20) === 'short')
check('a policy ask is the one a rule can be stored for', client.isPolicyAsk(policyPrompt) === true)
check('a sandbox escalation is not', client.isPolicyAsk(pending) === false)
const toolAsk = { ...pending, toolName: 'plugin_manager' }
check('a management tool\'s escalation is a tool operation a rule can be stored for',
  client.isToolAsk(toolAsk) === true)
check('a shell escalation is not', client.isToolAsk(pending) === false)
check('another tool\'s escalation is not', client.isToolAsk({ ...pending, toolName: 'write' }) === false)
check('and a policy prompt is not', client.isToolAsk(policyPrompt) === false)
check('an absent interaction is not', client.isToolAsk(undefined) === false)

console.log('apply')
const registrations = []
const dictionaries = []
const definitions = []
const ctx = {
  effect: (factory) => factory(),
  locale: {
    register: (ns, dicts) => { dictionaries.push({ ns, dicts }); return () => {} },
    bind: (ns) => (key, params) => (params === undefined ? key : `${key}(${JSON.stringify(params)})`),
  },
  slots: {
    inject: (_name, factory) => factory(),
    register: (options, component) => { registrations.push({ options, component }); return () => {} },
  },
  sessions: { binding: () => undefined },
  uiConversation: { events: { register: (definition) => { definitions.push(definition); return () => {} } } },
}
client.apply(ctx)
const card = registrations.find(entry => entry.options.name === 'conversation.composer')
check('a composer chain entry is registered', card?.options?.name === 'conversation.composer', JSON.stringify(registrations.map(entry => entry.options.name)))
check('it runs before the built-in approval card (priority 1)', (card?.options?.priority ?? 99) < 1, String(card?.options?.priority))
check('it declares its dictionary namespace', card?.options?.locale === 'dshAllow', String(card?.options?.locale))
check('select matches an escalation', card?.options?.select({ pendingInteraction: pending }) === pending)
check('select passes other interactions through', card?.options?.select({ pendingInteraction: { kind: 'question' } }) === null)
check('no Web-facing conversation view is registered any more',
  registrations.every(entry => entry.options.name !== 'conversation.view'),
  JSON.stringify(registrations.map(entry => entry.options.name)))
check('the remember action rides the composer inject face',
  typeof card?.options?.inject === 'function'
  && typeof card.options.inject()?.remember === 'function',
  JSON.stringify(Object.keys(card?.options?.inject?.() ?? {})))
check('the dictionary is registered for both locales and balanced',
  dictionaries.length === 1 && dictionaries[0].ns === 'dshAllow'
  && Object.keys(dictionaries[0].dicts.zh).length === Object.keys(dictionaries[0].dicts.en).length,
  JSON.stringify(dictionaries.map(entry => entry.ns)))

console.log('the decision row')
const chatDefinition = definitions.find(entry => entry.target === 'chat')
const trajectoryDefinition = definitions.find(entry => entry.target === 'trajectory')
check('a Chat business definition is registered',
  definitions.length === 2 && chatDefinition?.kind === 'allow-decision',
  JSON.stringify(definitions.map(entry => [entry.kind, entry.target])))
check('and a Trajectory one beside it, from the same event',
  trajectoryDefinition?.kind === 'trajectory-allow-decision', String(trajectoryDefinition?.kind))
check('their kinds differ, because the registry keys definitions by kind alone',
  chatDefinition?.kind !== trajectoryDefinition?.kind,
  `${String(chatDefinition?.kind)} / ${String(trajectoryDefinition?.kind)}`)
const decisionEvent = {
  type: client.DECISION_EVENT,
  seq: 7,
  time: 1_700_000_000_000,
  data: { origin: 'rule', action: null, command: 'rm -rf build', missing: [] },
}
check('both claim their own event type only',
  chatDefinition?.match(decisionEvent)?.role === 'start'
  && trajectoryDefinition?.match(decisionEvent)?.role === 'start'
  && chatDefinition?.match({ type: 'tool/call', seq: 1, data: {} }) === null
  && trajectoryDefinition?.match({ type: 'tool/call', seq: 1, data: {} }) === null,
  JSON.stringify(chatDefinition?.match(decisionEvent)))
check('a row renderer is registered under the same kind',
  registrations.some(entry => entry.options.name === 'conversation.chat.node' && entry.options.key === 'allow-decision'),
  JSON.stringify(registrations.map(entry => entry.options.name)))
const decisionContext = {
  key: 'allow-decision:k',
  kind: 'allow-decision',
  id: 'allow:7',
  state: { seq: 7, record: decisionEvent.data },
  start: { event: decisionEvent, location: { kind: 'unresolved' } },
}
const builtNode = chatDefinition.buildViewNode(decisionContext)
check('the built node carries the record and its log position',
  builtNode?.kind === 'allow-decision' && builtNode?.anchorSeq === 7
  && builtNode?.data === decisionEvent.data && builtNode?.target === 'chat',
  JSON.stringify(builtNode))

console.log('the trajectory row')
const trajectoryNode = trajectoryDefinition.buildViewNode({
  ...decisionContext,
  state: { seq: 7, time: decisionEvent.time, record: decisionEvent.data },
})
check('the trajectory target gets a plugin-extension row',
  trajectoryNode?.data?.kind === 'node' && trajectoryNode?.data?.node?.kind === 'extension',
  JSON.stringify(trajectoryNode?.data))
check('the row text is this plugin symbol plus dictionary copy, not a raw discriminant',
  trajectoryNode?.data?.node?.text === '📋 logOriginRule · rm -rf build',
  String(trajectoryNode?.data?.node?.text))
check('and the payload rides along for the details panel',
  trajectoryNode?.data?.node?.value === decisionEvent.data
  && trajectoryNode?.data?.node?.key === client.DECISION_EVENT
  && trajectoryNode?.data?.node?.time === decisionEvent.time,
  JSON.stringify(trajectoryNode?.data?.node))
check('the trajectory definition builds nothing without a matched start',
  trajectoryDefinition.buildViewNode({ ...decisionContext, state: undefined }) === null)
const toneOf = (origin) => trajectoryDefinition.buildViewNode({
  ...decisionContext,
  state: { seq: 7, time: 0, record: { origin, action: null, command: 'ls' } },
})?.data?.node?.tone
const tones = ['rule', 'baseline', 'auto-review', 'human', 'policy']
  .map(origin => `${origin}=${String(toneOf(origin))}`)
check('each origin asks for its own ledger tone',
  tones.join(' ') === 'rule=positive baseline=neutral auto-review=accent human=warning policy=critical',
  tones.join(' '))
check('the tone vocabulary is closed: an unknown origin falls back to neutral',
  toneOf('mystery') === 'neutral', String(toneOf('mystery')))
const emojiOf = (record) => trajectoryDefinition.buildViewNode({
  ...decisionContext,
  state: { seq: 7, time: 0, record: { command: 'ls', ...record } },
})?.data?.node?.text.split(' ')[0]
// Colour separates origins; the symbol has to separate the two human outcomes
// too, which share one origin.
const symbols = [
  ['allow once', emojiOf({ origin: 'human', action: 'allow-once' })],
  ['always allow', emojiOf({ origin: 'human', action: 'always-allow' })],
  ['denied', emojiOf({ origin: 'human', action: 'deny' })],
  ['cancelled', emojiOf({ origin: 'human', action: 'cancelled' })],
  ['no answerer', emojiOf({ origin: 'human', action: 'unavailable' })],
  ['rule', emojiOf({ origin: 'rule', action: null })],
  ['baseline', emojiOf({ origin: 'baseline', action: null })],
  ['auto review', emojiOf({ origin: 'auto-review', action: null })],
  ['policy', emojiOf({ origin: 'policy', action: null })],
]
check('every decision category carries its own symbol',
  new Set(symbols.map(([, symbol]) => symbol)).size === 8,
  symbols.map(([name, symbol]) => `${name}=${String(symbol)}`).join(' '))
check('a human denial and the plugin refusing its own share the denial symbol',
  emojiOf({ origin: 'human', action: 'deny' }) === emojiOf({ origin: 'policy', action: null }),
  `${String(emojiOf({ origin: 'human', action: 'deny' }))} / ${String(emojiOf({ origin: 'policy', action: null }))}`)
check('and an unknown origin still gets one',
  typeof emojiOf({ origin: 'mystery', action: null }) === 'string',
  String(emojiOf({ origin: 'mystery', action: null })))

if (found === null) {
  console.log('  skip render assertion (set DSH_CHECKOUT to a checkout with React installed)')
} else {
  const react = found.react
  const t = (key, params) => (params === undefined ? key : `${key}(${JSON.stringify(params)})`)
  hooks = 0
  plan = [pendingInfo]
  const html = found.server.renderToStaticMarkup(react.createElement(card.component, { matched: pending, t }))
  check('the card renders the approval chrome', html.includes('dsha_card') && html.includes('dsha_strip'), html.slice(0, 200))
  check('the card renders 拒绝 and 允许一次', html.includes('reject') && html.includes('allowOnce'), html)
  check('the card shows the reason the host sent', html.includes('escalate sandbox to danger-full-access'), html)
  check('an escalation offers no always-allow button: a wider fence is not a stored rule',
    !html.includes('alwaysAllow'), html)

  const toolHtml = found.server.renderToStaticMarkup(react.createElement(card.component, { matched: toolAsk, t }))
  check('a management tool\'s escalation offers exactly one always-allow button',
    toolHtml.split('alwaysAllow').length - 1 === 1, toolHtml)
  check('beside 拒绝 and 允许一次',
    toolHtml.includes('reject') && toolHtml.includes('allowOnce'), toolHtml)
  check('and shows the reason the host sent',
    toolHtml.includes('escalate sandbox to danger-full-access'), toolHtml)

  const policyAsk = { ...pending, reason: 'dsh-allow: delete is not granted in the workspace' }
  const policyHtml = found.server.renderToStaticMarkup(react.createElement(card.component, { matched: policyAsk, t }))
  check('a policy ask offers exactly one always-allow button',
    policyHtml.split('alwaysAllow').length - 1 === 1, policyHtml)
  check('beside 拒绝 and 允许一次', policyHtml.includes('reject') && policyHtml.includes('allowOnce'), policyHtml)
  check('and carries the host reason verbatim',
    policyHtml.includes('delete is not granted in the workspace'), policyHtml)
  check('the card reads nothing from a host route any more: no detail rows',
    !policyHtml.includes('dsha_row') && !policyHtml.includes('dsha_meta'), policyHtml)

  const row = registrations.find(entry => entry.options.name === 'conversation.chat.node')
  const rowHtml = found.server.renderToStaticMarkup(react.createElement(row.component, { node: builtNode, t }))
  check('the decision row shows its origin and the command',
    rowHtml.includes('logOriginRule') && rowHtml.includes('rm -rf build'), rowHtml)
  const refusalHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'policy',
        action: 'deny',
        command: null,
        reason: 'delete is not granted in the workspace',
        missing: [{ operation: 'delete', path: '/w/build' }],
      },
    },
    t,
  }))
  check('a refusal row names the action and the missing capability',
    refusalHtml.includes('logDeny') && refusalHtml.includes('delete /w/build'), refusalHtml)
  const humanHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: { kind: 'allow-decision', data: { origin: 'human', action: 'always-allow', command: 'rm -rf build', missing: [] } },
    t,
  }))
  check('a human decision names the action the user chose',
    humanHtml.includes('logAlwaysAllow'), humanHtml)
  const ruleHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'rule', action: null, command: 'ls', matchedRules: [{ path: '/w', operation: null }],
        rules: [], missing: [],
      },
    },
    t,
  }))
  check('a rule allow names the rule path that answered',
    ruleHtml.includes('logPaths') && ruleHtml.includes('/w'), ruleHtml)
  const toolRuleHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'rule', action: 'allow-once', command: null,
        subject: 'plugin_manager list_plugins',
        reason: 'the stored tool rule answers this operation, so this call does not need the user',
        matchedRules: [{ id: 't1', tool: 'plugin_manager', action: 'list_plugins', source: 'user', label: 'plugin_manager list_plugins' }],
        missing: [],
      },
    },
    t,
  }))
  check('a tool-rule allow names the tool rule that answered',
    toolRuleHtml.includes('logToolRules') && toolRuleHtml.includes('plugin_manager list_plugins'), toolRuleHtml)
  const storedHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'human', action: 'always-allow', command: 'ls',
        rules: [{ path: '/w/build', operation: null }], missing: [],
      },
    },
    t,
  }))
  check('an always-allow names the rules the button stored',
    storedHtml.includes('logStoredRules') && storedHtml.includes('/w/build'), storedHtml)
  const storedToolHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'human', action: 'always-allow', command: null,
        rules: [{ id: 't1', tool: 'plugin_manager', action: 'set_plugin', target: 'dsh-balance', label: 'plugin_manager set_plugin dsh-balance' }],
        missing: [],
      },
    },
    t,
  }))
  check('and an always-allow for a tool operation names the tool rule instead of a path',
    storedToolHtml.includes('logToolRules') && storedToolHtml.includes('plugin_manager set_plugin dsh-balance')
    && !storedToolHtml.includes('logStoredRules'), storedToolHtml)
  const fallbackHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'rule', action: null, command: 'ls',
        matchedRules: [{ tool: 'plugin_manager', action: 'list_bundles' }], missing: [],
      },
    },
    t,
  }))
  check('a tool rule without a label still renders as tool + action',
    fallbackHtml.includes('logToolRules') && fallbackHtml.includes('plugin_manager list_bundles'), fallbackHtml)
  const reviewHtml = found.server.renderToStaticMarkup(react.createElement(row.component, {
    node: {
      kind: 'allow-decision',
      data: {
        origin: 'auto-review', action: null, command: 'ls', missing: [],
        review: { verdict: 'ALLOW', latencyMs: 412, route: 'deepseek-chat' },
      },
    },
    t,
  }))
  check('an auto-reviewed allow carries its verdict and latency',
    reviewHtml.includes('logReviewer') && reviewHtml.includes('ALLOW') && reviewHtml.includes('412'), reviewHtml)
  check('and every row keeps its origin visible for the ledger',
    rowHtml.includes('data-origin="rule"') && refusalHtml.includes('data-origin="policy"')
    && humanHtml.includes('data-origin="human"'), rowHtml + refusalHtml + humanHtml)
}

console.log(failures === 0 ? '\nPASS' : `\n${String(failures)} FAILURE(S)`)
process.exit(failures === 0 ? 0 : 1)

/** Locate React and its server renderer inside a DSH checkout's pnpm store. */
function findReact() {
  const checkouts = [process.env.DSH_CHECKOUT].filter((value) => typeof value === 'string' && value !== '')
  for (const checkout of checkouts) {
    try {
      const store = join(checkout, 'node_modules/.pnpm')
      const react = readdirSync(store).find((name) => /^react@\d/u.test(name))
      const dom = readdirSync(store).find((name) => /^react-dom@\d/u.test(name))
      if (react === undefined || dom === undefined) continue
      return {
        react: require(join(store, react, 'node_modules/react')),
        server: require(join(store, dom, 'node_modules/react-dom/server')),
      }
    }
    catch {
      // No store at this checkout: try the next candidate.
    }
  }
  return null
}
