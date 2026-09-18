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
const stubRequire = (specifier) => {
  if (specifier === 'react') {
    if (found === null) return { createElement: () => null, useState: () => [null, () => {}], useEffect: () => {} }
    return {
      ...found.react,
      // The first hook of the panel is the fetched record; rendering it
      // directly is what a browser shows once `/dsh-allow/pending` answered.
      useState: (initial) => { hooks += 1; return [hooks === 1 ? pendingInfo : initial, () => {}] },
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
const labels = (list) => client.alwaysText((key, params) => `${key}(${JSON.stringify(params)})`, list)
check('one rule names itself', labels([{ label: 'delete · /w/build' }]) === 'alwaysOne({"rule":"delete · /w/build"})', labels([{ label: 'delete · /w/build' }]))
check('two rules are listed', labels([{ label: 'a' }, { label: 'b' }]) === 'alwaysMany({"rules":"a + b"})', labels([{ label: 'a' }, { label: 'b' }]))
const many = labels(Array.from({ length: 5 }, (_value, index) => ({ label: `r${String(index)}` })))
check('a long list is capped with a count', many.includes('+2'), many)

console.log('apply')
let registration = null
const ctx = {
  effect: (factory) => factory(),
  locale: { register: () => () => {} },
  slots: { inject: (_name, factory) => factory(), register: (options, component) => { registration = { options, component }; return () => {} } },
}
client.apply(ctx)
check('a composer chain entry is registered', registration?.options?.name === 'conversation.composer', JSON.stringify(registration?.options?.name))
check('it runs before the built-in approval card (priority 1)', (registration?.options?.priority ?? 99) < 1, String(registration?.options?.priority))
check('it declares its dictionary namespace', registration?.options?.locale === 'dshAllow', String(registration?.options?.locale))
check('select matches an escalation', registration?.options?.select({ pendingInteraction: pending }) === pending)
check('select passes other interactions through', registration?.options?.select({ pendingInteraction: { kind: 'question' } }) === null)

if (found === null) {
  console.log('  skip render assertion (set DSH_CHECKOUT to a checkout with React installed)')
} else {
  const react = found.react
  const t = (key, params) => (params === undefined ? key : `${key}(${JSON.stringify(params)})`)
  const html = found.server.renderToStaticMarkup(react.createElement(registration.component, { matched: pending, t }))
  check('the card renders the approval chrome', html.includes('dsha_card') && html.includes('dsha_strip'), html.slice(0, 200))
  check('the card renders 拒绝 and 允许一次', html.includes('reject') && html.includes('allowOnce'), html)
  check('the card shows the reason', html.includes('escalate sandbox to danger-full-access'), html)
  check('the card names the missing operation', html.includes('>delete<'), html)
  check('the card names the missing path', html.includes('/Users/tester/project/build'), html)
  check('the card names the command', html.includes('rm -rf build'), html)
  check('the card shows the sandbox mode', html.includes('workspace-write'), html)
  check('exactly one always-allow button is offered', html.split('alwaysOne').length - 1 === 1, html)
  check('and no folder button exists', !html.includes('alwaysFolder') && !html.includes('alwaysFile'), html)
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
