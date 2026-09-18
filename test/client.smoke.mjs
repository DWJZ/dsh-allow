/**
 * dsh-allow browser smoke test — loads the client bundle outside a browser and
 * checks the chain registration it installs, plus a server-side render of the
 * card.
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

const stubRequire = (specifier) => {
  if (specifier === 'react') return found === null ? { createElement: () => null, useState: () => [], useEffect: () => {} } : found.react
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

console.log('escalation predicate')
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
const policyPrompt = { ...pending, reason: 'dsh-allow: rm deletes files (rm -rf build)' }
check('a policy prompt is claimed by this card', client.escalationOf(policyPrompt) === policyPrompt)
check('a non-approval interaction is ignored', client.escalationOf({ kind: 'question' }) === null)
check('an absent interaction is ignored', client.escalationOf(undefined) === null)

console.log('always label')
check('one rule names itself', client.alwaysLabel((key, params) => `${key}:${JSON.stringify(params)}`, ['gh repo view']) === 'alwaysOne:{"rule":"gh repo view"}')
check('several rules are listed', client.alwaysLabel((key, params) => `${key}:${JSON.stringify(params)}`, ['cp', 'echo']) === 'alwaysMany:{"rules":"cp + echo"}')

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
  check('without the pending lookup the third button is absent', !html.includes('alwaysOne') && !html.includes('alwaysMany'), html)
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
