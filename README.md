---
description: "dsh-allow: the approval card gains an always-allow button, and remembered command prefixes stop asking."
---

# dsh-allow

English | [中文](README.zh.md)

The permission card grows a third button — **总是允许「pnpm dsh plugin」开头的命令** — and the rules it writes live in your harness home, managed with `/allow`. Click it and the command continues; the same command prefix never asks again.

## What it does

DSH keeps a file sandbox: a command that writes outside the session workspace is denied, and the model may retry it with `sandbox_permissions`, which raises an approval card. That card is fine the first time and tedious the tenth, because the same handful of operations keep coming back (`pnpm dsh plugin …`, `brew install …`, `gh repo view …`).

- **A remembered rule** settles the escalation in the host before any UI sees it — no card, no click.
- **No rule** shows the approval card with three buttons:
  - `拒绝` — deny the call.
  - `总是允许「gh repo view」开头的命令` — store that rule, then allow this call.
  - `允许一次` — allow this call only.
- **Every other approval request** (hooks, `write`/`edit` path escalations, anything that is not a sandbox escalation) keeps the built-in card untouched.

A rule is scoped by **tool + requested sandbox mode + the command's leading words**, and it only ever covers a **single command** (see below), so allowing `pnpm dsh plugin` never allows `rm`, and a rule recorded for `danger-full-access` does not cover a different request. The prefix drops a leading `cd … &&`, drops `VAR=value`, reduces the program to its basename (`/opt/homebrew/bin/gh` → `gh`), and then keeps words until the first flag, path, or shell operator. The button names the exact prefix before you agree to it.

## What a rule does not cover

**A compound line never rides a rule.** `brew install gh && rm -rf /` starts with the words a rule for `brew install gh` names, but the rule grants the whole line — so the second half would ride along. Such a line is therefore never matched against rules and never offers the always-allow button: the card says why and asks every time. A leading `cd … &&` chain is the one exception, because the rule names the program after it (`cd /tmp && brew install gh` is rememberable as `brew install gh`). Pipes, semicolons, redirects, `$(…)`, backticks, and multi-line commands all count as compound.

**Paths are not part of a rule.** A rule names a command, not a directory. Path scoping is the sandbox's job: under `workspace-write` the *session workspace* plus the platform temp areas are writable with no prompt at all, and everything outside them is denied — which is where this card appears. So "let me write under `~` but ask for `/`" is expressed by making the session workspace `~` (add it as a workspace and start the session there), not by a rule. Rules then only decide which *programs* may reach outside that boundary.

## Install

```sh
# from GitHub
dsh plugin --profile web add github:DWJZ/dsh-allow

# local development
dsh plugin --profile web add link:/path/to/dsh-allow
```

## `/allow`

```
/allow                                  # same as /allow list
/allow add bash danger-full-access pnpm dsh plugin
/allow remove 2
/allow clear
```

## Rules file

`$DSH_HOME/dsh-allow.json` (override with the `rulesFile` config field):

```json
{
  "version": 1,
  "rules": [
    { "id": "r1758000000000", "hits": 4, "tool": "bash", "mode": "danger-full-access", "prefix": "pnpm dsh plugin" }
  ]
}
```

Unreadable or hand-edited files degrade to "no rules" rather than blocking approvals; deleting a rule just means the card asks again.

## How the card is built

The built-in approval card's action row is fixed (`拒绝` / `允许一次`), and its only slot is the command detail — a plugin cannot add a button to that component. This plugin therefore registers its own `conversation.composer` chain entry at a lower priority than the built-in one, and renders a card with the same markup and the same CSS declarations, plus the extra button. It matches only sandbox escalations, so every other approval still renders through the built-in card.

The two host routes behind it:

- `GET /dsh-allow/pending?sessionId=…&callId=…` — what this approval would remember (prefix + command), so the button can name it. Loopback only.
- `POST /dsh-allow/remember` — store the rule. Same-origin loopback only.

## Test

```sh
npm test        # host suite + browser suite
```

The host suite covers prefix derivation, the escalation shape, rule storage and matching, the pending store's identity and expiry rules, both routes (including their refusals), and the `/allow` grammar. The browser suite loads the client bundle, checks the chain registration and its escalation predicate, and server-renders the card. Set `DSH_CHECKOUT=<dsh checkout>` for the render assertion.

## Limits

- Only **bash/pwsh command** escalations get the third button; `write`/`edit` path escalations keep the built-in card.
- The card is this plugin's own render, not the built-in component, so a future change to the harness's card markup is not inherited automatically.
- It reads the escalation out of the logged tool call, so an approval request without a call id is left to the built-in card.

## License

[MIT](LICENSE)
