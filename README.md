---
description: "dsh-allow: remembers sandbox-escalation approvals so the same command prefix stops asking."
---

# dsh-allow

English | [中文](README.zh.md)

Ask once, allow from then on. The permission dialog gains a third answer — **总是允许「…」开头的命令** — and the rules it writes live in your harness home, managed with `/allow`.

## What it does

DSH keeps a file sandbox: a command that writes outside the session workspace is denied, and the model may retry it with `sandbox_permissions`, which raises an approval prompt. That prompt is fine the first time and tedious the tenth, because the same handful of operations keep coming back (`pnpm dsh plugin …`, `brew install …`, `git push …`).

This plugin listens on the `approval/request` waterfall *ahead of* the built-in answerer:

- **A remembered rule** allows the call silently — no dialog at all.
- **No rule** asks with three answers:
  - `允许一次` — allow this call only.
  - `总是允许「pnpm dsh plugin」开头的命令` — store a rule, then allow.
  - `拒绝` — deny the call.
- **Every other approval request** (hooks, file edits, anything that is not a sandbox escalation) is delegated to the built-in answerer unchanged.

A rule is scoped by **tool + requested sandbox mode + the command's leading words**, so allowing `pnpm dsh plugin` never allows `rm`, and a rule recorded for `danger-full-access` does not silently cover a wider request. The prefix is derived by dropping a leading `cd … &&`, dropping `VAR=value` assignments, and keeping words until the first flag, path, or shell operator — and the dialog shows the exact prefix before you agree to it.

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

Unreadable or hand-edited files degrade to "no rules" rather than blocking approvals; a rule that no longer exists simply means the dialog asks again.

## Test

```sh
node test/smoke.mjs
```

Covers prefix derivation, the escalation shape, rule storage and matching, all three dialog answers, silent allowance on a stored rule, hit counting, delegation for non-escalation and unanswerable requests, and the `/allow` grammar.

## Limits

- Only **bash/pwsh command** escalations are remembered; the `write`/`edit` tools' path escalations still use the built-in prompt.
- The plugin reads the escalation out of the logged tool call (its `sandbox_permissions` and `command` arguments), so it needs the call id the approval request carries — a request without one is delegated.

## License

[MIT](LICENSE)
