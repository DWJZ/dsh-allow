---
description: "dsh-allow: a deterministic approval layer over shell commands — parse, classify, allow / prompt / forbid, remember narrow rules."
---

# dsh-allow

English | [中文](README.zh.md)

A deterministic approval layer over every shell command the agent runs: the line is parsed, each simple command is classified, and the whole request gets the strictest verdict — `allow`, `prompt`, or `forbidden`. An approval card can remember a narrow structured rule; a remembered command never lets a different command ride along.

```
touch x && rm -rf /        →  forbidden   (even with "always allow touch")
git status && touch foo    →  allow
git status && rm file      →  prompt
echo "rm -rf /"            →  allow       (quoted text is not a command)
bash -c 'rm -rf /'         →  forbidden   (wrapper parsed recursively)
bash -c "$UNKNOWN"         →  prompt      (cannot be proven)
python -c '…'              →  prompt      (arbitrary code)
echo k > ~/.ssh/authorized_keys → prompt  (credential path)
```

## Where it hooks in

```
model writes a command
      ↓
bash / pwsh tool call
      ↓
tools/pre-execute  ← this plugin: parse → policy → decide
      ↓ allow                 ↓ prompt                    ↓ forbidden
   sandbox (unchanged)   approval card: allow once /   deny, no escalation
                         always allow / deny
      ↓
process execution
```

`tools/pre-execute` is the documented policy seam (see the TODO in `tool-bash`), and it is the only path a shell command takes, so no execution path bypasses the gate. The pre-execute listener is registered with `prepend: true`, so a `forbidden` verdict cannot be overridden by another listener.

## Decisions

- **allow** — no policy rule objects; execution continues to the sandbox, which stays the fence for filesystem writes. A stored `allow` rule also lands here.
- **prompt** — the approval card asks. `Allow once` answers only the current call and writes nothing; `Always allow` stores the suggested rules — one per parsable command (`cp` + `echo`), or the exact command text when part of the line cannot be pinned. `Deny` refuses the call.
- **remembered** — a command line whose every member matches an allow rule also answers the sandbox's escalation question silently, so a command you allowed once stops asking for good. Set `autoApproveEscalations: false` to keep every widening manual.
- **forbidden** — denied outright with a reason. No approval is requested and no escalation is possible, because the denied operation is destructive regardless of who approves it.

## How a command is analysed

1. `src/parse.js` splits the line on unquoted `&&`, `||`, `;`, `|`, `&`, and newlines, then tokenizes each segment with quoting and escapes intact. `echo "a && b"` is one command; `$(…)`, backticks, globs, subshells, groups, control keywords, here-documents, and dynamic executables all make the line **unanalysable**.
2. `sh -c '…'`, `bash -lc '…'`, and `eval '…'` are parsed **recursively** (depth 4). A wrapper whose program is dynamic is unanalysable.
3. Here-document bodies (`<<EOF … EOF`) are **stdin data, not shell source**, so they are removed before parsing — a Python line inside one is no longer read as a command. The reader is still judged: `python3 -` or a shell without `-c` takes its program from stdin, which is code execution — pinned only as the exact command text.
4. `$(…)` and backticks are parsed recursively too: the substituted commands join the same line and are aggregated with it (`echo "$(rm -rf /)"` is forbidden). A substitution the parser cannot reduce makes the whole line a prompt, and a substituted **program name** is always unanalysable, so `$(printf rm) -rf /` is never allowed.
5. Every simple command's argv is classified by the built-in table and matched against stored rules, then the request takes the strictest member: `forbidden > prompt > allow`.
6. Unanalysable lines are `prompt` and match no per-command rule — the fail-closed rule for shell syntax this parser does not model. They can still be pinned as one exact command, which is the only rule that reaches them.

## Inline execution: shell wrappers and interpreters

A capable interpreter may run, but its capability is never remembered broadly. One function, `validatePersistentRule()`, decides what may be stored; `RuleStore` re-checks on write and again on read, so a UI bug, a future caller, or a hand-edited file cannot persist `bash -c` or `python -c` as an always-allow rule.

| Command | Handling |
|---|---|
| `bash -lc 'cargo test'` | the inner shell source is parsed recursively and judged as `cargo test`; Always allow stores `["cargo","test"]`, never `bash -lc` |
| `bash -lc 'touch x && rm -rf /'` | the inner commands are judged and aggregated → `forbidden`; the outer shell cannot hide them |
| `bash -lc 'X=$Y; $X foo'` | the inner source cannot be parsed → the invocation is **opaque** → `prompt` |
| `python -c 'print(123)'` | inline code is **opaque arbitrary execution** → `prompt`; the only rule offered pins the exact text: `["python","-c","print(123)"]` |
| `python tools/check.py` | a script file, pinned as `["python","tools/check.py"]`, which also covers `… --verbose` |
| `python -` / `bash` without `-c`, here-documents | the program comes from stdin, so argv cannot pin it → `prompt`, but the whole line can be pinned to its own text (an exact-source rule) |
| Anything the parser cannot reduce (`for …; do …; done`) | `prompt`, likewise pinnable to its own text |

**Exact-source rules**: when nothing per-command can be pinned (stdin programs, here-documents, syntax the parser does not model), the card adds *Always allow this exact command*. The rule stores the whole command text and matches only byte-identical text (surrounding whitespace ignored) — the same text runs the same program.

- **A mixed line gets both**: the parsable members keep their minimal capability rules and the whole line is added as an exact pin, so no command is left unsilenceable.
- **Hard denials are the one exception**: the built-in catastrophic verdicts (`rm -rf /`, `mkfs`, `dd of=/dev/…`) are not rememberable by default. A deployment that wants to pin those exact lines sets `allowForbiddenSource: true` (default `false`); only then does the card offer the pin and honour it.

**Broad rules that are refused** (the store throws on write; the reader ignores them):

```
bash · sh · zsh · dash · ksh · fish · pwsh        (alone)
bash -c · bash -lc · sh -c · zsh -c …             (a flag with no program text)
python · python3 · node · perl · ruby · lua · deno eval · php -r · osascript -e
python - · node -                                 (program from stdin)
eval · source · exec                              (alone)
```

Programs that run code *selected by their arguments* follow the same standard (a rule must name the operation, not just the program): `git` (`-c alias.x='!cmd'`, `--exec-path`), `npm`/`pnpm`/`yarn`/`bun`, `make`, `docker`/`podman`/`kubectl`, `ssh`, `sudo`/`su`/`doas`, `env`/`xargs`/`nohup`/`timeout`/`nice`. So a bare `git` rule is refused while `git status` is fine, and a bare `sudo` rule is refused while `sudo apt update` is fine.

The test is whether the rule pins the program that will run — the code string after an inline flag, or a script path. `python -c 'print(123)'` and `python -c 'print(456)'` are different capabilities. `forbidden` always wins: an exact allow rule never covers `rm -rf /`, not even inside `bash -lc 'rm -rf /'`.

The card says which one it is: inline code gets **Always allow this exact command**, while a parsed wrapper names the inner command (`Always allow "cargo test"`).

## Built-in policy

Argument-aware, not a name blacklist. Destructive shapes are recognised from the flags and targets:

| Area | Example | Verdict |
|---|---|---|
| catastrophic | `rm -rf /`, `rm -rf ~`, `rm -rf /*`, `rm -rf .` at `/`, `mkfs*`, `dd of=/dev/sda`, `> /dev/sda` | forbidden |
| destructive | `rm`, `rmdir`, `mv`, `truncate`, `dd`, `shred`, `git reset --hard`, `git clean -fdx`, `git push --force` | prompt |
| privilege | `sudo`, `su`, `doas` | prompt |
| permissions | `chmod`, `chown` (recursive or world-writable noted) | prompt |
| process / service | `kill`, `pkill`, `killall`, `systemctl`, `service`, `launchctl`, `mount`, `umount` | prompt |
| code execution | `sh` without `-c`, `python -c`, `node -e`, `eval`, `exec`, `source` | prompt |
| environment | `PATH=`, `LD_PRELOAD=`, `DYLD_*`, `PYTHONPATH=`, `NODE_OPTIONS=`, `BASH_ENV=`, `export PATH=…` | prompt |
| redirection | `> /etc/*`, `> ~/.ssh/*`, `> ~/.bashrc`, any dynamic target | prompt |
| background | `cmd &` | prompt |
| network | `curl -o`, `wget -O`, `ssh`, `scp`, `rsync`, `nc` | prompt |
| containers | `docker`, `podman` | prompt |
| paths | `rm -rf .` at `/` or `$HOME`; `~`, `..`, and `/x/..` are normalized before comparison | forbidden / prompt by cwd |

When one member of a line can never be remembered (inline code, a substituted program name), the other members still get their suggestions and the card says that part of the line keeps asking; a line containing a forbidden command suggests nothing at all.

A command nothing matches defers to the sandbox (`defaultDecision: allow`); set `defaultDecision: prompt` to gate everything.

## Persistent rules are structured

`$DSH_HOME/dsh-allow.json`:

```json
{
  "version": 2,
  "rules": [
    { "id": "r1", "decision": "allow", "executable": "git", "argvPrefix": ["status"], "hits": 4 },
    { "id": "r2", "decision": "forbidden", "executable": "dd", "argvPrefix": [] }
  ]
}
```

Matching is structural: executable (basename, so `/usr/bin/git` and `git` are one program) plus a literal argv prefix. `git reset --hard` does not match `['git','status']`. A command carrying an expanded argument (`git status "$X"`) is **not** covered by an `allow` rule. Suggestions are the narrowest useful form: the executable, plus the leading subcommand for programs that have one (`git status`, `pnpm install`); flags and paths are never included.

## `/allow`

```
/allow                                        # list rules with hit counts
/allow add allow git status                   # add a rule by hand
/allow add forbidden dd
/allow remove 2
/allow clear
```

## Audit log

Every decision appends one NDJSON line to `$DSH_HOME/dsh-allow-audit.ndjson`: timestamp, tool, cwd, raw command, parsed commands, decision, reason, risk, whether the line was analysable, and the matched rules. Credential-shaped text (`api_key=…`, `Authorization: Bearer …`, private keys) is redacted before writing; environment values are never recorded.

## Configuration

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json
    auditFile: /path/to/audit.ndjson
    audit: true
    defaultDecision: allow      # or prompt: gate every command
    autoApproveEscalations: true # false: a remembered command still asks before widening the sandbox
    allowForbiddenSource: false   # true: also offer/honour an exact pin for hard-denied lines
```

## Test

```sh
npm test        # policy suite, host suite, browser suite
```

`test/policy.spec.mjs` runs the required cases and bypass attempts (`touch x; rm -rf /`, `||`, `|`, `(rm -rf /)`, `bash -c`, `eval`, `$COMMAND -rf /`, `$(printf rm)`, `rm -rf "$TARGET"`, `for … do rm …`, `if … then rm …`) and asserts that none of them is `allow`. `test/smoke.mjs` covers the gate, routes, rule store, audit redaction, the broad-rule refusals, and `/allow`. `test/client.smoke.mjs` renders the card (set `DSH_CHECKOUT` for that assertion).

## Limits

- The parser models a restricted shell, not bash. Anything outside it is `prompt`; only an exact command pin can reach it, never a per-command rule.
- A rule is scoped to one tool family (`bash`/`pwsh` commands); `write`/`edit` tools keep their own sandbox escalation.
- The card is this plugin's own render of the approval UI (the built-in card's action row is not extensible). It claims sandbox-escalation asks and policy prompts (a policy reason is marked with a `dsh-allow: ` prefix); other approvals keep the built-in card.
- Network egress is not sandboxed by DSH, so `curl`/`wget`/`ssh` are policy prompts rather than enforced restrictions.

## License

[MIT](LICENSE)
