---
description: "dsh-allow: filesystem permissions (read / write / create / delete / execute) per path for DSH shell calls, plus tool-operation rules for management calls that ask for a wider process fence, enforced in the process sandbox, with deny / allow once / always allow, and one row per decision in the conversation naming the rule, the baseline, the auto reviewer, the user, or the plugin itself as the layer that answered."
---

# dsh-allow

English | [中文](README.zh.md)

A filesystem permission layer for DSH. A command is judged by the filesystem capabilities it needs, never by how dangerous its name sounds, and the same policy is compiled into the profile the process actually runs under — so the children it starts and the code its command line never showed are held to it too.

```
cat README.md                  →  allow    (read inside the workspace)
cat ~/.ssh/id_ed25519          →  refused  (user data is fenced, whoever reads it)
python3 -c 'open("~/.ssh/id_ed25519").read()'
                               →  refused by the kernel, not found by the parser
echo x > out.md                →  allow    (create inside the workspace)
rm -rf build                   →  prompt   (delete is not granted in the workspace)
python3 -c 'os.remove(…)'      →  refused by the kernel while delete is ungranted
gh pr list                     →  prompt   (execute is not granted for that binary)
echo x > /Users/me/other/o     →  prompt   (create outside the workspace)
echo x > ~/.dsh/dsh-allow.json →  refused  (the permission store is never writable)
```

## Where it hooks in

```
model writes a command
      ↓
bash / pwsh tool call
      ↓
tools/pre-execute  ← this plugin: parse → derive effects → resolve (path, capability)
      ↓ allow                    ↓ prompt                     ↓ refuse
  ctx.sandbox.confine        approval card: deny / always    no escalation
      ↓                      allow / allow once
  Seatbelt profile compiled from the SAME rules
      ↓
the process tree (children, grandchildren, inline code)
```

`tools/pre-execute` is the documented policy seam and the only path a shell command takes. The sandbox provider is not replaced: the plugin wraps the registered provider's `confine` and hands it the profile compiled from the effective policy, delegating to the provider's own implementation on every platform it does not handle. `tools/post-execute` spends the one-shot grants, and a small guard on the file-changing tools refuses the permission store.

A management tool never reaches that gate: its call grants no filesystem capability and asks the approval waterfall for a wider process fence instead, so it is judged there, by a tool-operation rule of its own kind.

## Capabilities and rules

Five capabilities are modelled, and a rule grants some of them for one path:

| capability | means |
| --- | --- |
| `read` | read a file, list a directory |
| `write` | change an existing file (content, mode, owner, times) |
| `create` | create a new file or directory |
| `delete` | unlink, remove, rmdir, rename away |
| `execute` | start a file as a program |

`execute` does not mean "no script may run": `python3 foo.py` needs `execute` for the interpreter and `read` for `foo.py`, because `foo.py` is never `execve`'d.

A stored rule is a path plus an access map, never a command line:

```json
{
  "version": 3,
  "rules": [
    { "id": "f1", "path": "/Users/me/project/build", "recursive": true,
      "access": { "write": true, "create": true, "delete": true },
      "hits": 2, "createdAt": "2026-01-01T00:00:00.000Z" }
  ]
}
```

`recursive: true` covers the whole subtree; `recursive: false` covers exactly that path, which is what the card's "always allow" writes for a single file or binary.

## Tool-operation rules

A second kind of rule answers the calls that ask for a wider process fence instead of a path. `plugin_manager` is the tool built that way: every action escalates to `danger-full-access`, because a profile change installs and runs Host code outside the workspace fence, so the filesystem policy has nothing to say about it — and with no rule to consult, reading the plugin list asks again on every single call.

A tool rule names an operation of one tool, never a command line:

```json
{
  "version": 3,
  "rules": [
    { "id": "f1", "path": "/Users/me/project/build", "recursive": true,
      "access": { "delete": true }, "hits": 2, "createdAt": "2026-01-01T00:00:00.000Z" }
  ],
  "tools": [
    { "id": "t1", "tool": "plugin_manager", "action": "list_plugins",
      "hits": 4, "createdAt": "2026-01-01T00:00:00.000Z" },
    { "id": "t2", "tool": "plugin_manager", "action": "set_plugin", "target": "dsh-balance",
      "hits": 1, "createdAt": "2026-01-01T00:00:00.000Z" }
  ]
}
```

`tools` is a section of the same file the path rules live in, so it inherits the same protection — no shell command, no file tool and no rule can write it — and a build that only reads `rules` ignores it rather than refusing the file.

| action | what a rule may name |
| --- | --- |
| `list_plugins`, `list_bundles`, `list_version_exemptions` | the action alone, because it reads and changes nothing |
| `set_plugin`, `set_bundle`, `install_bundle`, `remove_bundle` | the action plus its exact target, so allowing one plugin never allows the next |
| `set_version_exemption` | nothing: the tool's own contract requires the user to answer that exact plugin/runtime pair every time |

Two calls are never answered by a rule, however the store reads: one carrying `acceptRisk: true`, which is a risk the user has to accept, and one carrying `approvedBuilds`, which grants install scripts. Both decide a question the user is asked directly.

An action this vocabulary does not name is a call no rule may answer, so a tool this plugin does not judge — and a call whose arguments cannot be read — takes the ordinary path to the card.

Tool rules answer under every `escalation` policy, because a rule for one tool operation IS the user's own authorization for that operation. A `sandbox_permissions` escalation on a shell command is the other case and still needs `escalation: rule`.

## The permission store is not the agent's to change

The rules file and the audit log are **hard-protected**: `write`, `create` and `delete` are refused for every writer, user rules included, and the compiled profile refuses them again after every grant. That covers `$DSH_HOME/dsh-allow.json` and `$DSH_HOME/dsh-allow-audit.ndjson`, wherever the configuration points them.

The same protection is applied to the file-changing tools (`write`, `edit`, `str_replace_editor`), so an agent cannot rewrite its own rules with a file tool either; the harness's own fence stays in charge of every other file tool call.

The harness home (`~/.dsh`) is readable and nothing more, so a shell command cannot rewrite the state that judges it.

A repository checked out into the workspace cannot widen anything: dsh-allow does **not** read a `.dsh-allow.json` from the workspace. Repository-controlled content must never grant host access.

## Precedence

Highest first; the lowest level that states the capability answers, and inside one level the more specific path wins:

1. **Platform-protected paths** — `/System`, `/bin`, `/sbin`, `/usr` (except `/usr/local`), `/AppleInternal`, `/private/var/db`, `/dev` and the permission store refuse `write`/`create`/`delete` for every writer, user rules included.
2. **Explicit rules** — the rules file (`source: user`) and the approved call's one-shot grant (`source: session`).
3. **Platform baseline** — the workspace, the temp areas, the harness home, and the system paths macOS needs.
4. **Global default** — not granted.

Paths are compared as canonical absolute paths, component by component: `~`, relative spellings, `.`, `..` and symlinked ancestors are resolved before matching, so `/tmp/x` and `/private/tmp/x` are one path and no rule can be escaped with `../`. Every operation is resolved against both the spelling used and the path behind its symlinks, which is how a grant for `/opt/homebrew/bin/gh` and a grant for the Cellar binary it points at each work without opening the rest of the prefix. The workspace root itself is matched as a path like any other, and a rule for a path never covers a sibling that merely shares a prefix (`/w/build` does not cover `/w/build-2`).

A tool-operation rule sits outside this ladder: it answers a call that grants no filesystem capability at all, so no path rule can answer one of those calls and no tool rule can answer a shell command.

## Defaults and the platform baseline

Inside the workspace: `read`, `write`, `create` and `execute` are allowed, `delete` is not.

The temp areas grant all five. System paths grant what macOS itself needs: `read` + `execute` for `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, `/System`, `/Library/Apple` and `/Library/Developer`; `read` for `/etc`, `/var`, `/usr`, `/usr/share`, `/Library`, `/Applications`, `/dev` and `/opt/homebrew`.

Below the home directory, `read` + `execute` are also granted for the toolchains a user installs (`~/.nvm`, `~/.local`, `~/.cargo`, `~/.rustup`, `~/.bun`, `~/.deno`, `~/.volta`, `~/.pyenv`, `~/.rbenv`, `~/.sdkman`, `~/.go`, `~/.asdf`, `~/.gem`, `~/Library/pnpm`) and `read` alone for the configuration a tool needs to start (`~/.gitconfig`, `~/.config/git`, `~/.gitignore`). These are paths a program must read to run at all; they hold programs and settings, not secrets.

Everything else — `$HOME` outside the workspace, `~/Documents`, `~/Library`, and every credential store in it — is closed until the user opens it, and the read fence withholds its contents meanwhile. A `read-only` session narrows the baseline the same way the sandbox mode does: the workspace keeps `read` + `execute` and loses the rest, and no rule may hand a write back inside a read-only session.

## Homebrew and symlinked executables

Homebrew is deliberately not a granted prefix: `/opt/homebrew` is readable, but `/opt/homebrew/**` is not executable, so every Homebrew binary is authorized one file at a time. `always allow` on `execute /opt/homebrew/bin/gh` stores that one path, and the stored rule does not cover a second tool.

## How effects are read from a command

The line is parsed with `tree-sitter` + `tree-sitter-bash` (structure — pipelines, lists, control flow, substitutions, redirections, here-documents, function bodies), and each simple command is turned into `(path, capability)` pairs from what the program does with its arguments: `rm` deletes its operands, `mkdir` creates them, `mv` deletes the sources and creates the target, `cp` reads the sources and creates the target, `grep` reads its path argument but never its pattern, `sed -i` reads and writes its file, `dd if=` reads and `of=` creates, `curl -o` creates. Redirections are effects too: `>` writes or creates its target, `<` reads it, and the null device and the standard streams are ignored. `sudo`, `doas`, `env`, `nice`, `nohup`, `timeout`, `command` and `exec` are followed to the program they start, so `sudo rm -rf build` is still a delete of `build`.

Nothing is inferred from a program's name beyond that reading, and only the execute effect is derived for programs outside the table — a program whose file effects are invisible from the command line (`git status`) needs no path grant at all.

## Inline programs run only behind a fence that can back them

`python3 -c '…'`, `node -e '…'`, `eval` and a shell program the parser cannot reduce are not judged by their text and are not pinned to it. They are allowed only when the process sandbox can actually hold them to the policy: either the kernel fences all five capabilities — the `guarded` level does, because it withholds user-data reads, writes and executions — or the working directory already grants all five, so there is nothing left to withhold. Anything else — no `sandbox-exec`, a profile that would not apply, a mode that does not confine — makes them ask, with one button that grants the five capabilities for that directory.

A computed path for a visible operation is different: `rm -rf "$DIR"` states a delete whose target cannot be checked, so it asks rather than riding on a grant. Once the operation is granted for the working directory the line stops asking, and the sandbox bounds the run-time path to what was opened.

## The card

`deny`, one `always allow` button, and `allow once`, plus the real missing capability:

```
Filesystem permission required
Operation: delete
Path:      /Users/me/project/build
Command:   rm -rf build
Sandbox:   workspace-write
```

`always allow` writes the narrowest rules for exactly what the card names — one per path in the line, recursive only when that path is a directory that already exists — and never widens a grant to the folder around it. Opening a folder on purpose is a deliberate act: `/allow add delete . folder`. A management tool's ask carries no path, so the same button writes the one tool rule that call names: the action alone for a read-only action, the action plus its exact target otherwise.

`allow once` is genuinely once, and it is kept from leaking sideways by two mechanisms. The grant is bound to the call the user approved, so the decision layer only ever sees it for that call; the profile builder recognises it again by the command line that call is running, because a confinement is told its session but not its call. And while a grant is live, every other call in the same session waits for the holder to settle before it is judged — so two overlapping calls can never share one grant. `tools/post-execute` drops the grant the moment that call settles, with a ten-minute expiry as a backstop; it is never written to the rules file, and the next call asks again.

A `sandbox_permissions` escalation is a wider process fence, not a filesystem capability, so the default `escalation: ask` keeps it a human decision: one approval lets a command run outside its mode, which the capability rules cannot answer for. With `escalation: rule`, an escalation for a call a rule, a directory baseline, or an auto review already settled follows that same decision instead of asking again: the user has granted every capability the line needs, and re-asking decides nothing new. The ledger keeps that origin, so an escalation answered this way never reads as a human answer.

## Auto review (optional)

A permission request the policy cannot settle normally waits for a click. With `autoReview.enabled` it goes to the session's own model first:

```
missing (path, capability)
        ↓
   auto reviewer  ── ALLOW → the same one-shot grant the card writes → run
        ↓ ASK / timeout / error / anything else
   the card: deny / always allow / allow once
```

The reviewer is not a security boundary and has exactly two answers:

| verdict | what happens |
| --- | --- |
| `ALLOW` | only when the request clearly follows from the user's latest message and is narrowly scoped. It reuses the existing call-scoped one-shot grant — the same path the card's `allow once` takes — so the call is bound, the profile carries it by command, and it is spent when the call settles. |
| `ASK` | everything else: uncertainty, a wider path than the request implies, a sensitive path the user never mentioned, no model route, no LLM service, a timeout, a transport error, a non-JSON answer, or a verdict that is not one of the two. |

A failed review records the terminal finish its call ended on — kind, provider code, and message — so an unreachable reviewer names its cause instead of only reporting that it could not answer. The call is bounded to a small answer budget, and an answer the model did write still reaches the parser when that budget runs out.

It can never deny, never write a rule, never widen the workspace, never touch the permission store or the sandbox profile, and it has no memory of past approvals: persistent rules are still the user's decision alone, and the deterministic policy runs first, so an existing rule never reaches the reviewer.

What it is told is only the analyzed request and the user's own words:

```json
{
  "command": "cp report.pdf ~/Downloads/report.pdf",
  "cwd": "/Users/me/project",
  "workspace": "/Users/me/project",
  "requestedPermissions": [
    { "operation": "create", "path": "/Users/me/Downloads/report.pdf" },
    { "operation": "write", "path": "/Users/me/Downloads/report.pdf" }
  ],
  "userMessages": ["把报告保存到 Downloads"]
}
```

`userMessages` holds at most three messages, and only events whose source is the user: a `user/message` injected by a plugin, a notice, a tool result, the command line, repository text, a web page and the agent's own claims are never treated as authorization, and the system prompt says so explicitly. No conversation history, no tool output, and no approval history is sent.

```yaml
    autoReview:
      enabled: false        # off by default; the card stays in charge
      timeoutMs: 10000      # a timeout is an ASK
      # provider: inherit   # default: the session's latest model/selection route,
      #                     # else the route its latest request used
      # model: inherit
```

Every review is logged and audited with the command, the requested capabilities, the verdict, the reason, the latency and the model route — never with file contents, secrets, or hidden reasoning.

## The approval ledger

Every decision this layer makes is audited twice: the audit log the policy layer owns, and one informational session event (`dsh-allow/decision`) that the interface renders twice from the same log — a row beside the tool call in **Chat**, and a row in the **Trajectory** ledger.

The trajectory row needs no renderer of its own: it is an `extension` record carrying this plugin's localized summary, its tone, and the raw audit record — the summary and tone label the row, and the shared details payload tab shows the record. Each origin has its own colour in both views: `rule` green, `baseline` grey, `auto-review` blue, `human` amber, `policy` red. Every row also leads with a symbol — `✅` allow once, `♾️` always allow, `🚫` denied, `↩️` cancelled, `⌛` no answerer, `📋` rule, `⚪` baseline, `🤖` auto review — because colour separates origins and the two human outcomes share one.

A decision row is one event, so a prompt and the human answer that settled it are two rows and the ledger follows the traffic rather than collapsing it:

| origin | what answered |
| --- | --- |
| `rule` | a stored rule or a deployment grant — the row names the rule's path and the capabilities it granted |
| `baseline` | the platform baseline: the workspace, the temp areas, the harness home, the system paths |
| `auto-review` | the optional reviewer answered `ALLOW`; the row carries its verdict, reason, latency and model route |
| `human` | the user answered: allow once, always allow (with the rules the button wrote), deny, cancelled, or no answerer |
| `policy` | this plugin refused on its own: a platform-protected path, or a line the shell grammar cannot parse |

The event is log-only and carries the envelope's `ignorable` marker, so it never reaches a model request, and a build that does not know the type skips it instead of refusing the session. Nothing here is served over HTTP: the row reads the session's own log, and the audit file stays what the policy layer consults for history and hit counts.

Records written before this version stay in the audit file only, so a session's ledger starts from the first decision made after the upgrade.

## The macOS backend

`src/macos.js` compiles a rule set into a Seatbelt (`sandbox-exec`) profile, and the mapping was measured against the kernel, not assumed:

| capability | SBPL operations |
| --- | --- |
| `read` | `file-read-data` (with `file-read-metadata` left allowed so paths still resolve) |
| `write` | `file-write-data`, `file-write-xattr`, `file-write-mode`, `file-write-flags`, `file-write-owner`, `file-write-times` |
| `create` | `file-write-create` |
| `delete` | `file-write-unlink` |
| `execute` | `process-exec` |

`delete` is genuinely separable from `write`: a profile that allows `file-write-data` and `file-write-create` under a subtree while withholding `file-write-unlink` lets a process rewrite and create files there while `rm`, `rmdir`, `rename`, `python -c 'os.remove(…)'` and `node -e 'fs.rmSync(…)'` all fail with EPERM — in the process, in its children and in its grandchildren. `create` alone is enough to make a new file *and* fill it; it is `write` that governs changing a file that already exists. Seatbelt filters match the path the kernel resolved, so rule paths are canonicalized before they are rendered, and a rule keeps the spelling it was granted under next to the path that spelling resolves to, so a grant for `/opt/homebrew/bin/gh` also covers the Cellar binary it points at — and vice versa.

Two Seatbelt details shape the profile. A wildcard denial loses to a specific allowance (`(deny file-write* …)` does not stop `(allow file-write-data …)`), so the permission store is refused by naming every write operation. And a profile that withholds *every* read makes `/bin/sh` abort before it runs anything.

Reads are therefore fenced the way a macOS runtime survives: `(deny file-read-data (subpath "/Users"))` and the same for `/Volumes`, written before the rules, with the workspace, the temp areas, the harness home, user-installed toolchains, a few home configuration files and every read grant re-opening exactly what they name. A program reads everything the platform needs; a file in the home that no rule names — `~/.ssh/id_ed25519`, `~/.aws/credentials`, `~/.config/gh/hosts.yml` — is refused by the kernel whatever command tries it, `python3 -c`, `node -e` and `bash -c` included.

How much of the policy reaches the kernel is **probed** at the first call for each mode and workspace, with the real profile and real commands; the verdict is cached and reported by `/allow status`:

| level | means |
| --- | --- |
| `full` | every read is withheld and re-allowed rule by rule; macOS aborts under it |
| `guarded` | write, create, delete, execute, and reads under the user-data areas |
| `process` | write, create, delete and execute |
| `writes` | write, create and delete |

`/allow status` reports the level as `full`, `partial` or `off` beside the per-capability flags.

`enforce: 'auto'` walks that list strongest first and keeps the first level the probe accepts — on a normal macOS that is `guarded`. `enforce: full` accepts nothing less than `full` and reports `off` if the kernel refuses it. A compilation failure is reported rather than swallowed, and it does not replace the profile with a wider one.

## `/allow`

```
/allow                           list the stored rules
/allow status                    the defaults, the fence level, and per-capability flags
/allow add delete,write build folder
/allow add execute /opt/homebrew/bin/gh file
/allow remove 2
/allow clear

/allow tool                      list the stored tool-operation rules
/allow tool add plugin_manager list_plugins
/allow tool add plugin_manager set_plugin dsh-balance
/allow tool remove 1
/allow tool clear
```

`add` resolves a relative path against the session workspace; `folder` (the default) covers the subtree and `file` covers exactly that path. Every rule written here is a persistent user rule, the same shape the card's `always allow` stores. `clear` empties the path rules and leaves the tool rules alone; `/allow tool clear` does the reverse. `tool add` refuses a rule the vocabulary does not allow — an unknown tool or action, a mutating action without its exact target, and the one action that owes the user a fresh answer.

## Configuration

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json          # default $DSH_HOME/dsh-allow.json
    auditFile: /path/to/audit.ndjson        # default $DSH_HOME/dsh-allow-audit.ndjson
    audit: true                             # false turns the audit log off
    appendSessionEvents: false              # true also records each decision as a session event
    escalation: ask                         # ask | rule: who answers a sandbox escalation the rule already covers
    sessionGrantTtlMs: 600000               # backstop lifetime of "allow once"
    enforce: auto                           # auto | full | guarded | process | writes | off
    autoReview:                             # optional: let the model answer "allow once"
      enabled: false                        # the card stays in charge when off
      timeoutMs: 10000
    grants:                                 # deployment grants, same shape as a stored rule
      - path: /opt/homebrew
        recursive: true
        access: { read: true, execute: true }
    toolGrants:                             # deployment grants, same shape as a stored tool rule
      - tool: plugin_manager
        action: list_plugins
```

A `rules.json` written by dsh-allow 0.1 (the command-prefix model) reads as empty and is kept as `<rulesFile>.v2.bak` on the first write; those rules said nothing about filesystem capabilities and cannot be translated.

## Test

```sh
npm test              # units, host wiring, card render, the audit ledger, and the real-sandbox suite
npm run test:unit     # policy, effects, enforcement, reviewer, decisions, audit ledger
npm run test:sandbox  # macOS Seatbelt integration (needs a host that can start sandbox-exec)
```

`test/reviewer.spec.mjs` injects the model and covers what the reviewer is told (only real user messages, the analyzed permissions, the fixed prompt), every answer shape (`ALLOW`, `ASK`, fenced JSON, prose, an unknown verdict, an empty answer), and every failure path (no route, no LLM service, a provider throw, a terminal error chunk, a timeout, an invalid answer). `test/smoke.mjs` covers the gate integration: an `ALLOW` runs the call through the existing call-scoped one-shot grant and leaves the rules file untouched, while an `ASK`, a failing reviewer and a disabled reviewer all leave the card in charge.

`test/audit.spec.mjs` covers the ledger end to end without a host: which layer a decision records as its origin and which rules it names, the single record one human decision produces whichever half of the card answered, the records a half-written line, a foreign approval or an unrecognized outcome must not produce, and the `/allow log` rendering. `test/smoke.mjs` asserts every decision also lands in the session log as an ignorable event. `test/client.smoke.mjs` renders the decision row through React and asserts its origin badge, its command and the capability it was missing.

`test/toolrules.spec.mjs` covers the tool-operation vocabulary on its own: which actions a rule may name and what each one needs, what a call reads as, which call is never answered by a rule (`acceptRisk`, `approvedBuilds`, the exemption action, an unreadable action), and that a hand-edited rule never widens itself. `test/smoke.mjs` runs the same questions through the approval waterfall — the card that appears without a rule, the rule that answers the next identical call without one, the target that is not covered, and the human answer the ledger records either way.

`test/sandbox.integration.mjs` runs the real kernel and covers:

- the permission store refusing every writer, and refusing them again while a rule grants the folder around it;
- `rm`, `rmdir`, `rename`, `python -c 'os.remove'` and `node -e 'fs.rmSync'` all denied while writes and creates succeed, and delete granted again;
- write and create withheld on their own, and `create` alone creating and filling a new file;
- reads refused for `cat`, `python`, `node` and `bash`, for `python → sh` and `python → cat` grandchildren, and re-opened by a single read grant;
- `/bin/sh`, `python3`, `node`, `git --version` and `gh --version` all running under the same read fence;
- an execute fence denying ungranted binaries, and a grant for a symlink running the binary it points at;
- a malformed profile running nothing, and writes outside the workspace refused unless granted.

It skips with a notice when `sandbox-exec` cannot apply a profile — including when the test itself runs inside another Seatbelt sandbox — so run it from a plain terminal.
CI sets `DSH_ALLOW_REQUIRE_SEATBELT=1` on its macOS job, which turns that skip into a failure: a green run there means the kernel was exercised, not skipped.

## Limits

- A Mac whose `xcode-select` points into an Xcode bundle keeps `git`, `python3` and `clang` behind shims that exec into `/Applications/Xcode*.app/Contents/Developer`, which the baseline does not reach: it grants the Command Line Tools under `/Library/Developer`, not an Xcode developer directory. Such a host opens it once — `/allow add read,execute /Applications/Xcode.app/Contents/Developer folder` — or the kernel refuses those commands while the policy allows them.
- A decision row is rendered from the session log the browser already holds, so a session longer than that window keeps every row it loaded.
- A chunk boundary that lands inside an audit line drops that line from an answer, rather than reporting a decision the reader could not parse.
- Records written before this version carry no `sessionId`, so they never appear in a session's ledger.
- Path resolution still works inside the fenced areas: `stat` and directory listing leak metadata, only file contents are withheld.
- A tool that keeps its configuration and its token together under the home needs one read grant for that directory: `gh`, `aws`, `docker` and friends report their own error until `~/.config/<tool>` is granted. Denying `hosts.yml`, `credentials` and `id_ed25519` by default is the point; granting them is a deliberate act.
- The strongest read fence (`enforce: full`) is expressible but not survivable on this host: macOS reads more than the policy baseline names, so `/bin/sh` aborts under it. `auto` settles on `guarded`.
- Other Seatbelt findings: a wildcard denial loses to a specific allowance, so refusals name their operations; an unreadable path still resolves, so metadata is not hidden.
- `create` alone creates and fills a new file; changing a file that already exists needs `write`.
- Renaming needs `delete` for the source plus `create` for the target.
- Read effects are derived for a fixed table of programs; the fence, not the table, is the boundary.
- A tool rule is matched against the arguments of the call the session logged, so a tool this plugin does not judge, an action its vocabulary does not name, and a call whose arguments cannot be read all reach the card however the store reads.
- An `install_bundle` rule names the exact specification the call carried: a rule for `pkg@1.0.0` does not cover `pkg@1.1.0`.
- A tool rule answers one operation, not the filesystem effects of running it: the process the plugin manager starts is as confined as any other call the session makes.
- The card offers `always allow` on every management tool's ask, because the browser half cannot read the call's arguments. A call the host refuses to remember — the exemption action, a risk acknowledgement, a build-script approval — answers that click with the reason instead of storing a rule.
- Effects the command line does not show are judged by the sandbox, not by the parser: an effect the program table does not know is left to the fence rather than guessed.
- `allow once` is serialized per session rather than per call: while the grant is live, another call in that session waits for the approved call to settle. A call id carried into the sandbox policy would remove the wait, and the core does not pass one today.
- The macOS profile runner path is `/usr/bin/sandbox-exec`; a host where Seatbelt lives elsewhere falls back to the harness's own profile and reports `off`.
- Auto review is a convenience, not a boundary: a wrong or manipulated model can allow a request the user would have denied. What bounds it is what it can allow — one call, the narrowest rules for that request — and that the kernel still enforces the policy underneath.
- The reviewer adds one model call in front of a prompt, so a card can appear up to `timeoutMs` later than it otherwise would.

## License

MIT
