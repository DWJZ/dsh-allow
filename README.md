---
description: "dsh-allow: filesystem permissions (read / write / create / delete / execute) per path for DSH shell calls, enforced in the process sandbox, with deny / allow once / always allow."
---

# dsh-allow

English | [中文](README.zh.md)

A filesystem permission layer for DSH. A command is judged by the filesystem capabilities it needs, never by how dangerous its name sounds, and the same policy is compiled into the profile the process actually runs under — so the children it starts and the code its command line never showed are held to it too.

```
cat README.md                  →  allow    (read inside the workspace)
echo x > out.md                →  allow    (create inside the workspace)
rm -rf build                   →  prompt   (delete is not granted in the workspace)
python3 -c 'os.remove(…)'      →  denied by the kernel while delete is ungranted
gh pr list                     →  prompt   (execute is not granted for that binary)
echo x > /Users/me/other/o     →  prompt   (create outside the workspace)
echo x > ~/.dsh/dsh-allow.json →  refuse   (the permission store is never writable)
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

## Defaults and the platform baseline

Inside the workspace: `read`, `write`, `create` and `execute` are allowed, `delete` is not.

The temp areas grant all five. System paths grant what macOS itself needs: `read` + `execute` for `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, `/System`, `/Library/Apple` and `/Library/Developer`; `read` for `/etc`, `/var`, `/usr`, `/usr/share`, `/Library`, `/Applications`, `/dev` and `/opt/homebrew`.

Everything else — including `$HOME` outside the workspace — is closed until the user opens it. A `read-only` session narrows the baseline the same way the sandbox mode does: the workspace keeps `read` + `execute` and loses the rest, and no rule may hand a write back inside a read-only session.

## Homebrew and symlinked executables

Homebrew is deliberately not a granted prefix: `/opt/homebrew` is readable, but `/opt/homebrew/**` is not executable, so every Homebrew binary is authorized one file at a time. `always allow` on `execute /opt/homebrew/bin/gh` stores that one path, and the stored rule does not cover a second tool.

## How effects are read from a command

The line is parsed with `tree-sitter` + `tree-sitter-bash` (structure — pipelines, lists, control flow, substitutions, redirections, here-documents, function bodies), and each simple command is turned into `(path, capability)` pairs from what the program does with its arguments: `rm` deletes its operands, `mkdir` creates them, `mv` deletes the sources and creates the target, `cp` reads the sources and creates the target, `grep` reads its path argument but never its pattern, `sed -i` reads and writes its file, `dd if=` reads and `of=` creates, `curl -o` creates. Redirections are effects too: `>` writes or creates its target, `<` reads it, and the null device and the standard streams are ignored. `sudo`, `doas`, `env`, `nice`, `nohup`, `timeout`, `command` and `exec` are followed to the program they start, so `sudo rm -rf build` is still a delete of `build`.

Nothing is inferred from a program's name beyond that reading, and only the execute effect is derived for programs outside the table — a program whose file effects are invisible from the command line (`git status`) needs no path grant at all.

## Inline programs run only behind a fence that can back them

`python3 -c '…'`, `node -e '…'`, `eval` and a shell program the parser cannot reduce are not judged by their text and are not pinned to it. They are allowed only when the process sandbox can actually hold them to the policy: either the kernel fences all five capabilities, or the working directory already grants all five, so there is nothing left to withhold. Anything else — no `sandbox-exec`, a profile that would not apply, a mode that does not confine — makes them ask, with one button that grants the five capabilities for that directory.

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

`always allow` writes the narrowest rules for exactly what the card names — one per path in the line, recursive only when that path is a directory that already exists — and never widens a grant to the folder around it. Opening a folder on purpose is a deliberate act: `/allow add delete . folder`.

`allow once` is genuinely once, and it is kept from leaking sideways by two mechanisms. The grant is bound to the call the user approved, so the decision layer only ever sees it for that call; the profile builder recognises it again by the command line that call is running, because a confinement is told its session but not its call. And while a grant is live, every other call in the same session waits for the holder to settle before it is judged — so two overlapping calls can never share one grant. `tools/post-execute` drops the grant the moment that call settles, with a ten-minute expiry as a backstop; it is never written to the rules file, and the next call asks again.

A `sandbox_permissions` escalation is a wider process fence, not a filesystem capability, so it is **never** approved automatically — not even for a command whose capabilities are all granted. One approval lets a command run outside its mode; that decision belongs to the user.

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

## Configuration

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json          # default $DSH_HOME/dsh-allow.json
    auditFile: /path/to/audit.ndjson        # default $DSH_HOME/dsh-allow-audit.ndjson
    audit: true                             # false turns the audit log off
    sessionGrantTtlMs: 600000               # backstop lifetime of "allow once"
    enforce: auto                           # auto | full | guarded | process | writes | off
    grants:                                 # deployment grants, same shape as a stored rule
      - path: /opt/homebrew
        recursive: true
        access: { read: true, execute: true }
```

A `rules.json` written by dsh-allow 0.1 (the command-prefix model) reads as empty and is kept as `<rulesFile>.v2.bak` on the first write; those rules said nothing about filesystem capabilities and cannot be translated.

## Test

```sh
npm test              # units, host wiring, card render, and the real-sandbox suite
npm run test:unit     # policy, effects, enforcement, decisions
npm run test:sandbox  # macOS Seatbelt integration (needs a host that can start sandbox-exec)
```

`test/sandbox.integration.mjs` runs the real kernel and covers: the permission store refusing every writer, `rm` / `rmdir` / `rename` / `python -c 'os.remove'` / `node -e 'fs.rmSync'` all denied while writes and creates succeed, delete granted again, write and create withheld on their own, the read fence denying `cat` and `open().read()`, an execute fence denying ungranted binaries, `python → sh` and `node → sh` grandchildren inheriting every restriction, a malformed profile running nothing, and writes outside the workspace refused unless granted. It skips with a notice when `sandbox-exec` cannot apply a profile — including when the test itself runs inside another Seatbelt sandbox — so run it from a plain terminal.

## Limits

- Path resolution still works inside the fenced areas: `stat` and directory listing leak metadata, only file contents are withheld.
- A tool that keeps its configuration and its token together under the home needs one read grant for that directory: `gh`, `aws`, `docker` and friends report their own error until `~/.config/<tool>` is granted. Denying `hosts.yml`, `credentials` and `id_ed25519` by default is the point; granting them is a deliberate act.
- Effects the command line does not show are judged by the sandbox, not by the parser: an effect the program table does not know is left to the fence rather than guessed.
- `create` alone lets a process create and fill a new file; changing a file that already exists needs `write`.
- The strongest read fence (`enforce: full`) is expressible but not survivable on this host: macOS reads more than the policy baseline names, so `/bin/sh` aborts under it. The guarded fence is what `auto` settles on.
- The weaker seatbelt findings: an unreadable path still resolves (metadata stays allowed), and a wildcard denial needs its operations named.
- Renaming needs `delete` for the source plus `create` for the target.
- Read effects are derived for a fixed table of programs; the fence, not the table, is the boundary.
- While a one-shot grant is live, a concurrently running call in the same session could use it: the sandbox is told by session, the decision by call.
- The macOS profile runner path is `/usr/bin/sandbox-exec`; a host where Seatbelt lives elsewhere falls back to the harness's own profile and reports `off`.

## License

MIT
