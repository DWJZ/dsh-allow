---
description: "dsh-allow: filesystem permissions (read / write / create / delete / execute) per path for DSH shell calls, with deny / allow once / always allow."
---

# dsh-allow

English | [中文](README.zh.md)

A filesystem permission layer over every shell command the agent runs. A command is judged by the filesystem capabilities it needs, never by how dangerous its name sounds: `rm build` asks because `delete(/…/build)` is not granted, `chmod 600 build` asks because `write(/…/build)` is not granted, and `echo x > new.txt` runs because `create` is granted in the workspace. Granting one path never opens its neighbours, and granting `execute` for one binary never opens the rest of its prefix.

```
cat README.md               →  allow    (read inside the workspace)
echo x > out.md             →  allow    (create inside the workspace)
rm -rf build                →  prompt   (delete is not granted in the workspace)
mkdir build && rm -rf build →  prompt   (as strict as its strictest member)
python3 -c '…'              →  allow    (see "Inline programs": the sandbox fences it)
gh pr list                  →  prompt   (execute is not granted for that binary)
echo x > /Users/me/other/o  →  prompt   (create outside the workspace)
sudo rm -rf /System/Library →  forbid   (the platform reserves that path)
```

## Where it hooks in

```
model writes a command
      ↓
bash / pwsh tool call
      ↓
tools/pre-execute  ← this plugin: parse → derive effects → resolve (path, capability)
      ↓ allow                    ↓ prompt                     ↓ forbidden
  DSH sandbox (unchanged)   approval card: deny / always    refuse, no escalation
                            allow / allow once
      ↓
process execution
```

`tools/pre-execute` is the documented policy seam and the only path a shell command takes, so nothing bypasses the gate. The listener is registered with `prepend: true`, so a `forbidden` verdict cannot be overridden by another policy.

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

`recursive: true` covers the whole subtree; `recursive: false` covers exactly that path, which is what the card's "always allow this file" writes for a single binary or file.

## Precedence

Highest first; the lowest level that states the capability answers, and inside one level the more specific path wins:

1. **Platform-protected paths** — `/System`, `/bin`, `/sbin`, `/usr` (except `/usr/local`), `/AppleInternal`, `/private/var/db` and `/dev` refuse `write`/`create`/`delete` for every writer, user rules included. `/dev/null`, the standard streams and `/usr/local` are excepted.
2. **Explicit rules** — the rules file (`source: user`) and this session's "allow once" grants (`source: session`).
3. **Workspace rules** — a `.dsh-allow.json` in the session workspace.
4. **Platform baseline** — the workspace, the temp areas, the harness home, and the system paths macOS needs.
5. **Global default** — not granted.

Paths are compared as canonical absolute paths, component by component: `~`, relative spellings, `.`, `..` and symlinked ancestors are resolved before matching, so `/tmp/x` and `/private/tmp/x` are one path and no rule can be escaped with `../`. Every operation is resolved against both the spelling used and the path behind its symlinks, which is how a grant for `/opt/homebrew/bin/gh` and a grant for the Cellar binary it points at each work without opening the rest of the prefix.

## Defaults and the platform baseline

Inside the workspace: `read`, `write`, `create` and `execute` are allowed, `delete` is not.

The plugin's temp areas and the harness home grant all five. System paths grant what macOS itself needs: `read` + `execute` for `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/lib`, `/usr/libexec`, `/System`, `/Library/Apple` and `/Library/Developer`; `read` for `/etc`, `/var`, `/usr`, `/usr/share`, `/Library`, `/Applications`, `/dev` and `/opt/homebrew`.

Everything else — including `$HOME` outside the workspace — is closed until the user opens it. A `read-only` session narrows the baseline the same way the sandbox mode does: the workspace keeps `read` + `execute` and loses the rest.

## Homebrew and symlinked executables

Homebrew is deliberately not a granted prefix: `/opt/homebrew` is readable, but `/opt/homebrew/**` is not executable, so every Homebrew binary is authorized one file at a time. `always allow` on `execute /opt/homebrew/bin/gh` stores grants for both the name the user saw and the Cellar binary it resolves to, and neither grant covers a second tool.

## How effects are read from a command

The line is parsed with `tree-sitter` + `tree-sitter-bash` (structure — pipelines, lists, control flow, substitutions, redirections, here-documents), and each simple command is turned into `(path, capability)` pairs from what the program does with its arguments: `rm` deletes its operands, `mkdir` creates them, `mv` deletes the sources and creates the target, `cp` reads the sources and creates the target, `grep` reads its path argument but never its pattern, `sed -i` reads and writes its file, `dd if=` reads and `of=` creates, `curl -o` creates. Redirections are effects too: `>` writes or creates its target, `<` reads it, and the null device and the standard streams are ignored. `sudo`, `doas`, `env`, `nice`, `nohup`, `timeout`, `command` and `exec` are followed to the program they start, so `sudo rm -rf build` is still a delete of `build`.

Nothing is inferred from a program's name beyond that reading, and only the execute effect is derived for programs outside the table — a program whose file effects are invisible from the command line (`git status`) needs no path grant at all.

## Inline programs: no exact-source approval

`python3 -c '…'`, `node -e '…'`, `eval` and a shell program the parser cannot reduce are not judged by their text and are not pinned to it: two different `python3 -c` lines with the same capabilities behave the same way, so the second one does not ask because the source differs. The sandbox confines the process, and only when no sandbox mode is enforcing (an unknown mode, or `danger-full-access`) does such a line ask — that is the fail-closed branch.

A computed path for a visible operation is different: `rm -rf "$DIR"` states a delete whose target cannot be checked, so it asks rather than riding on a grant. Once the operation is granted for the working directory the line stops asking, and the sandbox bounds the run-time path to what was opened.

## The card

`deny`, `always allow this file`, `always allow this folder` (when the two differ) and `allow once`, plus the real missing capability:

```
Filesystem permission required
Operation: delete
Path:      /Users/me/project/build
Command:   rm -rf build
Sandbox:   workspace-write
```

`always allow` writes a persistent rule; `allow once` grants the capability to this session only, in memory, for ten minutes, and never touches the rules file.

## The macOS backend

`src/macos.js` compiles a rule set into a Seatbelt (`sandbox-exec`) profile, and the mapping was measured against the kernel, not assumed:

| capability | SBPL operations |
| --- | --- |
| `read` | `file-read*` |
| `write` | `file-write-data`, `file-write-attributes`, `file-write-mode`, `file-write-flags`, `file-write-owner`, `file-write-times` |
| `create` | `file-write-create` |
| `delete` | `file-write-unlink` |
| `execute` | `process-exec` |

`delete` is genuinely separable from `write` on macOS: a profile that allows `file-write-data` and `file-write-create` under a subtree while withholding `file-write-unlink` lets a process rewrite and create files there while `rm`, `rmdir` and `rename` all fail with EPERM — including for child processes, which inherit the profile. Seatbelt filters match the path the kernel resolved, so rule paths are canonicalized before they are rendered.

`test/sandbox.integration.mjs` proves all of this against the real kernel: workspace read/write/create allowed, delete denied, a delete grant making it work again, writes outside the workspace denied, an execute fence denying ungranted binaries, symlinked binaries matched through their real path, `python3 -c 'os.remove(…)'` and a child shell denied, and a profile the kernel refuses running nothing.

## What is enforced, and where

| capability | command-level gate (this plugin) | OS sandbox today |
| --- | --- | --- |
| `write`, `create` | yes | yes — anything outside the workspace roots is denied by DSH's Seatbelt profile |
| `delete` | yes, for effects visible in the line | **not yet** — DSH's profile grants `file-write*` under the workspace, which includes unlink |
| `read` | yes | no — reads pass through every mode |
| `execute` | yes | no — the profile does not fence `process-exec` |

The honest consequence: an opaque program (`python3 -c 'os.remove(…)'`) is not stopped by the policy, and a read outside the workspace that the line does not spell out is not stopped by the sandbox. Closing the delete gap is one line in `@deepseek-ai/dsh-sandbox-local`'s profile — `(deny file-write-unlink (subpath …))` for roots whose rules withhold delete — fed by the capability set; `/allow status` prints the same table in the terminal.

## `/allow`

```
/allow                          list the stored rules
/allow status                   the defaults and the enforcement table
/allow add delete,write build folder
/allow add execute /opt/homebrew/bin/gh file
/allow remove 2
/allow clear
```

## Audit log

Every non-silent decision is appended to `$DSH_HOME/dsh-allow-audit.ndjson` as one JSON line: the command, the working directory, the decision, the mode, and the `(capability, path)` pairs behind it. Credential-shaped text is redacted before it is written.

## Configuration

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json          # default $DSH_HOME/dsh-allow.json
    auditFile: /path/to/audit.ndjson        # default $DSH_HOME/dsh-allow-audit.ndjson
    audit: true                             # false turns the audit log off
    sessionGrantTtlMs: 600000               # how long "allow once" lasts
    autoApproveEscalations: true            # a granted command answers its own escalation
    grants:                                 # deployment grants, same shape as a stored rule
      - path: /opt/homebrew
        recursive: true
        access: { read: true, execute: true }
```

A `rules.json` written by dsh-allow 0.1 (the command-prefix model) reads as empty and is kept as `<rulesFile>.v2.bak` on the first write; those rules said nothing about filesystem capabilities and cannot be translated.

## Test

```sh
npm test              # units, host wiring, card render, and the real-sandbox suite
npm run test:unit     # policy, effects, decisions
npm run test:sandbox  # macOS Seatbelt integration (needs a host that can start sandbox-exec)
```

The sandbox suite skips with a notice when `sandbox-exec` cannot apply a profile — including when the test itself runs inside another Seatbelt sandbox — so run it from a plain terminal to exercise the kernel.

## Limits

- The card decides per command line; a program whose effects the line does not show is fenced by the sandbox, not by this policy.
- `read` and `execute` are command-level today (see the enforcement table); the macOS mapping that would move them into the kernel is implemented and tested in `src/macos.js`.
- `create` alone cannot produce a non-empty file on macOS: filling it needs `file-write-data` too, which is why grants for creating usually also carry `write`.
- Renaming needs `delete` for the source plus `create` for the target.
- Read effects are derived for a fixed table of programs; an effect this table does not know is left to the sandbox rather than guessed.

## License

MIT
