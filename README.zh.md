---
description: "dsh-allow:按路径给 DSH shell 调用授予 read / write / create / delete / execute 文件权限,并在进程沙箱里真正强制;卡片上给「拒绝 / 允许一次 / 总是允许」,另有「审批」标签页显示每次判定是谁拍的板。"
---

# dsh-allow

[English](README.md) | 中文

给 DSH 加一层**文件系统权限**。判断依据是这条命令需要哪些文件能力,而不是命令名听起来多危险;同一份策略还会被编译成进程真正运行其下的 profile —— 所以它启动的子进程、以及命令行里根本没露出来的代码,同样受这份策略约束。

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

上例逐条读作:工作区内的 `cat` 允许;`~/.ssh/id_ed25519` 一律拒绝, 谁读都一样;`python3 -c` 里的读取由内核拒绝, 而不是被解析器发现;工作区内写入允许;工作区默认不授予 delete, 所以 `rm -rf build` 询问;delete 未授权时 `os.remove` 由内核拒绝;`gh pr list` 因为那个二进制没有 execute 而询问;工作区外的写入询问;权限库永远不可写, 所以写它一律拒绝。

## 挂在哪一层

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

这张图读作:模型写出命令 → bash / pwsh 工具调用 → 本插件在 `tools/pre-execute` 上解析、推导文件效果、逐条解析 (路径, 能力);允许就交给 `ctx.sandbox.confine`, 询问就出审批卡片(拒绝 / 总是允许 / 允许一次), 拒绝则不能提权;进程跑在同一套规则编译出的 Seatbelt profile 下, 整棵进程树(子进程、孙进程、内联代码)都受它约束。

`tools/pre-execute` 是文档化的策略接缝,也是 shell 命令唯一的路径。插件**不替换** sandbox provider:它包住已注册 provider 的 `confine`,把由当前有效策略编译出的 profile 交给它,自己处理不了的平台原样委托回去。`tools/post-execute` 负责把「允许一次」用掉,另有一道针对写文件工具的小闸门拦下权限库。

## 能力与规则

模型里有五种文件能力,一条规则只为某个路径授予其中若干种:

| 能力 | 含义 |
| --- | --- |
| `read` | 读文件、列目录 |
| `write` | 修改已有文件(内容、权限位、属主、时间) |
| `create` | 新建文件或目录 |
| `delete` | unlink / remove / rmdir / rename 移走 |
| `execute` | 把某个文件作为程序启动 |

`execute` 不等于「禁止运行任何脚本」:`python3 foo.py` 需要解释器的 `execute` 和 `foo.py` 的 `read`,因为 `foo.py` 本身没有被 `execve`。

持久规则是「路径 + 能力表」,不是命令行:

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

`recursive: true` 覆盖整棵子树;`recursive: false` 只覆盖这一个路径 —— 卡片上的「总是允许」对单个文件、单个二进制写的就是后者。

## 权限库不是 agent 能改的

规则文件与审计日志属于**硬保护路径**:`write`/`create`/`delete` 对任何人(包括用户规则)都拒绝,编译出的 profile 还会在所有授权之后再次拒绝。覆盖 `$DSH_HOME/dsh-allow.json` 与 `$DSH_HOME/dsh-allow-audit.ndjson`,配置指到哪就保护到哪。

同一道保护也加在写文件的工具上(`write`、`edit`、`str_replace_editor`),所以 agent 也不能用文件工具改写自己的规则;其它文件工具调用仍由 harness 自己的围栏负责。

harness home(`~/.dsh`)只读,shell 命令改不了「审判它的那套状态」。

clone 进 workspace 的仓库也无法给自己扩权:dsh-allow **不会**读取 workspace 里的 `.dsh-allow.json`。仓库内容永远不该授予宿主机权限。

## 优先级

从高到低,某个能力第一次被某一级明确表态就按它执行;同一级内部,路径更具体的优先:

1. **平台保留路径** —— `/System`、`/bin`、`/sbin`、`/usr`(除 `/usr/local`)、`/AppleInternal`、`/private/var/db`、`/dev`,以及权限库本体,其 `write`/`create`/`delete` 对任何人(包括用户规则)都拒绝。
2. **显式规则** —— 规则文件(`source: user`)与本次获批调用的一次性授权(`source: session`)。
3. **平台基线** —— workspace、临时目录、harness home,以及 macOS 自身需要的系统路径。
4. **全局默认** —— 未授予。

路径按规范化后的绝对路径逐段比较:`~`、相对路径、`.`、`..`、以及符号链接祖先都会先解析,所以 `/tmp/x` 与 `/private/tmp/x` 是同一条路径,也无法用 `../` 绕过规则。每次判定会同时拿「写法路径」和「真实路径」去匹配,因此 `/opt/homebrew/bin/gh` 的授权和它指向的 Cellar 二进制的授权各自有效,又都不会打开 `/opt/homebrew` 其余部分。workspace 根自身也只是普通路径;一条规则绝不会覆盖只是前缀相同的兄弟目录(`/w/build` 不覆盖 `/w/build-2`)。

## 默认权限与平台基线

workspace 内:`read`、`write`、`create`、`execute` 允许,`delete` 默认拒绝。

临时目录五种全允许。系统路径给 macOS 必需的部分:`/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/lib`、`/usr/libexec`、`/System`、`/Library/Apple`、`/Library/Developer` 给 `read` + `execute`;`/etc`、`/var`、`/usr`、`/usr/share`、`/Library`、`/Applications`、`/dev`、`/opt/homebrew` 只给 `read`。

home 目录之下还会额外放开两类:`read` + `execute` 给用户自己装的工具链(`~/.nvm`、`~/.local`、`~/.cargo`、`~/.rustup`、`~/.bun`、`~/.deno`、`~/.volta`、`~/.pyenv`、`~/.rbenv`、`~/.sdkman`、`~/.go`、`~/.asdf`、`~/.gem`、`~/Library/pnpm`),只给 `read` 给程序启动必需的少量配置(`~/.gitconfig`、`~/.config/git`、`~/.gitignore`)。这些路径是「程序要跑起来就非读不可」的,里面放的是程序与设置,不是凭据。

其余位置(workspace 之外的 `$HOME`、`~/Documents`、`~/Library`,以及其中所有凭据库)在你打开之前都是关着的,同时读围栏会扣住它们的内容。`read-only` 会话会把基线按沙箱模式收窄:workspace 只保留 `read` + `execute`,而且在只读会话里没有任何规则能把写权限加回来。

## Homebrew 与符号链接可执行文件

Homebrew 的前缀**不是**默认可执行的:`/opt/homebrew` 可读,但 `/opt/homebrew/**` 不可执行,因此每个 Homebrew 二进制都要单独授权一次。对 `execute /opt/homebrew/bin/gh` 点「总是允许」只会写这一条路径,不会顺带覆盖第二个工具。

## 命令的文件效果怎么读出来

命令行用 `tree-sitter` + `tree-sitter-bash` 解析(结构:管道、列表、控制流、替换、重定向、here-document、函数体),然后按程序对参数做了什么,把每条简单命令变成 `(路径, 能力)`:`rm` 删除操作数、`mkdir` 创建、`mv` 删源建目标、`cp` 读源建目标、`grep` 读路径参数但绝不把 pattern 当路径、`sed -i` 读写同一个文件、`dd if=` 读而 `of=` 建、`curl -o` 建。重定向也算效果:`>` 写或建、`<` 读,空设备与标准流忽略。`sudo`、`doas`、`env`、`nice`、`nohup`、`timeout`、`command`、`exec` 会被跟到真正启动的程序,所以 `sudo rm -rf build` 仍然是一次对 `build` 的 delete。

除此之外不从程序名推断任何东西;不在表里的程序只推导 `execute` —— 命令行看不出文件效果的程序(`git status`)完全不需要路径授权。

## 看不清效果的程序,只在沙箱撑得住时才直接跑

`python3 -c '…'`、`node -e '…'`、`eval`,以及解析器无法还原的 shell 程序,既不会按文本判定,也不会被固定成原文规则。只有当进程沙箱真能按策略管住它们时才直接执行:要么内核把五种能力都围住了(`guarded` 就算 —— 用户数据区的读、写、执行都在里面),要么工作目录本身已经授予了全部五种 —— 也就是没有任何东西可以被藏起来。其余情况(没有 `sandbox-exec`、profile 应用不上、当前模式不隔离进程)一律先问,卡片上的那颗按钮就是为这个目录授予五种能力。

「操作可见但路径是算出来的」是另一回事:`rm -rf "$DIR"` 明确是一次 delete,但路径无法核对,所以它会问,而不是搭上一条已有授权。一旦该操作在工作目录上被授予,它就不再询问,而沙箱会把运行期路径限制在你打开的范围里。

## 卡片

`拒绝`、**唯一一个**`总是允许`按钮,以及`允许一次`,并显示真正缺的那一项:

```
Filesystem permission required
Operation: delete
Path:      /Users/me/project/build
Command:   rm -rf build
Sandbox:   workspace-write
```

卡片上的字段读作:需要文件权限 / 操作 delete / 路径 /Users/me/project/build / 命令 rm -rf build / 沙箱 workspace-write。

「总是允许」只写卡片上念出来的那几条最窄规则 —— 命令行里每个路径一条,只有路径本身是已存在的目录时才带 `/**`,绝不顺手把路径所在的文件夹打开;想主动打开文件夹就明确写 `/allow add delete . folder`。

「允许一次」是真的只允许一次,而且有两道机制防止它横向泄漏:授权绑定到你批准的那一次调用,判定层只在那次调用看得见它;profile 构建时则靠「那次调用正在跑的命令行」再认一次 —— 因为一次 confinement 只知道会话、不知道调用。此外,只要有一条一次性授权还活着,同会话的其它调用都会先等它结算再被判定,所以两次重叠的调用不可能共用一条授权。调用结束时 `tools/post-execute` 立刻丢掉它(十分钟过期只是兜底);它绝不写规则文件,下一次调用仍然会问。

`sandbox_permissions` 提权是「更宽的进程围栏」,不是文件能力,所以**永不自动批准** —— 即使这条命令需要的能力全都已授权。一次批准就等于让命令跑到模式之外,这个决定属于用户。

## 自动复核(可选)

策略定不下来的权限请求,正常要等人点一下。打开 `autoReview.enabled` 后,它先交给本会话自己的模型:

```
missing (path, capability)
        ↓
   auto reviewer  ── ALLOW → the same one-shot grant the card writes → run
        ↓ ASK / timeout / error / anything else
   the card: deny / always allow / allow once
```

这张图读作:缺少的 (路径, 能力) 先交给自动复核, `ALLOW` 就写入与卡片「允许一次」完全相同的那条一次性授权并执行;`ASK`、超时、报错或其它任何情况都落回卡片 —— 拒绝 / 总是允许 / 允许一次。

复核不是安全边界,它只有两个答案:

| 判定 | 行为 |
| --- | --- |
| `ALLOW` | 仅当这次请求明显来自用户最新那句话、且范围很窄时。它复用已有的「按调用绑定的一次性授权」—— 和卡片上「允许一次」走同一条路 —— 所以调用被绑定、profile 按命令认领、调用结束即回收。 |
| `ASK` | 其余一切:不确定、路径比用户要求宽、用户从没提过的敏感路径、没有模型路由、没有 LLM 服务、超时、传输错误、不是 JSON、判定不是这两个值之一。 |

它**永不**拒绝、永不写规则、永不扩大 workspace、永不碰权限库或 sandbox profile,也没有任何审批记忆:持久规则仍然只由用户决定;确定性策略先跑,所以已有规则根本不会走到复核。

送给它的只有「分析过的请求」和「用户自己的话」:

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

`userMessages` 最多三条,而且只取 source 为用户的 `user/message`:插件注入的 user/message、notice、工具结果、命令行文本、仓库内容、网页、以及主 agent 自己的声明,都不算授权 —— system prompt 里写死了这条。会话历史、工具输出、历史审批次数都不会发出去。

```yaml
    autoReview:
      enabled: false        # off by default; the card stays in charge
      timeoutMs: 10000      # a timeout is an ASK
      # provider: inherit   # default: the session's latest model/selection route
      # model: inherit
```

三个字段读作:`enabled` 默认关闭, 关着时一切照旧由卡片决定;`timeoutMs` 是按 `ASK` 处理的超时;`provider` / `model` 默认继承会话最近一次 model/selection 路由。

每次复核都会写日志与审计:命令、请求的能力、判定、理由、耗时、模型路由 —— 不写文件内容、凭据、或隐藏推理。

## 审批记录

这一层做出的每一个判定都会写进审计日志,而这个日志就摆在判定发生的地方:「对话 / 轨迹」旁边多了一个**审批**标签页。

```
Conversation views:   Chat  │  Trajectory  │  Approvals
```

标签页从审计日志里读回**当前会话**的判定,新的在下,比日志晚三秒:

| 来源 | 谁拍的板 |
| --- | --- |
| `rule` | 命中已存的规则或部署 grants —— 这一行会点名规则的路径和它授予的能力 |
| `baseline` | 平台基线:工作区、临时目录、harness home、系统路径 |
| `auto-review` | 可选的自动复核给了 `ALLOW`;这一行带判定、理由、耗时和模型路由 |
| `human` | 用户拍的板:允许一次、总是允许(连带按钮写入的规则)、拒绝、已取消、无人应答 |
| `policy` | 本插件自己拒绝的:平台保护路径,或 shell 语法解析不了的一行 |

默认放行藏在**显示默认放行**后面:工作区里它们是绝大多数,说明的信息也最少。一行代表一次工具调用 —— 询问和解答它的那次人工决定会合并成那唯一一行,所以这张表回答的是「这次是谁拍的板」,而不是回放事件流水。

标签页是只读的。它读 Web 宿主的 `GET /dsh-allow/audit?sessionId=…&limit=…&baseline=1`,宿主按固定块大小从审计日志**尾部**往回读 —— 繁忙的会话从最后一块就答完了,而在没有新写入的情况下再问一次一个字节都不会读。这条路由只走 loopback,不授予任何权限、不写规则、也不回答任何审批。

这个版本之前写下的记录没有 `sessionId`,会话读不回来,所以这张表从这个版本之后的第一个判定开始。

## macOS 后端

`src/macos.js` 会把规则集编译成 Seatbelt(`sandbox-exec`)profile,映射是对内核实测出来的,不是照抄的:

| 能力 | SBPL 操作 |
| --- | --- |
| `read` | `file-read-data`(同时保留 `file-read-metadata`,否则路径都解析不了) |
| `write` | `file-write-data`、`file-write-xattr`、`file-write-mode`、`file-write-flags`、`file-write-owner`、`file-write-times` |
| `create` | `file-write-create` |
| `delete` | `file-write-unlink` |
| `execute` | `process-exec` |

macOS 上 `delete` 与 `write` **确实可以分开**:在某个子树里允许 `file-write-data` 与 `file-write-create`、同时不授予 `file-write-unlink`,进程就能改写和新建文件,而 `rm`、`rmdir`、`rename`、`python -c 'os.remove(…)'`、`node -e 'fs.rmSync(…)'` 全部 EPERM —— 本进程、子进程、孙进程都一样。单独的 `create` 就足以新建并把内容写进去;管「改动已存在的文件」的是 `write`。Seatbelt 的过滤器匹配内核解析后的路径,所以渲染前必须先规范化;一条规则会同时记住「用户写的那个名字」和它解析到的路径,所以 `/opt/homebrew/bin/gh` 的授权也覆盖它指向的 Cellar 二进制 —— 反之亦然。

有两个 Seatbelt 细节决定了 profile 的写法:通配的拒绝会被具体的允许压过去(`(deny file-write* …)` 拦不住 `(allow file-write-data …)`),所以权限库是逐操作写出拒绝的;而一个扣掉**所有**读取的 profile 会让 `/bin/sh` 在跑任何东西之前直接 abort。

所以读围栏采用 macOS 运行时扛得住的形式:在规则之前先写 `(deny file-read-data (subpath "/Users"))`(以及 `/Volumes`),再由规则把 workspace、临时目录、harness home、用户装的工具链、几个 home 配置文件,以及每一条读授权重新打开。平台自己需要读的东西照读;home 里没有被任何规则点名的文件 —— `~/.ssh/id_ed25519`、`~/.aws/credentials`、`~/.config/gh/hosts.yml` —— 无论用 `python3 -c`、`node -e` 还是 `bash -c` 去读,都由内核直接拒绝。

策略有多少真正下沉到内核,会在每个「模式 + workspace」的首次调用上**实测**:用真实 profile 跑真实命令,结果缓存下来并由 `/allow status` 报告:

| 层级 | 含义 |
| --- | --- |
| `full` | 所有读取都扣掉、逐条规则再打开;macOS 会在它下面 abort |
| `guarded` | write/create/delete/execute,以及用户数据区域的读取 |
| `process` | write/create/delete/execute |
| `writes` | 只有 write/create/delete |

`/allow status` 会把层级报告成 `full`/`partial`/`off`,并逐能力给出是否在内核层。

`enforce: 'auto'` 从上到下取探测通过的第一个层级 —— 普通 macOS 上就是 `guarded`;`enforce: full` 只接受 `full`,内核做不到就报告 `off`。编译失败会被报告而不是被吞掉,也不会被一个更宽的 profile 顶替。

## `/allow`

```
/allow                           list the stored rules
/allow status                    the defaults, the fence level, and per-capability flags
/allow add delete,write build folder
/allow add execute /opt/homebrew/bin/gh file
/allow remove 2
/allow clear
```

前两条是查询:列出已记住的规则, 以及报告默认权限、当前围栏层级与逐能力的强制情况;后四条是改动:按最窄的规则添加、按编号删除、清空全部。

`add` 的相对路径按会话 workspace 解析;`folder`(默认)覆盖整棵子树,`file` 只覆盖那一个路径。这里写的都是持久用户规则,与卡片上「总是允许」写入的形状一致。

## 配置

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json          # default $DSH_HOME/dsh-allow.json
    auditFile: /path/to/audit.ndjson        # default $DSH_HOME/dsh-allow-audit.ndjson
    audit: true                             # false turns the audit log off
    sessionGrantTtlMs: 600000               # backstop lifetime of "allow once"
    enforce: auto                           # auto | full | guarded | process | writes | off
    autoReview:                             # optional: let the model answer "allow once"
      enabled: false                        # the card stays in charge when off
      timeoutMs: 10000
    grants:                                 # deployment grants, same shape as a stored rule
      - path: /opt/homebrew
        recursive: true
        access: { read: true, execute: true }
```

每一项读作:`rulesFile` / `auditFile` 默认落在 `$DSH_HOME` 下的 `dsh-allow.json` 与 `dsh-allow-audit.ndjson`;`audit: false` 关闭审计;`sessionGrantTtlMs` 是「允许一次」的兜底有效期;`enforce` 取 auto / full / guarded / process / writes / off;`autoReview` 是可选的自动复核, 关着时卡片说了算。

dsh-allow 0.1 写出的 `rules.json`(命令前缀模型)会被读成空规则,并在第一次写入时留成 `<rulesFile>.v2.bak`:那些规则描述的是命令,不是文件能力,无法翻译。

## 测试

```sh
npm test              # units, host wiring, card render, the audit ledger, and the real-sandbox suite
npm run test:unit     # policy, effects, enforcement, reviewer, decisions, audit ledger
npm run test:sandbox  # macOS Seatbelt integration (needs a host that can start sandbox-exec)
```

三条命令分别是:全部测试(单元 + 宿主接线 + 卡片渲染 + 审批记录 + 真实沙箱)、只跑单元、以及 macOS Seatbelt 集成(需要能启动 `sandbox-exec` 的宿主)。

`test/reviewer.spec.mjs` 注入模型,覆盖「告诉复核什么」(只有真实用户消息、分析过的权限、固定的 prompt)、各种答案形态(`ALLOW`、`ASK`、带围栏的 JSON、自然语言、未知判定、空答案),以及所有失败路径(没有路由、没有 LLM 服务、provider 抛错、终止错误块、超时、答案不合法)。`test/smoke.mjs` 覆盖闸门接线:`ALLOW` 走既有的按调用一次性授权、规则文件一个字节不改;`ASK`、复核失败、以及复核关闭时,都由卡片接管。

`test/audit.spec.mjs` 不依赖宿主,把审批记录端到端跑一遍:一次判定记成哪个来源、点名了哪些规则;不管卡片是从哪一半回答的,一次人工决定只产出一行;半行、别人的审批、认不出的 outcome 都不能产出记录;尾部读取的块边界、会话过滤与字节上限;以及审计路由的方法、loopback、条数与 baseline 规则。`test/client.smoke.mjs` 另外用 React 渲染这个标签页,断言一次调用一行,且字典之外没有任何文案。

`test/sandbox.integration.mjs` 跑的是真内核,覆盖:权限库对任何写入者都拒绝;`rm` / `rmdir` / `rename` / `python -c 'os.remove'` / `node -e 'fs.rmSync'` 全部被拒而写和建正常;再授予 delete 后又能删;单独关闭 write 与 create;读围栏让 `cat` 和 `open().read()` 失败;execute 围栏拒绝未授权二进制;`python → sh` 与 `node → sh` 的孙进程继承全部限制;内核拒绝的 profile 一个字节也不执行;workspace 外写入除非被授权否则一律拒绝。覆盖的内容包括:

- 权限库对任何写入者都拒绝 —— 即使有规则把它所在的目录整个开放,依然拒绝;
- `rm`、`rmdir`、`rename`、`python -c 'os.remove'`、`node -e 'fs.rmSync'` 全部被拒而写入与新建正常,再授予 delete 后又能删;
- 单独关闭 write、单独关闭 create,以及「只有 create」时能新建并写入内容;
- 读被拒:`cat`、`python`、`node`、`bash`,以及 `python → sh`、`python → cat` 孙进程;给一条读授权后又能读;
- 同一份读围栏下 `/bin/sh`、`python3`、`node`、`git --version`、`gh --version` 全部正常运行;
- execute 围栏拒绝未授权的二进制;给符号链接授权后它能启动指向的那个二进制;
- 内核拒绝的 profile 一个字节也不执行;workspace 外写入除非被授权否则一律拒绝。

当 `sandbox-exec` 无法应用 profile 时(包括测试本身跑在另一层 Seatbelt 沙箱里),它会打印明显的 SKIP —— 要在真内核上验证,请从普通终端运行。

## 限制

- 「审批」标签页最多读审计日志最后 4 MiB、每次最多 500 条,打开期间每三秒重读一次:超长会话更早的判定会落在这个窗口之外。
- 块边界正好落在一行审计记录中间时,那一行会被丢掉,而不是报出一条读不完整的判定。
- 这个版本之前写下的记录没有 `sessionId`,所以永远不会出现在会话的审批记录里。
- 被围住的区域仍然可以解析路径:`stat`、列目录会泄漏 metadata,被扣掉的只是文件内容。
- 把配置和令牌放在同一个目录下的工具需要一条针对该目录的读授权:`gh`、`aws`、`docker` 之类在授予 `~/.config/<tool>` 之前会报自己的错。默认拒掉 `hosts.yml`、`credentials`、`id_ed25519` 正是目的,想打开是明确的动作。
- 命令行看不出效果的部分由沙箱判定,而不是由解析器猜:程序表里没有的效果一律交给围栏。
- 单独的 `create` 可以新建并写入内容;改动已存在的文件需要 `write`。
- 最强的读围栏(`enforce: full`)「能表达但活不下来」:macOS 自己要读的东西比策略基线列出的更多,`/bin/sh` 会直接 abort;`auto` 落在 guarded 围栏上。
- 两个较弱的 Seatbelt 结论:不可读的路径仍然可被解析(metadata 始终放行);通配拒绝必须逐操作写出来。
- 改名需要源的 `delete` 加目标的 `create`。
- 读效果只为固定的一张程序表推导;真正的边界是围栏,不是这张表。
- 「允许一次」是按会话串行、而不是按调用并行的:授权存活期间,同会话的其它调用会等被批准的那次结算。若核心把 callId 传进 sandbox policy,这个等待就能去掉 —— 目前核心不传。
- profile runner 固定为 `/usr/bin/sandbox-exec`;Seatbelt 不在这个位置的宿主会退回到 harness 自己的 profile 并报告 `off`。
- 自动复核是便利,不是边界:一个错误或被诱导的模型可能放行用户本会拒绝的请求。限制它的是「它能放行什么」—— 一次调用、只针对该请求的最窄规则 —— 以及底下仍有内核在强制策略。
- 复核会在卡片前多一次模型调用,所以卡片最多可能晚 `timeoutMs` 出现。

## 许可证

MIT
