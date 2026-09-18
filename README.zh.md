---
description: "dsh-allow：shell 命令的确定性审批层——解析、分类、allow / prompt / forbidden，并把最窄的规则记下来。"
---

# dsh-allow

[English](README.md) | 中文

对 agent 要跑的每条 shell 命令做确定性审批：先解析命令行，逐条判定每个简单命令，整条请求取**最严**的结果——`allow`、`prompt` 或 `forbidden`。审批卡片可以记住一条**结构化窄规则**；记住过一条命令，绝不会让别的命令搭便车。

```
touch x && rm -rf /        →  forbidden   (即使已经「总是允许 touch」)
git status && touch foo    →  allow
git status && rm file      →  prompt
echo "rm -rf /"            →  allow       (引号里的是文本，不是命令)
bash -c 'rm -rf /'         →  forbidden   (wrapper 递归解析)
bash -c "$UNKNOWN"         →  prompt      (无法证明)
python -c '…'              →  prompt      (任意代码)
echo k > ~/.ssh/authorized_keys → prompt  (凭据路径)
```

## 挂在哪一层

```
模型写出命令
      ↓
bash / pwsh 工具调用
      ↓
tools/pre-execute  ← 本插件：解析 → 策略 → 决策
      ↓ allow                 ↓ prompt                    ↓ forbidden
   沙箱(不变,仍是写围栏)   审批卡片: 允许一次 /            直接拒绝,不可升级
                          总是允许 / 拒绝
      ↓
真正执行
```

`tools/pre-execute` 是文档指定的策略接缝（`tool-bash` 里的 TODO 正指向它），也是 shell 命令的唯一路径，所以不存在绕过审批的执行路径。监听器以 `prepend: true` 注册，`forbidden` 不会被别的监听器覆盖。

## 三种决策

- **allow** —— 没有规则反对，交给沙箱（沙箱仍是文件写入的围栏）；命中已记住的 `allow` 规则也走这里。
- **prompt** —— 弹审批卡片。`允许一次` 只回答本次、不写任何东西；`总是允许` 写入建议的规则——可解析的每条命令一条（如 `cp` + `echo`），钉不住时则写入**整条命令原文**；`拒绝` 拒绝本次调用。
- **已记住** —— 整行每条命令都被 allow 规则覆盖时，沙箱的提权询问也会被静默批准，于是「允许过的命令」以后彻底不再问。想保留每次手动确认，把 `autoApproveEscalations` 设为 `false`。
- **forbidden** —— 直接拒绝并给理由，不询问、也不可升级：这类操作无论谁批准都是破坏性的。

## 命令怎么被分析

1. `src/parse.js` 用 **tree-sitter + tree-sitter-bash**（真正的 bash 语法）解析，只读它给出的树：语句、管道、`&&`/`||`/`;`、`for`/`if`/`while`/`case`、子 shell、命令替换、重定向、here-doc 都由语法决定。`echo "a && b"` 是一条命令；`for f in a b; do echo $f; done` 里的命令会被逐条判定；here-doc 正文是独立节点，不会被当成命令。
2. `bash -lc '…'`、`sh -c '…'` 的**内层程序会递归解析**（深度 4），逐条判定后取最严；内层解析不出来则整个调用视为 opaque → `prompt`。
3. `$(…)` 与反引号里的命令**算作同一行的命令**，先于外层执行并参与聚合；被替换出来的**程序名**（`$(printf rm) -rf /`）视为动态可执行 → 整行无法分析。
4. 语法树报错的输入（真正的语法错误，如引号不闭合、`if` 没有 `fi`）**直接拒绝**：shell 本来也跑不了它，所以不给审批、也不给规则。
3. 每个简单命令的 argv 由内置表分类、与存储规则匹配，然后整条请求取最严：`forbidden > prompt > allow`。
4. 无法分析的行是 `prompt`，且不会命中任何「按命令」的规则——这就是对 parser 不理解的 shell 语法的 fail-closed；但这类行仍可按**整条原文**固化，那也是唯一能命中它们的规则。

## 内联代码执行（shell wrapper 与解释器）

高能力程序可以执行，但**不能把「任意代码执行」记成宽泛规则**。规则写不写得进去由 `validatePersistentRule()` 一处判定，`RuleStore` 写入前再判一次，读取时第三次过滤——所以 UI bug、未来调用方、手改配置都塞不进 `bash -c` / `python -c` 这类规则。

| 命令 | 处理 |
|---|---|
| `bash -lc 'cargo test'` | **递归解析**内部 shell → 按 `cargo test` 判定；Always Allow 生成的是 `["cargo","test"]`，不是 `bash -lc` |
| `bash -lc 'touch x && rm -rf /'` | 内部逐条判定后取最严 → `forbidden`（外层是 bash 不能绕过） |
| `bash -lc 'X=$Y; $X foo'` | 内层解析失败 → 整个调用视为 **opaque** → `prompt` |
| `python -c 'print(123)'` | 内联代码视为 **opaque 任意代码** → `prompt`；Always Allow 只能生成**精确到原文**的规则 `["python","-c","print(123)"]` |
| `python tools/check.py` | 属于**脚本文件执行**，生成 `["python","tools/check.py"]`，之后 `… --verbose` 等不同参数照样命中 |
| `python -` / `bash`（无 `-c`）、heredoc 程序 | 程序来自 stdin，argv 钉不住 → `prompt`；但可以**把整条命令原文钉死**（exact-source 规则） |
| 无法解析的行（`for …; do …; done` 等） | `prompt`；同样可以按原文钉死 |

**exact-source 规则**：当 per-command 钉不住（stdin 程序、heredoc、parser 不支持的语法）时，卡片补一条「总是允许这条完全相同的命令」——规则记录**整条命令文本**，只有文本完全相同（忽略首尾空白）才命中。同文本 ⇒ 同能力。

- **混合行两条都给**：可解析的部分照旧给最小 capability 规则（`cd`、`git add`…），整行再补一条 exact pin，所以**没有命令是你无法永久放行的**。
- **硬拒绝是唯一例外**：`rm -rf /`、`mkfs`、`dd of=/dev/…` 这类内置灾难判定默认仍不可记忆。想让它们也能按原文固化的部署，把配置 `allowForbiddenSource` 设为 `true`（默认 `false`）——打开后卡片会给「总是允许这条完全相同的命令」，且该 pin 才会生效。

**内置策略只有两类硬结果**：语法错误 → 直接拒绝（无法运行的命令没必要审批）；其余风险一律收拢成 `prompt` + 一条具体规则。`forbidden` 另外保留给**你自己**写的规则（`/allow add forbidden …`），默认一条都没有。

**被明确拒绝的宽泛规则**（写入时抛错，读取时忽略）：

```
bash · sh · zsh · dash · ksh · fish · pwsh        （单独出现）
bash -c · bash -lc · sh -c · zsh -c …             （只有开关，没有代码文本）
python · python3 · node · perl · ruby · lua · deno eval · php -r · osascript -e
python - · node -                                 （从 stdin 读程序）
eval · source · exec                              （单独出现）
```

另外，**靠参数选择要运行什么**的程序也按同一标准（规则必须带具体操作，不能只写程序名）：`git`（`-c alias.x='!cmd'`、`--exec-path`）、`npm`/`pnpm`/`yarn`/`bun`、`make`、`docker`/`podman`/`kubectl`、`ssh`、`sudo`/`su`/`doas`、`env`/`xargs`/`nohup`/`timeout`/`nice`。所以 `git` 单独一条会被拒绝，`git status` 可以；`sudo` 单独一条会被拒绝，`sudo apt update` 可以。

判定规则：**规则必须把「将要运行的程序」钉死**——要么是内联开关后的那段代码文本，要么是脚本路径。`python -c 'print(123)'` 与 `python -c 'print(456)'` 是两条不同的能力，前者不会覆盖后者。`forbidden` 永远优先：即使存在精确 allow 规则，`rm -rf /` 仍然拒绝（`bash -lc 'rm -rf /'` 也一样）。

卡片上的文案也跟着区分：内联代码给的是「**总是允许这条完全相同的命令**」，解析成功的外层则显示内层命令（`总是允许「cargo test」`）。

## 内置策略

看参数，不看名字黑名单：

| 类别 | 例子 | 决策 |
|---|---|---|
| 灾难性 | `rm -rf /`、`rm -rf ~`、`rm -rf /*`、cwd 为 `/` 时的 `rm -rf .`、`mkfs*`、`dd of=/dev/sda`、`> /dev/sda` | forbidden |
| 破坏性 | `rm`、`rmdir`、`mv`、`truncate`、`dd`、`shred`、`git reset --hard`、`git clean -fdx`、`git push --force` | prompt |
| 提权 | `sudo`、`su`、`doas` | prompt |
| 权限 | `chmod`、`chown`（递归/全局可写会额外标注） | prompt |
| 进程/服务 | `kill`、`pkill`、`killall`、`systemctl`、`service`、`launchctl`、`mount`、`umount` | prompt |
| 代码执行 | 不带 `-c` 的 `sh`、`python -c`、`node -e`、`eval`、`exec`、`source` | prompt |
| 环境变量 | `PATH=`、`LD_PRELOAD=`、`DYLD_*`、`PYTHONPATH=`、`NODE_OPTIONS=`、`BASH_ENV=`、`export PATH=…` | prompt |
| 重定向 | `> /etc/*`、`> ~/.ssh/*`、`> ~/.bashrc`、动态目标 | prompt |
| 后台 | `cmd &` | prompt |
| 网络 | `curl -o`、`wget -O`、`ssh`、`scp`、`rsync`、`nc` | prompt |
| 容器 | `docker`、`podman` | prompt |
| 路径 | cwd 为 `/` 或 `$HOME` 时的 `rm -rf .`；比较前先归一化 `~`、`..`、`/x/..` | 按 cwd 给 forbidden / prompt |

一行里只要有一条命令钉不住（stdin 程序、被替换出来的程序名、parser 不支持的语法），其余命令的最小 capability 规则照旧给，**整行再补一条 exact pin**，所以不存在无法永久放行的行；含硬拒绝（可解析的 `rm -rf /` 等）的行默认不给建议，除非打开 `allowForbiddenSource`。

建议规则的粒度：**风险程序多记参数、但不全量匹配**——`rm -rf build` → `["-rf","build"]`（因此 `rm -rf other` 仍会问）、`chmod 777 /etc/x` → `["777","/etc/x"]`、`git reset --hard` → `["reset"]`；重定向触发的提示会**同时**给出最小能力规则和整行 exact。

没有任何规则命中的命令交给沙箱（`defaultDecision: allow`）；想全量把关就把它设成 `prompt`。

## 持久规则是结构化的

`$DSH_HOME/dsh-allow.json`：

```json
{
  "version": 2,
  "rules": [
    { "id": "r1", "decision": "allow", "executable": "git", "argvPrefix": ["status"], "hits": 4 },
    { "id": "r2", "decision": "forbidden", "executable": "dd", "argvPrefix": [] }
  ]
}
```

匹配是结构化的：可执行文件名（取 basename，所以 `/usr/bin/git` 与 `git` 是同一个程序）+ 字面量 argv 前缀。`git reset --hard` 不会命中 `['git','status']`；带展开参数的命令（`git status "$X"`）**不会**被 `allow` 规则覆盖。建议规则取最窄可用形式：程序名，加上有子命令的程序的子命令（`git status`、`pnpm install`）；选项和路径永不进入建议。

## `/allow`

```
/allow                                        # 列出规则与命中次数
/allow add allow git status                   # 手工加一条
/allow add forbidden dd
/allow remove 2
/allow clear
```

## 审计日志

每次决策往 `$DSH_HOME/dsh-allow-audit.ndjson` 追加一行 NDJSON：时间、工具、cwd、原始命令、解析出的命令、决策、理由、风险、是否可分析、命中的规则。写入前会脱敏凭据形态的文本（`api_key=…`、`Authorization: Bearer …`、私钥），环境变量的值从不记录。

## 配置

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json
    auditFile: /path/to/audit.ndjson
    audit: true
    defaultDecision: allow      # 或 prompt：全量把关
    autoApproveEscalations: true # false：已记住的命令在扩大沙箱权限时仍需确认
    allowForbiddenSource: false   # true：硬拒绝的行也提供并认可「整条原文」的固化
```

## 测试

```sh
npm test        # 策略套件 + 宿主套件 + 浏览器套件
```

`test/policy.spec.mjs` 跑规定用例与绕过尝试（`touch x; rm -rf /`、`||`、`|`、`(rm -rf /)`、`bash -c`、`eval`、`$COMMAND -rf /`、`$(printf rm)`、`rm -rf "$TARGET"`、`for … do rm …`、`if … then rm …`），断言其中没有任何一个是 `allow`。`test/smoke.mjs` 覆盖 gate、两条路由、规则存储、审计脱敏、宽规则拒绝与 `/allow`。`test/client.smoke.mjs` 渲染卡片（设置 `DSH_CHECKOUT` 才跑该断言）。

## 限制

- parser 建模的是受限 shell，不是 bash。它覆盖不到的语法一律 `prompt`，只有「整条原文」的固化能命中，按命令的规则永远不行。
- 规则只作用于 `bash`/`pwsh` 命令行；`write`/`edit` 工具仍走自己的沙箱升级。
- 卡片是本插件自己渲染的审批界面（内置卡片的按钮行不可扩展）：它接管沙箱升级请求与策略提示（策略提示的 reason 以 `dsh-allow: ` 开头做标记），其它审批仍走内置卡片。
- DSH 目前不对网络出站做沙箱，因此 `curl`/`wget`/`ssh` 是策略提示，而不是强制限制。

## 许可证

[MIT](LICENSE)
