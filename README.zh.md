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
- **prompt** —— 弹审批卡片。`允许一次` 只回答本次、不写任何东西；`总是允许` 写入建议的窄规则（行内每条命令一条，例如 `cp` + `echo`）；`拒绝` 拒绝本次调用。
- **已记住** —— 整行每条命令都被 allow 规则覆盖时，沙箱的提权询问也会被静默批准，于是「允许过的命令」以后彻底不再问。想保留每次手动确认，把 `autoApproveEscalations` 设为 `false`。
- **forbidden** —— 直接拒绝并给理由，不询问、也不可升级：这类操作无论谁批准都是破坏性的。

## 命令怎么被分析

1. `src/parse.js` 按未加引号的 `&&`、`||`、`;`、`|`、`&`、换行切分，再按引号与转义切词。`echo "a && b"` 是一条命令；`$(…)`、反引号、通配符、子 shell、分组、控制关键字、here-doc、动态可执行文件都会让整行变成**无法分析**。
2. `sh -c '…'`、`bash -lc '…'`、`eval '…'` 会**递归解析**（深度 4）；wrapper 的程序名是动态的 → 无法分析。
2a. here-document（`<<EOF … EOF`）的**正文是 stdin 数据，不是 shell 源码**：解析前先剥掉，所以正文里的 Python/文本行不会再被当成命令；但读取它的程序照样判定——`python3 -`、`bash`（无 `-c`）属于「从 stdin 读程序」，按代码执行 prompt 且不可记忆。
2b. `$(…)` 与反引号**也递归解析**：替换体里的命令算作同一行的命令，一起按最严聚合（`echo "$(rm -rf /)"` → forbidden）；替换体解析不出来时整行降级为 `prompt`；被替换出来的**程序名**永远是动态可执行 → 无法分析（`$(printf rm) -rf /` 不会被放行）。
3. 每个简单命令的 argv 由内置表分类、与存储规则匹配，然后整条请求取最严：`forbidden > prompt > allow`。
4. 无法分析的行是 `prompt`，并且**永远不会**命中 `allow` 规则——这就是对 parser 不理解的 shell 语法的 fail-closed。

## 内联代码执行（shell wrapper 与解释器）

高能力程序可以执行，但**不能把「任意代码执行」记成宽泛规则**。规则写不写得进去由 `validatePersistentRule()` 一处判定，`RuleStore` 写入前再判一次，读取时第三次过滤——所以 UI bug、未来调用方、手改配置都塞不进 `bash -c` / `python -c` 这类规则。

| 命令 | 处理 |
|---|---|
| `bash -lc 'cargo test'` | **递归解析**内部 shell → 按 `cargo test` 判定；Always Allow 生成的是 `["cargo","test"]`，不是 `bash -lc` |
| `bash -lc 'touch x && rm -rf /'` | 内部逐条判定后取最严 → `forbidden`（外层是 bash 不能绕过） |
| `bash -lc 'X=$Y; $X foo'` | 内层解析失败 → 整个调用视为 **opaque** → `prompt` |
| `python -c 'print(123)'` | 内联代码视为 **opaque 任意代码** → `prompt`；Always Allow 只能生成**精确到原文**的规则 `["python","-c","print(123)"]` |
| `python tools/check.py` | 属于**脚本文件执行**，生成 `["python","tools/check.py"]`，之后 `… --verbose` 等不同参数照样命中 |
| `python -` / `bash`（无 `-c`） | 程序来自 stdin → `prompt`，且**无法固定**，不给规则 |

**被明确拒绝的宽泛规则**（写入时抛错，读取时忽略）：

```
bash · sh · zsh · dash · ksh · fish · pwsh        （单独出现）
bash -c · bash -lc · sh -c · zsh -c …             （只有开关，没有代码文本）
python · python3 · node · perl · ruby · lua · deno eval · php -r · osascript -e
python - · node -                                 （从 stdin 读程序）
eval · source · exec                              （单独出现）
```

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

一行里只要有一条命令**不可记忆**（内联代码、被替换出来的程序名），其余命令的建议规则仍然会给（卡片上照常出现按钮），同时提示「这行有每次都问的部分」；含 forbidden 的行则不给任何建议。

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
```

## 测试

```sh
npm test        # 策略套件 + 宿主套件 + 浏览器套件
```

`test/policy.spec.mjs` 跑规定用例与绕过尝试（`touch x; rm -rf /`、`||`、`|`、`(rm -rf /)`、`bash -c`、`eval`、`$COMMAND -rf /`、`$(printf rm)`、`rm -rf "$TARGET"`、`for … do rm …`、`if … then rm …`），断言其中没有任何一个是 `allow`。`test/smoke.mjs` 覆盖 gate、两条路由、规则存储、审计脱敏与 `/allow`。`test/client.smoke.mjs` 渲染卡片（设置 `DSH_CHECKOUT` 才跑该断言）。

## 限制

- parser 建模的是受限 shell，不是 bash。它覆盖不到的语法一律 `prompt`，永不 `allow`。
- 规则只作用于 `bash`/`pwsh` 命令行；`write`/`edit` 工具仍走自己的沙箱升级。
- 卡片是本插件自己渲染的审批界面（内置卡片的按钮行不可扩展）：它接管沙箱升级请求与策略提示（策略提示的 reason 以 `dsh-allow: ` 开头做标记），其它审批仍走内置卡片。
- DSH 目前不对网络出站做沙箱，因此 `curl`/`wget`/`ssh` 是策略提示，而不是强制限制。

## 许可证

[MIT](LICENSE)
