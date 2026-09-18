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
3. 每个简单命令的 argv 由内置表分类、与存储规则匹配，然后整条请求取最严：`forbidden > prompt > allow`。
4. 无法分析的行是 `prompt`，并且**永远不会**命中 `allow` 规则——这就是对 parser 不理解的 shell 语法的 fail-closed。

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
- 卡片是本插件自己渲染的审批界面（内置卡片的按钮行不可扩展），只接管策略标记过的命令。
- DSH 目前不对网络出站做沙箱，因此 `curl`/`wget`/`ssh` 是策略提示，而不是强制限制。

## 许可证

[MIT](LICENSE)
