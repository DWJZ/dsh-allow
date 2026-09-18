---
description: "dsh-allow：审批卡片多一个「总是允许」按钮，记住的命令前缀不再询问。"
---

# dsh-allow

[English](README.md) | 中文

审批卡片上多出第三个按钮——**总是允许「pnpm dsh plugin」开头的命令**——写下的规则存在你的 harness home 里，用 `/allow` 管理。点它，这次调用直接继续；同样的命令前缀以后不再询问。

## 它做什么

DSH 有文件沙箱：写会话工作区之外的命令会被拦下，模型可以带 `sandbox_permissions` 重试，这会弹出审批卡片。第一次弹没问题，第十次就很烦——因为反复出现的总是同几件事（`pnpm dsh plugin …`、`brew install …`、`gh repo view …`）。

- **命中已记住的规则**：在宿主侧就结束这次提权，界面根本不出现。
- **没有规则**：审批卡片给三个按钮：
  - `拒绝` —— 本次调用不执行。
  - `总是允许「gh repo view」开头的命令` —— 先记规则，再放行这一次。
  - `允许一次` —— 只放行这一次。
- **其它审批请求**（hooks、`write`/`edit` 的路径提权、任何不是沙箱提权的请求）仍然走内置卡片，插件不碰。

规则的匹配维度是 **工具 + 请求的沙箱模式 + 命令开头几个词**，而且只覆盖**单条命令**（见下），所以允许了 `pnpm dsh plugin` 不会顺带允许 `rm`；为 `danger-full-access` 记的规则也不会覆盖别的请求。前缀的推导：去掉开头 `cd … &&`、去掉 `VAR=value`、程序名取 basename（`/opt/homebrew/bin/gh` → `gh`），然后一直取到第一个选项、路径或 shell 操作符。**按钮上写的就是将要记住的那串前缀**。

## 规则管不到的两件事

**复合命令永远不会套用规则。** `brew install gh && rm -rf /` 的开头正是 `brew install gh` 这条规则的名字，但规则放行的是**整行**——后半段会一起被批准。所以这种命令行既不参与规则匹配，也不显示「总是允许」按钮：卡片会说明原因，每次都问。唯一的例外是开头的 `cd … &&` 链，因为规则命名的是它后面的那个程序（`cd /tmp && brew install gh` 可以记成 `brew install gh`）。管道、分号、重定向、`$(…)`、反引号、多行命令都算复合命令。

**路径不属于规则。** 规则命名的是命令，不是目录。路径作用域是沙箱的职责：`workspace-write` 下**会话工作区**加上平台临时目录本来就免审批可写，之外的一律拒绝——卡片正是出现在那里。所以「让我写 `~`，但 `/` 要审批」的正确表达方式是**把会话工作区设成 `~`**（把 `~` 加为工作区并在那里开会话），而不是写规则。规则随后只决定哪些**程序**可以越过这条边界。

## 安装

```sh
# GitHub 源
dsh plugin --profile web add github:DWJZ/dsh-allow

# 本地开发
dsh plugin --profile web add link:/path/to/dsh-allow
```

## `/allow`

```
/allow                                  # 等于 /allow list
/allow add bash danger-full-access pnpm dsh plugin
/allow remove 2
/allow clear
```

## 规则文件

`$DSH_HOME/dsh-allow.json`（可用配置项 `rulesFile` 改路径）：

```json
{
  "version": 1,
  "rules": [
    { "id": "r1758000000000", "hits": 4, "tool": "bash", "mode": "danger-full-access", "prefix": "pnpm dsh plugin" }
  ]
}
```

文件读不出来或手改坏了只会退化成「没有规则」，不会卡住审批；删掉规则的效果就是重新弹一次卡。

## 卡片是怎么做的

内置审批卡片的按钮行是写死的（`拒绝` / `允许一次`），它唯一的插槽是命令详情——插件没法给那个组件加按钮。所以本插件以更低的 priority 在 `conversation.composer` 这条 chain 上注册自己的条目，用**同样的 DOM 结构和同样的 CSS 声明**渲染一张卡片，只在中间多一个按钮。它只匹配沙箱提权，其它审批照旧由内置卡片渲染。

它背后的两条宿主路由：

- `GET /dsh-allow/pending?sessionId=…&callId=…` —— 这次提权会记住什么（前缀 + 命令），供按钮念出前缀。仅限回环。
- `POST /dsh-allow/remember` —— 写入规则。仅限回环且同源。

## 测试

```sh
npm test        # 宿主套件 + 浏览器套件
```

宿主套件覆盖：前缀推导、提权识别、规则读写与匹配、pending 存储的身份与过期规则、两条路由（含各种拒绝路径）、`/allow` 语法。浏览器套件加载客户端 bundle，检查 chain 注册与提权判定，并做一次服务端渲染。设置 `DSH_CHECKOUT=<dsh 检出目录>` 才会跑渲染断言。

## 限制

- 只有 **bash/pwsh 命令**的提权会多出第三个按钮；`write`/`edit` 的路径提权仍用内置卡片。
- 卡片是本插件自己渲染的，不是内置组件，所以 harness 以后改卡片结构不会自动继承。
- 提权信息来自会话日志里的工具调用，因此没有 call id 的审批请求交回内置卡片。

## 许可证

[MIT](LICENSE)
