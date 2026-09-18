---
description: "dsh-allow：记住沙箱提权审批，同类命令不再反复询问。"
---

# dsh-allow

[English](README.md) | 中文

问一次，以后放行。权限弹窗多出第三个选项——**总是允许「…」开头的命令**——写下的规则存在你的 harness home 里，用 `/allow` 管理。

## 它做什么

DSH 有文件沙箱：写会话工作区之外的命令会被拦下，模型可以带 `sandbox_permissions` 重试，这会弹出一次审批。第一次弹没问题，第十次就很烦——因为反复出现的总是同几件事（`pnpm dsh plugin …`、`brew install …`、`git push …`）。

本插件挂在 `approval/request` 这条 waterfall 上，**排在内置应答者之前**：

- **命中已记住的规则**：直接放行，不弹任何东西。
- **没有规则**：弹三个选项：
  - `允许一次` —— 只放行这一次。
  - `总是允许「pnpm dsh plugin」开头的命令` —— 先记规则，再放行。
  - `拒绝` —— 本次调用不执行。
- **其它审批请求**（hooks、文件编辑、任何不是沙箱提权的请求）原样交给内置应答者。

规则的匹配维度是 **工具 + 请求的沙箱模式 + 命令开头几个词**，所以允许了 `pnpm dsh plugin` 不会顺带允许 `rm`；为 `danger-full-access` 记的规则也不会覆盖更宽的请求。前缀的推导方式是：去掉开头的 `cd … &&`、去掉 `VAR=value` 赋值，然后一直取到第一个选项、路径或 shell 操作符为止——**弹窗里显示的就是将要记住的那串前缀**，你同意什么、它就记什么。

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

文件读不出来或手改坏了只会退化成「没有规则」，不会卡住审批；规则被删掉的效果就是重新弹一次窗。

## 测试

```sh
node test/smoke.mjs
```

覆盖：前缀推导、提权请求的识别、规则读写与匹配、三种弹窗答案、命中规则时的静默放行、命中计数、非提权/无法询问时的委派，以及 `/allow` 的语法。

## 限制

- 只记住 **bash/pwsh 命令**的提权；`write`/`edit` 工具的路径提权仍走内置弹窗。
- 插件是从会话日志里的工具调用（`sandbox_permissions` 与 `command` 参数）识别提权的，因此需要审批请求带上 call id；没有 call id 的请求一律委派。

## 许可证

[MIT](LICENSE)
