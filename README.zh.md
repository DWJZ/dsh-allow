---
description: "dsh-allow:按路径授予 DSH shell 调用的 read / write / create / delete / execute 文件权限,卡片上给「拒绝 / 允许一次 / 总是允许」。"
---

# dsh-allow

[English](README.md) | 中文

给 agent 每次 shell 调用加一层**文件系统权限**。判断依据是这条命令需要哪些文件能力,而不是命令名听起来多危险:`rm build` 会问,是因为 `delete(/…/build)` 没被授予;`chmod 600 build` 会问,是因为 `write(/…/build)` 没被授予;`echo x > new.txt` 直接通过,是因为 workspace 里 `create` 是允许的。授权一个路径不会顺带打开它的邻居,授权一个可执行文件也不会打开它所在的整个前缀。

```
cat README.md               →  允许    (workspace 内 read)
echo x > out.md             →  允许    (workspace 内 create)
rm -rf build                →  询问    (workspace 默认不授予 delete)
mkdir build && rm -rf build →  询问    (整行取最严的一条)
python3 -c '…'              →  允许    (见「内联程序」:交给系统层沙箱)
gh pr list                  →  询问    (这个二进制没被授予 execute)
echo x > /Users/me/other/o  →  询问    (workspace 外 create)
sudo rm -rf /System/Library →  拒绝    (平台保留路径)
```

## 挂在哪一层

```
模型写出一条命令
      ↓
bash / pwsh 工具调用
      ↓
tools/pre-execute  ← 本插件:解析 → 推导文件效果 → 逐条解析 (路径, 能力)
      ↓ 允许                     ↓ 询问                        ↓ 拒绝
  DSH 沙箱(不改动)         审批卡片:拒绝 / 总是允许 /        直接拒绝,不能提权
                          允许一次
      ↓
进程执行
```

`tools/pre-execute` 是文档化的策略接缝,也是 shell 命令唯一的路径,没有旁路。监听器用 `prepend: true` 注册,所以别人无法覆盖「拒绝」。

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

`recursive: true` 覆盖整棵子树;`recursive: false` 只覆盖这一个路径 —— 卡片上的「总是允许这个文件」写的就是后者(单个二进制、单个文件)。

## 优先级

从高到低,某个能力第一次被某一级明确表态就按它执行;同一级内部,路径更具体的优先:

1. **平台保留路径** —— `/System`、`/bin`、`/sbin`、`/usr`(除 `/usr/local`)、`/AppleInternal`、`/private/var/db`、`/dev` 的 `write`/`create`/`delete` 对任何人(包括用户规则)都拒绝;`/dev/null`、标准流与 `/usr/local` 例外。
2. **显式规则** —— 规则文件(`source: user`)与本会话的「允许一次」(`source: session`)。
3. **工作区规则** —— 会话 workspace 里的 `.dsh-allow.json`。
4. **平台基线** —— workspace、临时目录、harness home,以及 macOS 自身需要的系统路径。
5. **全局默认** —— 未授予。

路径按规范化后的绝对路径逐段比较:`~`、相对路径、`.`、`..`、以及符号链接祖先都会先解析,所以 `/tmp/x` 与 `/private/tmp/x` 是同一条路径,也无法用 `../` 绕过规则。每次判定会同时拿「写法路径」和「真实路径」去匹配,因此 `/opt/homebrew/bin/gh` 的授权和它指向的 Cellar 二进制的授权各自有效,又都不会打开 `/opt/homebrew` 其余部分。

## 默认权限与平台基线

workspace 内:`read`、`write`、`create`、`execute` 允许,`delete` 默认拒绝。

插件自己的临时目录与 harness home 五种全允许。系统路径给 macOS 必需的部分:`/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/lib`、`/usr/libexec`、`/System`、`/Library/Apple`、`/Library/Developer` 给 `read` + `execute`;`/etc`、`/var`、`/usr`、`/usr/share`、`/Library`、`/Applications`、`/dev`、`/opt/homebrew` 只给 `read`。

其余位置(包括 workspace 之外的 `$HOME`)在你打开之前都是关着的。`read-only` 会话会把基线收窄得和沙箱模式一致:workspace 只保留 `read` + `execute`。

## Homebrew 与符号链接可执行文件

Homebrew 的前缀**不是**默认可执行的:`/opt/homebrew` 可读,但 `/opt/homebrew/**` 不可执行,因此每个 Homebrew 二进制都要单独授权一次。对 `execute /opt/homebrew/bin/gh` 点「总是允许」只会写这一条路径,不会顺带覆盖第二个工具;因为判定会同时比对写法路径与它解析到的目标,同一个名字下次再经由符号链接启动时这条授权依然有效。

## 命令的文件效果怎么读出来

命令行用 `tree-sitter` + `tree-sitter-bash` 解析(结构:管道、列表、控制流、替换、重定向、here-document),然后按程序对参数做了什么,把每条简单命令变成 `(路径, 能力)`:`rm` 删除操作数、`mkdir` 创建、`mv` 删源建目标、`cp` 读源建目标、`grep` 读路径参数但绝不把 pattern 当路径、`sed -i` 读写同一个文件、`dd if=` 读而 `of=` 建、`curl -o` 建。重定向也算效果:`>` 写或建、`<` 读,空设备与标准流忽略。`sudo`、`doas`、`env`、`nice`、`nohup`、`timeout`、`command`、`exec` 会被跟到真正启动的程序,所以 `sudo rm -rf build` 仍然是一次对 `build` 的 delete。

除此之外不从程序名推断任何东西;不在表里的程序只推导 `execute` —— 命令行看不出文件效果的程序(`git status`)完全不需要路径授权。

## 内联程序:不再按整行原文审批

`python3 -c '…'`、`node -e '…'`、`eval`,以及解析器无法还原的 shell 程序,既不会按文本判定,也不会被固定成原文规则:两条源码不同、能力相同的 `python3 -c` 行为一致,不会因为源码变了再问一次。运行由沙箱约束进程;只有在**没有**任何沙箱模式在约束时(模式未知,或 `danger-full-access`)这种行才会询问 —— 这是 fail closed 的那一支。

「操作可见但路径是算出来的」是另一回事:`rm -rf "$DIR"` 明确是一次 delete,但路径无法核对,所以它会问,而不是搭上一条已有授权。一旦该操作在工作目录上被授予,它就不再询问,而沙箱会把运行期路径限制在你打开的范围里。

## 卡片

`拒绝`、**唯一一个**`总是允许`按钮,以及`允许一次`,并显示真正缺的那一项:

```
需要文件权限
操作: delete
路径: /Users/me/project/build
命令: rm -rf build
沙箱: workspace-write
```

「总是允许」只写卡片上念出来的那几条最窄规则 —— 命令行里每个路径一条,只有路径本身是已存在的目录时才带 `/**`,绝不顺手把路径所在的文件夹打开;想主动打开文件夹就明确写 `/allow add delete . folder`。「允许一次」只在内存里给本会话授权,默认十分钟后过期,绝不写规则文件。

## macOS 后端

`src/macos.js` 会把规则集编译成 Seatbelt(`sandbox-exec`)profile,映射是对内核实测出来的,不是照抄的:

| 能力 | SBPL 操作 |
| --- | --- |
| `read` | `file-read*` |
| `write` | `file-write-data`、`file-write-attributes`、`file-write-mode`、`file-write-flags`、`file-write-owner`、`file-write-times` |
| `create` | `file-write-create` |
| `delete` | `file-write-unlink` |
| `execute` | `process-exec` |

macOS 上 `delete` 与 `write` **确实可以分开**:在某个子树里允许 `file-write-data` 与 `file-write-create`、同时不授予 `file-write-unlink`,进程就能改写和新建文件,而 `rm`、`rmdir`、`rename` 全部 EPERM —— 子进程同样继承这个 profile。Seatbelt 的过滤器匹配内核解析后的路径,所以渲染前必须先规范化。

`test/sandbox.integration.mjs` 拿真内核验证了以上全部:workspace 读/写/建允许、删除被拒、授予 delete 后又能删、workspace 外写入被拒、execute 围栏拒绝未授权二进制、符号链接二进制按真实路径匹配、`python3 -c 'os.remove(…)'` 与子 shell 都被拒、内核拒绝的 profile 一个字节也不执行。

## 到底在哪里被强制

| 能力 | 命令级闸门(本插件) | 今天的 OS 沙箱 |
| --- | --- | --- |
| `write`、`create` | 有 | 有 —— workspace 根之外一律被 DSH 的 Seatbelt profile 拒绝 |
| `delete` | 有,限于命令行能看出的效果 | **还没有** —— DSH profile 在 workspace 下授予 `file-write*`,其中包含 unlink |
| `read` | 有 | 没有 —— 任何模式下读都放行 |
| `execute` | 有 | 没有 —— profile 不管 `process-exec` |

诚实的结果:看不清效果的程序(`python3 -c 'os.remove(…)'`)不会被策略拦下;命令行没写出来的 workspace 外读取也不会被沙箱拦下。把 delete 下沉到内核只差 `@deepseek-ai/dsh-sandbox-local` profile 里的一行 —— 对「规则未授予 delete」的根加 `(deny file-write-unlink (subpath …))`,由能力集喂给它;`/allow status` 会在终端打印上面这张表。

## `/allow`

```
/allow                          列出已记住的规则
/allow status                   默认权限与强制层现状
/allow add delete,write build folder
/allow add execute /opt/homebrew/bin/gh file
/allow remove 2
/allow clear
```

## 审计日志

每次非静默判定都会往 `$DSH_HOME/dsh-allow-audit.ndjson` 追加一行 JSON:命令、工作目录、决策、沙箱模式,以及支撑它的 `(能力, 路径)` 列表。凭据形状的文本在落盘前会被打码。

## 配置

```yaml
- id: dsh-allow
  config:
    rulesFile: /path/to/rules.json          # 默认 $DSH_HOME/dsh-allow.json
    auditFile: /path/to/audit.ndjson        # 默认 $DSH_HOME/dsh-allow-audit.ndjson
    audit: true                             # false 关闭审计
    sessionGrantTtlMs: 600000               # 「允许一次」的有效期
    autoApproveEscalations: true            # 已授权的命令自己回答提权询问
    grants:                                 # 部署级授权,字段与持久规则一致
      - path: /opt/homebrew
        recursive: true
        access: { read: true, execute: true }
```

dsh-allow 0.1 写出的 `rules.json`(命令前缀模型)会被读成空规则,并在第一次写入时留成 `<rulesFile>.v2.bak`:那些规则描述的是命令,不是文件能力,无法翻译。

## 测试

```sh
npm test              # 单元 + 宿主接线 + 卡片渲染 + 真实沙箱
npm run test:unit     # 策略、效果推导、决策
npm run test:sandbox  # macOS Seatbelt 集成(需要能启动 sandbox-exec 的宿主)
```

当 `sandbox-exec` 无法应用 profile 时(包括测试本身跑在另一层 Seatbelt 沙箱里),集成套件会打印明显的 SKIP;要在真内核上验证,请从普通终端运行它。

## 限制

- 卡片按命令行判定;命令行看不出效果的程序由沙箱约束,而不是由本策略约束。
- `read` 与 `execute` 目前是命令级的(见强制层表格);把它们下沉到内核所需的 macOS 映射已经在 `src/macos.js` 里实现并测试。
- macOS 上只有 `create` 无法写出非空文件:填内容还需要 `file-write-data`,所以创建类授权通常同时带 `write`。
- 改名需要源的 `delete` 加目标的 `create`。
- 读效果只为固定的一张程序表推导;表里没有的效果交给沙箱,而不是猜。

## 许可证

MIT
