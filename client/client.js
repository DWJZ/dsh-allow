/**
 * dsh-allow — browser half (lazy-CJS 客户端 bundle)。
 *
 * 在 `conversation.composer` 这条 chain 上以更高优先级(priority 0 < 内置的 1)
 * 注册一张**同款审批卡片**,接管两类审批:
 *
 *   - 沙箱提权请求(reason 里 `escalate sandbox to <mode>:`)
 *   - 本插件权限策略的询问(reason 里 `dsh-allow: ` 前缀)
 *
 * 卡片回答的是「缺哪个文件权限」,三个出口 —— 拒绝 / 总是允许 / 允许一次。
 * 两个出口都不经宿主接口:「允许一次」就是 approval waterfall 的返回值本身,
 * 「总是允许」走会话命令通道 `/allow remember <callId>`,由宿主写入它自己从待
 * 审批记录推导出的最窄规则 —— 文件规则,或受管工具的一次工具操作规则。
 *
 * 样式逐条照抄 `ui-approval` 的 ApprovalPanel.module.css(用内联 <style> 注入),
 * 所以外观与内置卡片一致。
 */
window.__ModuleLoader__.load({
	id: "dsh-allow",
	factory: (require) => {
		var module = { exports: {} };
		var exports = module.exports;
		Object.defineProperty(exports, Symbol.toStringTag, { value: "Module" });
		const React = require("react");
		const primitives = require("@deepseek-ai/dsh-client-ui-primitives");

		//#region styles
		const CSS_ID = "dsh-allow/styles.css";
		if (typeof document !== "undefined" && document.querySelector('style[data-plugin-css="' + CSS_ID + '"]') === null) {
			const tag = document.createElement("style");
			tag.dataset.plugin = "dsh-allow";
			tag.dataset.pluginCss = CSS_ID;
			tag.textContent = [
				".dsha_root{display:flex;flex-direction:column;align-items:center;padding:8px calc(var(--dsh-composer-side-clearance) + 16px) 12px}",
				".dsha_card{overflow:hidden;width:100%;max-width:var(--dsh-chat-content-width);border:1px solid var(--dsw-alias-state-warn-secondary);border-radius:20px;background:var(--dsw-specific-input-major);box-shadow:var(--dsw-shadow-lv2)}",
				".dsha_strip{display:flex;align-items:center;gap:8px;padding:10px 16px;background:var(--dsw-alias-state-warn-tertiary);color:var(--dsw-alias-state-warn-primary);font-size:13px;line-height:18px}",
				".dsha_dot{width:8px;height:8px;border-radius:50%;background:var(--dsw-alias-state-warn-primary)}",
				".dsha_body{display:flex;flex-direction:column;gap:6px;box-sizing:border-box;max-height:var(--dsh-composer-text-max-height);overflow-y:auto;padding:12px 16px 0}",
				".dsha_headline{color:var(--dsw-alias-label-primary);font-size:15px;font-weight:500;line-height:24px;word-break:break-word}",
				".dsha_row{display:flex;gap:8px;font-size:13px;line-height:20px}",
				".dsha_key{flex:0 0 auto;min-width:48px;color:var(--dsw-alias-label-tertiary)}",
				".dsha_value{color:var(--dsw-alias-label-primary);font-family:var(--ds-font-family-code);word-break:break-all}",
				".dsha_command{color:var(--dsw-alias-label-tertiary);font-family:var(--ds-font-family-code);font-size:13px;line-height:20px;word-break:break-all}",
				".dsha_actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:14px 16px;flex-wrap:wrap}",
				".dsha_ellipsis{display:inline-block;max-width:32ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}",
				".dsha_notice{padding:0 16px 10px;font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary)}",
				".dsha_hint{padding:0 16px 10px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}",
				".dsha_meta{display:flex;flex-wrap:wrap;gap:4px 16px;padding:6px 16px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}",
				".dsha_log{display:flex;flex-direction:column;height:100%;min-height:0;width:100%;box-sizing:border-box;overflow:hidden;color:var(--dsw-alias-label-primary);background:var(--dsw-alias-bg-layer-1)}",
				".dsha_logBar{display:flex;align-items:center;gap:12px;flex:0 0 auto;padding:10px 16px;border-bottom:1px solid var(--dsw-alias-border-l1)}",
				".dsha_logTitle{font-size:14px;font-weight:500;line-height:22px}",
				".dsha_logCount{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary)}",
				".dsha_logSpacer{flex:1}",
				".dsha_logList{flex:1;min-height:0;overflow-y:auto;padding:12px 16px calc(var(--dsh-composer-height,152px) + 16px)}",
				".dsha_logNote{padding:24px 4px;font-size:13px;line-height:20px;color:var(--dsw-alias-label-secondary)}",
				".dsha_logRow{display:flex;flex-direction:column;gap:4px;padding:10px 12px;border:1px solid var(--dsw-alias-border-l1);border-radius:12px;background:var(--dsw-alias-bg-layer-2)}",
				".dsha_logRow+.dsha_logRow{margin-top:8px}",
				".dsha_logTop{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap}",
				".dsha_logTime{font-size:12px;line-height:16px;color:var(--dsw-alias-label-secondary);font-variant-numeric:tabular-nums}",
				".dsha_logBadge{font-size:12px;line-height:16px;padding:1px 8px;border:1px solid currentColor;border-radius:999px;white-space:nowrap}",
				// 同一来源在对话与轨迹里必须是同一个颜色:这里的取值与
				// ORIGIN_TONES 一一对应(人工=琥珀、自动复核=品牌蓝)。
				".dsha_logBadge[data-origin=human]{color:var(--dsw-alias-state-warn-primary)}",
				".dsha_logBadge[data-origin=rule]{color:var(--dsw-alias-state-success-primary)}",
				".dsha_logBadge[data-origin=auto-review]{color:var(--dsw-alias-brand-primary-new-colorprimary-new-color)}",
				".dsha_logBadge[data-origin=policy]{color:var(--dsw-alias-state-error-primary)}",
				".dsha_logBadge[data-origin=baseline],.dsha_logBadge[data-origin=legacy]{color:var(--dsw-alias-label-secondary)}",
				".dsha_logCommand{font-family:var(--ds-font-family-code);font-size:13px;line-height:20px;word-break:break-all}",
				".dsha_logDetail{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);word-break:break-all}",
				".dsha_logReason{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}",
				".dsha_decision{display:flex;align-items:baseline;gap:8px;flex-wrap:wrap;padding:6px 0;font-size:12px;line-height:18px}",
				".dsha_decisionEmoji{flex:0 0 auto;font-size:12px;line-height:18px}",
				".dsha_decisionCommand{font-family:var(--ds-font-family-code);font-size:12px;line-height:18px;word-break:break-all}",
				".dsha_decisionDetail{color:var(--dsw-alias-label-secondary);word-break:break-all}"
			].join("");
			document.head.appendChild(tag);
		}
		//#endregion

		//#region locale
		const NS = "dshAllow";
		const zh = {
			waiting: "需要文件权限",
			reject: "拒绝",
			allowOnce: "允许一次",
			alwaysAllow: "总是允许",
			remembering: "正在记住…",
			rememberFailed: "没记住:{message}",
			cannotRemember: "这次没法记住，只能用「允许一次」:{reason}",
			operation: "操作",
			path: "路径",
			command: "命令",
			mode: "沙箱:{mode}",
			cwd: "工作目录:{cwd}",
			escalation: "需要批准:{toolName}",
			unknownHint: "这行里有看不清的部分(内联代码、变量等)，系统层沙箱照样拦得住越界操作。",
			detailAria: "权限请求详情",
			viewAllowLog: "审批",
			logTitle: "审批记录",
			logScope: "只看当前会话",
			logShowBaseline: "显示默认放行",
			logHideBaseline: "隐藏默认放行",
			logLoading: "正在读取…",
			logEmpty: "这个会话还没有需要审批的记录。",
			logError: "读取审批记录失败:{message}",
			logTruncated: "只显示最近 {count} 条。",
			logOriginRule: "规则放行",
			logOriginBaseline: "默认放行",
			logOriginAutoReview: "自动审核放行",
			logOriginHuman: "人工",
			logOriginPolicy: "策略拒绝",
			logOriginLegacy: "早期记录",
			logAllowOnce: "允许一次",
			logAlwaysAllow: "总是允许",
			logDeny: "拒绝",
			logCancelled: "已取消",
			logUnavailable: "无人应答",
			logStoredRules: "写入规则:{rules}",
			logReviewer: "自动审核:{verdict}({latency} ms，{route})",
			logPaths: "路径:{paths}",
			logToolRules: "工具规则:{rules}"
		};
		const en = {
			waiting: "Filesystem permission required",
			reject: "Deny",
			allowOnce: "Allow once",
			alwaysAllow: "Always allow",
			remembering: "Remembering…",
			rememberFailed: "Not remembered: {message}",
			cannotRemember: "This cannot be remembered; only \u201callow once\u201d is available: {reason}",
			operation: "Operation",
			path: "Path",
			command: "Command",
			mode: "Sandbox: {mode}",
			cwd: "Working directory: {cwd}",
			escalation: "Approval required: {toolName}",
			unknownHint: "Part of this line cannot be read (inline code, variables); the OS sandbox still fences what it touches.",
			detailAria: "Approval request detail",
			viewAllowLog: "Approvals",
			logTitle: "Approval ledger",
			logScope: "This session only",
			logShowBaseline: "Show default allows",
			logHideBaseline: "Hide default allows",
			logLoading: "Reading…",
			logEmpty: "No approval decisions in this session yet.",
			logError: "Could not read the approval ledger: {message}",
			logTruncated: "Showing the {count} most recent records.",
			logOriginRule: "Rule",
			logOriginBaseline: "Default",
			logOriginAutoReview: "Auto-reviewed",
			logOriginHuman: "Human",
			logOriginPolicy: "Policy refusal",
			logOriginLegacy: "Earlier record",
			logAllowOnce: "allowed once",
			logAlwaysAllow: "always allowed",
			logDeny: "denied",
			logCancelled: "cancelled",
			logUnavailable: "no answerer",
			logStoredRules: "Rules stored: {rules}",
			logReviewer: "Auto review: {verdict} ({latency} ms, {route})",
			logPaths: "Paths: {paths}",
			logToolRules: "Tool rules: {rules}"
		};
		//#endregion

		/** 宿主在提权请求的 reason 上打的标记。 */
		const ESCALATION = /^escalate sandbox to [a-z-]+:/u;
		const POLICY_REASON = "dsh-allow: ";
		/**
		 * 这些工具的提权请求本身就是一次「工具操作」,所以宿主能把它记成
		 * 工具操作规则(而不是进程围栏),卡片可以给「总是允许」。
		 */
		const REMEMBERABLE_TOOLS = new Set(["plugin_manager"]);

		/**
		 * 这条待审批是不是由本插件接管(提权请求,或权限策略的询问)。
		 * @param pending - composer 上的待处理交互。
		 * @returns 命中的待审批对象,否则 null。
		 */
		function escalationOf(pending) {
			if (pending === null || pending === undefined) return null;
			if (pending.kind !== "approval") return null;
			if (typeof pending.reason !== "string") return null;
			if (ESCALATION.test(pending.reason) || pending.reason.startsWith(POLICY_REASON)) return pending;
			return null;
		}

		/**
		 * 这条待审批是不是权限策略的询问(而不是沙箱提权)。只有它带得出可记住的文件规则。
		 * @param pending - composer 上的待处理交互。
		 * @returns 是则为 true。
		 */
		function isPolicyAsk(pending) {
			return pending !== null && pending !== undefined
				&& typeof pending.reason === "string"
				&& pending.reason.startsWith(POLICY_REASON);
		}

		/**
		 * 这条待审批是不是一次「工具操作」的提权(某个受管工具要求更宽的进程围栏)。
		 * 它的参数由宿主从会话日志读回,所以记住的是「工具 + 动作 [+ 目标]」,
		 * 而不是任何文件路径。
		 * @param pending - composer 上的待处理交互。
		 * @returns 是则为 true。
		 */
		function isToolAsk(pending) {
			return pending !== null && pending !== undefined
				&& typeof pending.toolName === "string"
				&& REMEMBERABLE_TOOLS.has(pending.toolName)
				&& typeof pending.reason === "string"
				&& ESCALATION.test(pending.reason);
		}

		/**
		 * Shorten one display string, keeping the head and marking the cut.
		 * @param text - full text.
		 * @param max - longest accepted length.
		 * @returns the text, truncated with an ellipsis when needed.
		 */
		function shorten(text, max) {
			return text.length <= max ? text : text.slice(0, max - 1) + "\u2026";
		}

		/**
		 * 同款审批卡片 + 文件权限出口。
		 * @param props.matched - 命中的待审批(Remote waterfall 的本次请求)。
		 * @param props.t - 由 `locale: NS` 注入的翻译函数。
		 */
		function AllowPanel(props) {
			const pending = props.matched;
			const t = props.t;
			const [answered, setAnswered] = React.useState(false);
			const [busy, setBusy] = React.useState(null);
			const [error, setError] = React.useState(null);

			const answer = (outcome) => {
				setAnswered(true);
				void pending.answer(outcome).catch(() => { setAnswered(false); });
			};

			/**
			 * 「总是允许」:走会话命令通道让宿主写入这次命中的最窄规则,成功后再以
			 * allowed-once 结束审批。规则由宿主从它自己的待审批记录推导,浏览器半
			 * 不需要知道内容,也就不需要任何宿主接口。
			 */
			const remember = () => {
				setBusy("remember");
				setError(null);
				void (async () => {
					try {
						const result = await props.remember(pending.sessionId, pending.callId);
						if (result === undefined || result.ok !== true) {
							throw new Error(result?.error?.message ?? "宿主没有受理这次记住请求");
						}
						if (result.value?.matched !== true) {
							throw new Error("宿主没有受理 /allow remember");
						}
						answer("allowed-once");
					} catch (cause) {
						setBusy(null);
						setError(cause && cause.message ? cause.message : String(cause));
					}
				})();
			};

			const disabled = answered || busy !== null;
			const buttons = [
				React.createElement(primitives.Button, {
					key: "reject",
					variant: "outline",
					disabled: disabled,
					onClick: () => { answer("rejected"); }
				}, t("reject"))
			];
			// 「总是允许」对两类询问开放:权限策略的询问(记住文件规则),以及受管工具
			// 的提权请求(记住「工具 + 动作 [+ 目标]」)。单纯的沙箱提权要的是更宽的
			// 进程围栏,那不是权限库能记住的东西,所以只有拒绝 / 允许一次。
			if (isPolicyAsk(pending) || isToolAsk(pending)) {
				buttons.push(React.createElement(primitives.Button, {
					key: "always",
					variant: "outline",
					disabled: disabled,
					onClick: remember
				}, busy === "remember" ? t("remembering") : t("alwaysAllow")));
			}
			// 「允许一次」不经宿主接口:approval waterfall 的返回值本身就是答案,
			// 宿主那一半观察到 allowed-once 时自行授予本次命令所需的能力。
			buttons.push(React.createElement(primitives.Button, {
				key: "once",
				variant: "primary",
				disabled: disabled,
				onClick: () => { answer("allowed-once"); }
			}, t("allowOnce")));

			return React.createElement("div", { className: "dsha_root", "data-approval-key": pending.key },
				React.createElement("div", { className: "dsha_card" },
					React.createElement("div", { className: "dsha_strip" },
						React.createElement("span", { className: "dsha_dot" }),
						t("waiting")),
					React.createElement("div", { className: "dsha_body", tabIndex: 0, role: "group", "aria-label": t("detailAria") },
						React.createElement("div", { className: "dsha_headline" },
							typeof pending.reason === "string" && pending.reason !== "" ? pending.reason : t("escalation", { toolName: pending.toolName }))),
					error === null ? null : React.createElement("div", { className: "dsha_notice" }, t("rememberFailed", { message: error })),
					React.createElement("div", { className: "dsha_actions" }, buttons)));
		}


		//#region decisions
		/** 宿主给每条策略决定写下的会话事件类型。 */
		const DECISION_EVENT = "dsh-allow/decision";
		/** 记录来源的分类文案。 */
		const ORIGIN_KEYS = {
			rule: "logOriginRule",
			baseline: "logOriginBaseline",
			"auto-review": "logOriginAutoReview",
			human: "logOriginHuman",
			policy: "logOriginPolicy",
			legacy: "logOriginLegacy"
		};
		/**
		 * 来源 → 轨迹标签的色调。轨迹侧只提供这套封闭语义,配色由它自己拥有,
		 * 所以这里给的是「该有多醒目」,不是颜色。
		 */
		const ORIGIN_TONES = {
			rule: "positive",
			baseline: "neutral",
			"auto-review": "accent",
			human: "warning",
			policy: "critical",
			legacy: "neutral"
		};
		/** 人工动作的文案;自动记录没有 action,按 origin 归类即可。 */
		const ACTION_KEYS = {
			"allow-once": "logAllowOnce",
			"always-allow": "logAlwaysAllow",
			deny: "logDeny",
			cancelled: "logCancelled",
			unavailable: "logUnavailable"
		};
		/**
		 * 一行决定前面的符号。颜色只能分出「来源」,而「允许一次」和「总是允许」
		 * 来源相同,所以符号按动作优先、来源兜底 —— 扫一眼就能分清是哪一类。
		 */
		const ACTION_EMOJI = {
			"allow-once": "✅",
			"always-allow": "♾️",
			deny: "🚫",
			cancelled: "↩️",
			unavailable: "⌛"
		};
		/** 没有人工动作时的符号(规则放行、默认放行、自动复核、插件自拒)。 */
		const ORIGIN_EMOJI = {
			rule: "📋",
			baseline: "⚪",
			"auto-review": "🤖",
			human: "👤",
			policy: "🚫",
			legacy: "•"
		};

		/**
		 * 一条决定该配哪个符号。
		 * @param record - 宿主写下的审计记录。
		 * @returns 一个符号。
		 */
		function decisionEmoji(record) {
			return ACTION_EMOJI[record.action]
				?? ORIGIN_EMOJI[originOfRecord(record)]
				?? ORIGIN_EMOJI.legacy;
		}

		/**
		 * 一条决定在 Chat 流里的身份:一个事件一行,seq 就是它的稳定身份,
		 * 所以同一次调用的「询问」和「人工答复」各占一行,重放时也各归各位。
		 * @param event - 会话事件。
		 * @returns 该事件的渲染标识。
		 */
		function decisionIdOf(event) {
			return "allow:" + String(event.seq);
		}

		/**
		 * 一条审计记录的来源分类;这个字段之前写下的记录归为 legacy。
		 * @param record - 宿主写下的审计记录。
		 * @returns 来源分类。
		 */
		function originOfRecord(record) {
			return typeof record.origin === "string" ? record.origin : "legacy";
		}

		/**
		 * 一条决定的标签字典键:人工动作优先,自动记录按来源归类。
		 * @param record - 宿主写下的审计记录。
		 * @returns 本命名空间里的字典键。
		 */
		function decisionLabelKey(record) {
			const origin = originOfRecord(record);
			return ACTION_KEYS[record.action]
				?? (ORIGIN_KEYS[origin] === undefined ? "logOriginLegacy" : ORIGIN_KEYS[origin]);
		}

		/**
		 * 一条决定在轨迹账本里的一行摘要:符号 + 本地化标签 + 命令(或原因)。
		 * @param record - 宿主写下的审计记录。
		 * @param translate - 本命名空间的翻译函数。
		 * @returns 一行摘要文本。
		 */
		function decisionSummary(record, translate) {
			const head = decisionEmoji(record) + " " + translate(decisionLabelKey(record));
			const said = typeof record.command === "string" && record.command !== ""
				? record.command
				: (typeof record.reason === "string" ? record.reason : "");
			return said === "" ? head : head + " · " + shorten(said, 120);
		}

		/**
		 * 轨迹定义:同一条事件在轨迹账本里占一行。
		 *
		 * 行类型由 ui-trajectory 提供(`extension`),插件只提供文案与负载,所以
		 * 轨迹侧不需要认识任何一个插件的字段。文案在建节点时由本插件的字典生成。
		 * @param translate - 本命名空间在当前语言下的翻译函数。
		 * @returns 轨迹标的的业务定义。
		 */
		function createTrajectoryDefinition(translate) {
			const fold = (match) => ({
				seq: match.event.seq,
				time: typeof match.event.time === "number" ? match.event.time : 0,
				record: match.event.data
			});
			return {
				// Definitions are keyed by kind across every target, so the ledger
				// row carries its own name: the chat kind is the keyed-slot entry
				// the chat renderer dispatches on, and this one only names the row.
				kind: "trajectory-allow-decision",
				target: "trajectory",
				match: (event) => (event.type === DECISION_EVENT
					? { id: decisionIdOf(event), role: "start" }
					: null),
				start: (_context, match) => fold(match),
				update: (context, match) => (match.event.type === DECISION_EVENT ? fold(match) : context.state),
				buildViewNode: (context) => {
					const current = context.state;
					if (current === undefined) return null;
					return {
						key: context.key,
						kind: context.kind,
						id: context.id,
						target: "trajectory",
						anchorSeq: current.seq,
						location: context.start !== undefined && context.start.location !== undefined
							? context.start.location
							: { kind: "unresolved" },
						data: {
							kind: "node",
							node: {
								kind: "extension",
								seq: current.seq,
								time: current.time,
								key: DECISION_EVENT,
								text: decisionSummary(current.record, translate),
								value: current.record,
								tone: ORIGIN_TONES[originOfRecord(current.record)] ?? "neutral"
							}
						}
					};
				}
			};
		}

		/**
		 * 一条策略决定的紧凑行:来源徽章 + 命令(或原因) + 细节。
		 * @param props.node - 本行对应的 Chat Node,负载是宿主写下的审计记录。
		 * @param props.t - 本命名空间的翻译函数。
		 * @returns 这一行的元素。
		 */
		function AllowDecisionRow(props) {
			const t = props.t;
			const record = props.node !== undefined && props.node !== null && typeof props.node.data === "object" && props.node.data !== null
				? props.node.data
				: {};
			const origin = originOfRecord(record);
			const label = t(decisionLabelKey(record));
			const said = typeof record.command === "string" && record.command !== ""
				? record.command
				: (typeof record.reason === "string" && record.reason !== "" ? record.reason : null);
			const detail = decisionDetail(record, t);
			return React.createElement("div", { className: "dsha_decision" },
				// 与轨迹行同一个符号:两个视图扫一眼是同一套标记。
				React.createElement("span", { className: "dsha_decisionEmoji", "aria-hidden": "true" }, decisionEmoji(record)),
				React.createElement("span", { className: "dsha_logBadge", "data-origin": origin }, label),
				said === null ? null : React.createElement("span", { className: "dsha_decisionCommand" }, shorten(said, 160)),
				detail === null ? null : React.createElement("span", { className: "dsha_decisionDetail" }, detail));
		}

		/**
		 * 一行决定里除命令以外的细节:命中/写入的规则路径、自动复核的判定,
		 * 或这次调用还缺哪些能力。文案全部取自既有字典键。
		 * @param record - 宿主写下的审计记录。
		 * @param t - 本命名空间的翻译函数。
		 * @returns 要显示的细节,没有可说的则为 null。
		 */
		function decisionDetail(record, t) {
			const paths = (entries) => {
				if (!Array.isArray(entries)) return "";
				const seen = [];
				for (const entry of entries) {
					const path = String(entry?.path ?? "");
					if (path !== "" && !seen.includes(path)) seen.push(path);
				}
				return seen.join(", ");
			};
			// 工具操作规则没有路径,标签是「工具 + 动作 [+ 目标]」,所以单独渲染。
			const toolRules = (entries) => {
				if (!Array.isArray(entries)) return "";
				const seen = [];
				for (const entry of entries) {
					if (typeof entry?.tool !== "string") continue;
					const label = String(entry.label
						?? [entry.tool, entry.action, entry.target].filter((part) => typeof part === "string" && part !== "").join(" "));
					if (label !== "" && !seen.includes(label)) seen.push(label);
				}
				return seen.join(", ");
			};
			if (record.origin === "rule") {
				const toolNamed = toolRules(record.matchedRules);
				if (toolNamed !== "") return t("logToolRules", { rules: toolNamed });
				const named = paths(record.matchedRules);
				if (named !== "") return t("logPaths", { paths: named });
			}
			if (record.action === "always-allow") {
				const toolStored = toolRules(record.rules);
				if (toolStored !== "") return t("logToolRules", { rules: toolStored });
				const stored = paths(record.rules);
				if (stored !== "") return t("logStoredRules", { rules: stored });
			}
			if (record.origin === "auto-review" && record.review !== undefined && record.review !== null) {
				return t("logReviewer", {
					verdict: String(record.review.verdict ?? ""),
					latency: String(record.review.latencyMs ?? ""),
					route: String(record.review.route ?? "")
				});
			}
			const missing = Array.isArray(record.missing)
				? record.missing
					.map((entry) => String(entry?.operation ?? "") + " " + String(entry?.path ?? ""))
					.join(", ")
					.trim()
				: "";
			return missing === "" ? null : missing;
		}

		/**
		 * Chat 业务定义:把宿主的每条 `dsh-allow/decision` 事件折成一行,紧挨着
		 * 它所回答的那次工具调用。事件是 log-only(非 surface)的,所以这条路
		 * 既不进模型上下文,也不需要任何宿主接口。
		 */
		const allowDecisionDefinition = {
			kind: "allow-decision",
			target: "chat",
			match: (event) => (event.type === DECISION_EVENT
				? { id: decisionIdOf(event), role: "start" }
				: null),
			start: (_context, match) => ({ seq: match.event.seq, record: match.event.data }),
			update: (context, match) => (match.event.type === DECISION_EVENT
				? { seq: match.event.seq, record: match.event.data }
				: context.state),
			buildViewNode: (context) => {
				const state = context.state;
				if (state === undefined) return null;
				return {
					key: context.key,
					kind: "allow-decision",
					id: context.id,
					target: "chat",
					anchorSeq: state.seq,
					location: context.start !== undefined && context.start.location !== undefined
						? context.start.location
						: { kind: "unresolved" },
					visibility: "visible",
					data: state.record
				};
			}
		};
		//#endregion

		//#region plugin
		const inject = ["slots", "locale", "sessions", "uiConversation"];

		/** 注册字典、同款审批卡片,以及每条策略决定在对话流里的一行。 */
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register(NS, { zh, en }), "dsh-allow: dictionaries");
			// 每条决定都由宿主写进会话日志,这里把那条事件折成一行,渲染在它回答的
			// 工具调用旁边 —— 数据全程来自事件流,没有宿主接口参与。
			ctx.effect(() => ctx.uiConversation.events.register(allowDecisionDefinition), "dsh-allow: decision definition");
			// 同一条事件再进轨迹账本一份:轨迹的行类型由宿主提供,文案由本插件的字典生成。
			ctx.effect(() => ctx.uiConversation.events.register(
				createTrajectoryDefinition((key, params) => ctx.locale.bind(NS)(key, params))
			), "dsh-allow: trajectory definition");
			ctx.slots.inject("conversation.chat.node", () => {
				const dispose = ctx.slots.register({
					name: "conversation.chat.node",
					key: "allow-decision",
					locale: NS
				}, AllowDecisionRow);
				return () => { dispose(); };
			});
			// priority 0 排在内置审批卡片(priority 1)之前:本插件接管的审批由本卡片渲染,
			// 其它审批 select 返回 null,链继续走到内置卡片。
			ctx.slots.inject("conversation.composer", () => {
				const dispose = ctx.slots.register({
					name: "conversation.composer",
					priority: 0,
					select: ({ pendingInteraction }) => escalationOf(pendingInteraction),
					locale: NS,
					// 记住动作走会话命令通道,由宿主写入它自己推导出的规则。
					inject: () => ({
						remember: (sessionId, callId) => {
							const binding = ctx.sessions.binding(sessionId);
							if (binding === undefined) {
								return Promise.resolve({
									ok: false,
									error: { code: "NO_SESSION", message: "这个会话还没有物化" }
								});
							}
							return binding.session.command("/allow remember " + callId);
						}
					})
				}, AllowPanel);
				return () => { dispose(); };
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		// 供离线冒烟测试使用。
		exports.escalationOf = escalationOf;
		exports.isPolicyAsk = isPolicyAsk;
		exports.isToolAsk = isToolAsk;
		exports.shorten = shorten;
		exports.AllowPanel = AllowPanel;
		exports.AllowDecisionRow = AllowDecisionRow;
		exports.allowDecisionDefinition = allowDecisionDefinition;
		exports.createTrajectoryDefinition = createTrajectoryDefinition;
		exports.DECISION_EVENT = DECISION_EVENT;
		//#endregion

		return module.exports;
	}
});
