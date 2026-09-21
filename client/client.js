/**
 * dsh-allow — browser half (lazy-CJS 客户端 bundle)。
 *
 * 在 `conversation.composer` 这条 chain 上以更高优先级(priority 0 < 内置的 1)
 * 注册一张**同款审批卡片**,接管两类审批:
 *
 *   - 沙箱提权请求(reason 里 `escalate sandbox to <mode>:`)
 *   - 本插件权限策略的询问(reason 里 `dsh-allow: ` 前缀)
 *
 * 卡片回答的是「缺哪个文件权限」:操作(operation)、路径(path)、命令(command),
 * 以及三个出口 —— 拒绝 / 总是允许(写持久规则) / 允许一次(只写会话规则)。
 * 宿主在 `/dsh-allow/pending` 上给出这次缺什么、能记住什么。
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
				".dsha_logBadge[data-origin=human]{color:var(--dsw-alias-brand-primary)}",
				".dsha_logBadge[data-origin=rule]{color:var(--dsw-alias-state-success-primary)}",
				".dsha_logBadge[data-origin=auto-review]{color:var(--dsw-alias-state-success-primary)}",
				".dsha_logBadge[data-origin=policy]{color:var(--dsw-alias-state-error-primary)}",
				".dsha_logBadge[data-origin=baseline],.dsha_logBadge[data-origin=legacy]{color:var(--dsw-alias-label-secondary)}",
				".dsha_logCommand{font-family:var(--ds-font-family-code);font-size:13px;line-height:20px;word-break:break-all}",
				".dsha_logDetail{font-size:12px;line-height:18px;color:var(--dsw-alias-label-secondary);word-break:break-all}",
				".dsha_logReason{font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}"
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
			alwaysOne: "总是允许：{rule}",
			alwaysMany: "总是允许 {rules}",
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
			logPaths: "路径:{paths}"
		};
		const en = {
			waiting: "Filesystem permission required",
			reject: "Deny",
			allowOnce: "Allow once",
			alwaysOne: "Always allow: {rule}",
			alwaysMany: "Always allow {rules}",
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
			logPaths: "Paths: {paths}"
		};
		//#endregion

		/** 宿主在提权请求的 reason 上打的标记。 */
		const ESCALATION = /^escalate sandbox to [a-z-]+:/u;
		const POLICY_REASON = "dsh-allow: ";

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
		 * Shorten one display string, keeping the head and marking the cut.
		 * @param text - full text.
		 * @param max - longest accepted length.
		 * @returns the text, truncated with an ellipsis when needed.
		 */
		function shorten(text, max) {
			return text.length <= max ? text : text.slice(0, max - 1) + "\u2026";
		}

		/**
		 * 「总是允许」按钮上的文案:把这次会写入的规则念出来(最多 3 条,再多给数量)。
		 * @param t - 本命名空间的翻译函数。
		 * @param suggestions - 宿主给出的最窄规则。
		 * @returns 按钮文字。
		 */
		function alwaysText(t, suggestions) {
			const labels = suggestions.map((suggestion) => suggestion.label);
			if (labels.length === 1) return t("alwaysOne", { rule: labels[0] });
			const head = labels.length <= 3 ? labels.join(" + ") : labels.slice(0, 3).join(" + ") + " +" + String(labels.length - 3) + "\u2026";
			return t("alwaysMany", { rules: head });
		}

		/** 读取这次审批缺什么、能记住什么;失败返回 null(卡片退化成两按钮)。 */
		async function readPending(pending) {
			if (typeof pending.sessionId !== "string" || typeof pending.callId !== "string") return null;
			try {
				const query = "?sessionId=" + encodeURIComponent(pending.sessionId) + "&callId=" + encodeURIComponent(pending.callId);
				const response = await fetch("/dsh-allow/pending" + query, {
					cache: "no-store",
					headers: { accept: "application/json" }
				});
				if (!response.ok) return null;
				const data = await response.json();
				return data && data.ok === true ? data : null;
			} catch {
				return null;
			}
		}

		/**
		 * 同款审批卡片 + 文件权限出口。
		 * @param props.matched - 命中的待审批(Remote waterfall 的本次请求)。
		 * @param props.t - 由 `locale: NS` 注入的翻译函数。
		 */
		function AllowPanel(props) {
			const pending = props.matched;
			const t = props.t;
			const [info, setInfo] = React.useState(null);
			const [answered, setAnswered] = React.useState(false);
			const [busy, setBusy] = React.useState(null);
			const [error, setError] = React.useState(null);

			React.useEffect(() => {
				let cancelled = false;
				void readPending(pending).then((value) => {
					if (!cancelled) setInfo(value);
				});
				return () => { cancelled = true; };
			}, [pending]);

			const answer = (outcome) => {
				setAnswered(true);
				void pending.answer(outcome).catch(() => { setAnswered(false); });
			};

			/** 先调宿主写入/授予,成功后再以 allowed-once 结束这次审批。 */
			const post = (path, body, tag, fallback) => {
				setBusy(tag);
				setError(null);
				void (async () => {
					try {
						const response = await fetch(path, {
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify(Object.assign({
								sessionId: pending.sessionId,
								callId: pending.callId
							}, body))
						});
						if (response.status === 404 || response.status === 405) {
							// 宿主那一半还是旧版本(浏览器半会热更新,宿主半不会):
							// 没有这条路由,就退回到内置的「允许一次」语义。
							if (fallback === true) { answer("allowed-once"); return; }
							throw new Error("HTTP " + String(response.status));
						}
						const data = await response.json().catch(() => null);
						if (!response.ok || data?.ok !== true) {
							throw new Error(data?.error ?? ("HTTP " + String(response.status)));
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
			const suggestions = info === null || !Array.isArray(info.suggestions) ? [] : info.suggestions;
			if (info !== null && info.rememberable === true && suggestions.length > 0) {
				// 只有一个「总是允许」按钮:写入的就是卡片上念出来的那几条最窄规则。
				buttons.push(React.createElement(primitives.Button, {
					key: "always",
					variant: "outline",
					disabled: disabled,
					title: suggestions.map((suggestion) => suggestion.label).join(" + "),
					onClick: () => { post("/dsh-allow/remember", {}, "remember"); }
				}, busy === "remember"
					? t("remembering")
					: React.createElement("span", { className: "dsha_ellipsis" }, shorten(alwaysText(t, suggestions), 48))));
			}
			buttons.push(React.createElement(primitives.Button, {
				key: "once",
				variant: "primary",
				disabled: disabled,
				onClick: () => { post("/dsh-allow/once", {}, "once", true); }
			}, busy === "once" ? t("remembering") : t("allowOnce")));

			const missing = info === null || !Array.isArray(info.missing) ? [] : info.missing;
			const rows = [];
			for (const [index, entry] of missing.entries()) {
				rows.push(React.createElement("div", { className: "dsha_row", key: "op-" + String(index) },
					React.createElement("span", { className: "dsha_key" }, t("operation")),
					React.createElement("span", { className: "dsha_value" }, entry.operation)));
				rows.push(React.createElement("div", { className: "dsha_row", key: "path-" + String(index) },
					React.createElement("span", { className: "dsha_key" }, t("path")),
					React.createElement("span", { className: "dsha_value" }, entry.path)));
			}

			return React.createElement("div", { className: "dsha_root", "data-approval-key": pending.key },
				React.createElement("div", { className: "dsha_card" },
					React.createElement("div", { className: "dsha_strip" },
						React.createElement("span", { className: "dsha_dot" }),
						t("waiting")),
					React.createElement("div", { className: "dsha_body", tabIndex: 0, role: "group", "aria-label": t("detailAria") },
						React.createElement("div", { className: "dsha_headline" },
							typeof pending.reason === "string" && pending.reason !== "" ? pending.reason : t("escalation", { toolName: pending.toolName })),
						rows.length > 0 ? rows : null,
						info === null ? null : React.createElement("div", { className: "dsha_row" },
							React.createElement("span", { className: "dsha_key" }, t("command")),
							React.createElement("span", { className: "dsha_command" }, info.command)),
						info === null ? null : React.createElement("div", { className: "dsha_meta" },
							React.createElement("span", null, t("mode", { mode: info.mode === null || info.mode === undefined ? "unknown" : info.mode })),
							React.createElement("span", null, t("cwd", { cwd: info.cwd })))),
					error === null ? null : React.createElement("div", { className: "dsha_notice" }, t("rememberFailed", { message: error })),
					info !== null && Array.isArray(info.unknown) && info.unknown.length > 0
						? React.createElement("div", { className: "dsha_hint" }, t("unknownHint"))
						: null,
					info !== null && info.rememberable !== true
						? React.createElement("div", { className: "dsha_hint" }, t("cannotRemember", { reason: info.reason }))
						: null,
					React.createElement("div", { className: "dsha_actions" }, buttons)));
		}

		//#region approval ledger
		/** 审批记录标签页的轮询间隔(毫秒)。 */
		const LOG_POLL_MS = 3000;
		/** 一次向宿主拉取的记录条数。 */
		const LOG_PAGE_LIMIT = 200;
		/** 来源分类的权重:同一个 callId 上更权威的记录会取代较弱的。 */
		const ORIGIN_RANK = { human: 4, "auto-review": 3, policy: 2, rule: 1, baseline: 0, legacy: 0 };
		const ORIGIN_LABEL = {
			rule: "logOriginRule",
			baseline: "logOriginBaseline",
			"auto-review": "logOriginAutoReview",
			human: "logOriginHuman",
			policy: "logOriginPolicy",
			legacy: "logOriginLegacy"
		};
		const ACTION_LABEL = {
			"allow-once": "logAllowOnce",
			"always-allow": "logAlwaysAllow",
			deny: "logDeny",
			cancelled: "logCancelled",
			unavailable: "logUnavailable"
		};

		/**
		 * 读当前会话最近的审批记录。
		 * @param sessionId - 当前会话 id。
		 * @param showBaseline - 是否连默认放行一起要。
		 * @returns 宿主返回的记录与截断标记。
		 */
		async function readLedger(sessionId, showBaseline) {
			const query = "?sessionId=" + encodeURIComponent(sessionId)
				+ "&limit=" + String(LOG_PAGE_LIMIT)
				+ (showBaseline ? "&baseline=1" : "");
			const response = await fetch("/dsh-allow/audit" + query, {
				cache: "no-store",
				headers: { accept: "application/json" }
			});
			if (!response.ok) throw new Error("HTTP " + String(response.status));
			const data = await response.json();
			if (data === null || data.ok !== true) throw new Error("bad answer");
			return {
				entries: Array.isArray(data.entries) ? data.entries : [],
				truncated: data.truncated === true
			};
		}

		/** 一条记录的来源权重。 */
		function rankOf(entry) {
			return ORIGIN_RANK[entry.origin] ?? 0;
		}

		/**
		 * 每个工具调用只留一行:同一 callId 上更权威的记录取代较弱的,行位置保持
		 * 该调用第一次出现的位置,所以轮询到新决策时已有行不会跳动。
		 * @param entries - 宿主返回的记录,由旧到新。
		 * @returns 每行一条的记录。
		 */
		function collapse(entries) {
			const rows = new Map();
			for (const [index, entry] of entries.entries()) {
				const key = typeof entry.callId === "string" && entry.callId !== ""
					? entry.callId
					: "record-" + String(index);
				const previous = rows.get(key);
				if (previous === undefined || rankOf(entry) >= rankOf(previous)) rows.set(key, entry);
			}
			return Array.from(rows.values());
		}

		/** 一行里的时间,读不出来时为空。 */
		function timeOf(entry) {
			const at = typeof entry.at === "string" ? new Date(entry.at) : null;
			return at === null || Number.isNaN(at.getTime()) ? "" : at.toLocaleTimeString();
		}

		/** 一行里点名的路径:优先说缺什么,其次说哪条规则放行的。 */
		function detailOf(entry) {
			const labels = [];
			for (const item of entry.missing ?? []) labels.push(item.operation + " " + (item.path ?? entry.command ?? ""));
			if (labels.length > 0) return labels.join(", ");
			if (entry.origin !== "rule") return "";
			for (const rule of entry.matchedRules ?? []) {
				const access = Object.keys(rule.access ?? {}).join("+");
				labels.push((access === "" ? "" : access + " ") + rule.path);
			}
			return labels.join(", ");
		}

		/** 一行里自动审核那次的结论。 */
		function reviewOf(t, entry) {
			if (entry.review === null || typeof entry.review !== "object") return null;
			return t("logReviewer", {
				verdict: entry.review.verdict ?? "?",
				latency: entry.review.latencyMs === undefined ? "?" : String(entry.review.latencyMs),
				route: entry.review.route ?? "inherit"
			});
		}

		/** 一行里「总是允许」写下的规则。 */
		function storedRulesOf(t, entry) {
			if (entry.action !== "always-allow" || !Array.isArray(entry.rules) || entry.rules.length === 0) return null;
			return t("logStoredRules", { rules: entry.rules.map((rule) => rule.label ?? rule.path).join(" + ") });
		}

		/**
		 * 一行审批记录。
		 * @param props.entry - 一条审计记录。
		 * @param props.t - 本命名空间的翻译函数。
		 */
		function LedgerRow(props) {
			const entry = props.entry;
			const t = props.t;
			const action = ACTION_LABEL[entry.action];
			const detail = detailOf(entry);
			const review = reviewOf(t, entry);
			const stored = storedRulesOf(t, entry);
			const time = timeOf(entry);
			return React.createElement("div", { className: "dsha_logRow" },
				React.createElement("div", { className: "dsha_logTop" },
					time === "" ? null : React.createElement("span", { className: "dsha_logTime" }, time),
					React.createElement("span", { className: "dsha_logBadge", "data-origin": entry.origin },
						ORIGIN_LABEL[entry.origin] === undefined ? entry.origin : t(ORIGIN_LABEL[entry.origin])),
					action === undefined ? null : React.createElement("span", { className: "dsha_logTime" }, t(action))),
				entry.command === null || entry.command === undefined
					? null
					: React.createElement("div", { className: "dsha_logCommand" }, entry.command),
				detail === "" ? null : React.createElement("div", { className: "dsha_logDetail" }, t("logPaths", { paths: detail })),
				stored === null ? null : React.createElement("div", { className: "dsha_logDetail" }, stored),
				review === null ? null : React.createElement("div", { className: "dsha_logDetail" }, review),
				entry.reason === null || entry.reason === undefined
					? null
					: React.createElement("div", { className: "dsha_logReason" }, entry.reason));
		}

		/**
		 * 审批记录标签页:当前会话里每一次决策是谁拍的板。
		 *
		 * 只读,只走宿主那条 loopback 读路由;它不写规则、不回答任何审批。
		 * @param props.sessionId - 当前会话 id。
		 * @param props.t - 由 `locale: NS` 注入的翻译函数。
		 */
		function AllowLogView(props) {
			const t = props.t;
			const sessionId = typeof props.sessionId === "string" ? props.sessionId : null;
			const [state, setState] = React.useState({ status: "loading", entries: [], truncated: false, error: null });
			const [showBaseline, setShowBaseline] = React.useState(false);

			React.useEffect(() => {
				if (sessionId === null) return undefined;
				let cancelled = false;
				const load = () => {
					void readLedger(sessionId, showBaseline).then((answer) => {
						if (!cancelled) {
							setState({ status: "ready", entries: answer.entries, truncated: answer.truncated, error: null });
						}
					}, (cause) => {
						if (!cancelled) {
							setState({
								status: "error",
								entries: [],
								truncated: false,
								error: cause && cause.message ? cause.message : String(cause)
							});
						}
					});
				};
				load();
				const timer = setInterval(load, LOG_POLL_MS);
				return () => {
					cancelled = true;
					clearInterval(timer);
				};
			}, [sessionId, showBaseline]);

			const rows = collapse(state.entries);
			const body = [];
			if (sessionId === null) body.push(React.createElement("div", { className: "dsha_logNote", key: "nosession" }, t("logEmpty")));
			else if (state.status === "loading") body.push(React.createElement("div", { className: "dsha_logNote", key: "loading" }, t("logLoading")));
			else if (state.status === "error") body.push(React.createElement("div", { className: "dsha_logNote", key: "error" }, t("logError", { message: String(state.error) })));
			else if (rows.length === 0) body.push(React.createElement("div", { className: "dsha_logNote", key: "empty" }, t("logEmpty")));
			else {
				for (const [index, entry] of rows.entries()) body.push(React.createElement(LedgerRow, { key: "row-" + String(index), entry, t }));
				if (state.truncated) body.push(React.createElement("div", { className: "dsha_logNote", key: "truncated" }, t("logTruncated", { count: String(rows.length) })));
			}

			return React.createElement("div", { className: "dsha_log" },
				React.createElement("div", { className: "dsha_logBar" },
					React.createElement("span", { className: "dsha_logTitle" }, t("logTitle")),
					React.createElement("span", { className: "dsha_logCount" }, t("logScope")),
					React.createElement("span", { className: "dsha_logSpacer" }),
					React.createElement(primitives.Button, {
						variant: showBaseline ? "primary" : "outline",
						onClick: () => { setShowBaseline(!showBaseline); }
					}, showBaseline ? t("logHideBaseline") : t("logShowBaseline"))),
				React.createElement("div", { className: "dsha_logList" }, body));
		}
		//#endregion

		//#region plugin
		const inject = ["slots", "locale"];

		/** 注册字典、同款审批卡片,以及轨迹旁边的审批记录标签页。 */
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register(NS, { zh, en }), "dsh-allow: dictionaries");
			// priority 0 排在内置审批卡片(priority 1)之前:本插件接管的审批由本卡片渲染,
			// 其它审批 select 返回 null,链继续走到内置卡片。
			ctx.slots.inject("conversation.composer", () => {
				const dispose = ctx.slots.register({
					name: "conversation.composer",
					priority: 0,
					select: ({ pendingInteraction }) => escalationOf(pendingInteraction),
					locale: NS
				}, AllowPanel);
				return () => { dispose(); };
			});
			// 「对话 / 轨迹」旁边的第三个标签页。label 走 thunk,所以跟着当前语言走。
			ctx.slots.inject("conversation.view", () => {
				const t = ctx.locale.bind(NS);
				const dispose = ctx.slots.register({
					name: "conversation.view",
					id: "allow-log",
					order: 20,
					locale: NS,
					label: () => t("viewAllowLog")
				}, AllowLogView);
				return () => { dispose(); };
			});
		}

		exports.apply = apply;
		exports.inject = inject;
		// 供离线冒烟测试使用。
		exports.escalationOf = escalationOf;
		exports.shorten = shorten;
		exports.alwaysText = alwaysText;
		exports.AllowPanel = AllowPanel;
		exports.collapse = collapse;
		exports.detailOf = detailOf;
		exports.AllowLogView = AllowLogView;
		//#endregion

		return module.exports;
	}
});
