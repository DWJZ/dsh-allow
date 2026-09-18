/**
 * dsh-allow — browser half (lazy-CJS 客户端 bundle)。
 *
 * 在 `conversation.composer` 这条 chain 上以更高优先级(priority 0 < 内置的 1)
 * 注册一张**同款审批卡片**,只接管沙箱提权请求(靠 reason 里
 * `escalate sandbox to <mode>:` 前缀识别),其它审批原样落到内置卡片。
 *
 * 卡片除了「拒绝 / 允许一次」,多一个「总是允许「<前缀>」开头的命令」:
 * 点击时先 POST `/dsh-allow/remember`(宿主按 callId 查出命令与前缀并写入规则),
 * 成功后再以 `allowed-once` 结束这次审批 —— 于是这一次继续执行,以后同类命令
 * 由宿主的规则匹配直接放行,连卡片都不会出现。
 *
 * 样式逐条照抄 `ui-approval` 的 ApprovalPanel.module.css(用内联 <style> 注入),
 * 所以外观与内置卡片一致;命令文本来自 `/dsh-allow/pending`。
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
				".dsha_headline{color:var(--dsw-alias-label-primary);font-size:15px;font-weight:500;line-height:24px}",
				".dsha_command{color:var(--dsw-alias-label-tertiary);font-family:var(--ds-font-family-code);font-size:13px;line-height:20px;word-break:break-all}",
				".dsha_actions{display:flex;justify-content:flex-end;align-items:center;gap:8px;padding:14px 16px;flex-wrap:nowrap}",
				".dsha_ellipsis{display:inline-block;max-width:42ch;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;vertical-align:bottom}",
				".dsha_notice{padding:0 16px 10px;font-size:12px;line-height:18px;color:var(--dsw-alias-state-error-primary)}",
				".dsha_hint{padding:0 16px 10px;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}",
				".dsha_meta{display:flex;flex-wrap:wrap;gap:4px 16px;padding:6px 16px 0;font-size:12px;line-height:18px;color:var(--dsw-alias-label-tertiary)}"
			].join("");
			document.head.appendChild(tag);
		}
		//#endregion

		//#region locale
		const NS = "dshAllow";
		const zh = {
			waiting: "等待审批",
			reject: "拒绝",
			allowOnce: "允许一次",
			alwaysOne: "总是允许「{rule}」开头的命令",
			alwaysMany: "总是允许 {rules} 这类命令",
			alwaysExact: "总是允许这条完全相同的命令",
			remembering: "正在记住…",
			rememberFailed: "没记住:{message}",
			cannotRemember: "这条命令不会被记住:{reason}",
			partialHint: "这行里含不可记忆的部分(内联代码等),它每次都会问;这个按钮只记住其余命令。",
			pinHint: "这个按钮会记住这条完全相同的命令,并把其中可解析的部分也记成规则。",
			risk: "风险:{risk}",
			cwd: "工作目录:{cwd}",
			escalation: "需要批准:{toolName}",
			detailAria: "权限请求详情"
		};
		const en = {
			waiting: "Waiting for approval",
			reject: "Reject",
			allowOnce: "Allow once",
			alwaysOne: "Always allow commands starting with \u201c{rule}\u201d",
			alwaysMany: "Always allow commands like {rules}",
			alwaysExact: "Always allow this exact command",
			remembering: "Remembering…",
			rememberFailed: "Not remembered: {message}",
			cannotRemember: "This command cannot be remembered: {reason}",
			partialHint: "Part of this line can never be remembered (inline code and the like) and keeps asking; this button only stores the rest.",
			pinHint: "This button stores this exact command, plus a rule for each part of it that can be named.",
			risk: "Risk: {risk}",
			cwd: "Working directory: {cwd}",
			escalation: "Approval required: {toolName}",
			detailAria: "Approval request detail"
		};
		//#endregion

		/** 宿主在提权请求的 reason 上打的标记。 */
		const ESCALATION = /^escalate sandbox to [a-z-]+:/u;
		const POLICY_REASON = "dsh-allow: ";

		/**
		 * 这条待审批是不是沙箱提权(只有提权才由本插件接管)。
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
		 * 「总是允许」按钮上的文案(把将要记住的前缀念出来)。
		 * @param t - 本命名空间的翻译函数。
		 * @param prefix - 宿主推导出的命令前缀。
		 * @returns 按钮文字。
		 */
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
		 * Name the rules one button would store, capped so a long list stays one line.
		 * @param t - namespace translator.
		 * @param labels - rule descriptions.
		 * @returns the button label.
		 */
		function alwaysLabelText(t, labels, exact) {
			if (exact === true) return t("alwaysExact");
			if (labels.length <= 3) return alwaysLabel(t, labels);
			return t("alwaysMany", { rules: labels.slice(0, 3).join(" + ") + " +" + String(labels.length - 3) + "\u2026" });
		}

		function alwaysLabel(t, labels) {
			if (labels.length === 1) return t("alwaysOne", { rule: labels[0] });
			return t("alwaysMany", { rules: labels.join(" + ") });
		}

		/** 读取这次提权的命令与前缀;失败返回 null(卡片退化成内置的两按钮)。 */
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
		 * 同款审批卡片 + 「总是允许这类命令」。
		 * @param props.matched - 命中的待审批(Remote waterfall 的本次请求)。
		 * @param props.t - 由 `locale: NS` 注入的翻译函数。
		 */
		function AllowPanel(props) {
			const pending = props.matched;
			const t = props.t;
			const [info, setInfo] = React.useState(null);
			const [answered, setAnswered] = React.useState(false);
			const [busy, setBusy] = React.useState(false);
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

			const rememberThenAllow = () => {
				setBusy(true);
				setError(null);
				void (async () => {
					try {
						const response = await fetch("/dsh-allow/remember", {
							method: "POST",
							headers: { "content-type": "application/json" },
							body: JSON.stringify({ sessionId: pending.sessionId, callId: pending.callId })
						});
						const data = await response.json().catch(() => null);
						if (!response.ok || data?.ok !== true) {
							throw new Error(data?.error ?? ("HTTP " + String(response.status)));
						}
						answer("allowed-once");
					} catch (cause) {
						setBusy(false);
						setError(cause && cause.message ? cause.message : String(cause));
					}
				})();
			};

			const disabled = answered || busy;
			const buttons = [
				React.createElement(primitives.Button, {
					key: "reject",
					variant: "outline",
					disabled: disabled,
					onClick: () => { answer("rejected"); }
				}, t("reject"))
			];
			const labels = info === null || !Array.isArray(info.labels) ? [] : info.labels;
			if (info !== null && info.rememberable === true && labels.length > 0) {
				buttons.push(React.createElement(primitives.Button, {
					key: "always",
					variant: "outline",
					disabled: disabled,
					title: info.command,
					onClick: rememberThenAllow
				}, busy
					? t("remembering")
					: React.createElement("span", { className: "dsha_ellipsis" }, shorten(alwaysLabelText(t, labels), 56))));
			}
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
							typeof pending.reason === "string" && pending.reason !== "" ? pending.reason : t("escalation", { toolName: pending.toolName })),
						info === null ? null : React.createElement("div", { className: "dsha_command" }, info.command),
						info === null ? null : React.createElement("div", { className: "dsha_meta" },
							React.createElement("span", null, t("risk", { risk: info.risk })),
							React.createElement("span", null, t("cwd", { cwd: info.cwd })))),
					error === null ? null : React.createElement("div", { className: "dsha_notice" }, t("rememberFailed", { message: error })),
					info !== null && info.partial === true
						? React.createElement("div", { className: "dsha_hint" }, t("partialHint"))
						: null,
					info !== null && info.pinsLine === true && labels.length > 0
						? React.createElement("div", { className: "dsha_hint" }, t("pinHint"))
						: null,
					info !== null && info.rememberable !== true
						? React.createElement("div", { className: "dsha_hint" }, t("cannotRemember", { reason: info.reason }))
						: null,
					React.createElement("div", { className: "dsha_actions" }, buttons)));
		}

		//#region plugin
		const inject = ["slots", "locale"];

		/** 注册字典与同款审批卡片。 */
		function apply(ctx) {
			ctx.effect(() => ctx.locale.register(NS, { zh, en }), "dsh-allow: dictionaries");
			// priority 0 排在内置审批卡片(priority 1)之前:提权请求由本卡片渲染,
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
		}

		exports.apply = apply;
		exports.inject = inject;
		// 供离线冒烟测试使用。
		exports.escalationOf = escalationOf;
		exports.alwaysLabel = alwaysLabel;
		exports.alwaysLabelText = alwaysLabelText;
		exports.shorten = shorten;
		exports.AllowPanel = AllowPanel;
		//#endregion

		return module.exports;
	}
});
