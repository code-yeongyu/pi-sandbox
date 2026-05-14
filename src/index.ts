// src/index.ts — Extension factory: pi.registerTool / pi.registerCommand / pi.registerFlag / pi.on(...)

import { createPromptHandler } from "./approvals/prompt.js";
import { ApprovalStore } from "./approvals/store.js";
import { registerSandboxCommand } from "./commands/sandbox.js";
import { registerSandboxAllowCommand } from "./commands/sandbox-allow.js";
import { registerSandboxDenyCommand } from "./commands/sandbox-deny.js";
import { registerSandboxStatusCommand } from "./commands/sandbox-status.js";
import { registerSandboxSwitchCommand } from "./commands/sandbox-switch.js";
import { toAgentContextBlock } from "./explain/render-agent-context.js";
import { reapOrphans } from "./lifecycle/orphan-reaper.js";
import { onSessionShutdown } from "./lifecycle/session-shutdown.js";
import { onSessionStart } from "./lifecycle/session-start.js";
import {
	createBashToolDefinition,
	createEditToolDefinition,
	createReadToolDefinition,
	createWriteToolDefinition,
	type ExtensionAPI,
} from "./pi/index.js";
import type { SandboxManager } from "./sandbox/manager.js";
import { toBashOperations } from "./tools/bash-adapter.js";
import { toEditOperations } from "./tools/edit-adapter.js";
import { toReadOperations } from "./tools/read-adapter.js";
import { toWriteOperations } from "./tools/write-adapter.js";
import { installFooter } from "./tui/footer.js";
import { type InstalledWidget, installWidget } from "./tui/widget.js";

type FlagCapableExtensionAPI = ExtensionAPI & {
	registerFlag?: (
		name: string,
		options: { readonly type: "boolean"; readonly default: boolean; readonly description: string },
	) => void;
};

let manager: SandboxManager | null = null;
let approvalStore: ApprovalStore | null = null;
let disposeFooter: (() => void) | null = null;
let installedWidget: InstalledWidget | null = null;

export default function piSandboxExtension(pi: ExtensionAPI): void {
	const flagCapablePi: FlagCapableExtensionAPI = pi;
	flagCapablePi.registerFlag?.("no-sandbox", {
		type: "boolean",
		default: false,
		description: "Disable pi-sandbox enforcement",
	});

	void reapOrphans().catch(() => undefined);

	pi.on("session_start", async (_event, ctx) => {
		const result = await onSessionStart(pi, ctx);
		if (!result.ok) return;
		manager = result.value;
		approvalStore = new ApprovalStore();
		manager.setCwd(ctx.cwd ?? process.cwd());
		manager.setPromptHandler(createPromptHandler(ctx.ui, approvalStore));
		await manager.reloadEffectivePolicy();
		const uiPi = { ...pi, ui: ctx.ui };
		disposeFooter = installFooter(uiPi, manager);
		installedWidget = installWidget(uiPi, manager);
		installedWidget.update();
		manager.setBlockHandler((block) => installedWidget?.update(block));
		registerSandboxCommand(pi, manager, approvalStore);
		registerSandboxStatusCommand(pi, manager, approvalStore);
		registerSandboxSwitchCommand(pi, manager, approvalStore);
		registerSandboxAllowCommand(pi, manager, approvalStore);
		registerSandboxDenyCommand(pi, manager, approvalStore);
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		if (manager === null) return;
		disposeFooter?.();
		installedWidget?.dispose();
		await onSessionShutdown(manager, ctx);
		manager = null;
		approvalStore?.clear();
		approvalStore = null;
		disposeFooter = null;
		installedWidget = null;
	});

	pi.on("session_start", async (_event, ctx) => {
		if (manager === null) return;
		const cwd = ctx.cwd ?? process.cwd();
		pi.registerTool(createBashToolDefinition(cwd, { operations: toBashOperations(manager) }));
		pi.registerTool(createReadToolDefinition(cwd, { operations: toReadOperations(manager) }));
		pi.registerTool(createWriteToolDefinition(cwd, { operations: toWriteOperations(manager) }));
		pi.registerTool(createEditToolDefinition(cwd, { operations: toEditOperations(manager) }));
	});

	pi.on("before_agent_start", async (event) => {
		if (manager === null) return undefined;
		return {
			systemPrompt: `${event.systemPrompt}\n${toAgentContextBlock(manager.getEffectivePolicy(), manager.getCapability())}`,
		};
	});

	pi.on("user_bash", async () => {
		if (manager === null) return undefined;
		return { operations: toBashOperations(manager) };
	});
}
