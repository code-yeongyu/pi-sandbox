// src/index.ts — Extension factory: pi.registerTool / pi.registerCommand / pi.registerFlag / pi.on(...)
import { type QemuDoctorReport, runQemuDoctor } from "./backends/qemu/doctor.js";
import { toAgentContextBlock } from "./explain/render-agent-context.js";
import { toSandboxStatus } from "./explain/render-tui.js";
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

type FlagCapableExtensionAPI = ExtensionAPI & {
	registerFlag?: (
		name: string,
		options: { readonly type: "boolean"; readonly default: boolean; readonly description: string },
	) => void;
};

let manager: SandboxManager | null = null;

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
		if (result.ok) manager = result.value;
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		if (manager === null) return;
		await onSessionShutdown(manager, ctx);
		manager = null;
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

	pi.on("tool_call", async () => undefined);
	pi.on("tool_result", async () => undefined);

	pi.registerCommand("sandbox-status", {
		description: "Print active pi-sandbox status",
		handler: async (_args, ctx) => {
			if (manager === null) {
				ctx.ui.notify("pi-sandbox: not initialized", "warning");
				return;
			}
			const effectivePolicy = manager.getEffectivePolicy();
			const qemuDoctor =
				effectivePolicy.backend.kind === "qemu"
					? `\n${formatQemuDoctor(await runQemuDoctor(ctx.cwd ?? process.cwd()))}`
					: "";
			ctx.ui.notify(`${toSandboxStatus(effectivePolicy, manager.getMode(), [], [])}${qemuDoctor}`, "info");
		},
	});
}

function formatQemuDoctor(report: QemuDoctorReport): string {
	return [
		"qemu doctor:",
		`binaryPath: ${report.binaryPath ?? "missing"}`,
		`version: ${report.version ?? "unknown"}`,
		`accelerator: ${report.accelerator}`,
		`fixture: present=${report.fixture.present} checksum=${report.fixture.checksumMatch} manifest=${report.fixture.manifestSha256 ?? "missing"}`,
		...report.checks.map((check) => `doctor ${check.name}: ${check.status} (${check.details})`),
	].join("\n");
}
