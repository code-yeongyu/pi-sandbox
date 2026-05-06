import type { ApprovalStore } from "../approvals/store.js";
import { formatSandboxStatus, type SandboxStatusManager } from "../tui/status-command.js";
import type { CommandRegistrar } from "./types.js";

export function registerSandboxStatusCommand(
	pi: CommandRegistrar,
	manager: SandboxStatusManager,
	store: ApprovalStore,
): void {
	pi.registerCommand("sandbox-status", {
		description: "Print active pi-sandbox status",
		handler: async (_args, ctx) => {
			ctx.ui.notify(formatSandboxStatus(manager, store), "info");
		},
	});
}
