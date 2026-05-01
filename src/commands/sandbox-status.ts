import type { ApprovalStore } from "../approvals/store.js";
import type { ExtensionAPI } from "../pi/index.js";
import type { SandboxManager } from "../sandbox/manager.js";
import { formatSandboxStatus } from "../tui/status-command.js";

export function registerSandboxStatusCommand(pi: ExtensionAPI, manager: SandboxManager, store: ApprovalStore): void {
	pi.registerCommand("sandbox-status", {
		description: "Print active pi-sandbox status",
		handler: async (_args, ctx) => {
			ctx.ui.notify(formatSandboxStatus(manager, store), "info");
		},
	});
}
