import type { ApprovalStore } from "../approvals/store.js";
import { formatSandboxStatus, type SandboxStatusManager } from "../tui/status-command.js";
import type { CommandRegistrar } from "./types.js";

export function registerSandboxCommand(
	pi: CommandRegistrar,
	manager: SandboxStatusManager,
	store: ApprovalStore,
): void {
	pi.registerCommand("sandbox", {
		description: "Show pi-sandbox help and status summary",
		handler: async (_args, ctx) => {
			ctx.ui.notify(
				[
					"pi-sandbox commands:",
					"/sandbox-status - full sandbox status",
					"/sandbox-switch <backend> - validate backend switch; restart required for runtime backend changes",
					"/sandbox-allow <class> <target> - add project allow grant",
					"/sandbox-deny <class> <target> - add project deny grant",
					"",
					formatSandboxStatus(manager, store),
				].join("\n"),
				"info",
			);
		},
	});
}
