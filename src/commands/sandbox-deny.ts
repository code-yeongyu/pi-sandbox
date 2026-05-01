import type { ApprovalStore } from "../approvals/store.js";
import type { ExtensionAPI } from "../pi/index.js";
import type { SandboxManager } from "../sandbox/manager.js";
import { parseGrantArgs, persistProjectGrant } from "./grants.js";

export function registerSandboxDenyCommand(pi: ExtensionAPI, manager: SandboxManager, _store: ApprovalStore): void {
	pi.registerCommand("sandbox-deny", {
		description: "Persist a typed pi-sandbox deny grant",
		handler: async (args, ctx) => {
			const parsed = parseGrantArgs(args);
			if (parsed === null) {
				ctx.ui.notify(
					"usage: /sandbox-deny <file.read|file.write|domain|url-prefix|port|binary> <target>",
					"error",
				);
				return;
			}
			const persisted = await persistProjectGrant(ctx.cwd ?? process.cwd(), parsed, "deny");
			if (!persisted.ok) {
				ctx.ui.notify(persisted.message, "error");
				return;
			}
			const reloaded = await manager.reloadEffectivePolicy();
			if (!reloaded.ok) {
				ctx.ui.notify(reloaded.error.remediation, "error");
				return;
			}
			ctx.ui.notify(`pi-sandbox deny grant added: ${parsed.class} ${parsed.target}`, "info");
		},
	});
}
