import type { ApprovalStore } from "../approvals/store.js";
import { BackendKindSchema } from "../policy/desired.js";
import type { CommandRegistrar } from "./types.js";

export function registerSandboxSwitchCommand(pi: CommandRegistrar, _manager: object, _store: ApprovalStore): void {
	pi.registerCommand("sandbox-switch", {
		description: "Validate a pi-sandbox backend switch",
		handler: async (args, ctx) => {
			const backend = args.trim();
			const parsed = BackendKindSchema.safeParse(backend);
			if (!parsed.success) {
				ctx.ui.notify(`Unknown sandbox backend: ${backend || "<empty>"}`, "error");
				return;
			}
			ctx.ui.notify(
				`Sandbox backend '${parsed.data}' is valid. Runtime backend switching requires session restart because backend factories and lifecycle are session-scoped.`,
				"info",
			);
		},
	});
}
