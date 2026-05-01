import type { ExtensionUIContext } from "../pi/index.js";
import { confirmPermissionPrompt } from "../tui/permission-prompt.js";
import { createPromptBatcher } from "./batching.js";
import type { ApprovalStore, GrantClass } from "./store.js";

export type PromptDecision = {
	readonly requestId: string;
	readonly class: string;
	readonly sanitizedTarget: string;
	readonly matchedRule: string;
};

export type PromptHandler = (prompt: PromptDecision) => Promise<boolean>;

export function createPromptHandler(ui: ExtensionUIContext, store: ApprovalStore): PromptHandler {
	const batcher = createPromptBatcher(250);
	return async (prompt) =>
		batcher.run(prompt.requestId, async () => {
			const approved = await confirmPermissionPrompt(ui, prompt);
			if (approved) {
				store.add({
					requestId: prompt.requestId,
					class: grantClassForPrompt(prompt.class),
					target: prompt.sanitizedTarget,
					addedAt: Date.now(),
				});
			}
			return approved;
		});
}

function grantClassForPrompt(promptClass: string): GrantClass {
	if (promptClass === "network") return "domain";
	if (promptClass === "process") return "binary";
	return "file.write";
}
