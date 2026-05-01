import type { PromptDecision } from "../approvals/prompt.js";
import type { ExtensionUIContext } from "../pi/index.js";

export function renderPermissionPrompt(prompt: PromptDecision): { readonly title: string; readonly message: string } {
	return {
		title: "pi-sandbox approval required",
		message: [
			"sandbox-prompt",
			`class: ${prompt.class}`,
			`target: ${prompt.sanitizedTarget}`,
			`matchedRule: ${prompt.matchedRule}`,
			`requestId: ${prompt.requestId}`,
			"Allow this request for the current session?",
		].join("\n"),
	};
}

export async function confirmPermissionPrompt(ui: ExtensionUIContext, prompt: PromptDecision): Promise<boolean> {
	const rendered = renderPermissionPrompt(prompt);
	return ui.confirm(rendered.title, rendered.message);
}
