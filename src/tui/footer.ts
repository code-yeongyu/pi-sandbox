import { toTuiFooter } from "../explain/render-tui.js";
import type { ExtensionAPI, ExtensionUIContext } from "../pi/index.js";
import type { SandboxManager } from "../sandbox/manager.js";

export function installFooter(pi: ExtensionAPI, manager: SandboxManager): () => void {
	if (!hasUi(pi)) return () => undefined;
	pi.ui.setFooter(() => ({
		invalidate: () => undefined,
		render: () => [toTuiFooter(manager.getEffectivePolicy(), manager.getMode())],
	}));
	return () => pi.ui.setFooter(undefined);
}

function hasUi(pi: ExtensionAPI): pi is ExtensionAPI & { readonly ui: ExtensionUIContext } {
	if (!isRecord(pi)) return false;
	const ui = pi.ui;
	return isRecord(ui) && typeof ui.setFooter === "function";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null;
}
