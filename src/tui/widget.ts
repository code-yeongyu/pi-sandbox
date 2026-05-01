import { toTuiWidget } from "../explain/render-tui.js";
import type { ExtensionAPI, ExtensionUIContext } from "../pi/index.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export type InstalledWidget = {
	readonly update: (lastBlock?: SandboxBlockV1) => void;
	readonly dispose: () => void;
};

export function installWidget(pi: ExtensionAPI, manager: SandboxManager): InstalledWidget {
	if (!hasUi(pi)) return { update: () => undefined, dispose: () => undefined };
	return {
		update(lastBlock) {
			pi.ui.setWidget("sandbox", [...toTuiWidget(manager.getEffectivePolicy(), manager.getMode(), lastBlock)], {
				placement: "aboveEditor",
			});
		},
		dispose() {
			pi.ui.setWidget("sandbox", undefined);
		},
	};
}

function hasUi(pi: ExtensionAPI): pi is ExtensionAPI & { readonly ui: ExtensionUIContext } {
	if (!isRecord(pi)) return false;
	const ui = pi.ui;
	return isRecord(ui) && typeof ui.setWidget === "function";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null;
}
