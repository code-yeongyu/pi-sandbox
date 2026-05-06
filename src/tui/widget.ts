import { toTuiWidget } from "../explain/render-tui.js";
import type { EffectivePolicy } from "../policy/effective.js";
import type { SandboxMode } from "../sandbox/mode.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export type InstalledWidget = {
	readonly update: (lastBlock?: SandboxBlockV1) => void;
	readonly dispose: () => void;
};

export type WidgetManager = {
	readonly getEffectivePolicy: () => EffectivePolicy;
	readonly getMode: () => SandboxMode;
};

type WidgetUiContainer = {
	readonly ui?: {
		readonly setWidget?: (
			name: string,
			lines: string[] | undefined,
			options?: { readonly placement: "aboveEditor" | "belowEditor" },
		) => void;
	};
};

type WidgetUiReady = {
	readonly ui: {
		readonly setWidget: (
			name: string,
			lines: string[] | undefined,
			options?: { readonly placement: "aboveEditor" | "belowEditor" },
		) => void;
	};
};

export function installWidget(pi: WidgetUiContainer, manager: WidgetManager): InstalledWidget {
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

function hasUi(pi: WidgetUiContainer): pi is WidgetUiContainer & WidgetUiReady {
	if (!isRecord(pi)) return false;
	const ui = pi.ui;
	return isRecord(ui) && typeof ui.setWidget === "function";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null;
}
