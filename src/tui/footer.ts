import { toTuiFooter } from "../explain/render-tui.js";
import type { EffectivePolicy } from "../policy/effective.js";
import type { SandboxMode } from "../sandbox/mode.js";

export type FooterManager = {
	readonly getEffectivePolicy: () => EffectivePolicy;
	readonly getMode: () => SandboxMode;
};

type FooterProvider = {
	readonly invalidate: () => void;
	readonly render: () => string[];
};

type FooterUiContainer = {
	readonly ui?: {
		readonly setFooter?: (factory: (() => FooterProvider) | undefined) => void;
	};
};

type FooterUiReady = {
	readonly ui: {
		readonly setFooter: (factory: (() => FooterProvider) | undefined) => void;
	};
};

export function installFooter(pi: FooterUiContainer, manager: FooterManager): () => void {
	if (!hasUi(pi)) return () => undefined;
	pi.ui.setFooter(() => ({
		invalidate: () => undefined,
		render: () => [toTuiFooter(manager.getEffectivePolicy(), manager.getMode())],
	}));
	return () => pi.ui.setFooter(undefined);
}

function hasUi(pi: FooterUiContainer): pi is FooterUiContainer & FooterUiReady {
	if (!isRecord(pi)) return false;
	const ui = pi.ui;
	return isRecord(ui) && typeof ui.setFooter === "function";
}

function isRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null;
}
