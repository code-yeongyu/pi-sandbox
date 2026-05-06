import { describe, expect, it, vi } from "vitest";

import { onSessionShutdown } from "../../../src/lifecycle/session-shutdown.js";
import type { ExtensionContext, ExtensionUIContext } from "../../../src/pi/index.js";
import type { SandboxManager } from "../../../src/sandbox/manager.js";

describe("onSessionShutdown", () => {
	it("#given active manager #when session shuts down #then manager is disposed and sandbox UI is cleared", async () => {
		// given
		const dispose = vi.fn(async () => undefined);
		const setStatus = vi.fn();
		const setWidget = vi.fn();
		const manager = Object.create(null) as SandboxManager;
		Object.defineProperty(manager, "dispose", { value: dispose });
		const context = { cwd: "/workspace", ui: fakeUi({ setStatus, setWidget }) } as ExtensionContext;

		// when
		await onSessionShutdown(manager, context);

		// then
		expect(dispose).toHaveBeenCalledTimes(1);
		expect(setStatus).toHaveBeenCalledWith("sandbox", undefined);
		expect(setWidget).toHaveBeenCalledWith("sandbox", undefined);
	});
});

function fakeUi(overrides: Pick<ExtensionUIContext, "setStatus" | "setWidget">): ExtensionUIContext {
	return {
		select: async () => undefined,
		confirm: async () => false,
		input: async () => undefined,
		notify: () => undefined,
		onTerminalInput: () => () => undefined,
		setStatus: overrides.setStatus,
		setWorkingMessage: () => undefined,
		setWorkingVisible: () => undefined,
		setWorkingIndicator: () => undefined,
		setHiddenThinkingLabel: () => undefined,
		setWidget: overrides.setWidget,
		setFooter: () => undefined,
		setHeader: () => undefined,
		setTitle: () => undefined,
		custom: async () => {
			throw new Error("custom UI is not available in test harness");
		},
		pasteToEditor: () => undefined,
		setEditorText: () => undefined,
		getEditorText: () => "",
		editor: async () => undefined,
		addAutocompleteProvider: () => undefined,
		setEditorComponent: () => undefined,
		getEditorComponent: () => undefined,
		theme: undefined as never,
		getAllThemes: () => [],
		getTheme: () => undefined,
		setTheme: () => ({ success: false, error: "not available in test harness" }),
		getToolsExpanded: () => false,
		setToolsExpanded: () => undefined,
	};
}
