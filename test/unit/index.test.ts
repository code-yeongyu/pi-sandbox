import { createEventBus, type ExtensionAPI, type ExtensionHandler } from "@mariozechner/pi-coding-agent";
import { describe, expect, it } from "vitest";
import piSandboxExtension from "../../src/index.js";

type RegisteredFlag = {
	readonly type: "boolean" | "string";
	readonly default?: boolean | string;
	readonly description?: string;
};

describe("pi sandbox extension factory", () => {
	it("#given extension api #when factory runs #then lifecycle hooks and no-sandbox flag are registered", () => {
		const events: string[] = [];
		const flags = new Map<string, RegisteredFlag>();
		const pi: ExtensionAPI = {
			on: (event: string, _handler: ExtensionHandler<never, never>) => {
				events.push(event);
			},
			registerTool: () => undefined,
			registerCommand: () => undefined,
			registerShortcut: () => undefined,
			registerFlag: (name: string, options: RegisteredFlag) => {
				flags.set(name, options);
			},
			getFlag: () => undefined,
			registerMessageRenderer: () => undefined,
			sendMessage: () => undefined,
			sendUserMessage: () => undefined,
			appendEntry: () => undefined,
			setSessionName: () => undefined,
			getSessionName: () => undefined,
			setLabel: () => undefined,
			exec: async () => ({ code: 0, killed: false, stdout: "", stderr: "" }),
			getActiveTools: () => [],
			getAllTools: () => [],
			setActiveTools: () => undefined,
			getCommands: () => [],
			setModel: async () => false,
			getThinkingLevel: () => "medium",
			setThinkingLevel: () => undefined,
			registerProvider: () => undefined,
			unregisterProvider: () => undefined,
			events: createEventBus(),
		};

		piSandboxExtension(pi);

		expect(flags.get("no-sandbox")).toEqual({
			type: "boolean",
			default: false,
			description: "Disable pi-sandbox enforcement",
		});
		expect(events).toEqual([
			"session_start",
			"session_shutdown",
			"session_start",
			"before_agent_start",
			"user_bash",
			"tool_call",
			"tool_result",
		]);
	});
});
