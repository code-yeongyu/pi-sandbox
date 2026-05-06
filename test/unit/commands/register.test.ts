import { describe, expect, it } from "vitest";

import { ApprovalStore } from "../../../src/approvals/store.js";
import { registerSandboxCommand } from "../../../src/commands/sandbox.js";
import { registerSandboxStatusCommand } from "../../../src/commands/sandbox-status.js";
import { registerSandboxSwitchCommand } from "../../../src/commands/sandbox-switch.js";
import type { CommandRegistrar, SandboxCommandContext, SandboxCommandOptions } from "../../../src/commands/types.js";
import { makeEffectivePolicy } from "../helpers/effective-policy.js";

type MinimalManager = Parameters<typeof registerSandboxCommand>[1];

function createManager(): MinimalManager {
	return {
		getEffectivePolicy: () => makeEffectivePolicy(),
		getMode: () => ({
			kind: "enforcing",
			backend: "justbash",
			capabilities: makeEffectivePolicy().backend.capabilities,
		}),
		getRecentBlocks: () => [],
	};
}

function createApi(commands: Map<string, SandboxCommandOptions>): CommandRegistrar {
	return {
		registerCommand: (name, options) => {
			commands.set(name, options);
		},
	};
}

function createContext(notifications: Array<readonly [string, string]>): SandboxCommandContext {
	return {
		cwd: process.cwd(),
		ui: {
			notify: (message, type) => {
				notifications.push([message, type]);
			},
		},
	};
}

describe("sandbox command registration", () => {
	it("#given sandbox command #when invoked #then help and status are notified", async () => {
		const commands = new Map<string, SandboxCommandOptions>();
		const notifications: Array<readonly [string, string]> = [];
		registerSandboxCommand(createApi(commands), createManager(), new ApprovalStore());

		await commands.get("sandbox")?.handler("", createContext(notifications));

		expect(notifications[0]?.[1]).toBe("info");
		expect(notifications[0]?.[0]).toContain("/sandbox-status - full sandbox status");
		expect(notifications[0]?.[0]).toContain("pi-sandbox status");
	});

	it("#given sandbox-status command #when invoked #then formatted status is notified", async () => {
		const commands = new Map<string, SandboxCommandOptions>();
		const notifications: Array<readonly [string, string]> = [];
		registerSandboxStatusCommand(createApi(commands), createManager(), new ApprovalStore());

		await commands.get("sandbox-status")?.handler("", createContext(notifications));

		expect(notifications).toHaveLength(1);
		expect(notifications[0]?.[0]).toContain("backend: justbash (available)");
	});

	it("#given sandbox-switch command #when backend is invalid #then error includes sanitized empty marker", async () => {
		const commands = new Map<string, SandboxCommandOptions>();
		const notifications: Array<readonly [string, string]> = [];
		registerSandboxSwitchCommand(createApi(commands), createManager(), new ApprovalStore());

		await commands.get("sandbox-switch")?.handler("   ", createContext(notifications));

		expect(notifications[0]).toEqual(["Unknown sandbox backend: <empty>", "error"]);
	});

	it("#given sandbox-switch command #when backend is valid #then restart caveat is notified", async () => {
		const commands = new Map<string, SandboxCommandOptions>();
		const notifications: Array<readonly [string, string]> = [];
		registerSandboxSwitchCommand(createApi(commands), createManager(), new ApprovalStore());

		await commands.get("sandbox-switch")?.handler("docker", createContext(notifications));

		expect(notifications[0]?.[0]).toContain("Runtime backend switching requires session restart");
		expect(notifications[0]?.[1]).toBe("info");
	});
});
