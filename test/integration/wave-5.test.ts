import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createPromptBatcher } from "../../src/approvals/batching.js";
import { createPromptHandler, type PromptDecision } from "../../src/approvals/prompt.js";
import { ApprovalStore, typedGrantRequestId } from "../../src/approvals/store.js";
import { registerSandboxAllowCommand } from "../../src/commands/sandbox-allow.js";
import { toTuiFooter, toTuiWidget } from "../../src/explain/render-tui.js";
import type { ExtensionAPI, ExtensionUIContext } from "../../src/pi/index.js";
import type { DesiredBackendConfig } from "../../src/policy/desired.js";
import type { SandboxBackend } from "../../src/sandbox/backend.js";
import { BackendRegistry } from "../../src/sandbox/backend-registry.js";
import { SandboxManager } from "../../src/sandbox/manager.js";
import type { PathMapper } from "../../src/sandbox/path-mapper.js";
import type { Result, SandboxFailure } from "../../src/security/failure.js";
import { formatSandboxStatus } from "../../src/tui/status-command.js";
import { fullCapability, makeBlock, makeEffectivePolicy } from "../unit/helpers/effective-policy.js";

type Notification = { readonly message: string; readonly type: "info" | "warning" | "error" | undefined };
type CommandOptions = Parameters<ExtensionAPI["registerCommand"]>[1];
type CommandContext = Parameters<CommandOptions["handler"]>[1];
type CapturedCommand = { readonly handler: (args: string, ctx: CommandContext) => Promise<void> };

let temporaryDirectory: string | null = null;

afterEach(async () => {
	if (temporaryDirectory !== null) await rm(temporaryDirectory, { recursive: true, force: true });
	temporaryDirectory = null;
});

function ok<TValue>(value: TValue): Result<TValue, SandboxFailure> {
	return { ok: true, value };
}

function fakePathMapper(): PathMapper {
	return {
		hostToSandboxPath: (hostPath) => ({ ok: true, value: `/sandbox${hostPath}` }),
		sandboxToHostPath: (sandboxPath) => ({ ok: true, value: sandboxPath.replace(/^\/sandbox/, "") }),
		canRepresent: () => true,
	};
}

function fakeBackend(): SandboxBackend {
	return {
		kind: "justbash",
		capabilities: fullCapability,
		pathMapper: fakePathMapper(),
		lifecycle: {
			init: async () => ok(undefined),
			dispose: async () => undefined,
			health: async () => ({ healthy: true, backend: "justbash", latencyMs: 1 }),
			probe: async () => [],
		},
		bash: { exec: async () => ok({ exitCode: 0 }) },
		read: { readFile: async () => ok(Buffer.from("ok")), access: async () => ok(undefined) },
		write: { writeFile: async () => ok(undefined), mkdir: async () => ok(undefined) },
	};
}

function registryWithBackend(backend: SandboxBackend): BackendRegistry {
	const registry = new BackendRegistry();
	registry.register("justbash", async (_config: DesiredBackendConfig) => ok(backend));
	return registry;
}

async function createManager(handler?: (prompt: PromptDecision) => Promise<boolean>): Promise<SandboxManager> {
	const options = handler === undefined ? {} : { promptHandler: handler };
	const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy(), options);
	await manager.init();
	return manager;
}

function createUi(confirmResult: boolean, notifications: Notification[] = []): ExtensionUIContext {
	const ui: ExtensionUIContext = {
		select: async () => undefined,
		confirm: async () => confirmResult,
		input: async () => undefined,
		notify: (message, type) => {
			notifications.push({ message, type });
		},
		onTerminalInput: () => () => undefined,
		setStatus: () => undefined,
		setWorkingMessage: () => undefined,
		setWorkingVisible: () => undefined,
		setWorkingIndicator: () => undefined,
		setHiddenThinkingLabel: () => undefined,
		setWidget: () => undefined,
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
	return ui;
}

function createCommandPi(commands: Map<string, CapturedCommand>): ExtensionAPI {
	return {
		registerCommand(name, options) {
			commands.set(name, { handler: options.handler });
		},
	} as ExtensionAPI;
}

function createCommandContext(cwd: string, ui: ExtensionUIContext): CommandContext {
	return { cwd, ui } as CommandContext;
}

describe("Wave 5 approvals and TUI", () => {
	it("#given approval store #when grant is added and removed #then round trip is tracked", () => {
		const store = new ApprovalStore();

		store.add({ requestId: "request-1", class: "file.read", target: "/tmp/foo", addedAt: 1 });

		expect(store.has("request-1")).toBe(true);
		expect(store.list()).toMatchInlineSnapshot(`
			[
			  {
			    "addedAt": 1,
			    "class": "file.read",
			    "requestId": "request-1",
			    "target": "/tmp/foo",
			  },
			]
		`);
		store.remove("request-1");
		expect(store.has("request-1")).toBe(false);
	});

	it("#given prompt batcher #when same request repeats within window #then prompt is deduped", async () => {
		let now = 10;
		let calls = 0;
		const batcher = createPromptBatcher(250, () => now);

		const first = await batcher.run("same", async () => {
			calls += 1;
			return true;
		});
		const second = await batcher.run("same", async () => {
			calls += 1;
			return false;
		});
		now = 20;
		const different = await batcher.run("different", async () => {
			calls += 1;
			return false;
		});

		expect([first, second, different]).toEqual([true, true, false]);
		expect(calls).toBe(2);
	});

	it("#given approving prompt handler #when manager reruns decision #then executor succeeds and grant is stored", async () => {
		const store = new ApprovalStore();
		const handler = createPromptHandler(createUi(true), store);
		const manager = await createManager(handler);

		const result = await manager.run(
			{ kind: "fs.write", path: `${process.cwd()}/.env`, content: "secret" },
			async () => ok("ran"),
		);

		expect(result).toEqual({ ok: true, value: "ran" });
		expect(store.list()).toHaveLength(1);
	});

	it("#given declined prompt handler #when manager runs #then approval-required block is returned", async () => {
		const handler = async () => false;
		const manager = await createManager(handler);

		const result = await manager.run(
			{ kind: "fs.write", path: `${process.cwd()}/.env`, content: "secret" },
			async () => ok("ran"),
		);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("high_risk_approval_required");
		expect(result.error.remediation).toBe("User declined approval; re-run with explicit allow.");
	});

	it("#given sandbox allow command #when valid and invalid classes are used #then grant persists and error notifies", async () => {
		temporaryDirectory = await mkdtemp(join(tmpdir(), "pi-sandbox-wave5-"));
		await mkdir(join(temporaryDirectory, ".pi"), { recursive: true });
		const notifications: Notification[] = [];
		const commands = new Map<string, CapturedCommand>();
		const store = new ApprovalStore();
		const manager = await createManager();
		manager.setCwd(temporaryDirectory);
		registerSandboxAllowCommand(createCommandPi(commands), manager, store);
		const command = commands.get("sandbox-allow");
		expect(command).toBeDefined();
		if (command === undefined) return;

		await command.handler(
			"file.read /tmp/foo",
			createCommandContext(temporaryDirectory, createUi(true, notifications)),
		);
		await command.handler("bad /tmp/foo", createCommandContext(temporaryDirectory, createUi(true, notifications)));

		expect(store.has(typedGrantRequestId("file.read", "/tmp/foo"))).toBe(true);
		expect(notifications.some((entry) => entry.type === "error")).toBe(true);
	});

	it("#given status formatter #when policy has block and grant #then stable status includes required fields", async () => {
		const store = new ApprovalStore();
		store.add({ requestId: "request-1", class: "file.write", target: "/tmp/.env", addedAt: 1 });
		const manager = await createManager();
		manager.setBlockHandler(() => undefined);
		await manager.run({ kind: "network", method: "GET", url: "https://example.com/path" }, async () => ok("ran"));

		expect(formatSandboxStatus(manager, store)).toMatchInlineSnapshot(`
			"pi-sandbox status
			pi-sandbox: enforcing
			backend: justbash (available)
			file: read=enforced write=enforced
			network: deny allowlist=enforced
			omitted controls: none
			policy: desired1234567890 revision=7
			last block: network https://example.com/path network.mode=deny
			policy hash prefix: desired1
			grant hash prefix: grant123
			approvals: 1
			approval file.write: /tmp/.env (request-1)
			recent blocks: 1
			block permission_denied: network https://example.com/path network.mode=deny"
		`);
	});

	it("#given representative policy #when footer and widget render #then snapshots are stable", () => {
		const policy = makeEffectivePolicy();
		const mode = { kind: "enforcing", backend: "justbash", capabilities: fullCapability } as const;
		const block = makeBlock();

		expect(toTuiFooter(policy, mode)).toMatchInlineSnapshot(
			`"sandbox enforcing justbash fs=realpath-canonical-residual-toctou net=deny omitted=0 grants=grant123 rev=7:desired1"`,
		);
		expect(toTuiWidget(policy, mode, block)).toMatchInlineSnapshot(`
			[
			  "pi-sandbox: enforcing",
			  "backend: justbash (available)",
			  "file: read=enforced write=enforced",
			  "network: deny allowlist=enforced",
			  "omitted controls: none",
			  "policy: desired1234567890 revision=7",
			  "last block: network https://example.com/path network.mode=deny",
			]
		`);
	});
});
