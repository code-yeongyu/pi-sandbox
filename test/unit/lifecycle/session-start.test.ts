import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
	backendStateForConfig,
	onSessionStart,
	registerBackendFactories,
	resolveSessionBackendConfig,
} from "../../../src/lifecycle/session-start.js";
import type { ExtensionAPI, ExtensionContext, ExtensionUIContext } from "../../../src/pi/index.js";
import type { DesiredBackendConfig, EnvPolicy } from "../../../src/policy/desired.js";
import { BackendRegistry } from "../../../src/sandbox/backend-registry.js";

const envPolicy: EnvPolicy = {
	clearenv: true,
	allowlist: ["PATH"],
	denyPatterns: ["*_TOKEN"],
	scrubProxyEnv: true,
};

let testHome: string;
let testProject: string;
let originalHome: string | undefined;

beforeEach(async () => {
	originalHome = process.env.HOME;
	testHome = await mkdtemp(join(tmpdir(), "pi-sandbox-session-home-"));
	testProject = await mkdtemp(join(tmpdir(), "pi-sandbox-session-project-"));
	process.env.HOME = testHome;
});

afterEach(async () => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	await rm(testHome, { recursive: true, force: true });
	await rm(testProject, { recursive: true, force: true });
});

describe("session backend startup wiring", () => {
	it("#given concrete backend configs #when normalized for session #then backend kind is preserved", () => {
		const dockerConfig: DesiredBackendConfig = {
			kind: "docker",
			image: "node:22-alpine",
			networkMode: "none",
			readonlyRootfs: true,
			mounts: [],
			pullPolicy: "if-missing",
			capDrop: ["ALL"],
			securityOpt: ["no-new-privileges"],
			tmpfs: [],
		};
		const sshConfig: DesiredBackendConfig = {
			kind: "ssh",
			host: "sandbox.example",
			port: 22,
			username: "sandbox",
			auth: { kind: "kbi" },
			hostVerification: { strict: true },
			remoteRoot: "/srv/sandbox",
			proxyJump: [],
		};
		const qemuConfig: DesiredBackendConfig = {
			kind: "qemu",
			assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
			cpus: 1,
			memoryMb: 512,
			shareMode: "9p-readonly",
			network: "none",
			snapshot: true,
		};
		const nativeConfig: DesiredBackendConfig = { kind: "native", platform: "linux", mechanism: "bwrap" };

		expect(resolveSessionBackendConfig(dockerConfig)).toBe(dockerConfig);
		expect(resolveSessionBackendConfig(sshConfig)).toBe(sshConfig);
		expect(resolveSessionBackendConfig(qemuConfig)).toBe(qemuConfig);
		expect(resolveSessionBackendConfig(nativeConfig)).toBe(nativeConfig);
		expect(resolveSessionBackendConfig({ kind: "auto" }).kind).toBe("justbash");
		expect(backendStateForConfig(dockerConfig).kind).toBe("docker");
		expect(backendStateForConfig(sshConfig).kind).toBe("ssh");
		expect(backendStateForConfig(qemuConfig).kind).toBe("qemu");
		expect(backendStateForConfig(nativeConfig).kind).toBe("native");
	});

	it("#given registered factories #when docker ssh qemu resolve #then matching factory accepts selected config", async () => {
		const registry = new BackendRegistry();
		registerBackendFactories(registry, process.cwd(), envPolicy);

		const dockerResult = await registry.resolve({
			kind: "docker",
			image: "node:22-alpine",
			networkMode: "none",
			readonlyRootfs: true,
			mounts: [],
			pullPolicy: "never",
			capDrop: ["ALL"],
			securityOpt: ["no-new-privileges"],
			tmpfs: [],
		});
		const sshResult = await registry.resolve({
			kind: "ssh",
			host: "sandbox.example",
			port: 22,
			username: "sandbox",
			auth: { kind: "kbi" },
			hostVerification: { strict: true },
			remoteRoot: "/srv/sandbox",
			proxyJump: [],
		});
		const qemuResult = await registry.resolve({
			kind: "qemu",
			assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
			cpus: 1,
			memoryMb: 512,
			shareMode: "9p-readonly",
			network: "none",
			snapshot: true,
		});

		expect(dockerResult.ok).toBe(true);
		expect(sshResult.ok).toBe(true);
		expect(qemuResult.ok).toBe(true);
	});

	it("#given removed native mechanisms #when config parses #then schema rejects them before factories", async () => {
		await writeText(
			join(testProject, ".pi", "sandbox.json"),
			'{ "backend": { "kind": "native", "platform": "linux", "mechanism": "sandboxd" } }',
		);

		const result = await onSessionStart({} as ExtensionAPI, { cwd: testProject, ui: fakeUi() } as ExtensionContext);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("backend_missing");
		if (result.error.code !== "backend_missing") return;
		expect(result.error.availabilityReason).toBe("validation");
	});

	it("#given ssh state #when backend status is built #then no fake process isolation probe is reported", () => {
		const state = backendStateForConfig({
			kind: "ssh",
			host: "sandbox.example",
			port: 22,
			username: "sandbox",
			auth: { kind: "kbi" },
			hostVerification: { strict: true },
			remoteRoot: "/srv/sandbox",
			proxyJump: [],
		});

		expect(state.capabilities.processIsolation).toBe(false);
		expect(state.probeResults).toHaveLength(0);
	});

	it("#given missing primary backend and fallback configured #when session starts #then fallback backend starts", async () => {
		const nativeBackend =
			process.platform === "darwin"
				? '{ "kind": "native", "platform": "linux", "mechanism": "bwrap" }'
				: '{ "kind": "native", "platform": "darwin", "mechanism": "sandbox-exec" }';
		await writeText(
			join(testProject, ".pi", "sandbox.json"),
			`{ "backend": ${nativeBackend}, "fallbackBackends": ["justbash"] }`,
		);

		const result = await onSessionStart({} as ExtensionAPI, { cwd: testProject, ui: fakeUi() } as ExtensionContext);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const mode = result.value.getMode();
		expect(mode.kind).toBe("enforcing");
		if (mode.kind !== "enforcing") return;
		expect(mode.backend).toBe("justbash");
		expect(result.value.getDesiredBackendConfig().kind).toBe("justbash");
		await result.value.dispose();
	});
});

async function writeText(path: string, text: string): Promise<void> {
	await mkdir(join(path, ".."), { recursive: true });
	await writeFile(path, text);
}

function fakeUi(): ExtensionUIContext {
	return {
		select: async () => undefined,
		confirm: async () => false,
		input: async () => undefined,
		notify: () => undefined,
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
}
