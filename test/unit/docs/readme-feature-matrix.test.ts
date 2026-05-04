import { readFile } from "node:fs/promises";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { dockerCapability } from "../../../src/backends/docker/adapter.js";
import { qemuCapability } from "../../../src/backends/qemu/adapter.js";
import { backendStateForConfig } from "../../../src/lifecycle/session-start.js";
import type { DesiredBackendConfig, NetworkPolicy } from "../../../src/policy/desired.js";
import type { EffectiveBackendState } from "../../../src/policy/effective.js";
import { BackendRegistry } from "../../../src/sandbox/backend-registry.js";
import { SandboxManager } from "../../../src/sandbox/manager.js";
import { makeEffectivePolicy } from "../helpers/effective-policy.js";

const readmePath = path.join(process.cwd(), "README.md");

const restrictedNetworkPolicy: NetworkPolicy = {
	mode: "restricted",
	default: "deny",
	allowDomains: [],
	denyDomains: [],
	allowUrlPrefixes: ["https://example.com/api/"],
	allowPorts: [],
	allowCidrs: [],
	denyPrivateNetworks: true,
	denyMetadata: true,
	allowUnixSockets: false,
	scrubProxyEnv: true,
	dns: "deny",
};

const backendConfigs = {
	justbash: {
		kind: "justbash",
		fs: "read-write-root-locked",
		allowedBinaries: [],
		executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
	},
	docker: {
		kind: "docker",
		image: "node:22-alpine",
		networkMode: "none",
		readonlyRootfs: true,
		mounts: [],
		pullPolicy: "never",
		capDrop: ["ALL"],
		securityOpt: ["no-new-privileges"],
		tmpfs: [],
	},
	darwin: { kind: "native", platform: "darwin", mechanism: "sandbox-exec" },
	linux: { kind: "native", platform: "linux", mechanism: "bwrap" },
	qemu: {
		kind: "qemu",
		assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
		cpus: 1,
		memoryMb: 512,
		shareMode: "9p-readonly",
		network: "none",
		snapshot: true,
	},
	ssh: {
		kind: "ssh",
		host: "sandbox.example",
		port: 22,
		username: "sandbox",
		auth: { kind: "kbi" },
		hostVerification: { strict: true },
		remoteRoot: "/srv/pi-sandbox",
		proxyJump: [],
	},
} satisfies Record<string, DesiredBackendConfig>;

describe("README feature matrix", () => {
	it("#given README feature matrix #when parsed #then cells describe code-backed backend behavior", async () => {
		const markdown = await readFile(readmePath, "utf8");

		expect(matrixCell(markdown, "fileRead", 1)).toBe("host-root");
		expect(matrixCell(markdown, "fileWrite", 5)).toBe("share mode");
		expect(matrixCell(markdown, "restricted network", 6)).toBe("config error");
		expect(matrixCell(markdown, "networkDeny", 6)).toBe("transport only");
		expect(matrixCell(markdown, "processIsolation", 3)).toBe("seatbelt policy");
		expect(matrixCell(markdown, "processIsolation", 6)).toBe("transport only");
		expect(matrixCell(markdown, "persistence", 6)).toBe("remoteRoot lifecycle");
		expect(matrixCell(markdown, "denialAttribution", 6)).toBe("generic");
	});

	it("#given README-listed backends #when capabilities are built #then matrix claims match effective control states", () => {
		const states = {
			justbash: backendStateForConfig(backendConfigs.justbash),
			docker: backendStateForConfig(backendConfigs.docker),
			darwin: backendStateForConfig(backendConfigs.darwin),
			linux: backendStateForConfig(backendConfigs.linux),
			qemu: backendStateForConfig(backendConfigs.qemu),
			ssh: backendStateForConfig(backendConfigs.ssh),
		};

		expectEnforced(states.justbash, ["fileRead", "fileWrite", "networkDeny", "processIsolation", "envScrub"]);
		expectEnforced(states.docker, ["fileRead", "fileWrite", "networkDeny", "processIsolation", "envScrub"]);
		expectEnforced(states.linux, ["fileRead", "fileWrite", "networkDeny", "processIsolation", "envScrub"]);
		expectEnforced(states.qemu, ["fileRead", "networkDeny", "processIsolation", "envScrub"]);
		expectEnforced(states.darwin, ["fileRead", "fileWrite", "networkDeny", "envScrub", "persistence"]);
		expect(states.darwin.effectiveControls.processIsolation.state).toBe("simulated");
		expect(states.darwin.effectiveControls.pathMapping.state).toBe("omitted");

		expect(states.ssh.capabilities.fileRead).toBe(true);
		expect(states.ssh.capabilities.fileWrite).toBe(true);
		expect(states.ssh.capabilities.envScrub).toBe(true);
		expect(states.ssh.capabilities.pathMapping).toBe(true);
		expect(states.ssh.capabilities.networkDeny).toBe(false);
		expect(states.ssh.capabilities.processIsolation).toBe(false);
		expect(states.ssh.capabilities.persistence).toBe(false);
		expect(states.ssh.capabilities.denialAttribution).toBe(false);

		expect(dockerCapability({ ...backendConfigs.docker, networkMode: "bridge" }).networkDeny).toBe(false);
		expect(qemuCapability({ ...backendConfigs.qemu, shareMode: "9p-readonly" }).fileWrite).toBe(false);
		expect(qemuCapability({ ...backendConfigs.qemu, shareMode: "9p-readwrite" }).fileWrite).toBe(true);
		expect(qemuCapability({ ...backendConfigs.qemu, network: "hostfwd" }).networkDeny).toBe(false);
	});

	it("#given restricted network policy #when any README-listed backend initializes #then config is rejected before live backend resolution", async () => {
		const entries = Object.entries(backendConfigs);

		for (const [name, config] of entries) {
			const policy = makeEffectivePolicy({
				network: restrictedNetworkPolicy,
				backend: backendStateForConfig(config),
			});
			const manager = new SandboxManager(new BackendRegistry(), policy, { backendConfig: config });

			const result = await manager.init();

			expect(result.ok, name).toBe(false);
			if (result.ok) return;
			expect(result.error.code, name).toBe("capability_missing");
		}
	});
});

function matrixCell(markdown: string, control: string, columnIndex: number): string {
	const row = markdown.split("\n").find((line) => line.startsWith(`| ${control} |`));
	if (row === undefined) throw new Error(`README matrix row missing: ${control}`);
	const cell = row
		.split("|")
		.slice(1, -1)
		.map((value) => value.trim())
		.at(columnIndex);
	if (cell === undefined) throw new Error(`README matrix cell missing: ${control} column ${columnIndex}`);
	return cell;
}

function expectEnforced(
	state: EffectiveBackendState,
	controls: readonly (keyof EffectiveBackendState["effectiveControls"])[],
): void {
	for (const control of controls) {
		expect(state.effectiveControls[control].state, `${state.kind}.${control}`).toBe("enforced");
	}
}
