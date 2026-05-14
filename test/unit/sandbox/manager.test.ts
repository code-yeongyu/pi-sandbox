import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { typedGrantRequestId } from "../../../src/approvals/store.js";
import type { DesiredBackendConfig } from "../../../src/policy/desired.js";
import type { SandboxBackend } from "../../../src/sandbox/backend.js";
import { BackendRegistry } from "../../../src/sandbox/backend-registry.js";
import { SandboxManager } from "../../../src/sandbox/manager.js";
import type { PathMapper } from "../../../src/sandbox/path-mapper.js";
import type { Result, SandboxFailure } from "../../../src/security/failure.js";
import { createBlock } from "../../../src/security/failure.js";
import { fullCapability, makeEffectivePolicy } from "../helpers/effective-policy.js";

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

function fakeBackend(events: string[] = []): SandboxBackend {
	return {
		kind: "justbash",
		capabilities: fullCapability,
		pathMapper: fakePathMapper(),
		lifecycle: {
			init: async () => {
				events.push("init");
				return ok(undefined);
			},
			dispose: async () => {
				events.push("dispose");
			},
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

async function withProject<TValue>(callback: (projectPath: string) => Promise<TValue>): Promise<TValue> {
	const projectPath = await mkdtemp(join(tmpdir(), "pi-sandbox-manager-"));
	try {
		return await callback(projectPath);
	} finally {
		await rm(projectPath, { recursive: true, force: true });
	}
}

async function writeProjectGrant(
	projectPath: string,
	grant: { readonly action: "allow" | "deny"; readonly requestId: string },
): Promise<void> {
	const grantPath = join(projectPath, ".pi", "sandbox.grants.jsonc");
	await mkdir(join(grantPath, ".."), { recursive: true });
	await writeFile(grantPath, JSON.stringify([{ ...grant, scope: "project" }]));
}

describe("SandboxManager", () => {
	it("#given registered backend #when manager initializes #then lifecycle init is called", async () => {
		const events: string[] = [];
		const manager = new SandboxManager(registryWithBackend(fakeBackend(events)), makeEffectivePolicy());
		const result = await manager.init();
		expect(result.ok).toBe(true);
		expect(events).toContain("init");
	});

	it("#given explicit backend config #when manager initializes #then registry receives exact config", async () => {
		const backendConfig: DesiredBackendConfig = {
			kind: "docker",
			image: "custom:latest",
			networkMode: "bridge",
			readonlyRootfs: false,
			mounts: [{ hostPath: process.cwd(), sandboxPath: "/workspace", mode: "readwrite", persist: "host" }],
			pullPolicy: "never",
			memoryMb: 1024,
			cpuQuota: 50_000,
			capDrop: ["NET_RAW"],
			securityOpt: ["no-new-privileges"],
			tmpfs: ["/tmp:size=64m"],
		};
		let resolvedConfig: DesiredBackendConfig | null = null;
		const registry = new BackendRegistry();
		registry.register("docker", async (config) => {
			resolvedConfig = config;
			return ok(fakeBackend());
		});
		const manager = new SandboxManager(
			registry,
			makeEffectivePolicy({ backend: { ...makeEffectivePolicy().backend, kind: "docker" } }),
			{ backendConfig },
		);

		const result = await manager.init();

		expect(result.ok).toBe(true);
		expect(manager.getDesiredBackendConfig()).toBe(backendConfig);
		expect(resolvedConfig).toBe(backendConfig);
	});

	it("#given docker policy without matching backend config #when manager initializes #then it fails instead of resolving justbash", async () => {
		let called = false;
		const registry = new BackendRegistry();
		registry.register("justbash", async () => {
			called = true;
			return ok(fakeBackend());
		});
		const manager = new SandboxManager(
			registry,
			makeEffectivePolicy({ backend: { ...makeEffectivePolicy().backend, kind: "docker" } }),
		);

		const result = await manager.init();

		expect(result.ok).toBe(false);
		expect(called).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("backend_missing");
		if (result.error.code !== "backend_missing") return;
		expect(result.error.availabilityReason).toBe("backend-config-policy-kind-mismatch");
	});

	it("#given restricted network without gateway #when manager initializes #then capability failure is returned", async () => {
		let called = false;
		const registry = new BackendRegistry();
		registry.register("justbash", async () => {
			called = true;
			return ok(fakeBackend());
		});
		const policy = makeEffectivePolicy({
			network: {
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
			},
			backend: {
				...makeEffectivePolicy().backend,
				capabilities: { ...fullCapability, networkAllowlist: false, networkGateway: false },
			},
		});
		const manager = new SandboxManager(registry, policy);

		const result = await manager.init();

		expect(result.ok).toBe(false);
		expect(called).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("capability_missing");
	});

	it("#given initialized manager #when disposed #then backend dispose is called", async () => {
		const events: string[] = [];
		const manager = new SandboxManager(registryWithBackend(fakeBackend(events)), makeEffectivePolicy());
		await manager.init();
		await manager.dispose();
		expect(events).toContain("dispose");
	});

	it("#given initialized manager #when backend requested #then aggregate backend is returned", async () => {
		const backend = fakeBackend();
		const manager = new SandboxManager(registryWithBackend(backend), makeEffectivePolicy());
		await manager.init();
		expect(manager.getBackend()).toBe(backend);
	});

	it("#given allowed operation #when run #then executor is called", async () => {
		const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy());
		await manager.init();
		const result = await manager.run({ kind: "fs.read", path: `${process.cwd()}/README.md` }, async () => ok("ran"));
		expect(result).toEqual({ ok: true, value: "ran" });
	});

	it("#given denied operation #when run #then executor is not called", async () => {
		let called = false;
		const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy());
		await manager.init();
		const result = await manager.run(
			{ kind: "bash", command: "curl https://example.com", cwd: process.cwd() },
			async () => {
				called = true;
				return ok("ran");
			},
		);
		expect(result.ok).toBe(false);
		expect(called).toBe(false);
	});

	it("#given file read grant for sibling prefix #when reading outside path boundary #then executor is not called", async () => {
		await withProject(async (projectPath) => {
			let called = false;
			await writeProjectGrant(projectPath, {
				action: "allow",
				requestId: typedGrantRequestId("file.read", "/tmp/foo"),
			});
			const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy(), {
				cwd: projectPath,
			});
			await manager.init();
			const reload = await manager.reloadEffectivePolicy();
			expect(reload.ok).toBe(true);

			const result = await manager.run({ kind: "fs.read", path: "/tmp/foobar" }, async () => {
				called = true;
				return ok("ran");
			});

			expect(result.ok).toBe(false);
			expect(called).toBe(false);
		});
	});

	it("#given prompt decision #when run #then approval required failure is returned", async () => {
		const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy());
		await manager.init();
		const result = await manager.run(
			{ kind: "fs.write", path: `${process.cwd()}/.env`, content: "secret" },
			async () => ok("ran"),
		);
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("high_risk_approval_required");
	});

	it("#given approved prompt id #when run #then operation reaches executor", async () => {
		const operation = { kind: "fs.write", path: `${process.cwd()}/.env`, content: "secret" } as const;
		const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy());
		await manager.init();
		const blocked = await manager.run(operation, async () => ok("blocked"));
		expect(blocked.ok).toBe(false);
		if (blocked.ok || blocked.error.approvalId === undefined) return;
		manager.approveRequestId(blocked.error.approvalId);
		const allowed = await manager.run(operation, async () => ok("ran"));
		expect(allowed).toEqual({ ok: true, value: "ran" });
	});

	it("#given missing backend factory #when registry resolves #then backend missing is returned", async () => {
		const result = await new BackendRegistry().resolve({
			kind: "justbash",
			fs: "memory",
			allowedBinaries: [],
			executionLimits: { maxOutputBytes: 1, maxRuntimeMs: 1 },
		});
		expect(result.ok).toBe(false);
	});

	it("#given auto config #when registry resolves #then auto unresolved failure is returned", async () => {
		const result = await new BackendRegistry().resolve({ kind: "auto" });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("backend_missing");
	});

	it("#given executor backend failure #when run #then failure is preserved", async () => {
		const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy());
		await manager.init();
		const failure = createBlock({
			version: 1,
			code: "sandbox_backend_error",
			policyArea: "backend",
			operation: "test",
			sanitizedTarget: "fake",
			matchedRule: "executor",
			backend: "justbash",
			policyHash: "desired1234567890",
			policyRevision: 7,
			remediation: "Fix backend.",
			backendMessage: "boom",
		});
		const result = await manager.run({ kind: "fs.read", path: `${process.cwd()}/README.md` }, async () => ({
			ok: false,
			error: failure,
		}));
		expect(result).toEqual({ ok: false, error: failure });
	});
});
