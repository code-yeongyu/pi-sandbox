import { describe, expect, it } from "vitest";

import type { BackendCapability } from "../../../src/policy/capability.js";
import type { DesiredBackendConfig } from "../../../src/policy/desired.js";
import type { SandboxBackend } from "../../../src/sandbox/backend.js";
import { BackendRegistry } from "../../../src/sandbox/backend-registry.js";

const capabilities = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "not-provided",
	networkDeny: false,
	networkAllowlist: false,
	networkGateway: false,
	processIsolation: false,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: true,
	denialAttribution: true,
} as const satisfies BackendCapability;

const justbashConfig = {
	kind: "justbash",
	fs: "memory",
	allowedBinaries: [],
	executionLimits: { maxOutputBytes: 1024, maxRuntimeMs: 1000 },
} as const satisfies DesiredBackendConfig;

describe("BackendRegistry", () => {
	it("#given registered factory #when resolving matching backend #then returns factory backend", async () => {
		// given
		const registry = new BackendRegistry();
		const backend = fakeBackend("justbash");
		registry.register("justbash", async () => ({ ok: true, value: backend }));

		// when
		const result = await registry.resolve(justbashConfig);

		// then
		expect(result).toEqual({ ok: true, value: backend });
	});

	it("#given factory overwritten for backend kind #when resolving #then latest factory wins", async () => {
		// given
		const registry = new BackendRegistry();
		const firstBackend = fakeBackend("justbash");
		const secondBackend = fakeBackend("justbash");
		registry.register("justbash", async () => ({ ok: true, value: firstBackend }));
		registry.register("justbash", async () => ({ ok: true, value: secondBackend }));

		// when
		const result = await registry.resolve(justbashConfig);

		// then
		expect(result).toEqual({ ok: true, value: secondBackend });
	});

	it("#given no registered factory #when resolving backend #then reports missing factory", async () => {
		// given
		const registry = new BackendRegistry();

		// when
		const result = await registry.resolve(justbashConfig);

		// then
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.code).toBe("backend_missing");
		expect(result.error.matchedRule).toBe("backend.factory-missing");
	});
});

function fakeBackend(kind: "justbash"): SandboxBackend {
	return {
		kind,
		capabilities,
		pathMapper: {
			hostToSandboxPath: (hostPath: string) => ({ ok: true, value: hostPath }),
			sandboxToHostPath: (sandboxPath: string) => ({ ok: true, value: sandboxPath }),
			canRepresent: () => true,
		},
		lifecycle: {
			init: async () => ({ ok: true, value: undefined }),
			dispose: async () => undefined,
			health: async () => ({ healthy: true, backend: kind, latencyMs: 0 }),
			probe: async () => [],
		},
	};
}
