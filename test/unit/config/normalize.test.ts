import { describe, expect, it } from "vitest";

import { normalizeConfig } from "../../../src/config/normalize.js";
import { type SandboxRawConfig, SandboxRawConfigSchema } from "../../../src/config/schema.js";
import type { BackendCapability } from "../../../src/policy/capability.js";
import type { EffectiveBackendState } from "../../../src/policy/effective.js";

const gatewayCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "backend-mount-boundary",
	networkDeny: true,
	networkAllowlist: true,
	networkGateway: true,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: true,
	denialAttribution: true,
} satisfies BackendCapability;

const effectiveControls = {
	fileRead: { state: "enforced" },
	fileWrite: { state: "enforced" },
	fsPathResolution: { state: "enforced" },
	networkDeny: { state: "enforced" },
	networkAllowlist: { state: "enforced" },
	processIsolation: { state: "enforced" },
	envScrub: { state: "enforced" },
	stdoutCapture: { state: "enforced" },
	pathMapping: { state: "enforced" },
	persistence: { state: "enforced" },
	denialAttribution: { state: "enforced" },
} satisfies EffectiveBackendState["effectiveControls"];

function raw(config: unknown): SandboxRawConfig {
	return SandboxRawConfigSchema.parse(config);
}

function backendState(capabilities: BackendCapability = gatewayCapability): EffectiveBackendState {
	return {
		kind: "docker",
		status: "available",
		capabilities,
		effectiveControls,
		omittedControls: [],
		probeResults: [{ kind: "passed", evidence: "ok", control: "processIsolation" }],
		diagnostics: [],
	};
}

describe("normalizeConfig", () => {
	it("#given minimal config #when normalized #then schema defaults are applied", () => {
		const policy = normalizeConfig({}, backendState());

		expect(policy.network).toEqual({ mode: "deny" });
		expect(policy.file.defaultRead).toBe("deny");
	});

	it("#given full config #when normalized #then file policy is present", () => {
		const policy = normalizeConfig(raw({ file: { maxReadBytes: 1234 } }), backendState());

		expect(policy.file.maxReadBytes).toBe(1234);
		expect(policy.file.denyMagicLinks).toBe(true);
	});

	it("#given backend state #when normalized #then backend state is retained", () => {
		const state = backendState();

		const policy = normalizeConfig({}, state);

		expect(policy.backend.kind).toBe("docker");
		expect(policy.backend.status).toBe("available");
	});

	it("#given normalized policy #when inspected #then output is frozen", () => {
		const policy = normalizeConfig({}, backendState());

		expect(Object.isFrozen(policy)).toBe(true);
		expect(Object.isFrozen(policy.file)).toBe(true);
	});

	it("#given omitted network allowlist #when restricted network normalized #then restricted network is preserved", () => {
		const capability = { ...gatewayCapability, networkAllowlist: false } satisfies BackendCapability;

		const policy = normalizeConfig(
			raw({ network: { mode: "restricted", allowDomains: ["example.com"], denyDomains: [] } }),
			backendState(capability),
		);

		expect(policy.network.mode).toBe("restricted");
	});

	it("#given omitted network allowlist #when normalized #then failure diagnostic is added", () => {
		const capability = { ...gatewayCapability, networkAllowlist: false } satisfies BackendCapability;

		const policy = normalizeConfig(
			raw({ network: { mode: "restricted", allowDomains: ["example.com"], denyDomains: [] } }),
			backendState(capability),
		);

		expect(policy.backend.diagnostics[0]).toContain("session start fails");
	});

	it("#given omitted network allowlist #when normalized #then omitted control is marked", () => {
		const capability = { ...gatewayCapability, networkAllowlist: false } satisfies BackendCapability;

		const policy = normalizeConfig(
			raw({ network: { mode: "restricted", allowDomains: ["example.com"], denyDomains: [] } }),
			backendState(capability),
		);

		expect(policy.backend.omittedControls).toContain("networkAllowlist");
	});

	it("#given gateway-capable backend #when restricted network normalized #then restricted network is preserved", () => {
		const policy = normalizeConfig(
			raw({ network: { mode: "restricted", allowDomains: ["example.com"], denyDomains: [] } }),
			backendState(),
		);

		expect(policy.network.mode).toBe("restricted");
	});

	it("#given normalized policy #when hashes inspected #then hashes are populated", () => {
		const policy = normalizeConfig({}, backendState());

		expect(policy.desiredPolicyHash).toHaveLength(64);
		expect(policy.effectiveCapabilityHash).toHaveLength(64);
		expect(policy.grantHash).toHaveLength(64);
	});

	it("#given normalized policy #when inspected #then policy revision starts at one", () => {
		const policy = normalizeConfig({}, backendState());

		expect(policy.policyRevision).toBe(1);
	});
});
