import { describe, expect, it } from "vitest";
import {
	canonicalize,
	computeDesiredPolicyHash,
	computeEffectiveCapabilityHash,
	computeGrantHash,
	nextRevision,
} from "../../../src/config/hash.js";
import type { BackendCapability } from "../../../src/policy/capability.js";
import type { DesiredPolicy } from "../../../src/policy/desired.js";

const desiredPolicy = {
	backend: { kind: "auto" },
	fallbackBackends: [],
	backendUnavailable: "prompt",
	file: {
		defaultRead: "deny",
		defaultWrite: "deny",
		roots: [],
		denySpecialPaths: [],
		denyMagicLinks: true,
		highRiskWriteClasses: [],
		maxReadBytes: 1,
	},
	network: { mode: "deny" },
	process: { isolation: true, gitHooks: "prompt", capDrop: [] },
	env: { clearenv: true, allowlist: [], denyPatterns: [], scrubProxyEnv: true },
	approvals: {
		interactive: true,
		defaultOnNoUi: "deny",
		rememberSession: true,
		allowProjectWrites: true,
		allowGlobalWrites: false,
		batchWindowMs: 250,
	},
	tui: { statusLine: true, detailsWidget: "on-block", promptStyle: "compact" },
	agentAwareness: {
		injectSystemPrompt: true,
		decorateBlockedToolResults: true,
		includeAllowedPaths: true,
		includeAllowedDomains: false,
		includeAllowedBinaries: true,
	},
	audit: { enabled: true, path: ".pi/sandbox-audit.jsonl", includeToolArgs: "redacted" },
} satisfies DesiredPolicy;

const capability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "backend-mount-boundary",
	networkDeny: true,
	networkAllowlist: false,
	networkGateway: false,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: true,
	denialAttribution: true,
} satisfies BackendCapability;

describe("config hashes", () => {
	it("#given object keys in different order #when canonicalized #then strings match", () => {
		expect(canonicalize({ b: 2, a: 1 })).toBe(canonicalize({ a: 1, b: 2 }));
	});

	it("#given arrays #when canonicalized #then array order is preserved", () => {
		expect(canonicalize(["b", "a"])).not.toBe(canonicalize(["a", "b"]));
	});

	it("#given same desired policy #when hashed #then hash is deterministic", () => {
		expect(computeDesiredPolicyHash(desiredPolicy)).toBe(computeDesiredPolicyHash(desiredPolicy));
	});

	it("#given different desired policy #when hashed #then hash changes", () => {
		const changed = { ...desiredPolicy, backendUnavailable: "fail" } satisfies DesiredPolicy;

		expect(computeDesiredPolicyHash(changed)).not.toBe(computeDesiredPolicyHash(desiredPolicy));
	});

	it("#given grants in different order #when hashed #then grant hash is order independent", () => {
		const left = computeGrantHash([
			{ requestId: "b", action: "allow", scope: "once" },
			{ requestId: "a", action: "deny", scope: "project" },
		]);
		const right = computeGrantHash([
			{ requestId: "a", action: "deny", scope: "project" },
			{ requestId: "b", action: "allow", scope: "once" },
		]);

		expect(left).toBe(right);
	});

	it("#given grant action change #when hashed #then grant hash changes", () => {
		expect(computeGrantHash([{ requestId: "a", action: "allow", scope: "once" }])).not.toBe(
			computeGrantHash([{ requestId: "a", action: "deny", scope: "once" }]),
		);
	});

	it("#given same capability contract #when hashed #then hash is deterministic", () => {
		expect(computeEffectiveCapabilityHash(capability)).toBe(computeEffectiveCapabilityHash(capability));
	});

	it("#given transient probe data #when capability hashed #then transient fields are ignored", () => {
		const withProbeResults: BackendCapability & { probeResults: readonly string[] } = {
			...capability,
			probeResults: ["daemon restarted"],
		};

		expect(computeEffectiveCapabilityHash(withProbeResults)).toBe(computeEffectiveCapabilityHash(capability));
	});

	it("#given capability contract change #when hashed #then capability hash changes", () => {
		const changed = { ...capability, fileRead: false } satisfies BackendCapability;

		expect(computeEffectiveCapabilityHash(changed)).not.toBe(computeEffectiveCapabilityHash(capability));
	});

	it("#given current revision #when nextRevision called #then revision increments", () => {
		expect(nextRevision(41)).toBe(42);
	});
});
