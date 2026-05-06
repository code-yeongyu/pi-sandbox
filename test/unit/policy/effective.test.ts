import { describe, expect, it } from "vitest";

import {
	EffectiveBackendStateSchema,
	EffectivePolicySchema,
	HealthResultSchema,
	ProbeResultSchema,
} from "../../../src/policy/effective.js";
import { makeEffectivePolicy } from "../helpers/effective-policy.js";

const effectivePolicy = makeEffectivePolicy();
const backendState = effectivePolicy.backend;

describe("EffectiveBackendStateSchema", () => {
	it("#given complete backend state #when parsed #then capability evidence and diagnostics are retained", () => {
		const result = EffectiveBackendStateSchema.parse({
			...backendState,
			omittedControls: ["networkAllowlist"],
			diagnostics: ["restricted network requires gateway"],
		});

		expect(result.kind).toBe("justbash");
		expect(result.omittedControls).toEqual(["networkAllowlist"]);
		expect(result.diagnostics[0]).toContain("gateway");
	});

	it("#given unknown effective control #when parsed #then strict schema rejects it", () => {
		const result = EffectiveBackendStateSchema.safeParse({
			...backendState,
			effectiveControls: {
				...backendState.effectiveControls,
				networkGateway: { state: "enforced" },
			},
		});

		expect(result.success).toBe(false);
	});

	it("#given missing effective control #when parsed #then schema rejects incomplete evidence", () => {
		const { fileRead: _fileRead, ...incompleteControls } = backendState.effectiveControls;

		const result = EffectiveBackendStateSchema.safeParse({
			...backendState,
			effectiveControls: incompleteControls,
		});

		expect(result.success).toBe(false);
	});
});

describe("ProbeResultSchema", () => {
	it("#given passed probe #when parsed #then evidence and control are retained", () => {
		const result = ProbeResultSchema.parse({ kind: "passed", evidence: "blocked egress", control: "networkDeny" });

		expect(result.kind).toBe("passed");
		expect(result.control).toBe("networkDeny");
	});

	it("#given failed probe without required reason #when parsed #then schema rejects it", () => {
		const result = ProbeResultSchema.safeParse({
			kind: "failed",
			command: "curl https://example.com",
			exitCode: 0,
			control: "networkDeny",
		});

		expect(result.success).toBe(false);
	});
});

describe("EffectivePolicySchema", () => {
	it("#given complete effective policy #when parsed #then hashes and revision are retained", () => {
		const result = EffectivePolicySchema.parse(effectivePolicy);

		expect(result.desiredPolicyHash).toBe("desired1234567890");
		expect(result.policyRevision).toBe(7);
	});

	it("#given negative policy revision #when parsed #then schema rejects it", () => {
		const result = EffectivePolicySchema.safeParse({ ...effectivePolicy, policyRevision: -1 });

		expect(result.success).toBe(false);
	});
});

describe("HealthResultSchema", () => {
	it("#given backend health result #when parsed #then latency details are retained", () => {
		const result = HealthResultSchema.parse({ healthy: true, backend: "docker", latencyMs: 12, details: "ok" });

		expect(result.healthy).toBe(true);
		expect(result.latencyMs).toBe(12);
	});

	it("#given negative health latency #when parsed #then schema rejects it", () => {
		const result = HealthResultSchema.safeParse({ healthy: false, backend: "docker", latencyMs: -1 });

		expect(result.success).toBe(false);
	});
});
