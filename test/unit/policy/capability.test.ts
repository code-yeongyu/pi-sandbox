import { describe, expect, it } from "vitest";

import {
	BackendCapabilitySchema,
	FsPathResolutionSchema,
	SandboxControlSchema,
} from "../../../src/policy/capability.js";

const validCapability = {
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
} as const;

describe("BackendCapabilitySchema", () => {
	it("#given complete capability contract #when parsed #then all control booleans are retained", () => {
		const result = BackendCapabilitySchema.parse(validCapability);

		expect(result.fileRead).toBe(true);
		expect(result.networkAllowlist).toBe(false);
		expect(result.stdoutCapture).toBe("streaming");
	});

	it("#given missing capability field #when parsed #then schema rejects incomplete contract", () => {
		const { fileRead: _fileRead, ...incompleteCapability } = validCapability;

		const result = BackendCapabilitySchema.safeParse(incompleteCapability);

		expect(result.success).toBe(false);
	});

	it("#given extra capability field #when parsed #then strict schema rejects drift", () => {
		const result = BackendCapabilitySchema.safeParse({ ...validCapability, rawProbeOutput: "egress succeeded" });

		expect(result.success).toBe(false);
	});

	it("#given invalid stdout capture mode #when parsed #then schema rejects it", () => {
		const result = BackendCapabilitySchema.safeParse({ ...validCapability, stdoutCapture: "buffered" });

		expect(result.success).toBe(false);
	});
});

describe("capability enum schemas", () => {
	it("#given documented path resolution modes #when parsed #then all stable modes are accepted", () => {
		expect(FsPathResolutionSchema.options).toEqual([
			"kernel-openat2",
			"backend-mount-boundary",
			"realpath-canonical-residual-toctou",
			"not-provided",
		]);
	});

	it("#given re-exported sandbox control schema #when parsed #then security controls stay aligned", () => {
		expect(SandboxControlSchema.parse("networkAllowlist")).toBe("networkAllowlist");
		expect(SandboxControlSchema.safeParse("networkGateway").success).toBe(false);
	});
});
