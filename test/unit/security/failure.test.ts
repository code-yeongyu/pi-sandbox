import { describe, expect, it } from "vitest";

import {
	createBlock,
	type Result,
	SandboxAccessDeniedError,
	type SandboxBlockCode,
	SandboxBlockCodeSchema,
	SandboxBlockV1Schema,
} from "../../../src/security/failure.js";

const blockCodes = SandboxBlockCodeSchema.options;

const baseBlock = {
	version: 1,
	policyArea: "file.read",
	operation: "readFile",
	sanitizedTarget: "<project>/secret.txt",
	matchedRule: "default-read-deny",
	backend: "docker",
	policyHash: "policy-hash",
	policyRevision: 7,
	remediation: "Request file.read access for the project path.",
} as const;

function payloadFor(code: SandboxBlockCode): Record<string, unknown> {
	switch (code) {
		case "permission_denied":
			return {};
		case "backend_missing":
			return { availabilityReason: "Docker daemon is stopped" };
		case "dependency_missing":
			return { dependency: "docker" };
		case "capability_missing":
			return { control: "networkAllowlist" };
		case "backend_probe_failed":
			return { probeName: "docker-network-deny", probeOutput: "egress succeeded" };
		case "path_mapping_failed":
			return {
				pathEvidence: {
					kind: "outside-sandbox",
					hostPath: "~/Downloads/input.txt",
					reason: "path is outside configured roots",
				},
			};
		case "policy_hash_mismatch":
			return { expectedPolicyHash: "old-hash", actualPolicyHash: "new-hash" };
		case "secret_denied":
			return { secretClass: "env-token" };
		case "magic_link_denied":
			return { pathEvidence: { kind: "magic-link", path: "/proc/self/fd/1" } };
		case "high_risk_approval_required":
			return { riskClass: "dotenv", requestedScope: "project" };
		case "timeout":
			return { timeoutMs: 30_000 };
		case "sandbox_backend_error":
			return { backendMessage: "container exited before exec" };
	}
}

function validBlockInput(code: SandboxBlockCode): Record<string, unknown> {
	return {
		...baseBlock,
		code,
		...payloadFor(code),
	};
}

describe("createBlock", () => {
	it("#given each stable block code #when creating blocks #then validates every code-specific payload", () => {
		// given / when
		const blocks = blockCodes.map((code) => createBlock(validBlockInput(code)));

		// then
		expect(blocks).toHaveLength(12);
		expect(blocks.map((block) => block.code)).toEqual(blockCodes);
	});

	it("#given valid block input #when creating block #then returns frozen versioned block", () => {
		// given / when
		const block = createBlock(validBlockInput("permission_denied"));

		// then
		expect(block.version).toBe(1);
		expect(Object.isFrozen(block)).toBe(true);
	});

	it("#given approval id #when creating block #then preserves optional approval metadata", () => {
		// given / when
		const block = createBlock({ ...validBlockInput("permission_denied"), approvalId: "approval-1" });

		// then
		expect(block.approvalId).toBe("approval-1");
	});

	it("#given unknown block code #when parsing #then rejects the payload", () => {
		// given
		const input = { ...validBlockInput("permission_denied"), code: "unknown_code" };

		// when
		const result = SandboxBlockV1Schema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});

	it("#given extra top-level field #when parsing #then strict schema rejects the payload", () => {
		// given
		const input = { ...validBlockInput("permission_denied"), diagnostics: ["raw host path"] };

		// when
		const result = SandboxBlockV1Schema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});

	it("#given path mapping block without path evidence #when parsing #then rejects the payload", () => {
		// given
		const input = { ...baseBlock, code: "path_mapping_failed" };

		// when
		const result = SandboxBlockV1Schema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});

	it("#given capability missing block without control #when parsing #then rejects the payload", () => {
		// given
		const input = { ...baseBlock, code: "capability_missing" };

		// when
		const result = SandboxBlockV1Schema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});

	it("#given invalid policy revision #when parsing #then rejects negative values", () => {
		// given
		const input = { ...validBlockInput("permission_denied"), policyRevision: -1 };

		// when
		const result = SandboxBlockV1Schema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});

	it("#given access denied error #when constructed with block #then carries structured block", () => {
		// given
		const block = createBlock(validBlockInput("secret_denied"));

		// when
		const error = new SandboxAccessDeniedError(block);

		// then
		expect(error).toBeInstanceOf(Error);
		expect(error.name).toBe("SandboxAccessDeniedError");
		expect(error.block).toBe(block);
	});

	it("#given result union #when checking ok flag #then narrows success and failure branches", () => {
		// given
		const success: Result<string> = { ok: true, value: "allowed" };
		const failure: Result<string> = { ok: false, error: createBlock(validBlockInput("permission_denied")) };

		// when / then
		if (success.ok) {
			expect(success.value).toBe("allowed");
		}
		if (!failure.ok) {
			expect(failure.error.code).toBe("permission_denied");
		}
	});
});
