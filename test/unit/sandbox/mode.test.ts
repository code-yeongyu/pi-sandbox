import { describe, expect, it } from "vitest";

import type { BackendCapability } from "../../../src/policy/capability.js";
import { type SandboxMode, SandboxModeSchema } from "../../../src/sandbox/mode.js";

const capabilities = {
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
} as const satisfies BackendCapability;

function visibleStatus(mode: SandboxMode): string {
	switch (mode.kind) {
		case "enforcing":
			return `enforcing:${mode.backend}`;
		case "disabled-by-user":
			return `disabled:${mode.scope}`;
		case "missing":
			return `missing:${mode.reason}`;
	}
}

describe("SandboxMode", () => {
	it("#given enforcing mode #when constructed #then carries backend capabilities", () => {
		// given
		const mode = { kind: "enforcing", backend: "docker", capabilities } as const satisfies SandboxMode;

		// when / then
		expect(visibleStatus(mode)).toBe("enforcing:docker");
	});

	it("#given disabled mode #when constructed #then carries approval scope and visible reason", () => {
		// given
		const mode = {
			kind: "disabled-by-user",
			approvalId: "approval-1",
			scope: "session",
			visibleReason: "User disabled enforcement for this session.",
		} as const satisfies SandboxMode;

		// when / then
		expect(visibleStatus(mode)).toBe("disabled:session");
	});

	it("#given missing mode #when constructed #then exhaustive match handles it", () => {
		// given
		const mode = {
			kind: "missing",
			backend: "native",
			reason: "sandbox-exec missing",
		} as const satisfies SandboxMode;

		// when / then
		expect(visibleStatus(mode)).toBe("missing:sandbox-exec missing");
	});

	it("#given valid mode variants #when parsed #then schema accepts each discriminator", () => {
		// given
		const variants = [
			{ kind: "enforcing", backend: "docker", capabilities },
			{
				kind: "disabled-by-user",
				approvalId: "approval-1",
				scope: "project",
				visibleReason: "User disabled project enforcement.",
			},
			{ kind: "missing", backend: "native", reason: "sandbox-exec missing" },
		] as const;

		// when / then
		for (const variant of variants) expect(SandboxModeSchema.safeParse(variant).success).toBe(true);
	});

	it("#given extra keys or invalid discriminator #when parsed #then schema rejects invalid modes", () => {
		// given
		const invalidModes = [
			{ kind: "enforcing", backend: "docker", capabilities, extra: true },
			{ kind: "disabled-by-user", approvalId: "approval-1", scope: "global", visibleReason: "invalid scope" },
			{ kind: "paused", reason: "invalid discriminator" },
			{ kind: "missing" },
		] as const;

		// when / then
		for (const invalidMode of invalidModes) expect(SandboxModeSchema.safeParse(invalidMode).success).toBe(false);
	});
});
