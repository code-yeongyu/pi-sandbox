import { describe, expect, it } from "vitest";

import type { BackendCapability } from "../../../src/policy/capability.js";
import type { BackendAvailability } from "../../../src/sandbox/availability.js";

const capabilities = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "kernel-openat2",
	networkDeny: true,
	networkAllowlist: true,
	networkGateway: true,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: false,
	denialAttribution: true,
} as const satisfies BackendCapability;

describe("BackendAvailability", () => {
	it("#given available backend #when constructed #then carries capabilities", () => {
		// given
		const availability = {
			status: "available",
			backend: "docker",
			capabilities,
		} as const satisfies BackendAvailability;

		// when / then
		expect(availability.status).toBe("available");
	});

	it("#given degraded backend #when constructed #then requires at least one unsupported control", () => {
		// given
		const availability = {
			status: "degraded",
			backend: "ssh",
			capabilities,
			unsupportedControls: ["denialAttribution"],
			reason: "Remote guard is not installed.",
		} as const satisfies BackendAvailability;

		// when / then
		expect(availability.unsupportedControls[0]).toBe("denialAttribution");
	});

	it("#given experimental backend #when constructed #then carries reason", () => {
		// given
		const availability = {
			status: "experimental",
			backend: "native",
			capabilities,
			reason: "Landlock support is experimental.",
		} as const satisfies BackendAvailability;

		// when / then
		expect(availability.reason).toContain("experimental");
	});

	it("#given unavailable backend #when constructed #then carries failed probe results", () => {
		// given
		const availability = {
			status: "unavailable",
			backend: "qemu",
			reason: "qemu-system-x86_64 missing",
			probeResults: [
				{
					kind: "failed",
					command: "qemu-system-x86_64 --version",
					exitCode: 127,
					reason: "binary not found",
					control: "processIsolation",
				},
			],
		} as const satisfies BackendAvailability;

		// when / then
		expect(availability.probeResults[0]?.kind).toBe("failed");
	});
});
