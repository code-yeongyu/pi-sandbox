import { describe, expect, it } from "vitest";

import { toBashBlockedOutput } from "../../../src/explain/render-bash-output.js";
import { toToolCallReason } from "../../../src/explain/render-tool-call-reason.js";
import { toToolResultBlock } from "../../../src/explain/render-tool-result.js";
import { makeBlock } from "../helpers/effective-policy.js";

describe("toToolResultBlock", () => {
	it("#given block #when rendered #then result is marked error", () =>
		expect(toToolResultBlock(makeBlock()).isError).toBe(true));
	it("#given block #when rendered #then structured details include block", () =>
		expect(toToolResultBlock(makeBlock()).details.sandboxBlock.code).toBe("permission_denied"));
	it("#given block #when rendered #then text includes class", () =>
		expect(toToolResultBlock(makeBlock()).content[0]?.text).toContain("Class: network"));
	it("#given block #when rendered #then text includes target", () =>
		expect(toToolResultBlock(makeBlock()).content[0]?.text).toContain("Target: https://example.com/path"));
	it("#given block #when rendered #then text includes policy hash", () =>
		expect(toToolResultBlock(makeBlock()).content[0]?.text).toContain("PolicyHash: desired1234567890"));
	it("#given block #when rendered #then text includes remediation", () =>
		expect(toToolResultBlock(makeBlock()).content[0]?.text).toContain("How to proceed: Request access."));
});

describe("toBashBlockedOutput", () => {
	it("#given block #when rendered #then exit code is 126", () =>
		expect(toBashBlockedOutput(makeBlock()).exitCode).toBe(126));
	it("#given block #when rendered #then stderr includes sandbox marker", () =>
		expect(toBashBlockedOutput(makeBlock()).stderr).toContain("[pi-sandbox blocked: network]"));
	it("#given block #when rendered #then stderr includes rule", () =>
		expect(toBashBlockedOutput(makeBlock()).stderr).toContain("network.mode=deny"));
	it("#given block #when rendered #then stderr includes target", () =>
		expect(toBashBlockedOutput(makeBlock()).stderr).toContain("https://example.com/path"));
	it("#given block #when rendered #then stderr points to status command", () =>
		expect(toBashBlockedOutput(makeBlock()).stderr).toContain("/sandbox-status"));
	it("#given block #when rendered #then stderr ends with newline", () =>
		expect(toBashBlockedOutput(makeBlock()).stderr.endsWith("\n")).toBe(true));
});

describe("toToolCallReason", () => {
	it("#given block #when rendered #then block flag is true", () =>
		expect(toToolCallReason(makeBlock()).block).toBe(true));
	it("#given block #when rendered #then reason includes prefix", () =>
		expect(toToolCallReason(makeBlock()).reason).toContain("pi-sandbox:"));
	it("#given block #when rendered #then reason includes policy area", () =>
		expect(toToolCallReason(makeBlock()).reason).toContain("network denied"));
	it("#given block #when rendered #then reason includes target", () =>
		expect(toToolCallReason(makeBlock()).reason).toContain("https://example.com/path"));
	it("#given block #when rendered #then reason includes rule", () =>
		expect(toToolCallReason(makeBlock()).reason).toContain("network.mode=deny"));
	it("#given file block #when rendered #then reason reflects file area", () =>
		expect(toToolCallReason(makeBlock({ policyArea: "file.read", sanitizedTarget: "<project>/x" })).reason).toContain(
			"file.read denied",
		));
});
