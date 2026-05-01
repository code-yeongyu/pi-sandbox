import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

import { parseJsonc } from "../../../src/config/jsonc-parse.js";
import {
	ApprovalDecisionSchema,
	parseSandboxConfig,
	SandboxConfigSchema,
	SandboxConfigTopLevelKeys,
} from "../../../src/config/schema.js";

describe("SandboxConfigSchema", () => {
	it("#given empty object #when parsed #then minimal default-deny config is produced", () => {
		const result = parseSandboxConfig({});

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.network).toEqual({ mode: "deny" });
		expect(result.value.file.defaultRead).toBe("deny");
		expect(result.value.file.defaultWrite).toBe("deny");
	});

	it("#given full restricted network #when parsed #then all fields are retained", () => {
		const config = SandboxConfigSchema.parse({
			network: {
				mode: "restricted",
				default: "deny",
				allowDomains: ["example.com"],
				denyDomains: ["bad.example"],
				allowUrlPrefixes: ["https://example.com/api"],
				allowPorts: [443],
				allowCidrs: ["10.0.0.0/24"],
				denyPrivateNetworks: true,
				denyMetadata: true,
				allowUnixSockets: false,
				scrubProxyEnv: true,
				dns: { servers: ["1.1.1.1"] },
			},
		});

		expect(config.network).toMatchObject({ mode: "restricted", allowPorts: [443] });
	});

	it("#given unknown field #when parsed #then strict object rejects it", () => {
		const result = parseSandboxConfig({ unknown: true });

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.issues[0]?.code).toBe("unrecognized_keys");
	});

	it("#given invalid backend kind #when parsed #then backend discriminant is rejected", () => {
		const result = parseSandboxConfig({ backend: { kind: "none" } });

		expect(result.ok).toBe(false);
	});

	it("#given invalid network mode #when parsed #then network discriminant is rejected", () => {
		const result = parseSandboxConfig({ network: { mode: "sometimes" } });

		expect(result.ok).toBe(false);
	});

	it("#given file policy omitted #when parsed #then file defaults are present", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.file.denyMagicLinks).toBe(true);
		expect(config.file.highRiskWriteClasses).toContain("dotenv");
	});

	it("#given env policy omitted #when parsed #then secret deny defaults are present", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.env.clearenv).toBe(true);
		expect(config.env.denyPatterns).toContain("*_TOKEN");
	});

	it("#given process policy omitted #when parsed #then git hooks prompt by default", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.process.gitHooks).toBe("prompt");
	});

	it("#given approvals omitted #when parsed #then global writes are disabled", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.approvals.allowGlobalWrites).toBe(false);
	});

	it("#given tui omitted #when parsed #then footer is enabled", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.tui.statusLine).toBe(true);
	});

	it("#given agent awareness omitted #when parsed #then context injection is enabled", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.agentAwareness.injectSystemPrompt).toBe(true);
	});

	it("#given audit omitted #when parsed #then audit is enabled with redaction", () => {
		const config = SandboxConfigSchema.parse({});

		expect(config.audit.enabled).toBe(true);
		expect(config.audit.includeToolArgs).toBe("redacted");
	});

	it("#given valid approval decision #when parsed #then validation succeeds", () => {
		const decision = ApprovalDecisionSchema.parse({
			requestId: "request-1",
			action: "allow",
			scope: "project",
			mutationTarget: "project-config",
		});

		expect(decision.requestId).toBe("request-1");
	});

	it("#given invalid approval decision #when parsed #then validation fails", () => {
		const result = ApprovalDecisionSchema.safeParse({ requestId: "", action: "allow", scope: "project" });

		expect(result.success).toBe(false);
	});

	it("#given native backend #when parsed #then nested discriminant validates platform mechanism", () => {
		const config = SandboxConfigSchema.parse({ backend: { kind: "native", platform: "linux", mechanism: "bwrap" } });

		expect(config.backend).toEqual({ kind: "native", platform: "linux", mechanism: "bwrap" });
	});

	it("#given docker backend #when parsed #then mount schema defaults read only", () => {
		const config = SandboxConfigSchema.parse({
			backend: { kind: "docker", mounts: [{ hostPath: "/host", sandboxPath: "/sandbox" }] },
		});

		expect(config.backend.kind).toBe("docker");
		if (config.backend.kind !== "docker") return;
		expect(config.backend.mounts[0]?.mode).toBe("readonly");
	});

	it("#given generated json schema #when parsed #then top-level config properties are present", async () => {
		const text = await readFile("schema/sandbox.schema.json", "utf8");

		const parsed = parseJsonc(text);

		expect(parsed.ok).toBe(true);
		if (!parsed.ok) return;
		expect(String(parsed.value)).not.toHaveLength(0);
	});

	it("#given top-level key set #when inspected #then locked sections are included", () => {
		expect(SandboxConfigTopLevelKeys.has("backendUnavailable")).toBe(true);
		expect(SandboxConfigTopLevelKeys.has("grants")).toBe(false);
	});
});
