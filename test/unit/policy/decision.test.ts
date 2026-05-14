import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { decide } from "../../../src/policy/decision.js";
import type { SandboxOperation } from "../../../src/sandbox/operation.js";
import { makeEffectivePolicy } from "../helpers/effective-policy.js";

function decideOperation(operation: SandboxOperation, approvals: readonly string[] = []) {
	return decide({ operation, effectivePolicy: makeEffectivePolicy(), approvedRequestIds: new Set(approvals) });
}

describe("decide", () => {
	it("#given bash command with URL and denied network #when decided #then network denial is returned", () => {
		const decision = decideOperation({ kind: "bash", command: "curl https://example.com", cwd: process.cwd() });
		expect(decision.kind).toBe("deny");
		if (decision.kind !== "deny") return;
		expect(decision.block.policyArea).toBe("network");
	});

	it("#given fs read through proc fd #when decided #then magic link denial is returned", () => {
		const decision = decideOperation({ kind: "fs.read", path: "/proc/self/fd/1" });
		expect(decision.kind).toBe("deny");
		if (decision.kind !== "deny") return;
		expect(decision.block.code).toBe("magic_link_denied");
	});

	it("#given dotenv write inside root #when decided #then approval prompt is returned", () => {
		const decision = decideOperation({ kind: "fs.write", path: join(process.cwd(), ".env"), content: "TOKEN=value" });
		expect(decision.kind).toBe("prompt");
		if (decision.kind !== "prompt") return;
		expect(decision.class).toBe("dotenv");
	});

	it("#given normal write inside allowed root #when decided #then operation is allowed", () => {
		const decision = decideOperation({ kind: "fs.write", path: join(process.cwd(), "notes.txt"), content: "ok" });
		expect(decision).toEqual({ kind: "allow" });
	});

	it("#given restricted network without gateway #when decided #then capability missing denial is returned", () => {
		const policy = makeEffectivePolicy({
			network: {
				mode: "restricted",
				default: "deny",
				allowDomains: ["example.com"],
				denyDomains: [],
				allowUrlPrefixes: [],
				allowPorts: [],
				allowCidrs: [],
				denyPrivateNetworks: true,
				denyMetadata: true,
				allowUnixSockets: false,
				scrubProxyEnv: true,
				dns: "deny",
			},
			backend: {
				...makeEffectivePolicy().backend,
				capabilities: { ...makeEffectivePolicy().backend.capabilities, networkGateway: false },
			},
		});
		const decision = decide({
			operation: { kind: "network", method: "GET", url: "https://example.com" },
			effectivePolicy: policy,
			approvedRequestIds: new Set(),
		});
		expect(decision.kind).toBe("deny");
		if (decision.kind !== "deny") return;
		expect(decision.block.code).toBe("capability_missing");
	});

	it("#given approved high risk request id #when decided again #then prompt is bypassed", () => {
		const operation: SandboxOperation = {
			kind: "fs.write",
			path: join(process.cwd(), ".env"),
			content: "TOKEN=value",
		};
		const first = decideOperation(operation);
		expect(first.kind).toBe("prompt");
		if (first.kind !== "prompt") return;
		expect(decideOperation(operation, [first.requestId])).toEqual({ kind: "allow" });
	});

	it("#given read outside roots #when decided #then file read denial is returned", () => {
		const decision = decideOperation({ kind: "fs.read", path: "/tmp/outside-file" });
		expect(decision.kind).toBe("deny");
		if (decision.kind !== "deny") return;
		expect(decision.block.policyArea).toBe("file.read");
	});

	it("#given access inside root #when decided #then operation is allowed", () => {
		expect(decideOperation({ kind: "fs.access", path: join(process.cwd(), "notes.txt") })).toEqual({ kind: "allow" });
	});

	it("#given mkdir inside creatable root #when decided #then operation is allowed", () => {
		expect(decideOperation({ kind: "fs.mkdir", path: join(process.cwd(), "new-dir") })).toEqual({ kind: "allow" });
	});

	it("#given restricted network denied by default #when decided #then prompt is returned", () => {
		const policy = makeEffectivePolicy({
			network: {
				mode: "restricted",
				default: "deny",
				allowDomains: [],
				denyDomains: [],
				allowUrlPrefixes: [],
				allowPorts: [],
				allowCidrs: [],
				denyPrivateNetworks: true,
				denyMetadata: true,
				allowUnixSockets: false,
				scrubProxyEnv: true,
				dns: "deny",
			},
		});
		const decision = decide({
			operation: { kind: "network", method: "GET", url: "https://blocked.example" },
			effectivePolicy: policy,
			approvedRequestIds: new Set(),
		});
		expect(decision.kind).toBe("prompt");
	});

	it("#given restricted network allowed domain #when decided #then operation is allowed", () => {
		const policy = makeEffectivePolicy({
			network: {
				mode: "restricted",
				default: "deny",
				allowDomains: ["example.com"],
				denyDomains: [],
				allowUrlPrefixes: [],
				allowPorts: [],
				allowCidrs: [],
				denyPrivateNetworks: true,
				denyMetadata: true,
				allowUnixSockets: false,
				scrubProxyEnv: true,
				dns: "deny",
			},
		});
		const decision = decide({
			operation: { kind: "network", method: "GET", url: "https://api.example.com" },
			effectivePolicy: policy,
			approvedRequestIds: new Set(),
		});
		expect(decision).toEqual({ kind: "allow" });
	});

	it("#given restricted network denied domain #when decided #then prompt is returned", () => {
		const policy = makeEffectivePolicy({
			network: {
				mode: "restricted",
				default: "allow",
				allowDomains: [],
				denyDomains: ["bad.example"],
				allowUrlPrefixes: [],
				allowPorts: [],
				allowCidrs: [],
				denyPrivateNetworks: true,
				denyMetadata: true,
				allowUnixSockets: false,
				scrubProxyEnv: true,
				dns: "deny",
			},
		});
		const decision = decide({
			operation: { kind: "network", method: "GET", url: "https://bad.example" },
			effectivePolicy: policy,
			approvedRequestIds: new Set(),
		});
		expect(decision.kind).toBe("prompt");
	});

	it("#given process isolation disabled #when spawn is decided #then prompt is returned", () => {
		const policy = makeEffectivePolicy({ process: { isolation: false, gitHooks: "prompt", capDrop: [] } });
		const decision = decide({
			operation: { kind: "process.spawn", binary: "node", args: ["-v"], cwd: process.cwd() },
			effectivePolicy: policy,
			approvedRequestIds: new Set(),
		});
		expect(decision.kind).toBe("prompt");
	});

	it("#given npm install with denied network #when decided #then bridge network denial is returned", () => {
		const decision = decideOperation({ kind: "bash", command: "npm install", cwd: process.cwd() });
		expect(decision.kind).toBe("deny");
	});

	it("#given shell script write inside root #when decided #then executable prompt is returned", () => {
		const decision = decideOperation({ kind: "fs.write", path: join(process.cwd(), "run.sh"), content: "#!/bin/sh" });
		expect(decision.kind).toBe("prompt");
		if (decision.kind !== "prompt") return;
		expect(decision.class).toBe("executable");
	});
});
