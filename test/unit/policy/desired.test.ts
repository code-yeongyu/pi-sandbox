import { describe, expect, it } from "vitest";

import {
	DesiredBackendConfigSchema,
	type DesiredPolicy,
	DesiredPolicySchema,
	FilePolicySchema,
	type NetworkPolicy,
	NetworkPolicySchema,
} from "../../../src/policy/desired.js";

const filePolicy = {
	defaultRead: "deny",
	defaultWrite: "deny",
	roots: [
		{
			path: "<project>",
			read: true,
			write: true,
			create: true,
			delete: false,
			persist: "host",
			followSymlinks: false,
		},
	],
	denySpecialPaths: ["/proc", "/sys"],
	denyMagicLinks: true,
	highRiskWriteClasses: ["dotenv", "ssh-key"],
	maxReadBytes: 1_048_576,
} as const;

const processPolicy = {
	isolation: true,
	gitHooks: "prompt",
	capDrop: ["CAP_SYS_PTRACE"],
} as const;

const envPolicy = {
	clearenv: true,
	allowlist: ["PATH", "TERM"],
	denyPatterns: ["*_TOKEN", "*_SECRET"],
	scrubProxyEnv: true,
} as const;

const approvals = {
	interactive: true,
	defaultOnNoUi: "deny",
	rememberSession: true,
	allowProjectWrites: true,
	allowGlobalWrites: false,
	batchWindowMs: 250,
} as const;

const tui = {
	statusLine: true,
	detailsWidget: "on-block",
	promptStyle: "compact",
} as const;

const agentAwareness = {
	injectSystemPrompt: true,
	decorateBlockedToolResults: true,
	includeAllowedPaths: true,
	includeAllowedDomains: false,
	includeAllowedBinaries: true,
} as const;

const audit = {
	enabled: true,
	path: ".pi/sandbox-audit.jsonl",
	includeToolArgs: "redacted",
} as const;

describe("NetworkPolicy", () => {
	it("#given deny network policy #when assigning type #then discriminates by mode", () => {
		// given
		const policy = { mode: "deny" } as const satisfies NetworkPolicy;

		// when
		const result = NetworkPolicySchema.parse(policy);

		// then
		expect(result.mode).toBe("deny");
	});

	it("#given allow-all network policy #when assigning type #then schema accepts it", () => {
		// given
		const policy = { mode: "allow-all" } as const satisfies NetworkPolicy;

		// when
		const result = NetworkPolicySchema.parse(policy);

		// then
		expect(result.mode).toBe("allow-all");
	});

	it("#given restricted network policy #when assigning type #then requires structured gateway fields", () => {
		// given
		const policy = {
			mode: "restricted",
			default: "deny",
			allowDomains: ["example.com"],
			denyDomains: ["metadata.google.internal"],
			allowUrlPrefixes: ["https://example.com/api/"],
			allowPorts: [443],
			allowCidrs: ["203.0.113.0/24"],
			denyPrivateNetworks: true,
			denyMetadata: true,
			allowUnixSockets: false,
			scrubProxyEnv: true,
			dns: { servers: ["1.1.1.1"] },
		} as const satisfies NetworkPolicy;

		// when
		const result = NetworkPolicySchema.parse(policy);

		// then
		expect(result.mode).toBe("restricted");
	});
});

describe("DesiredBackendConfig", () => {
	it("#given native backend config #when parsing #then keeps nested platform mechanism discrimination", () => {
		// given
		const config = { kind: "native", platform: "linux", mechanism: "bwrap" } as const;

		// when
		const result = DesiredBackendConfigSchema.parse(config);

		// then
		expect(result.kind).toBe("native");
	});

	it("#given docker backend config #when parsing #then accepts hardened mount configuration", () => {
		// given
		const config = {
			kind: "docker",
			image: "node:22-alpine",
			networkMode: "none",
			readonlyRootfs: true,
			mounts: [{ hostPath: "/repo", sandboxPath: "/workspace", mode: "readonly", persist: "host" }],
			pullPolicy: "if-missing",
			memoryMb: 1024,
			cpuQuota: 50_000,
			capDrop: ["ALL"],
			securityOpt: ["no-new-privileges"],
			tmpfs: ["/tmp:rw,noexec,nosuid,nodev"],
		} as const;

		// when
		const result = DesiredBackendConfigSchema.parse(config);

		// then
		expect(result.kind).toBe("docker");
	});

	it("#given ssh backend config #when parsing #then accepts recursive proxy jump config", () => {
		// given
		const config = {
			kind: "ssh",
			host: "target.example.com",
			port: 22,
			username: "sandbox",
			auth: { kind: "agent", sock: "/tmp/agent.sock" },
			hostVerification: { strict: true, hostHash: "sha256:abc" },
			remoteRoot: "/srv/sandbox",
			proxyJump: [
				{
					kind: "ssh",
					host: "bastion.example.com",
					port: 22,
					username: "sandbox",
					auth: { kind: "kbi" },
					hostVerification: { strict: true, knownHostsPath: "~/.ssh/known_hosts" },
					remoteRoot: "/srv/bastion",
					proxyJump: [],
				},
			],
		} as const;

		// when
		const result = DesiredBackendConfigSchema.parse(config);

		// then
		expect(result.kind).toBe("ssh");
	});
});

describe("DesiredPolicy", () => {
	it("#given complete desired policy #when assigning type #then all locked sections are present", () => {
		// given
		const policy = {
			backend: { kind: "auto" },
			fallbackBackends: ["docker", "justbash"],
			backendMissing: "prompt",
			network: { mode: "deny" },
			file: filePolicy,
			process: processPolicy,
			env: envPolicy,
			approvals,
			tui,
			agentAwareness,
			audit,
		} as const satisfies DesiredPolicy;

		// when
		const result = DesiredPolicySchema.parse(policy);

		// then
		expect(result.backend.kind).toBe("auto");
	});

	it("#given file policy with unknown property #when parsing #then strict schema rejects it", () => {
		// given
		const input = { ...filePolicy, extra: true };

		// when
		const result = FilePolicySchema.safeParse(input);

		// then
		expect(result.success).toBe(false);
	});
});
