import type { BackendCapability } from "../../../src/policy/capability.js";
import type { EffectivePolicy } from "../../../src/policy/effective.js";
import type { SandboxBlockV1 } from "../../../src/security/failure.js";
import { createBlock } from "../../../src/security/failure.js";

export const fullCapability: BackendCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "realpath-canonical-residual-toctou",
	networkDeny: true,
	networkAllowlist: true,
	networkGateway: true,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: true,
	denialAttribution: true,
};

export function makeEffectivePolicy(overrides: Partial<EffectivePolicy> = {}): EffectivePolicy {
	const base: EffectivePolicy = {
		network: { mode: "deny" },
		file: {
			defaultRead: "deny",
			defaultWrite: "deny",
			roots: [
				{
					path: process.cwd(),
					read: true,
					write: true,
					create: true,
					delete: false,
					persist: "host",
					followSymlinks: false,
				},
			],
			denySpecialPaths: ["/proc", "/sys", "/dev"],
			denyMagicLinks: true,
			highRiskWriteClasses: ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"],
			maxReadBytes: 1024,
		},
		process: { isolation: true, gitHooks: "prompt", capDrop: [] },
		env: {
			clearenv: true,
			allowlist: ["PATH", "HOME", "TERM", "LANG"],
			denyPatterns: ["*_TOKEN"],
			scrubProxyEnv: true,
		},
		backend: {
			kind: "justbash",
			status: "available",
			capabilities: fullCapability,
			effectiveControls: {
				fileRead: { state: "enforced" },
				fileWrite: { state: "enforced" },
				fsPathResolution: { state: "enforced" },
				networkDeny: { state: "enforced" },
				networkAllowlist: { state: "enforced" },
				processIsolation: { state: "enforced" },
				envScrub: { state: "enforced" },
				stdoutCapture: { state: "enforced" },
				pathMapping: { state: "enforced" },
				persistence: { state: "enforced" },
				denialAttribution: { state: "enforced" },
			},
			omittedControls: [],
			probeResults: [],
			diagnostics: [],
		},
		desiredPolicyHash: "desired1234567890",
		grantHash: "grant1234567890",
		effectiveCapabilityHash: "cap1234567890",
		policyRevision: 7,
	};
	return { ...base, ...overrides };
}

export function makeBlock(overrides: Partial<SandboxBlockV1> = {}): SandboxBlockV1 {
	return createBlock({
		version: 1,
		code: "permission_denied",
		policyArea: "network",
		operation: "network",
		sanitizedTarget: "https://example.com/path",
		matchedRule: "network.mode=deny",
		backend: "justbash",
		policyHash: "desired1234567890",
		policyRevision: 7,
		remediation: "Request access.",
		...overrides,
	});
}
