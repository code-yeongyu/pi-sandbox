// src/backends/justbash/network.ts — NetworkConfig.allowedUrlPrefixes etc.
import type { NetworkConfig } from "just-bash";

import type { NetworkPolicy } from "../../policy/desired.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";

export function toJustbashNetworkConfig(
	policy: NetworkPolicy | undefined,
): Result<NetworkConfig | undefined, SandboxFailure> {
	if (policy === undefined || policy.mode === "deny") return { ok: true, value: undefined };
	if (policy.mode === "allow-all") return { ok: true, value: { dangerouslyAllowFullInternetAccess: true } };
	if (hasOmittedRestrictedFields(policy)) {
		return {
			ok: false,
			error: createBlock({
				version: 1,
				code: "capability_missing",
				policyArea: "network",
				operation: "network.configure",
				sanitizedTarget: "restricted-network-policy",
				matchedRule: "justbash.supports=allowUrlPrefixes-only",
				backend: "justbash",
				policyHash: "uninitialized",
				policyRevision: 0,
				remediation: "Use only network.allowUrlPrefixes with justbash or switch to a proxy-capable backend.",
				control: "networkAllowlist",
			}),
		};
	}
	return {
		ok: true,
		value: {
			allowedUrlPrefixes: [...policy.allowUrlPrefixes],
			denyPrivateRanges: policy.denyPrivateNetworks || policy.denyMetadata,
		},
	};
}

function hasOmittedRestrictedFields(policy: Extract<NetworkPolicy, { readonly mode: "restricted" }>): boolean {
	return (
		policy.allowDomains.length > 0 ||
		policy.denyDomains.length > 0 ||
		policy.allowPorts.length > 0 ||
		policy.allowCidrs.length > 0 ||
		policy.allowUnixSockets ||
		policy.dns !== "deny" ||
		policy.default !== "deny"
	);
}
