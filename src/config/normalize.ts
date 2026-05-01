import type { DesiredPolicy, NetworkPolicy } from "../policy/desired.js";
import type { EffectiveBackendState, EffectivePolicy } from "../policy/effective.js";
import { computeDesiredPolicyHash, computeEffectiveCapabilityHash, computeGrantHash } from "./hash.js";
import { SandboxConfigSchema, type SandboxRawConfig } from "./schema.js";

function deepFreeze<TValue>(value: TValue): Readonly<TValue> {
	if (typeof value !== "object" || value === null) return value;
	Object.freeze(value);
	for (const entry of Object.values(value)) deepFreeze(entry);
	return value;
}

function normalizeNetwork(
	network: NetworkPolicy,
	backendState: EffectiveBackendState,
): { readonly network: NetworkPolicy; readonly backend: EffectiveBackendState } {
	const allowlistUnsupported =
		!backendState.capabilities.networkAllowlist || !backendState.capabilities.networkGateway;
	if (network.mode !== "restricted" || !allowlistUnsupported) return { network, backend: backendState };
	return {
		network: { mode: "deny" },
		backend: {
			...backendState,
			unsupportedControls: [...new Set([...backendState.unsupportedControls, "networkAllowlist" as const])],
			diagnostics: [
				...backendState.diagnostics,
				"restricted network policy requires a gateway-capable backend; forced network mode to deny",
			],
		},
	};
}

export function normalizeConfig(merged: SandboxRawConfig, backendState: EffectiveBackendState): EffectivePolicy {
	const parsed = SandboxConfigSchema.parse(merged);
	const normalizedNetwork = normalizeNetwork(parsed.network, backendState);
	const desiredPolicy: DesiredPolicy = { ...parsed, network: normalizedNetwork.network };
	return deepFreeze({
		file: desiredPolicy.file,
		network: desiredPolicy.network,
		process: desiredPolicy.process,
		env: desiredPolicy.env,
		backend: normalizedNetwork.backend,
		desiredPolicyHash: computeDesiredPolicyHash(desiredPolicy),
		grantHash: computeGrantHash([]),
		effectiveCapabilityHash: computeEffectiveCapabilityHash(normalizedNetwork.backend.capabilities),
		policyRevision: 1,
	});
}
