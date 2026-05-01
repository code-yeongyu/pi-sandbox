import type { BackendCapability } from "../policy/capability.js";
import type { EffectivePolicy } from "../policy/effective.js";

export function toAgentContextBlock(effectivePolicy: EffectivePolicy, capability: BackendCapability): string {
	const unsupported = effectivePolicy.backend.unsupportedControls.length;
	const fileClasses = [
		capability.fileRead ? "project root read:available" : "project root read:unsupported",
		capability.fileWrite ? "project root write:available" : "project root write:unsupported",
		"home secrets:denied",
	];
	return [
		`<pi_sandbox active="true" backend="${effectivePolicy.backend.kind}" revision="${effectivePolicy.policyRevision}">`,
		`enforcement: ${effectivePolicy.backend.status}`,
		`mechanism: fs=${capability.fsPathResolution} network=${networkMechanism(capability)} stdout=${capability.stdoutCapture}`,
		`capabilities: ${fileClasses.join("; ")}`,
		`unsupportedDesiredRules: ${unsupported}`,
		`policyHash: ${effectivePolicy.desiredPolicyHash}`,
		"howToRequestAccess: use /sandbox-allow with a typed grant class after a block explains the sanitized target",
		"</pi_sandbox>",
	].join("\n");
}

function networkMechanism(capability: BackendCapability): string {
	if (capability.networkGateway) return "gateway";
	if (capability.networkAllowlist) return "allowlist";
	if (capability.networkDeny) return "deny-only";
	return "unsupported";
}
