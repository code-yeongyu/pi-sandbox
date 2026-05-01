import type { SandboxBlockV1 } from "../security/failure.js";

export function toToolCallReason(block: SandboxBlockV1): { readonly block: true; readonly reason: string } {
	return {
		block: true,
		reason: `pi-sandbox: ${block.policyArea} denied for ${block.sanitizedTarget} (${block.matchedRule})`,
	};
}
