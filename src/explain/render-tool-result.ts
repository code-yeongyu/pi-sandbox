import type { SandboxBlockV1 } from "../security/failure.js";

export function toToolResultBlock(block: SandboxBlockV1): {
	readonly content: ReadonlyArray<{ readonly type: "text"; readonly text: string }>;
	readonly details: { readonly sandboxBlock: SandboxBlockV1 };
	readonly isError: boolean;
} {
	const text = `[pi-sandbox blocked]\nClass: ${block.policyArea}\nTarget: ${block.sanitizedTarget}\nRule: ${block.matchedRule}\nBackend: ${block.backend}\nDecision: denied\nPolicyHash: ${block.policyHash}\nHow to proceed: ${block.remediation}`;
	return { content: [{ type: "text", text }], details: { sandboxBlock: block }, isError: true };
}
