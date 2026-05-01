import type { SandboxBlockV1 } from "../security/failure.js";

export function toBashBlockedOutput(block: SandboxBlockV1): { readonly stderr: string; readonly exitCode: number } {
	return {
		stderr: `[pi-sandbox blocked: ${block.policyArea}] ${block.matchedRule}: ${block.sanitizedTarget}\nRun /sandbox-status for details.\n`,
		exitCode: 126,
	};
}
