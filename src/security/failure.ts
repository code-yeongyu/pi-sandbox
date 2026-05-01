// src/security/failure.ts — SandboxBlockSchema + SandboxFailure union (Zod)
import { z } from "zod";

export const SandboxBlockCodeSchema = z.enum([
	"permission_denied",
	"backend_unavailable",
	"dependency_missing",
	"capability_unsupported",
	"backend_probe_failed",
	"path_mapping_failed",
	"policy_hash_mismatch",
	"secret_denied",
	"magic_link_denied",
	"high_risk_approval_required",
	"timeout",
	"sandbox_backend_error",
]);

export const SandboxBlockSchema = z
	.object({
		code: SandboxBlockCodeSchema,
		policyArea: z.enum(["file.read", "file.write", "network", "process", "env", "backend"]),
		operation: z.string(),
		sanitizedTarget: z.string(),
		matchedRule: z.string(),
		backend: z.string(),
		policyHash: z.string(),
		policyRevision: z.number().int().nonnegative(),
		approvalId: z.string().optional(),
		remediation: z.string(),
	})
	.strict();

export type SandboxBlockCode = z.infer<typeof SandboxBlockCodeSchema>;
export type SandboxBlock = z.infer<typeof SandboxBlockSchema>;

export type SandboxFailure = SandboxBlock & {
	diagnostics: readonly string[];
};
