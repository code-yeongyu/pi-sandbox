// src/security/failure.ts — SandboxBlockSchema + SandboxFailure union (Zod)
import { z } from "zod";

export const SandboxControlSchema = z.enum([
	"fileRead",
	"fileWrite",
	"fsPathResolution",
	"networkDeny",
	"networkAllowlist",
	"processIsolation",
	"envScrub",
	"stdoutCapture",
	"pathMapping",
	"persistence",
	"denialAttribution",
]);

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

export const PolicyAreaSchema = z.enum(["file.read", "file.write", "network", "process", "env", "backend"]);

export const BaseBlockSchema = z
	.object({
		version: z.literal(1),
		code: SandboxBlockCodeSchema,
		policyArea: PolicyAreaSchema,
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

const pathEvidenceSchema = z
	.object({
		kind: z.enum(["outside-sandbox", "non-representable", "case-collision", "symlink-loop"]),
		hostPath: z.string(),
		sandboxPath: z.string().optional(),
		reason: z.string().optional(),
	})
	.strict();

const magicLinkEvidenceSchema = z
	.object({
		kind: z.literal("magic-link"),
		path: z.string(),
	})
	.strict();

const highRiskWriteClassSchema = z.enum(["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"]);
const approvalScopeSchema = z.enum(["once", "session", "project", "global"]);

const permissionDeniedBlockSchema = BaseBlockSchema.extend({ code: z.literal("permission_denied") }).strict();
const backendUnavailableBlockSchema = BaseBlockSchema.extend({
	code: z.literal("backend_unavailable"),
	availabilityReason: z.string(),
}).strict();
const dependencyMissingBlockSchema = BaseBlockSchema.extend({
	code: z.literal("dependency_missing"),
	dependency: z.string(),
}).strict();
const capabilityUnsupportedBlockSchema = BaseBlockSchema.extend({
	code: z.literal("capability_unsupported"),
	control: SandboxControlSchema,
}).strict();
const backendProbeFailedBlockSchema = BaseBlockSchema.extend({
	code: z.literal("backend_probe_failed"),
	probeName: z.string(),
	probeOutput: z.string().optional(),
}).strict();
const pathMappingFailedBlockSchema = BaseBlockSchema.extend({
	code: z.literal("path_mapping_failed"),
	pathEvidence: pathEvidenceSchema,
}).strict();
const policyHashMismatchBlockSchema = BaseBlockSchema.extend({
	code: z.literal("policy_hash_mismatch"),
	expectedPolicyHash: z.string(),
	actualPolicyHash: z.string(),
}).strict();
const secretDeniedBlockSchema = BaseBlockSchema.extend({
	code: z.literal("secret_denied"),
	secretClass: z.string(),
}).strict();
const magicLinkDeniedBlockSchema = BaseBlockSchema.extend({
	code: z.literal("magic_link_denied"),
	pathEvidence: magicLinkEvidenceSchema,
}).strict();
const highRiskApprovalRequiredBlockSchema = BaseBlockSchema.extend({
	code: z.literal("high_risk_approval_required"),
	riskClass: highRiskWriteClassSchema,
	requestedScope: approvalScopeSchema.optional(),
}).strict();
const timeoutBlockSchema = BaseBlockSchema.extend({
	code: z.literal("timeout"),
	timeoutMs: z.number().int().nonnegative(),
}).strict();
const sandboxBackendErrorBlockSchema = BaseBlockSchema.extend({
	code: z.literal("sandbox_backend_error"),
	backendMessage: z.string(),
}).strict();

export const SandboxBlockV1Schema = z.discriminatedUnion("code", [
	permissionDeniedBlockSchema,
	backendUnavailableBlockSchema,
	dependencyMissingBlockSchema,
	capabilityUnsupportedBlockSchema,
	backendProbeFailedBlockSchema,
	pathMappingFailedBlockSchema,
	policyHashMismatchBlockSchema,
	secretDeniedBlockSchema,
	magicLinkDeniedBlockSchema,
	highRiskApprovalRequiredBlockSchema,
	timeoutBlockSchema,
	sandboxBackendErrorBlockSchema,
]);

export const SandboxFailureSchema = SandboxBlockV1Schema;

export type SandboxControl = z.infer<typeof SandboxControlSchema>;
export type SandboxBlockCode = z.infer<typeof SandboxBlockCodeSchema>;
export type PolicyArea = z.infer<typeof PolicyAreaSchema>;
export type BaseBlock = z.infer<typeof BaseBlockSchema>;
export type SandboxBlockV1 = z.infer<typeof SandboxBlockV1Schema>;
export type SandboxFailure = z.infer<typeof SandboxFailureSchema>;
export type Result<TValue, TError = SandboxFailure> =
	| { readonly ok: true; readonly value: TValue }
	| { readonly ok: false; readonly error: TError };

export class SandboxAccessDeniedError extends Error {
	public readonly block: SandboxBlockV1;

	public constructor(block: SandboxBlockV1) {
		super(block.remediation);
		this.name = "SandboxAccessDeniedError";
		this.block = block;
	}
}

export function createBlock(input: unknown): SandboxBlockV1 {
	return Object.freeze(SandboxBlockV1Schema.parse(input));
}
