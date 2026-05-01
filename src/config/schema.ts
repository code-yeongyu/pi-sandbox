// src/config/schema.ts — Zod schemas: SandboxConfigSchema, ApprovalDecisionSchema, etc.
import { z } from "zod";

export const ApprovalDecisionSchema = z
	.object({
		requestId: z.string(),
		action: z.enum(["allow", "deny"]),
		scope: z.enum(["once", "session", "project", "global"]),
		mutationTarget: z.enum(["project-config", "global-config"]).optional(),
	})
	.strict();

export const SandboxConfigSchema = z.object({}).strict();

export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;
export type SandboxConfig = z.infer<typeof SandboxConfigSchema>;
