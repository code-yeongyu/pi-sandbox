// src/sandbox/mode.ts — SandboxMode discriminated union
import { z } from "zod";
import type { BackendCapability } from "../policy/capability.js";
import { BackendCapabilitySchema } from "../policy/capability.js";
import { type BackendKind, BackendKindSchema } from "../policy/desired.js";

export const SandboxModeSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("enforcing"),
			backend: BackendKindSchema,
			capabilities: BackendCapabilitySchema,
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("disabled-by-user"),
			approvalId: z.string(),
			scope: z.enum(["session", "project"]),
			visibleReason: z.string(),
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("missing"),
			reason: z.string(),
			backend: BackendKindSchema.optional(),
		})
		.strict()
		.readonly(),
]);

export type SandboxMode =
	| { readonly kind: "enforcing"; readonly backend: BackendKind; readonly capabilities: BackendCapability }
	| {
			readonly kind: "disabled-by-user";
			readonly approvalId: string;
			readonly scope: "session" | "project";
			readonly visibleReason: string;
	  }
	| { readonly kind: "missing"; readonly reason: string; readonly backend?: BackendKind };
