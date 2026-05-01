// src/policy/capability.ts — BackendCapability + SandboxControl types
import { z } from "zod";

export type { SandboxControl } from "../security/failure.js";
export { SandboxControlSchema } from "../security/failure.js";

export const FsPathResolutionSchema = z.enum([
	"kernel-openat2",
	"backend-mount-boundary",
	"realpath-canonical-residual-toctou",
	"unsupported",
]);

export const BackendCapabilitySchema = z
	.object({
		fileRead: z.boolean(),
		fileWrite: z.boolean(),
		fsPathResolution: FsPathResolutionSchema,
		networkDeny: z.boolean(),
		networkAllowlist: z.boolean(),
		networkGateway: z.boolean(),
		processIsolation: z.boolean(),
		envScrub: z.boolean(),
		stdoutCapture: z.enum(["streaming", "exit-code-only"]),
		pathMapping: z.boolean(),
		persistence: z.boolean(),
		denialAttribution: z.boolean(),
	})
	.strict()
	.readonly();

export type FsPathResolution = z.infer<typeof FsPathResolutionSchema>;
export type BackendCapability = z.infer<typeof BackendCapabilitySchema>;
export type NonEmptyArray<TValue> = readonly [TValue, ...TValue[]];
