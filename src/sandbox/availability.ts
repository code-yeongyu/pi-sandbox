// src/sandbox/availability.ts — BackendAvailability + smoke probe orchestration
import { z } from "zod";

import {
	type BackendCapability,
	BackendCapabilitySchema,
	type NonEmptyArray,
	SandboxControlSchema,
} from "../policy/capability.js";
import { type BackendKind, BackendKindSchema } from "../policy/desired.js";
import { type ProbeResult, ProbeResultSchema } from "../policy/effective.js";
import type { SandboxControl } from "../security/failure.js";

export const BackendAvailabilitySchema = z.discriminatedUnion("status", [
	z
		.object({
			status: z.literal("available"),
			backend: BackendKindSchema,
			capabilities: BackendCapabilitySchema,
		})
		.strict()
		.readonly(),
	z
		.object({
			status: z.literal("degraded"),
			backend: BackendKindSchema,
			capabilities: BackendCapabilitySchema,
			unsupportedControls: z.array(SandboxControlSchema).nonempty().readonly(),
			reason: z.string(),
		})
		.strict()
		.readonly(),
	z
		.object({
			status: z.literal("experimental"),
			backend: BackendKindSchema,
			capabilities: BackendCapabilitySchema,
			reason: z.string(),
		})
		.strict()
		.readonly(),
	z
		.object({
			status: z.literal("unavailable"),
			backend: BackendKindSchema,
			reason: z.string(),
			probeResults: z.array(ProbeResultSchema).readonly(),
		})
		.strict()
		.readonly(),
]);

export type BackendAvailability =
	| { readonly status: "available"; readonly backend: BackendKind; readonly capabilities: BackendCapability }
	| {
			readonly status: "degraded";
			readonly backend: BackendKind;
			readonly capabilities: BackendCapability;
			readonly unsupportedControls: NonEmptyArray<SandboxControl>;
			readonly reason: string;
	  }
	| {
			readonly status: "experimental";
			readonly backend: BackendKind;
			readonly capabilities: BackendCapability;
			readonly reason: string;
	  }
	| {
			readonly status: "unavailable";
			readonly backend: BackendKind;
			readonly reason: string;
			readonly probeResults: readonly ProbeResult[];
	  };
