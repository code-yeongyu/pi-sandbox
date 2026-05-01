// src/policy/effective.ts — EffectivePolicy + EffectiveBackendState types
import { z } from "zod";
import type { SandboxControl } from "../security/failure.js";
import { type BackendCapability, BackendCapabilitySchema, SandboxControlSchema } from "./capability.js";
import {
	type BackendKind,
	BackendKindSchema,
	type EnvPolicy,
	EnvPolicySchema,
	type FilePolicy,
	FilePolicySchema,
	type NetworkPolicy,
	NetworkPolicySchema,
	type ProcessPolicy,
	ProcessPolicySchema,
} from "./desired.js";

export const ControlStateSchema = z.enum(["enforced", "simulated", "unverified", "unsupported"]);

export const ControlEvidenceSchema = z
	.object({
		state: ControlStateSchema,
		reason: z.string().optional(),
		probeName: z.string().optional(),
		probeRanAt: z.string().optional(),
	})
	.strict()
	.readonly();

export const EffectiveControlsSchema = z
	.object({
		fileRead: ControlEvidenceSchema,
		fileWrite: ControlEvidenceSchema,
		fsPathResolution: ControlEvidenceSchema,
		networkDeny: ControlEvidenceSchema,
		networkAllowlist: ControlEvidenceSchema,
		processIsolation: ControlEvidenceSchema,
		envScrub: ControlEvidenceSchema,
		stdoutCapture: ControlEvidenceSchema,
		pathMapping: ControlEvidenceSchema,
		persistence: ControlEvidenceSchema,
		denialAttribution: ControlEvidenceSchema,
	})
	.strict()
	.readonly();

export const ProbeResultSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("passed"),
			evidence: z.string(),
			control: SandboxControlSchema,
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("failed"),
			command: z.string(),
			exitCode: z.number().int().nullable(),
			signal: z.string().optional(),
			stderrExcerpt: z.string().optional(),
			reason: z.string(),
			fixHint: z.string().optional(),
			control: SandboxControlSchema,
		})
		.strict()
		.readonly(),
]);

export const EffectiveBackendStateSchema = z
	.object({
		kind: BackendKindSchema,
		status: z.enum(["available", "degraded", "experimental", "unavailable"]),
		capabilities: BackendCapabilitySchema,
		effectiveControls: EffectiveControlsSchema,
		unsupportedControls: z.array(SandboxControlSchema).readonly(),
		probeResults: z.array(ProbeResultSchema).readonly(),
		diagnostics: z.array(z.string()).readonly(),
	})
	.strict()
	.readonly();

export const EffectivePolicySchema = z
	.object({
		network: NetworkPolicySchema,
		file: FilePolicySchema,
		process: ProcessPolicySchema,
		env: EnvPolicySchema,
		backend: EffectiveBackendStateSchema,
		desiredPolicyHash: z.string(),
		grantHash: z.string(),
		effectiveCapabilityHash: z.string(),
		policyRevision: z.number().int().nonnegative(),
	})
	.strict()
	.readonly();

export const HealthResultSchema = z
	.object({
		healthy: z.boolean(),
		backend: BackendKindSchema,
		latencyMs: z.number().nonnegative(),
		details: z.string().optional(),
	})
	.strict()
	.readonly();

export type ControlState = z.infer<typeof ControlStateSchema>;
export type ControlEvidence = z.infer<typeof ControlEvidenceSchema>;
export type EffectiveControls = Readonly<Record<SandboxControl, ControlEvidence>>;
export type ProbeResult = z.infer<typeof ProbeResultSchema>;
export type EffectiveBackendState = {
	readonly kind: BackendKind;
	readonly status: "available" | "degraded" | "experimental" | "unavailable";
	readonly capabilities: BackendCapability;
	readonly effectiveControls: EffectiveControls;
	readonly unsupportedControls: readonly SandboxControl[];
	readonly probeResults: readonly ProbeResult[];
	readonly diagnostics: readonly string[];
};
export type EffectivePolicy = {
	readonly network: NetworkPolicy;
	readonly file: FilePolicy;
	readonly process: ProcessPolicy;
	readonly env: EnvPolicy;
	readonly backend: EffectiveBackendState;
	readonly desiredPolicyHash: string;
	readonly grantHash: string;
	readonly effectiveCapabilityHash: string;
	readonly policyRevision: number;
};
export type HealthResult = z.infer<typeof HealthResultSchema>;
export type { BackendKind } from "./desired.js";
