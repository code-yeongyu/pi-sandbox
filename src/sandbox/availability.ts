// src/sandbox/availability.ts — BackendAvailability + smoke probe orchestration
import type { BackendCapability, SandboxControl } from "../policy/capability.js";
import type { BackendKind, ProbeResult } from "../policy/effective.js";

type NonEmptyArray<TValue> = readonly [TValue, ...TValue[]];

export type BackendAvailability =
	| { status: "available"; backend: BackendKind; capabilities: BackendCapability }
	| {
			status: "degraded";
			backend: BackendKind;
			capabilities: BackendCapability;
			unsupportedControls: NonEmptyArray<SandboxControl>;
			reason: string;
	  }
	| { status: "experimental"; backend: BackendKind; capabilities: BackendCapability; reason: string }
	| { status: "unavailable"; backend: BackendKind; reason: string; probeResults: readonly ProbeResult[] };

export type SmokeProbePhase = "launch" | "capability-security";
