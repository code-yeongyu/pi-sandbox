import { expectTypeOf } from "expect-type";
import type {
	ControlEvidence,
	ControlState,
	EffectiveBackendState,
	EffectiveControls,
	EffectivePolicy,
	HealthResult,
	ProbeResult,
} from "../../src/policy/effective.js";
import type { SandboxControl } from "../../src/security/failure.js";

expectTypeOf<ControlState>().toEqualTypeOf<"enforced" | "simulated" | "unverified" | "omitted">();
expectTypeOf<ControlEvidence["state"]>().toEqualTypeOf<ControlState>();
expectTypeOf<ControlEvidence["reason"]>().toEqualTypeOf<string | undefined>();
expectTypeOf<ControlEvidence["probeName"]>().toEqualTypeOf<string | undefined>();
expectTypeOf<ControlEvidence["probeRanAt"]>().toEqualTypeOf<string | undefined>();
expectTypeOf<EffectiveControls>().toExtend<Readonly<Record<SandboxControl, ControlEvidence>>>();
expectTypeOf<ProbeResult>().toExtend<
	| { readonly kind: "passed"; readonly evidence: string; readonly control: SandboxControl }
	| {
			readonly kind: "failed";
			readonly command: string;
			readonly exitCode: number | null;
			readonly reason: string;
			readonly control: SandboxControl;
	  }
>();
expectTypeOf<EffectiveBackendState["effectiveControls"]>().toEqualTypeOf<EffectiveControls>();
expectTypeOf<EffectivePolicy["policyRevision"]>().toEqualTypeOf<number>();
expectTypeOf<HealthResult>().toExtend<{
	readonly healthy: boolean;
	readonly backend: EffectiveBackendState["kind"];
	readonly latencyMs: number;
}>();
