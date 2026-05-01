// src/sandbox/mode.ts — SandboxMode discriminated union
import type { BackendCapability } from "../policy/capability.js";
import type { BackendKind } from "../policy/effective.js";

export type SandboxMode =
	| { kind: "enforcing"; backend: BackendKind; capabilities: BackendCapability }
	| {
			kind: "disabled-by-user";
			approvalId: string;
			scope: "once" | "session" | "project" | "global";
			visibleReason: string;
	  }
	| { kind: "unavailable"; reason: string };
