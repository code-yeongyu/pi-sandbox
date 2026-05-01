// src/policy/capability.ts — BackendCapability + SandboxControl types
export type SandboxControl =
	| "fileRead"
	| "fileWrite"
	| "fsPathResolution"
	| "networkDeny"
	| "networkAllowlist"
	| "processIsolation"
	| "envScrub"
	| "stdoutCapture"
	| "pathMapping"
	| "persistence"
	| "denialAttribution";

export type SandboxControlEffectiveness = "enforced" | "simulated" | "unverified" | "unsupported";

export type ControlState<TDesired> = {
	desired: TDesired;
	effective: SandboxControlEffectiveness;
	evidence: readonly string[];
};

export type FsPathResolutionCapability =
	| "kernel-openat2"
	| "backend-mount-boundary"
	| "realpath-canonical(residual-risk:toctou)"
	| "unsupported";

export type StdoutCaptureCapability = "streaming" | "exit-code-only";

export type BackendCapability = {
	fileRead: ControlState<boolean>;
	fileWrite: ControlState<boolean>;
	fsPathResolution: ControlState<FsPathResolutionCapability>;
	networkDeny: ControlState<boolean>;
	networkAllowlist: ControlState<boolean>;
	processIsolation: ControlState<boolean>;
	envScrub: ControlState<boolean>;
	stdoutCapture: ControlState<StdoutCaptureCapability>;
	pathMapping: ControlState<boolean>;
	persistence: ControlState<"ephemeral" | "host" | "unsupported">;
	denialAttribution: ControlState<boolean>;
};
