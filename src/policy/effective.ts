// src/policy/effective.ts — EffectivePolicy + EffectiveBackendState types
import type { BackendCapability, SandboxControl } from "./capability.js";
import type { EnvPolicy, FilePolicy, NetworkPolicy, ProcessPolicy } from "./desired.js";

export type BackendKind = "native" | "docker" | "justbash" | "qemu" | "ssh";

export type NativeBackendConfig =
	| { kind: "native"; platform: "darwin"; mechanism: "sandbox-exec" }
	| { kind: "native"; platform: "linux"; mechanism: "bwrap" | "landlock-experimental" }
	| { kind: "native"; platform: "win32"; mechanism: "appcontainer" | "wsl2-bwrap" };

export type DesiredBackendConfig =
	| { kind: "auto" }
	| NativeBackendConfig
	| {
			kind: "docker";
			image: string;
			networkMode: "none" | "bridge";
			readonlyRootfs: boolean;
			mounts: readonly string[];
	  }
	| {
			kind: "justbash";
			fs: "memory" | "overlay" | "read-write-root-locked";
			allowedBinaries: readonly string[];
			allowedLibraries: readonly string[];
			network?: NetworkPolicy;
			customCommands: readonly string[];
			executionLimits: { timeoutMs: number; maxOutputBytes: number };
	  }
	| {
			kind: "qemu";
			assets: { mode: "smoke"; assetId: string } | { mode: "user"; kernelPath: string; initrdPath: string };
			cpus: number;
			memoryMb: number;
			shareMode: "ro-9p" | "controlled-rw";
			network: NetworkPolicy;
			snapshot: boolean;
	  }
	| {
			kind: "ssh";
			host: string;
			port: number;
			username: string;
			auth: { method: "password" | "private-key" | "agent" | "keyboard-interactive" | "hostbased" };
			hostVerification: { hostHash: string } | { hostVerifierCommand: string };
			remoteRoot: string;
			sync: "none" | "rsync";
			proxyJump?: string;
	  };

export type ProbeResult = {
	name: string;
	status: "passed" | "failed" | "skipped";
	evidence: string;
};

export type EffectiveBackendState = {
	kind: BackendKind;
	status: "available" | "degraded" | "experimental" | "unavailable";
	capabilities: BackendCapability;
	unsupportedControls: readonly SandboxControl[];
	probeResults: readonly ProbeResult[];
	diagnostics: readonly string[];
};

export type EffectivePolicy = {
	file: FilePolicy;
	network: NetworkPolicy;
	process: ProcessPolicy;
	env: EnvPolicy;
	backend: EffectiveBackendState;
	desiredPolicyHash: string;
	grantHash: string;
	effectiveCapabilityHash: string;
	policyRevision: number;
};
