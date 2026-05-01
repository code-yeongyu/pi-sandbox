// src/policy/desired.ts — DesiredPolicy types (NetworkPolicy, FilePolicy, ProcessPolicy, EnvPolicy)
import type { BackendKind, DesiredBackendConfig } from "./effective.js";

export type NetworkPolicy =
	| { mode: "deny" }
	| { mode: "allow-all" }
	| {
			mode: "restricted";
			default: "deny" | "allow";
			allowDomains: readonly string[];
			denyDomains: readonly string[];
			allowUrlPrefixes: readonly string[];
			allowPorts: readonly number[];
			allowCidrs: readonly string[];
			denyPrivateNetworks: boolean;
			denyMetadata: boolean;
			allowUnixSockets: boolean;
			scrubProxyEnv: boolean;
			dns: "deny" | "system" | { servers: readonly string[] };
	  };

export type FilePolicyRoot = {
	path: string;
	read: boolean;
	write: boolean;
	create: boolean;
	delete: boolean;
	persist: "ephemeral" | "host";
	followSymlinks: boolean;
};

export type HighRiskWriteClass = "dotenv" | "ssh-key" | "git-hook" | "shell-rc" | "npm-script" | "executable";

export type FilePolicy = {
	defaultRead: "deny" | "allow";
	defaultWrite: "deny" | "allow";
	roots: readonly FilePolicyRoot[];
	denySpecialPaths: readonly string[];
	denyMagicLinks: boolean;
	highRiskWriteClasses: readonly HighRiskWriteClass[];
	maxReadBytes: number;
};

export type ProcessPolicy = {
	gitHooks: "deny" | "allow" | "prompt";
	allowDebugging: boolean;
};

export type EnvPolicy = {
	mode: "clearenv" | "inherit-filtered";
	allow: readonly string[];
	denyPatterns: readonly string[];
};

export type DesiredPolicy = {
	backend: DesiredBackendConfig;
	fallbackBackends: readonly BackendKind[];
	backendUnavailable: "fail" | "prompt" | "disabled-by-user";
	file: FilePolicy;
	network: NetworkPolicy;
	process: ProcessPolicy;
	env: EnvPolicy;
};
