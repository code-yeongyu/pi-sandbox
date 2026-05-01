import type { BackendCapability, SandboxControl } from "../policy/capability.js";
import type { BackendKind } from "../policy/desired.js";
import type { HealthResult, ProbeResult } from "../policy/effective.js";
import type { Result, SandboxFailure } from "../security/failure.js";
import type { PathMapper } from "./path-mapper.js";

export interface SandboxBackend {
	readonly kind: BackendKind;
	readonly capabilities: BackendCapability;
	readonly pathMapper: PathMapper;
	readonly lifecycle: BackendLifecycle;
	readonly bash?: SandboxBashFacet;
	readonly read?: SandboxReadFacet;
	readonly write?: SandboxWriteFacet;
}

export interface SandboxBashFacet {
	exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>>;
}

export interface SandboxReadFacet {
	readFile(absolutePath: string): Promise<Result<Buffer, SandboxFailure>>;
	access(absolutePath: string): Promise<Result<void, SandboxFailure>>;
}

export interface SandboxWriteFacet {
	writeFile(absolutePath: string, content: string | Buffer): Promise<Result<void, SandboxFailure>>;
	mkdir(absolutePath: string): Promise<Result<void, SandboxFailure>>;
}

export interface BackendLifecycle {
	init(): Promise<Result<void, SandboxFailure>>;
	dispose(): Promise<void>;
	health(): Promise<HealthResult>;
	probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]>;
}

export type SandboxExecOptions = {
	readonly cwd: string;
	readonly env?: ReadonlyMap<string, string>;
	readonly signal?: AbortSignal;
	readonly timeoutMs?: number;
	readonly onData?: (data: Buffer) => void;
};
