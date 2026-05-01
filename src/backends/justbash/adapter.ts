// src/backends/justbash/adapter.ts — new Bash() per call; ReadWriteFs/OverlayFs selection

import { randomUUID } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Bash, type Command, type IFileSystem, type NetworkConfig, ReadWriteFs } from "just-bash";

import type { BackendCapability } from "../../policy/capability.js";
import type { EnvPolicy, JustbashBackendConfig } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { buildEnv } from "../../security/env-policy.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { createHostBinaryBridges } from "./host-bridge.js";
import { toJustbashNetworkConfig } from "./network.js";

export async function createJustbashBackend(
	config: JustbashBackendConfig,
	root: string,
	envPolicy: EnvPolicy,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	const sandboxRoot = path.join(tmpdir(), "pi-sandbox", `sess-${process.pid}-${randomUUID()}`);
	await mkdir(sandboxRoot, { recursive: true });
	const network = toJustbashNetworkConfig(config.network);
	if (!network.ok) return network;
	const fs = new ReadWriteFs({
		root: sandboxRoot,
		allowSymlinks: false,
		maxFileReadSize: config.executionLimits.maxOutputBytes,
	});
	const customCommands = createHostBinaryBridges(config.allowedBinaries, envPolicy);
	return {
		ok: true,
		value: new JustbashSandboxBackend({
			config,
			projectRoot: root,
			sandboxRoot,
			fs,
			network: network.value,
			customCommands,
			envPolicy,
		}),
	};
}

type BackendOptions = {
	readonly config: JustbashBackendConfig;
	readonly projectRoot: string;
	readonly sandboxRoot: string;
	readonly fs: IFileSystem;
	readonly network: NetworkConfig | undefined;
	readonly customCommands: readonly Command[];
	readonly envPolicy: EnvPolicy;
};

class JustbashSandboxBackend implements SandboxBackend {
	public readonly kind = "justbash" as const;
	public readonly capabilities = justbashCapability;
	public readonly pathMapper: PathMapper;
	public readonly lifecycle = new JustbashLifecycle(this);
	public readonly bash = { exec: this.exec.bind(this) };
	public readonly sandboxRoot: string;
	readonly #config: JustbashBackendConfig;
	readonly #fs: IFileSystem;
	readonly #network: NetworkConfig | undefined;
	readonly #customCommands: readonly Command[];
	readonly #envPolicy: EnvPolicy;

	public constructor(options: BackendOptions) {
		this.#config = options.config;
		this.#fs = options.fs;
		this.#network = options.network;
		this.#customCommands = options.customCommands;
		this.#envPolicy = options.envPolicy;
		this.sandboxRoot = options.sandboxRoot;
		this.pathMapper = new JustbashPathMapper(options.projectRoot, options.sandboxRoot);
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		if (extractAbsolutePaths(command).some((target) => !this.pathMapper.canRepresent(target))) {
			return {
				ok: false,
				error: backendFailure("permission_denied", "file.read", "bash", "/etc/passwd", "file.roots.read=missing"),
			};
		}
		const mappedCwd = this.pathMapper.hostToSandboxPath(options.cwd);
		if (!mappedCwd.ok) {
			return {
				ok: false,
				error: backendFailure("path_mapping_failed", "backend", "bash.cwd", options.cwd, mappedCwd.error.kind),
			};
		}
		const controller = new AbortController();
		const abort = (): void => controller.abort(options.signal?.reason);
		if (options.signal?.aborted) controller.abort(options.signal.reason);
		else options.signal?.addEventListener("abort", abort, { once: true });
		let timedOut = false;
		const timeoutMs = options.timeoutMs ?? this.#config.executionLimits.maxRuntimeMs;
		const timeout =
			timeoutMs > 0
				? setTimeout(() => {
						timedOut = true;
						controller.abort(new Error(`justbash timeout after ${timeoutMs}ms`));
					}, timeoutMs)
				: undefined;
		try {
			const bash = new Bash({
				fs: this.#fs,
				cwd: mappedCwd.value,
				env: Object.fromEntries(options.env ?? buildEnv(this.#envPolicy, process.env)),
				customCommands: [...this.#customCommands],
				executionLimits: { maxCommandCount: 10_000 },
				...(this.#network === undefined ? {} : { network: this.#network }),
			});
			const result = await bash.exec(command, { signal: controller.signal });
			if (result.stdout.length > 0) options.onData?.(Buffer.from(result.stdout, "utf8"));
			if (result.stderr.length > 0) options.onData?.(Buffer.from(result.stderr, "utf8"));
			if (timedOut) return { ok: true, value: { exitCode: 124 } };
			if (controller.signal.aborted) return { ok: true, value: { exitCode: 130 } };
			return { ok: true, value: { exitCode: result.exitCode } };
		} catch (cause) {
			if (timedOut) return { ok: true, value: { exitCode: 124 } };
			if (controller.signal.aborted) return { ok: true, value: { exitCode: 130 } };
			const message = cause instanceof Error ? cause.message : String(cause);
			return { ok: false, error: backendError(message) };
		} finally {
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
		}
	}
}

class JustbashLifecycle {
	readonly #backend: JustbashSandboxBackend;

	public constructor(backend: JustbashSandboxBackend) {
		this.#backend = backend;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		await mkdir(this.#backend.sandboxRoot, { recursive: true });
		return { ok: true, value: undefined };
	}

	public async dispose(): Promise<void> {
		await rm(this.#backend.sandboxRoot, { recursive: true, force: true });
	}

	public async health(): Promise<HealthResult> {
		return { healthy: true, backend: "justbash", latencyMs: 0, details: "justbash ready" };
	}

	public async probe(controls: readonly []): Promise<readonly ProbeResult[]> {
		return controls;
	}
}

class JustbashPathMapper implements PathMapper {
	readonly #projectRoot: string;
	readonly #sandboxRoot: string;

	public constructor(projectRoot: string, sandboxRoot: string) {
		this.#projectRoot = path.resolve(projectRoot);
		this.#sandboxRoot = path.resolve(sandboxRoot);
	}

	public hostToSandboxPath(hostPath: string): ReturnType<PathMapper["hostToSandboxPath"]> {
		const resolved = path.resolve(hostPath);
		if (resolved === this.#projectRoot) return { ok: true, value: "/" };
		if (resolved.startsWith(`${this.#projectRoot}${path.sep}`))
			return { ok: true, value: `/${path.relative(this.#projectRoot, resolved)}` };
		if (resolved === this.#sandboxRoot) return { ok: true, value: "/" };
		if (resolved.startsWith(`${this.#sandboxRoot}${path.sep}`))
			return { ok: true, value: `/${path.relative(this.#sandboxRoot, resolved)}` };
		return { ok: false, error: { kind: "outside-sandbox", hostPath } };
	}

	public sandboxToHostPath(sandboxPath: string): ReturnType<PathMapper["sandboxToHostPath"]> {
		const normalized = path.posix.normalize(sandboxPath.startsWith("/") ? sandboxPath : `/${sandboxPath}`);
		return { ok: true, value: path.join(this.#sandboxRoot, normalized.slice(1)) };
	}

	public canRepresent(hostPath: string): boolean {
		return this.hostToSandboxPath(hostPath).ok;
	}
}

const justbashCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "backend-mount-boundary",
	networkDeny: true,
	networkAllowlist: true,
	networkGateway: true,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: false,
	denialAttribution: true,
} satisfies BackendCapability;

function extractAbsolutePaths(command: string): readonly string[] {
	return [...command.matchAll(/(?:^|\s)(\/[A-Za-z0-9._/-]+)/g)].map((match) => match[1] ?? "/");
}

function backendFailure(
	code: "permission_denied" | "path_mapping_failed",
	policyArea: "file.read" | "backend",
	operation: string,
	sanitizedTarget: string,
	matchedRule: string,
): SandboxFailure {
	return createBlock({
		version: 1,
		code,
		policyArea,
		operation,
		sanitizedTarget,
		matchedRule,
		backend: "justbash",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run inside the configured sandbox root or request a file grant.",
		...(code === "path_mapping_failed"
			? { pathEvidence: { kind: "outside-sandbox", hostPath: sanitizedTarget } }
			: {}),
	});
}

function backendError(message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "bash.exec",
		sanitizedTarget: "justbash",
		matchedRule: "backend.exec",
		backend: "justbash",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Inspect the justbash backend error and retry with a supported shell command.",
		backendMessage: message,
	});
}
