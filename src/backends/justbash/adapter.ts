// src/backends/justbash/adapter.ts — new Bash() per call; ReadWriteFs/OverlayFs selection

import { randomUUID } from "node:crypto";
import {
	access as accessHostPath,
	mkdir,
	readFile as readHostFile,
	realpath,
	rm,
	writeFile as writeHostFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { Bash, type Command, type NetworkConfig, ReadWriteFs } from "just-bash";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
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
	const ownsSandboxRoot = config.fs !== "read-write-root-locked";
	const sandboxRoot = ownsSandboxRoot
		? path.join(tmpdir(), "pi-sandbox", `sess-${process.pid}-${randomUUID()}`)
		: path.resolve(root);
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
			ownsSandboxRoot,
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
	readonly ownsSandboxRoot: boolean;
	readonly fs: ReadWriteFs;
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
	public readonly read = { readFile: this.readFile.bind(this), access: this.access.bind(this) };
	public readonly write = { writeFile: this.writeFile.bind(this), mkdir: this.mkdir.bind(this) };
	public readonly sandboxRoot: string;
	public readonly ownsSandboxRoot: boolean;
	readonly #config: JustbashBackendConfig;
	readonly #fs: ReadWriteFs;
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
		this.ownsSandboxRoot = options.ownsSandboxRoot;
		this.pathMapper = new JustbashPathMapper(options.projectRoot, options.sandboxRoot);
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const deniedPath = extractAbsolutePaths(command).find((target) => !this.pathMapper.canRepresent(target));
		if (deniedPath !== undefined) {
			return {
				ok: false,
				error: backendFailure("permission_denied", "file.read", "bash", deniedPath, "file.roots.read=missing"),
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
			if (timedOut) return { ok: false, error: timeoutFailure(timeoutMs) };
			if (controller.signal.aborted) return { ok: true, value: { exitCode: 130 } };
			return { ok: true, value: { exitCode: result.exitCode } };
		} catch (cause) {
			if (timedOut) return { ok: false, error: timeoutFailure(timeoutMs) };
			if (controller.signal.aborted) return { ok: true, value: { exitCode: 130 } };
			const message = cause instanceof Error ? cause.message : String(cause);
			return { ok: false, error: backendError(message) };
		} finally {
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
		}
	}

	public async readFile(absolutePath: string): Promise<Result<Buffer, SandboxFailure>> {
		const mappedPath = await this.realPathForRead(absolutePath, "read.readFile");
		if (!mappedPath.ok) return mappedPath;
		try {
			return { ok: true, value: await readHostFile(mappedPath.value) };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		}
	}

	public async access(absolutePath: string): Promise<Result<void, SandboxFailure>> {
		const mappedPath = await this.realPathForRead(absolutePath, "read.access");
		if (!mappedPath.ok) return mappedPath;
		try {
			await accessHostPath(mappedPath.value);
			return { ok: true, value: undefined };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		}
	}

	public async writeFile(absolutePath: string, content: string | Buffer): Promise<Result<void, SandboxFailure>> {
		const mappedPath = await this.realPathForWrite(absolutePath, "write.writeFile");
		if (!mappedPath.ok) return mappedPath;
		try {
			await writeHostFile(mappedPath.value, content);
			return { ok: true, value: undefined };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		}
	}

	public async mkdir(absolutePath: string): Promise<Result<void, SandboxFailure>> {
		const mappedPath = await this.realPathForWrite(absolutePath, "write.mkdir");
		if (!mappedPath.ok) return mappedPath;
		try {
			await mkdir(mappedPath.value, { recursive: true });
			return { ok: true, value: undefined };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		}
	}

	private async realPathForRead(absolutePath: string, operation: string): Promise<Result<string, SandboxFailure>> {
		const mappedPath = this.pathMapper.hostToSandboxPath(absolutePath);
		if (!mappedPath.ok)
			return {
				ok: false,
				error: backendFailure("path_mapping_failed", "backend", operation, absolutePath, mappedPath.error.kind),
			};
		try {
			const root = await realpath(this.sandboxRoot);
			const target = await realpath(path.join(root, mappedPath.value.slice(1)));
			if (isInsideRoot(root, target)) return { ok: true, value: target };
			return {
				ok: false,
				error: backendFailure("permission_denied", "file.read", operation, absolutePath, "file.root.escape"),
			};
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		}
	}

	private async realPathForWrite(absolutePath: string, operation: string): Promise<Result<string, SandboxFailure>> {
		const mappedPath = this.pathMapper.hostToSandboxPath(absolutePath);
		if (!mappedPath.ok)
			return {
				ok: false,
				error: backendFailure("path_mapping_failed", "backend", operation, absolutePath, mappedPath.error.kind),
			};
		try {
			const root = await realpath(this.sandboxRoot);
			const target = path.resolve(root, mappedPath.value.slice(1));

			// Find nearest existing ancestor and verify it resolves inside root
			let parent = target;
			while (true) {
				try {
					await accessHostPath(parent);
					break;
				} catch {
					const next = path.dirname(parent);
					if (next === parent) break;
					parent = next;
				}
			}
			const realParent = await realpath(parent);
			if (!isInsideRoot(root, realParent)) {
				return {
					ok: false,
					error: backendFailure("permission_denied", "file.write", operation, absolutePath, "file.root.escape"),
				};
			}

			// If target exists, realpath it and verify it resolves inside root
			try {
				await accessHostPath(target);
				const realTarget = await realpath(target);
				if (!isInsideRoot(root, realTarget)) {
					return {
						ok: false,
						error: backendFailure("permission_denied", "file.write", operation, absolutePath, "file.root.escape"),
					};
				}
			} catch {
				// target does not exist, which is expected for new writes
			}

			return { ok: true, value: target };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
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
		if (!this.#backend.ownsSandboxRoot) return;
		await rm(this.#backend.sandboxRoot, { recursive: true, force: true });
	}

	public async health(): Promise<HealthResult> {
		return { healthy: true, backend: "justbash", latencyMs: 0, details: "justbash ready" };
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		return controls.map((control) => {
			if (justbashCapability[control] !== false) {
				return { kind: "passed", evidence: evidenceForControl(control), control };
			}
			return {
				kind: "failed",
				command: "probe-unsupported-control",
				exitCode: null,
				reason: "justbash does not enforce this control",
				fixHint: "Use a backend that supports the requested control.",
				control,
			};
		});
	}
}

function evidenceForControl(control: SandboxControl): string {
	if (control === "pathMapping") return "justbash maps host paths into its virtual filesystem";
	return `justbash capability ${control} is available`;
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
	networkAllowlist: false,
	networkGateway: false,
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
	policyArea: "file.read" | "file.write" | "backend",
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

function timeoutFailure(timeoutMs: number): SandboxFailure {
	return createBlock({
		version: 1,
		code: "timeout",
		policyArea: "backend",
		operation: "bash.exec",
		sanitizedTarget: "justbash",
		matchedRule: "execution.timeout",
		backend: "justbash",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Increase the command timeout or run a shorter command.",
		timeoutMs,
	});
}

function isInsideRoot(root: string, target: string): boolean {
	const relativePath = path.relative(root, target);
	return relativePath === "" || (!relativePath.startsWith("..") && !path.isAbsolute(relativePath));
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
