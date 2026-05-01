import path from "node:path";

import Dockerode from "dockerode";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
import type { DockerBackendConfig } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { buildDockerContainerOptions } from "./host-config.js";
import { ensureImage } from "./image-pull.js";

const DEFAULT_TIMEOUT_MS = 30_000;

export async function createDockerBackend(
	config: DockerBackendConfig,
	sessionRoot: string,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	return { ok: true, value: new DockerSandboxBackend(new Dockerode(), config, sessionRoot) };
}

class DockerSandboxBackend implements SandboxBackend {
	public readonly kind = "docker" as const;
	public readonly capabilities = dockerCapability;
	public readonly pathMapper: PathMapper;
	public readonly lifecycle: DockerLifecycle;
	public readonly bash = { exec: this.exec.bind(this) };
	readonly #docker: Dockerode;
	readonly #config: DockerBackendConfig;
	readonly #sessionRoot: string;

	public constructor(docker: Dockerode, config: DockerBackendConfig, sessionRoot: string) {
		this.#docker = docker;
		this.#config = config;
		this.#sessionRoot = path.resolve(sessionRoot);
		this.pathMapper = new DockerPathMapper(this.#sessionRoot);
		this.lifecycle = new DockerLifecycle(this.#docker, this.#config, this);
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const mappedCwd = this.pathMapper.hostToSandboxPath(options.cwd);
		if (!mappedCwd.ok) return { ok: false, error: pathMappingFailure(options.cwd, mappedCwd.error.kind) };
		const containerOptions = buildDockerContainerOptions(this.#config, this.#sessionRoot, {
			command: ["/bin/sh", "-lc", command],
			workingDir: mappedCwd.value,
			...(options.env === undefined ? {} : { env: options.env }),
		});
		if (!containerOptions.ok) return containerOptions;

		let container: Dockerode.Container | null = null;
		let timedOut = false;
		let abortRequested = false;
		let settled = false;
		const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		const timeout =
			timeoutMs > 0
				? setTimeout(() => {
						timedOut = true;
						void killContainer(container);
					}, timeoutMs)
				: undefined;
		const abort = (): void => {
			abortRequested = true;
			void killContainer(container);
		};
		if (options.signal?.aborted) abort();
		else options.signal?.addEventListener("abort", abort, { once: true });

		try {
			container = await this.#docker.createContainer(containerOptions.value);
			const stream = await container.attach({ stream: true, stdout: true, stderr: true });
			stream.on("data", (chunk: Buffer) => options.onData?.(stripDockerStreamHeaders(chunk)));
			stream.once("error", (cause) => options.onData?.(Buffer.from(`${errorMessage(cause)}\n`, "utf8")));
			await container.start();
			const waitResult: unknown = await container.wait();
			settled = true;
			if (timedOut) return { ok: true, value: { exitCode: 124 } };
			if (abortRequested) return { ok: true, value: { exitCode: 130 } };
			return { ok: true, value: { exitCode: statusCodeFromWait(waitResult) } };
		} catch (cause) {
			if (timedOut) return { ok: true, value: { exitCode: 124 } };
			if (abortRequested || options.signal?.aborted) return { ok: true, value: { exitCode: 130 } };
			return { ok: false, error: dockerFailure("bash.exec", "container", errorMessage(cause)) };
		} finally {
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			if (!settled) await killContainer(container);
			await removeContainer(container);
		}
	}
}

class DockerLifecycle {
	readonly #docker: Dockerode;
	readonly #config: DockerBackendConfig;
	readonly #backend: DockerSandboxBackend;

	public constructor(docker: Dockerode, config: DockerBackendConfig, backend: DockerSandboxBackend) {
		this.#docker = docker;
		this.#config = config;
		this.#backend = backend;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		try {
			await this.#docker.ping();
			await this.#docker.version();
			return ensureImage(this.#docker, this.#config.image, this.#config.pullPolicy);
		} catch (cause) {
			return { ok: false, error: dockerFailure("lifecycle.init", "daemon", errorMessage(cause)) };
		}
	}

	public async dispose(): Promise<void> {
		return undefined;
	}

	public async health(): Promise<HealthResult> {
		const startedAt = Date.now();
		try {
			await this.#docker.ping();
			return {
				healthy: true,
				backend: "docker",
				latencyMs: Date.now() - startedAt,
				details: "docker daemon reachable",
			};
		} catch (cause) {
			return { healthy: false, backend: "docker", latencyMs: Date.now() - startedAt, details: errorMessage(cause) };
		}
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		const requested = new Set<SandboxControl>(controls);
		const probes: ProbeResult[] = [];
		if (requested.has("networkDeny") && this.#config.networkMode === "none") {
			probes.push(await this.runExitProbe("networkDeny", "curl -m 2 https://example.com >/dev/null 2>&1", true));
		}
		if (requested.has("fsPathResolution")) {
			probes.push(await this.runOutputProbe("fsPathResolution", "ls /Users 2>/dev/null || true", ""));
		}
		if (requested.has("processIsolation")) {
			probes.push(
				await this.runOutputContainsProbe("processIsolation", "capsh --print 2>/dev/null || true", "Current:"),
			);
		}
		if (requested.has("fileWrite")) {
			probes.push(await this.runExitProbe("fileWrite", "touch /test-ro >/dev/null 2>&1", true));
		}
		return probes;
	}

	private async runExitProbe(control: SandboxControl, command: string, expectFailure: boolean): Promise<ProbeResult> {
		const cwd = probeCwd(this.#backend);
		if (!cwd.ok) return failedProbe(control, command, null, cwd.error.kind);
		const result = await this.#backend.bash.exec(command, { cwd: cwd.value });
		if (!result.ok) return failedProbe(control, command, null, result.error.remediation);
		const passed = expectFailure ? result.value.exitCode !== 0 : result.value.exitCode === 0;
		if (passed) return { kind: "passed", evidence: `docker probe ${command} exit=${result.value.exitCode}`, control };
		return failedProbe(control, command, result.value.exitCode, "unexpected probe exit code");
	}

	private async runOutputProbe(control: SandboxControl, command: string, expected: string): Promise<ProbeResult> {
		const chunks: Buffer[] = [];
		const cwd = probeCwd(this.#backend);
		if (!cwd.ok) return failedProbe(control, command, null, cwd.error.kind);
		const result = await this.#backend.bash.exec(command, {
			cwd: cwd.value,
			onData: (data) => chunks.push(data),
		});
		const output = Buffer.concat(chunks).toString("utf8").trim();
		if (result.ok && output === expected)
			return { kind: "passed", evidence: `docker probe output matched ${expected}`, control };
		return failedProbe(control, command, result.ok ? result.value.exitCode : null, output);
	}

	private async runOutputContainsProbe(
		control: SandboxControl,
		command: string,
		expected: string,
	): Promise<ProbeResult> {
		const chunks: Buffer[] = [];
		const cwd = probeCwd(this.#backend);
		if (!cwd.ok) return failedProbe(control, command, null, cwd.error.kind);
		const result = await this.#backend.bash.exec(command, {
			cwd: cwd.value,
			onData: (data) => chunks.push(data),
		});
		const output = Buffer.concat(chunks).toString("utf8");
		if (result.ok && output.includes(expected))
			return { kind: "passed", evidence: `docker probe output included ${expected}`, control };
		return failedProbe(control, command, result.ok ? result.value.exitCode : null, output.slice(0, 200));
	}
}

class DockerPathMapper implements PathMapper {
	readonly #sessionRoot: string;

	public constructor(sessionRoot: string) {
		this.#sessionRoot = path.resolve(sessionRoot);
	}

	public hostToSandboxPath(hostPath: string): ReturnType<PathMapper["hostToSandboxPath"]> {
		const resolved = path.resolve(hostPath);
		if (resolved === this.#sessionRoot) return { ok: true, value: "/workspace" };
		if (resolved.startsWith(`${this.#sessionRoot}${path.sep}`)) {
			const relativePath = path.relative(this.#sessionRoot, resolved).split(path.sep).join(path.posix.sep);
			return { ok: true, value: path.posix.join("/workspace", relativePath) };
		}
		return { ok: false, error: { kind: "outside-sandbox", hostPath } };
	}

	public sandboxToHostPath(sandboxPath: string): ReturnType<PathMapper["sandboxToHostPath"]> {
		const normalized = path.posix.normalize(sandboxPath.startsWith("/") ? sandboxPath : `/${sandboxPath}`);
		if (normalized === "/workspace") return { ok: true, value: this.#sessionRoot };
		if (normalized.startsWith("/workspace/"))
			return { ok: true, value: path.join(this.#sessionRoot, normalized.slice(11)) };
		if (normalized === "/") return { ok: true, value: this.#sessionRoot };
		return { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "outside /workspace" } };
	}

	public canRepresent(hostPath: string): boolean {
		return this.hostToSandboxPath(hostPath).ok;
	}
}

const dockerCapability = {
	fileRead: false,
	fileWrite: false,
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

async function killContainer(container: Dockerode.Container | null): Promise<void> {
	if (container === null) return;
	try {
		await container.kill({ signal: "SIGKILL" });
	} catch {
		return;
	}
}

async function removeContainer(container: Dockerode.Container | null): Promise<void> {
	if (container === null) return;
	try {
		await container.remove({ force: true });
	} catch {
		return;
	}
}

function stripDockerStreamHeaders(chunk: Buffer): Buffer {
	if (chunk.length < 8) return chunk;
	const streamType = chunk[0];
	const size = chunk.readUInt32BE(4);
	if ((streamType !== 1 && streamType !== 2) || size > chunk.length - 8) return chunk;
	return chunk.subarray(8, 8 + size);
}

function statusCodeFromWait(waitResult: unknown): number | null {
	if (typeof waitResult !== "object" || waitResult === null) return null;
	if (!("StatusCode" in waitResult)) return null;
	return typeof waitResult.StatusCode === "number" ? waitResult.StatusCode : null;
}

function probeCwd(backend: DockerSandboxBackend): ReturnType<PathMapper["sandboxToHostPath"]> {
	return backend.pathMapper.sandboxToHostPath("/");
}

function pathMappingFailure(target: string, kind: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "path_mapping_failed",
		policyArea: "backend",
		operation: "bash.cwd",
		sanitizedTarget: target,
		matchedRule: "docker.path-mapper.session-root",
		backend: "docker",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run Docker backend commands from inside the sandbox session root.",
		pathEvidence: { kind, hostPath: target },
	});
}

function failedProbe(control: SandboxControl, command: string, exitCode: number | null, reason: string): ProbeResult {
	return {
		kind: "failed",
		command,
		exitCode,
		stderrExcerpt: reason,
		reason,
		fixHint: "Inspect Docker image tools and daemon support for this hardening probe.",
		control,
	};
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}

function dockerFailure(operation: string, target: string, message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "docker.adapter",
		backend: "docker",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Check Docker daemon availability and container image compatibility.",
		backendMessage: message,
	});
}
