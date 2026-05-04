// src/backends/ssh/adapter.ts — ssh2 Client wrapper: streaming exec, abort, exit-code mapping
import path from "node:path";
import type { Duplex } from "node:stream";

import { Client, type ClientChannel, type ConnectConfig } from "ssh2";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
import type { SshBackendConfig } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions, SandboxReadFacet, SandboxWriteFacet } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { createStreamingRedactor } from "../../security/redactor.js";
import { createShellFileFacets } from "../shell-file-facets.js";
import { answerKeyboardInteractivePrompts, buildConnectConfig } from "./auth.js";
import { buildHostVerifier } from "./host-verify.js";
import { buildProxyJumpChain } from "./proxy-jump.js";

export async function createSshBackend(
	config: SshBackendConfig,
	sessionRoot: string,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	return { ok: true, value: new SshSandboxBackend(config, sessionRoot) };
}

class SshSandboxBackend implements SandboxBackend {
	public readonly kind = "ssh" as const;
	public readonly capabilities = sshCapability;
	public readonly pathMapper: PathMapper;
	public readonly lifecycle = new SshLifecycle(this);
	public readonly bash = { exec: this.exec.bind(this) };
	public readonly read: SandboxReadFacet;
	public readonly write: SandboxWriteFacet;
	readonly #config: SshBackendConfig;
	readonly #sessionRoot: string;
	#client: Client | null = null;
	#proxyClose: (() => void) | null = null;

	public constructor(config: SshBackendConfig, sessionRoot: string) {
		this.#config = config;
		this.#sessionRoot = path.resolve(sessionRoot);
		this.pathMapper = new SshPathMapper(sessionRoot, config.remoteRoot);
		const fileFacets = createShellFileFacets(this.kind, this.pathMapper, this.bash);
		this.read = fileFacets.read;
		this.write = fileFacets.write;
	}

	public async connect(): Promise<Result<void, SandboxFailure>> {
		if (this.#client !== null) return { ok: true, value: undefined };
		const connectConfig = buildConnectConfig(this.#config);
		if (!connectConfig.ok) return connectConfig;
		let socket: Duplex | undefined;
		if (this.#config.proxyJump.length > 0) {
			const chain = await buildProxyJumpChain(this.#config);
			if (!chain.ok) return chain;
			socket = chain.value.socket;
			this.#proxyClose = chain.value.close;
		}
		const client = new Client();
		if (this.#config.auth.kind === "kbi") client.on("keyboard-interactive", answerKeyboardInteractivePrompts);
		const result = await connectClient(
			client,
			withSocket(connectConfig.value, socket, buildHostVerifier(this.#config.hostVerification)),
		);
		if (!result.ok) {
			this.#proxyClose?.();
			this.#proxyClose = null;
			return result;
		}
		this.#client = client;
		const healthy = await this.execRemote("true", { cwd: this.#config.remoteRoot });
		return healthy.ok ? { ok: true, value: undefined } : healthy;
	}

	public async dispose(): Promise<void> {
		this.#client?.end();
		this.#client = null;
		this.#proxyClose?.();
		this.#proxyClose = null;
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const mappedCwd = this.pathMapper.hostToSandboxPath(options.cwd);
		if (!mappedCwd.ok) return { ok: false, error: pathMappingFailure(options.cwd, mappedCwd.error.kind) };
		return this.execRemote(scrubbedCommand(command, mappedCwd.value, options.env), options);
	}

	public async execRemote(
		command: string,
		options: Pick<SandboxExecOptions, "onData" | "signal" | "timeoutMs"> & { readonly cwd: string },
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		if (this.#client === null) return { ok: false, error: backendError("SSH client is not connected") };
		return executeOnClient(this.#client, command, options);
	}

	public async probeControl(control: SandboxControl): Promise<ProbeResult> {
		if (control === "envScrub") return this.probeEnvScrub();
		if (control === "pathMapping") {
			return { kind: "passed", evidence: "SSH host path maps to configured remoteRoot", control };
		}
		return {
			kind: "failed",
			command: "probe-unverified-control",
			exitCode: null,
			reason: "ssh-control-unverified-until-remote-guard",
			fixHint: "Install a remote guard before treating SSH controls as enforced.",
			control,
		};
	}

	private async probeEnvScrub(): Promise<ProbeResult> {
		const output: Buffer[] = [];
		const result = await this.exec("printenv", {
			cwd: this.#sessionRoot,
			onData: (data) => output.push(data),
			timeoutMs: 5_000,
		});
		const text = Buffer.concat(output).toString("utf8");
		if (!result.ok) return failedProbe("printenv", null, result.error.remediation, "envScrub");
		const leaked = text
			.split(/\r?\n/u)
			.map((line) => line.split("=", 1)[0] ?? "")
			.filter((name) => isSecretEnvName(name));
		if (text.includes("SSH_AUTH_SOCK=") || leaked.length > 0) {
			return failedProbe(
				"printenv",
				result.value.exitCode,
				`leaked remote env keys: ${leaked.join(",")}`,
				"envScrub",
			);
		}
		return {
			kind: "passed",
			evidence: "remote printenv contains no SSH_AUTH_SOCK or *_KEY/*_TOKEN/*_SECRET",
			control: "envScrub",
		};
	}
}

class SshLifecycle {
	readonly #backend: SshSandboxBackend;

	public constructor(backend: SshSandboxBackend) {
		this.#backend = backend;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		return this.#backend.connect();
	}

	public async dispose(): Promise<void> {
		await this.#backend.dispose();
	}

	public async health(): Promise<HealthResult> {
		const startedAt = performance.now();
		const result = await this.#backend.execRemote("true", { cwd: "/", timeoutMs: 5_000 });
		return {
			healthy: result.ok && result.value.exitCode === 0,
			backend: "ssh",
			latencyMs: performance.now() - startedAt,
			details: result.ok ? "ssh exec true completed" : result.error.remediation,
		};
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		const requested = await Promise.all(controls.map((control) => this.#backend.probeControl(control)));
		return requested;
	}
}

class SshPathMapper implements PathMapper {
	readonly #sessionRoot: string;
	readonly #remoteRoot: string;

	public constructor(sessionRoot: string, remoteRoot: string) {
		this.#sessionRoot = path.resolve(sessionRoot);
		this.#remoteRoot = path.posix.resolve(remoteRoot);
	}

	public hostToSandboxPath(hostPath: string): ReturnType<PathMapper["hostToSandboxPath"]> {
		const resolved = path.resolve(hostPath);
		if (resolved === this.#sessionRoot) return { ok: true, value: this.#remoteRoot };
		if (resolved.startsWith(`${this.#sessionRoot}${path.sep}`)) {
			return { ok: true, value: path.posix.join(this.#remoteRoot, path.relative(this.#sessionRoot, resolved)) };
		}
		return { ok: false, error: { kind: "outside-sandbox", hostPath } };
	}

	public sandboxToHostPath(sandboxPath: string): ReturnType<PathMapper["sandboxToHostPath"]> {
		const normalized = path.posix.resolve(this.#remoteRoot, sandboxPath);
		if (normalized === this.#remoteRoot) return { ok: true, value: this.#sessionRoot };
		if (normalized.startsWith(`${this.#remoteRoot}/`)) {
			return { ok: true, value: path.join(this.#sessionRoot, path.posix.relative(this.#remoteRoot, normalized)) };
		}
		return { ok: false, error: { kind: "outside-sandbox", hostPath: sandboxPath } };
	}

	public canRepresent(hostPath: string): boolean {
		return this.hostToSandboxPath(hostPath).ok;
	}
}

export const sshCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "backend-mount-boundary",
	networkDeny: false,
	networkAllowlist: false,
	networkGateway: false,
	processIsolation: false,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: true,
	persistence: false,
	denialAttribution: false,
} satisfies BackendCapability;

function withSocket(
	config: ConnectConfig,
	socket: Duplex | undefined,
	hostVerifier: (key: Buffer) => boolean,
): ConnectConfig {
	return { ...config, ...(socket === undefined ? {} : { sock: socket }), hostVerifier };
}

function connectClient(client: Client, config: ConnectConfig): Promise<Result<void, SandboxFailure>> {
	return new Promise((resolve) => {
		const cleanup = (): void => {
			client.removeListener("ready", onReady);
			client.removeListener("error", onError);
		};
		const onReady = (): void => {
			cleanup();
			resolve({ ok: true, value: undefined });
		};
		const onError = (error: Error): void => {
			cleanup();
			resolve({ ok: false, error: backendError(error.message) });
		};
		client.once("ready", onReady);
		client.once("error", onError);
		client.connect(config);
	});
}

function executeOnClient(
	client: Client,
	command: string,
	options: Pick<SandboxExecOptions, "onData" | "signal" | "timeoutMs">,
): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
	return new Promise((resolve) => {
		let stream: ClientChannel | null = null;
		let settled = false;
		const redactor = createStreamingRedactor(process.env);
		const finish = (result: Result<{ readonly exitCode: number | null }, SandboxFailure>): void => {
			if (settled) return;
			settled = true;
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			resolve(result);
		};
		const abort = (): void => {
			stream?.signal("KILL");
			client.end();
			finish({ ok: true, value: { exitCode: 130 } });
		};
		const timeout =
			options.timeoutMs !== undefined && options.timeoutMs > 0
				? setTimeout(() => {
						stream?.signal("KILL");
						client.end();
						finish({ ok: false, error: timeoutFailure(options.timeoutMs ?? 0) });
					}, options.timeoutMs)
				: undefined;
		if (options.signal?.aborted) {
			abort();
			return;
		}
		options.signal?.addEventListener("abort", abort, { once: true });
		client.exec(command, { allowHalfOpen: false }, (error, channel) => {
			if (error !== undefined) {
				finish({ ok: false, error: backendError(error.message) });
				return;
			}
			stream = channel;
			channel.on("data", (data: Buffer) => options.onData?.(redactor.redact(data)));
			channel.stderr.on("data", (data: Buffer) => options.onData?.(redactor.redact(data)));
			channel.on("close", (code: number | null) => finish({ ok: true, value: { exitCode: code } }));
		});
	});
}

function scrubbedCommand(command: string, cwd: string, env: ReadonlyMap<string, string> | undefined): string {
	const envAssignments = [...(env ?? new Map<string, string>())]
		.filter(([name]) => !isSecretEnvName(name))
		.map(([name, value]) => `${shellQuote(`${name}=${value}`)}`)
		.join(" ");
	const prefix = envAssignments.length > 0 ? `env -i ${envAssignments}` : "env -i";
	return `${prefix} sh -lc ${shellQuote(`cd ${shellQuote(cwd)} && ${command}`)}`;
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

function isSecretEnvName(name: string): boolean {
	return /(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD|^SSH_AUTH_SOCK$|^AWS_.+|^GCP_.+|^GOOGLE_APPLICATION_CREDENTIALS$)/iu.test(
		name,
	);
}

function failedProbe(command: string, exitCode: number | null, reason: string, control: SandboxControl): ProbeResult {
	return {
		kind: "failed",
		command,
		exitCode,
		reason,
		fixHint: "Install/probe a remote guard or tighten SSH backend configuration.",
		control,
	};
}

function pathMappingFailure(hostPath: string, reason: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "path_mapping_failed",
		policyArea: "backend",
		operation: "ssh.pathMap",
		sanitizedTarget: hostPath,
		matchedRule: reason,
		backend: "ssh",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run SSH commands from the configured session root so paths map to remoteRoot.",
		pathEvidence: { kind: "outside-sandbox", hostPath, reason },
	});
}

function timeoutFailure(timeoutMs: number): SandboxFailure {
	return createBlock({
		version: 1,
		code: "timeout",
		policyArea: "process",
		operation: "ssh.exec",
		sanitizedTarget: "ssh",
		matchedRule: "timeoutMs",
		backend: "ssh",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Increase the command timeout or simplify the remote command.",
		timeoutMs,
	});
}

function backendError(message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "ssh.exec",
		sanitizedTarget: "ssh",
		matchedRule: "ssh2",
		backend: "ssh",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Inspect SSH connectivity, authentication, host-key verification, and remote shell availability.",
		backendMessage: message,
	});
}
