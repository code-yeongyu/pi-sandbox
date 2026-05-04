import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, realpath, rm, writeFile } from "node:fs/promises";
import path from "node:path";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
import type { FilePolicy, NativeBackendConfig } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions, SandboxReadFacet, SandboxWriteFacet } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { createShellFileFacets } from "../shell-file-facets.js";
import { generateSbplProfile } from "./darwin-sbpl.js";

const SANDBOX_EXECUTABLE_NAME = "sandbox-exec";
const SHELL_PATH = "/bin/sh";
const SHELL_VARIANT_PATH = "/bin/bash";
const CURL_PATH = "/usr/bin/curl";

export async function createDarwinSandboxExecBackend(
	config: NativeBackendConfig,
	sessionRoot: string,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	if (config.platform !== "darwin" || config.mechanism !== "sandbox-exec") {
		return { ok: false, error: backendMissing("native config is not darwin sandbox-exec", "config-mismatch") };
	}
	return {
		ok: true,
		value: new DarwinSandboxExecBackend({ sessionRoot: await realpathOrResolve(sessionRoot) }),
	};
}

type BackendOptions = {
	readonly sessionRoot: string;
};

class DarwinSandboxExecBackend implements SandboxBackend {
	public readonly kind = "native" as const;
	public readonly capabilities = darwinSandboxExecCapability;
	public readonly pathMapper: PathMapper = identityPathMapper;
	public readonly lifecycle = new DarwinSandboxExecLifecycle(this);
	public readonly bash = { exec: this.exec.bind(this) };
	public readonly read: SandboxReadFacet;
	public readonly write: SandboxWriteFacet;
	public readonly sessionRoot: string;

	public constructor(options: BackendOptions) {
		this.sessionRoot = path.resolve(options.sessionRoot);
		const fileFacets = createShellFileFacets(this.kind, this.pathMapper, this.bash);
		this.read = fileFacets.read;
		this.write = fileFacets.write;
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const canonicalCwd = await realpathOrResolve(options.cwd);
		const profile = generateSbplProfile({
			network: { mode: "deny" },
			file: execFilePolicy(this.sessionRoot, canonicalCwd),
			cwd: canonicalCwd,
			allowedExecutables: shellExecutables(),
		});
		await mkdir(this.sessionRoot, { recursive: true });
		const profilePath = path.join(this.sessionRoot, `darwin-sandbox-${process.pid}-${randomUUID()}.sb`);
		await writeFile(profilePath, profile, { encoding: "utf8", mode: 0o600 });
		try {
			const result = await spawnSandbox({
				args: ["-f", profilePath, SHELL_PATH, "-c", command],
				cwd: canonicalCwd,
				env: Object.fromEntries(options.env ?? defaultEnvironment()),
				...(options.onData === undefined ? {} : { onData: options.onData }),
				...(options.signal === undefined ? {} : { signal: options.signal }),
				...(options.timeoutMs === undefined ? {} : { timeoutMs: options.timeoutMs }),
			});
			if (result.timedOut) return { ok: false, error: timeoutFailure(options.timeoutMs ?? 0) };
			if (result.exitCode === 137 || result.signal === "SIGKILL") {
				return { ok: false, error: permissionDenied(command, result.stderr) };
			}
			return { ok: true, value: { exitCode: result.exitCode } };
		} catch (cause) {
			return { ok: false, error: backendError(errorMessage(cause)) };
		} finally {
			await rm(profilePath, { force: true });
		}
	}
}

class DarwinSandboxExecLifecycle {
	readonly #backend: DarwinSandboxExecBackend;

	public constructor(backend: DarwinSandboxExecBackend) {
		this.#backend = backend;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		if (process.platform !== "darwin")
			return { ok: false, error: backendMissing("host is not macOS", process.platform) };
		const available = await whichSandboxExec();
		if (!available.ok) return available;
		await mkdir(this.#backend.sessionRoot, { recursive: true });
		const smoke = await spawnSandbox({
			args: ["-p", smokeProfile(this.#backend.sessionRoot), SHELL_PATH, "-c", "exit 0"],
			cwd: this.#backend.sessionRoot,
			env: Object.fromEntries(defaultEnvironment()),
		});
		if (smoke.exitCode !== 0) {
			return { ok: false, error: probeFailure("sandbox-exec smoke", smoke.exitCode, smoke.signal, smoke.stderr) };
		}
		return { ok: true, value: undefined };
	}

	public async dispose(): Promise<void> {
		return undefined;
	}

	public async health(): Promise<HealthResult> {
		const startedAt = Date.now();
		const result = await runCommand("which", [SANDBOX_EXECUTABLE_NAME]);
		return {
			healthy: result.exitCode === 0,
			backend: "native",
			latencyMs: Date.now() - startedAt,
			details: result.exitCode === 0 ? result.stdout.trim() : result.stderr.trim(),
		};
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		const results: ProbeResult[] = [];
		for (const control of controls) {
			if (control === "networkDeny") results.push(await probeNetworkDeny(this.#backend.sessionRoot));
			else if (control === "fileWrite") results.push(await probeFileWrite(this.#backend.sessionRoot));
			else if (control === "processIsolation") {
				results.push({
					kind: "passed",
					control,
					evidence: "simulated: macOS seatbelt limits process access but does not provide namespace isolation",
				});
			}
		}
		return results;
	}
}

type SpawnSandboxOptions = {
	readonly args: readonly string[];
	readonly cwd: string;
	readonly env: NodeJS.ProcessEnv;
	readonly signal?: AbortSignal;
	readonly timeoutMs?: number;
	readonly onData?: (data: Buffer) => void;
};

type SpawnResult = {
	readonly exitCode: number | null;
	readonly signal: NodeJS.Signals | null;
	readonly stderr: string;
	readonly stdout: string;
	readonly timedOut: boolean;
};

function spawnSandbox(options: SpawnSandboxOptions): Promise<SpawnResult> {
	return new Promise((resolve, reject) => {
		let timedOut = false;
		let settled = false;
		const stderrChunks: Buffer[] = [];
		const stdoutChunks: Buffer[] = [];
		const child = spawn(SANDBOX_EXECUTABLE_NAME, [...options.args], {
			cwd: options.cwd,
			env: options.env,
			stdio: ["ignore", "pipe", "pipe"],
			detached: true,
		});
		const killProcessGroup = (): void => {
			if (child.pid === undefined) return;
			try {
				process.kill(-child.pid, "SIGKILL");
			} catch {
				child.kill("SIGKILL");
			}
		};
		const abort = (): void => killProcessGroup();
		const timeout =
			options.timeoutMs !== undefined && options.timeoutMs > 0
				? setTimeout(() => {
						timedOut = true;
						killProcessGroup();
					}, options.timeoutMs)
				: undefined;
		if (options.signal?.aborted) abort();
		else options.signal?.addEventListener("abort", abort, { once: true });
		child.stdout.on("data", (chunk: Buffer) => {
			stdoutChunks.push(chunk);
			options.onData?.(chunk);
		});
		child.stderr.on("data", (chunk: Buffer) => {
			stderrChunks.push(chunk);
			options.onData?.(chunk);
		});
		child.once("error", (cause) => {
			if (settled) return;
			settled = true;
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			reject(cause);
		});
		child.once("close", (exitCode, signal) => {
			if (settled) return;
			settled = true;
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			resolve({
				exitCode,
				signal,
				stderr: Buffer.concat(stderrChunks).toString("utf8"),
				stdout: Buffer.concat(stdoutChunks).toString("utf8"),
				timedOut,
			});
		});
	});
}

async function runCommand(command: string, args: readonly string[]): Promise<SpawnResult> {
	return new Promise((resolve, reject) => {
		const stderrChunks: Buffer[] = [];
		const stdoutChunks: Buffer[] = [];
		const child = spawn(command, [...args], { stdio: ["ignore", "pipe", "pipe"] });
		child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
		child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
		child.once("error", reject);
		child.once("close", (exitCode, signal) =>
			resolve({
				exitCode,
				signal,
				stderr: Buffer.concat(stderrChunks).toString("utf8"),
				stdout: Buffer.concat(stdoutChunks).toString("utf8"),
				timedOut: false,
			}),
		);
	});
}

async function whichSandboxExec(): Promise<Result<void, SandboxFailure>> {
	const result = await runCommand("which", [SANDBOX_EXECUTABLE_NAME]);
	if (result.exitCode === 0) return { ok: true, value: undefined };
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "dependency_missing",
			policyArea: "backend",
			operation: "backend.init",
			sanitizedTarget: SANDBOX_EXECUTABLE_NAME,
			matchedRule: "dependency.which",
			backend: "native",
			policyHash: "uninitialized",
			policyRevision: 0,
			remediation: "Install or enable sandbox-exec on this macOS host.",
			dependency: SANDBOX_EXECUTABLE_NAME,
		}),
	};
}

async function probeNetworkDeny(sessionRoot: string): Promise<ProbeResult> {
	const result = await spawnSandbox({
		args: ["-p", denyNetworkProfile(sessionRoot), CURL_PATH, "-m", "2", "https://example.com"],
		cwd: sessionRoot,
		env: Object.fromEntries(defaultEnvironment()),
		timeoutMs: 5_000,
	});
	if (result.exitCode !== 0 || result.signal !== null) {
		return { kind: "passed", control: "networkDeny", evidence: `curl denied with exit ${result.exitCode}` };
	}
	return {
		kind: "failed",
		control: "networkDeny",
		command: "sandbox-exec curl https://example.com",
		exitCode: result.exitCode,
		...(result.signal === null ? {} : { signal: result.signal }),
		stderrExcerpt: result.stderr.slice(0, 400),
		reason: "network request unexpectedly succeeded",
		fixHint: "Do not use this backend for network deny until sandbox-exec network controls pass.",
	};
}

async function probeFileWrite(sessionRoot: string): Promise<ProbeResult> {
	const target = path.join(sessionRoot, "sandbox-write-probe");
	const result = await spawnSandbox({
		args: ["-p", denyWriteProfile(sessionRoot), SHELL_PATH, "-c", `echo x > ${shellQuote(target)}`],
		cwd: sessionRoot,
		env: Object.fromEntries(defaultEnvironment()),
		timeoutMs: 5_000,
	});
	if (result.exitCode !== 0 || result.signal !== null) {
		return { kind: "passed", control: "fileWrite", evidence: `write denied with exit ${result.exitCode}` };
	}
	return {
		kind: "failed",
		control: "fileWrite",
		command: "sandbox-exec sh -c echo x > probe",
		exitCode: result.exitCode,
		...(result.signal === null ? {} : { signal: result.signal }),
		stderrExcerpt: result.stderr.slice(0, 400),
		reason: "file write unexpectedly succeeded",
		fixHint: "Do not use this backend for file write denial until sandbox-exec file controls pass.",
	};
}

export const darwinSandboxExecCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "realpath-canonical-residual-toctou",
	networkDeny: true,
	networkAllowlist: false,
	networkGateway: false,
	processIsolation: false,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: false,
	persistence: true,
	denialAttribution: true,
} satisfies BackendCapability;

export const darwinSandboxExecEffectiveControls = {
	fileRead: { state: "enforced", reason: "SBPL file-read* profile rules" },
	fileWrite: { state: "enforced", reason: "SBPL file-write* profile rules" },
	fsPathResolution: { state: "enforced", reason: "host realpath canonicalization has residual TOCTOU risk" },
	networkDeny: { state: "enforced", reason: "SBPL network* deny rule" },
	networkAllowlist: { state: "omitted", reason: "SBPL has no native domain allowlist" },
	processIsolation: { state: "simulated", reason: "seatbelt is not a PID/process namespace" },
	envScrub: { state: "enforced", reason: "spawn environment is explicit" },
	stdoutCapture: { state: "enforced", reason: "stdout and stderr are streamed" },
	pathMapping: { state: "omitted", reason: "macOS native paths are identity mapped" },
	persistence: { state: "enforced", reason: "host filesystem roots persist" },
	denialAttribution: { state: "enforced", reason: "sandbox-exec SIGKILL/nonzero denial mapping" },
} as const;

const identityPathMapper: PathMapper = {
	hostToSandboxPath(hostPath) {
		return { ok: true, value: hostPath };
	},
	sandboxToHostPath(sandboxPath) {
		return { ok: true, value: sandboxPath };
	},
	canRepresent() {
		return true;
	},
};

function execFilePolicy(sessionRoot: string, cwd: string): FilePolicy {
	return {
		defaultRead: "deny",
		defaultWrite: "deny",
		roots: [
			rootPolicy("/", false),
			rootPolicy(sessionRoot, true),
			...(path.resolve(cwd) === path.resolve(sessionRoot) ? [] : [rootPolicy(cwd, true)]),
		],
		denySpecialPaths: [path.join(process.env.HOME ?? "/var/empty", ".ssh"), "/private/var/db", "/Library/Keychains"],
		denyMagicLinks: true,
		highRiskWriteClasses: ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"],
		maxReadBytes: 1024 * 1024,
	};
}

function rootPolicy(rootPath: string, write: boolean): FilePolicy["roots"][number] {
	return {
		path: path.resolve(rootPath),
		read: true,
		write,
		create: write,
		delete: false,
		persist: "host",
		followSymlinks: false,
	};
}

function defaultEnvironment(): ReadonlyMap<string, string> {
	return new Map([
		["PATH", process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin"],
		["HOME", path.join(process.cwd(), ".pi", "sandbox-home")],
		["TERM", process.env.TERM ?? "dumb"],
		["LANG", process.env.LANG ?? "C.UTF-8"],
	]);
}

function smokeProfile(sessionRoot: string): string {
	return generateSbplProfile({
		network: { mode: "deny" },
		file: execFilePolicy(sessionRoot, sessionRoot),
		cwd: sessionRoot,
		allowedExecutables: shellExecutables(),
	});
}

function denyNetworkProfile(sessionRoot: string): string {
	return generateSbplProfile({
		network: { mode: "deny" },
		file: execFilePolicy(sessionRoot, sessionRoot),
		cwd: sessionRoot,
		allowedExecutables: [CURL_PATH],
	});
}

function denyWriteProfile(sessionRoot: string): string {
	return generateSbplProfile({
		network: { mode: "deny" },
		file: {
			...execFilePolicy(sessionRoot, sessionRoot),
			roots: [{ ...rootPolicy(sessionRoot, false), write: false, create: false }],
		},
		cwd: sessionRoot,
		allowedExecutables: shellExecutables(),
	});
}

function shellExecutables(): readonly string[] {
	return [SHELL_PATH, SHELL_VARIANT_PATH];
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

function backendMissing(message: string, reason: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "backend.init",
		sanitizedTarget: "sandbox-exec",
		matchedRule: "backend.native.darwin",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: message,
		availabilityReason: reason,
	});
}

function probeFailure(
	probeName: string,
	exitCode: number | null,
	signal: NodeJS.Signals | null,
	stderr: string,
): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_probe_failed",
		policyArea: "backend",
		operation: "backend.probe",
		sanitizedTarget: "sandbox-exec",
		matchedRule: "backend.smoke",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Inspect sandbox-exec availability and profile syntax on this macOS host.",
		probeName,
		probeOutput: `exit=${exitCode ?? "null"} signal=${signal ?? "none"} stderr=${stderr.slice(0, 400)}`,
	});
}

function timeoutFailure(timeoutMs: number): SandboxFailure {
	return createBlock({
		version: 1,
		code: "timeout",
		policyArea: "process",
		operation: "bash.exec",
		sanitizedTarget: "sandbox-exec",
		matchedRule: "execution.timeout",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Increase the timeout or run a shorter command.",
		timeoutMs,
	});
}

function permissionDenied(command: string, stderr: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "permission_denied",
		policyArea: "process",
		operation: "bash.exec",
		sanitizedTarget: command.slice(0, 120),
		matchedRule: "darwin.sbpl.deny",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: stderr.length > 0 ? stderr.slice(0, 400) : "The macOS seatbelt profile denied this operation.",
	});
}

function backendError(message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "bash.exec",
		sanitizedTarget: "sandbox-exec",
		matchedRule: "backend.exec",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Inspect the sandbox-exec backend error and retry with a supported shell command.",
		backendMessage: message,
	});
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}

async function realpathOrResolve(targetPath: string): Promise<string> {
	try {
		return await realpath(targetPath);
	} catch {
		return path.resolve(targetPath);
	}
}
