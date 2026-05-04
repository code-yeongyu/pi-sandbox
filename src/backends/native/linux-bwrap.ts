import { spawn } from "node:child_process";
import path from "node:path";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
import type { FilePolicy, NativeBackendConfig, NetworkPolicy } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions, SandboxReadFacet, SandboxWriteFacet } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { createShellFileFacets } from "../shell-file-facets.js";
import { buildBwrapArgs } from "./linux-bwrap-args.js";

const BWRAP_BINARY = "bwrap";
const DEFAULT_TIMEOUT_MS = 30_000;
const SMOKE_ARGS = [
	"--unshare-user",
	"--unshare-pid",
	"--die-with-parent",
	"--ro-bind",
	"/usr",
	"/usr",
	"--proc",
	"/proc",
	"/bin/true",
] as const;

export async function createLinuxBwrapBackend(
	config: NativeBackendConfig,
	sessionRoot: string,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	if (config.platform !== "linux" || config.mechanism !== "bwrap") {
		return { ok: false, error: dependencyFailure("native-linux-bwrap", "native linux bwrap config required") };
	}
	return { ok: true, value: new LinuxBwrapBackend(sessionRoot) };
}

class LinuxBwrapBackend implements SandboxBackend {
	public readonly kind = "native" as const;
	public readonly capabilities = linuxBwrapCapability;
	public readonly pathMapper: PathMapper = new IdentityPathMapper();
	public readonly lifecycle = new LinuxBwrapLifecycle();
	public readonly bash = { exec: this.exec.bind(this) };
	public readonly read: SandboxReadFacet;
	public readonly write: SandboxWriteFacet;
	readonly #sessionRoot: string;

	public constructor(sessionRoot: string) {
		this.#sessionRoot = path.resolve(sessionRoot);
		const fileFacets = createShellFileFacets(this.kind, this.pathMapper, this.bash);
		this.read = fileFacets.read;
		this.write = fileFacets.write;
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const policy = buildExecutionPolicy({ sessionRoot: this.#sessionRoot, options });
		let bwrapArgs: readonly string[];
		try {
			bwrapArgs = [...buildBwrapArgs(policy), "/bin/sh", "-c", command];
		} catch (cause) {
			return { ok: false, error: magicLinkFailure(messageFromCause(cause), options.cwd) };
		}

		const result = await runBwrap(bwrapArgs, {
			timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
			...(options.signal === undefined ? {} : { signal: options.signal }),
			...(options.onData === undefined ? {} : { onStdout: options.onData, onStderr: options.onData }),
		});
		if (result.kind === "spawn-error") return { ok: false, error: backendError(result.message) };
		if (result.kind === "timeout") return { ok: false, error: timeoutFailure(result.timeoutMs) };
		if (result.kind === "aborted") return { ok: true, value: { exitCode: 130 } };
		if (isPermissionDenied(result.stderr)) {
			return {
				ok: false,
				error: permissionDeniedFailure(result.stderr.trim() || "bwrap denied operation", "bash.exec"),
			};
		}
		return { ok: true, value: { exitCode: result.exitCode } };
	}
}

class LinuxBwrapLifecycle {
	public async init(): Promise<Result<void, SandboxFailure>> {
		if (process.platform !== "linux") {
			return { ok: false, error: dependencyFailure("linux", `linux required, got ${process.platform}`) };
		}
		const smoke = await runSmoke();
		if (!smoke.ok) return smoke;
		return { ok: true, value: undefined };
	}

	public async dispose(): Promise<void> {
		return undefined;
	}

	public async health(): Promise<HealthResult> {
		const startedAt = Date.now();
		const smoke = await runSmoke();
		return {
			healthy: smoke.ok,
			backend: "native",
			latencyMs: Date.now() - startedAt,
			details: smoke.ok ? "bwrap smoke passed" : smoke.error.remediation,
		};
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		const selectedControls = controls.length === 0 ? bwrapProbeControls : controls;
		const probes = await Promise.all(
			selectedControls.map(async (control) => {
				if (control === "networkDeny") return networkDenyProbe();
				if (control === "fileWrite") return fileWriteProbe();
				if (control === "processIsolation") return processIsolationProbe();
				if (control === "fsPathResolution") return magicLinkDenyProbe();
				return omittedProbe(control);
			}),
		);
		return probes;
	}
}

class IdentityPathMapper implements PathMapper {
	public hostToSandboxPath(hostPath: string): ReturnType<PathMapper["hostToSandboxPath"]> {
		return { ok: true, value: hostPath };
	}

	public sandboxToHostPath(sandboxPath: string): ReturnType<PathMapper["sandboxToHostPath"]> {
		return { ok: true, value: sandboxPath };
	}

	public canRepresent(_hostPath: string): boolean {
		return true;
	}
}

type RunBwrapOptions = {
	readonly timeoutMs: number;
	readonly signal?: AbortSignal;
	readonly onStdout?: (data: Buffer) => void;
	readonly onStderr?: (data: Buffer) => void;
};

type RunBwrapResult =
	| {
			readonly kind: "exited";
			readonly exitCode: number | null;
			readonly signal: NodeJS.Signals | null;
			readonly stderr: string;
			readonly stdout: string;
	  }
	| { readonly kind: "timeout"; readonly timeoutMs: number; readonly stderr: string; readonly stdout: string }
	| { readonly kind: "aborted"; readonly stderr: string; readonly stdout: string }
	| { readonly kind: "spawn-error"; readonly message: string; readonly stderr: string; readonly stdout: string };

async function runSmoke(): Promise<Result<void, SandboxFailure>> {
	const result = await runBwrap(SMOKE_ARGS, { timeoutMs: 5_000 });
	if (result.kind === "exited" && result.exitCode === 0) return { ok: true, value: undefined };
	if (result.kind === "spawn-error") return { ok: false, error: dependencyFailure(BWRAP_BINARY, result.message) };
	return { ok: false, error: probeFailure("bwrap smoke", result) };
}

function runBwrap(args: readonly string[], options: RunBwrapOptions): Promise<RunBwrapResult> {
	return new Promise((resolve) => {
		const child = spawn(BWRAP_BINARY, args, { stdio: ["ignore", "pipe", "pipe"], detached: true });
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		let settled = false;
		let timedOut = false;
		let aborted = false;

		const settle = (result: RunBwrapResult): void => {
			if (settled) return;
			settled = true;
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
			resolve(result);
		};
		const killChildGroup = (): void => {
			if (child.pid !== undefined) {
				try {
					process.kill(-child.pid, "SIGKILL");
				} catch (cause) {
					if (!isNoSuchProcess(cause)) throw cause;
				}
			}
		};
		const abort = (): void => {
			aborted = true;
			killChildGroup();
		};
		const timeout =
			options.timeoutMs > 0
				? setTimeout(() => {
						timedOut = true;
						killChildGroup();
					}, options.timeoutMs)
				: undefined;

		child.stdout.on("data", (data: Buffer) => {
			stdout.push(data);
			options.onStdout?.(data);
		});
		child.stderr.on("data", (data: Buffer) => {
			stderr.push(data);
			options.onStderr?.(data);
		});
		child.on("error", (cause) => {
			settle({
				kind: "spawn-error",
				message: cause.message,
				stdout: joinBuffers(stdout),
				stderr: joinBuffers(stderr),
			});
		});
		child.on("close", (exitCode, signal) => {
			const output = { stdout: joinBuffers(stdout), stderr: joinBuffers(stderr) };
			if (timedOut) settle({ kind: "timeout", timeoutMs: options.timeoutMs, ...output });
			else if (aborted) settle({ kind: "aborted", ...output });
			else settle({ kind: "exited", exitCode, signal, ...output });
		});

		if (options.signal?.aborted) abort();
		else options.signal?.addEventListener("abort", abort, { once: true });
	});
}

type ExecutionPolicyOptions = {
	readonly sessionRoot: string;
	readonly options: SandboxExecOptions;
};

function buildExecutionPolicy(input: ExecutionPolicyOptions): {
	readonly network: NetworkPolicy;
	readonly file: FilePolicy;
	readonly cwd: string;
	readonly env: ReadonlyMap<string, string>;
	readonly allowedExecutables: readonly string[];
	readonly sessionRoot: string;
} {
	return {
		network: { mode: "deny" },
		file: {
			defaultRead: "deny",
			defaultWrite: "deny",
			roots: [
				{
					path: input.options.cwd,
					read: true,
					write: true,
					create: true,
					delete: true,
					persist: "host",
					followSymlinks: false,
				},
			],
			denySpecialPaths: ["/proc", "/sys"],
			denyMagicLinks: true,
			highRiskWriteClasses: [],
			maxReadBytes: 1024 * 1024,
		},
		cwd: input.options.cwd,
		env: input.options.env ?? new Map(),
		allowedExecutables: [],
		sessionRoot: input.sessionRoot,
	};
}

async function networkDenyProbe(): Promise<ProbeResult> {
	const args = [
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--unshare-net",
		"--ro-bind-try",
		"/usr",
		"/usr",
		"--ro-bind-try",
		"/bin",
		"/bin",
		"--proc",
		"/proc",
		"/bin/sh",
		"-c",
		"curl -m 2 https://example.com",
	];
	const result = await runBwrap(args, { timeoutMs: 5_000 });
	if (result.kind === "exited" && result.exitCode !== 0) {
		return { kind: "passed", evidence: "curl failed inside --unshare-net namespace", control: "networkDeny" };
	}
	return failedProbe("networkDeny", "bwrap network deny", result, "Expected curl to fail with --unshare-net.");
}

async function fileWriteProbe(): Promise<ProbeResult> {
	const args = [
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind",
		"/tmp",
		"/tmp",
		"--proc",
		"/proc",
		"/bin/sh",
		"-c",
		"echo x > /tmp/pi-sandbox-bwrap-probe",
	];
	const result = await runBwrap(args, { timeoutMs: 5_000 });
	if (result.kind === "exited" && result.exitCode !== 0 && isPermissionDenied(result.stderr)) {
		return { kind: "passed", evidence: "readonly /tmp bind rejected write", control: "fileWrite" };
	}
	return failedProbe("fileWrite", "bwrap readonly bind", result, "Expected readonly bind write to fail.");
}

async function processIsolationProbe(): Promise<ProbeResult> {
	const args = [
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind-try",
		"/usr",
		"/usr",
		"--ro-bind-try",
		"/bin",
		"/bin",
		"--proc",
		"/proc",
		"/bin/sh",
		"-c",
		"ps -eo pid=",
	];
	const result = await runBwrap(args, { timeoutMs: 5_000 });
	if (result.kind === "exited" && result.exitCode === 0 && processListLooksIsolated(result.stdout)) {
		return {
			kind: "passed",
			evidence: `pid namespace process list: ${result.stdout.trim()}`,
			control: "processIsolation",
		};
	}
	return failedProbe(
		"processIsolation",
		"bwrap pid namespace",
		result,
		"Expected only low sandbox PIDs to be visible.",
	);
}

async function magicLinkDenyProbe(): Promise<ProbeResult> {
	const args = [
		"--die-with-parent",
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind-try",
		"/usr",
		"/usr",
		"--ro-bind-try",
		"/bin",
		"/bin",
		"--proc",
		"/proc",
		"/bin/sh",
		"-c",
		"cat /proc/self/mem >/dev/null",
	];
	const result = await runBwrap(args, { timeoutMs: 5_000 });
	if (result.kind === "exited" && result.exitCode !== 0) {
		return { kind: "passed", evidence: "/proc/self/mem read failed", control: "fsPathResolution" };
	}
	return failedProbe("fsPathResolution", "bwrap proc magic-link", result, "Expected /proc/self/mem read to fail.");
}

function omittedProbe(control: SandboxControl): ProbeResult {
	return {
		kind: "failed",
		command: "bwrap probe",
		exitCode: null,
		reason: "probe-not-available-for-control",
		fixHint: "Request a Linux bwrap control probe provided by this backend.",
		control,
	};
}

function failedProbe(control: SandboxControl, command: string, result: RunBwrapResult, fixHint: string): ProbeResult {
	return {
		kind: "failed",
		command,
		exitCode: result.kind === "exited" ? result.exitCode : null,
		stderrExcerpt: truncate(result.stderr),
		reason: result.kind,
		fixHint,
		control,
	};
}

function processListLooksIsolated(stdout: string): boolean {
	const processIds = stdout
		.split(/\s+/)
		.map((entry) => Number.parseInt(entry, 10))
		.filter((processId) => Number.isInteger(processId));
	return processIds.length > 0 && processIds.every((processId) => processId > 0 && processId <= 20);
}

function isPermissionDenied(stderr: string): boolean {
	return /bwrap: .*permission denied|Operation not permitted|Read-only file system|Permission denied/i.test(stderr);
}

function isNoSuchProcess(cause: unknown): boolean {
	return cause instanceof Error && "code" in cause && cause.code === "ESRCH";
}

function joinBuffers(buffers: readonly Buffer[]): string {
	return Buffer.concat(buffers).toString("utf8");
}

function truncate(input: string): string {
	return input.length <= 500 ? input : input.slice(0, 500);
}

function messageFromCause(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}

function dependencyFailure(dependency: string, reason: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "dependency_missing",
		policyArea: "backend",
		operation: "backend.init",
		sanitizedTarget: dependency,
		matchedRule: "backend.dependency",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: reason,
		dependency,
	});
}

function probeFailure(probeName: string, result: RunBwrapResult): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_probe_failed",
		policyArea: "backend",
		operation: "backend.init",
		sanitizedTarget: "bwrap",
		matchedRule: "backend.smoke",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Install bubblewrap and enable unprivileged user namespaces for this host.",
		probeName,
		probeOutput: truncate(result.stderr),
	});
}

function permissionDeniedFailure(message: string, operation: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "permission_denied",
		policyArea: "backend",
		operation,
		sanitizedTarget: "bwrap",
		matchedRule: "bwrap.stderr",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: `The Linux bwrap backend denied this operation: ${message}`,
	});
}

function magicLinkFailure(message: string, target: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "magic_link_denied",
		policyArea: "file.read",
		operation: "bwrap.bind",
		sanitizedTarget: target,
		matchedRule: "file.denyMagicLinks",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: message,
		pathEvidence: { kind: "magic-link", path: target },
	});
}

function timeoutFailure(timeoutMs: number): SandboxFailure {
	return createBlock({
		version: 1,
		code: "timeout",
		policyArea: "process",
		operation: "bash.exec",
		sanitizedTarget: "bwrap",
		matchedRule: "execution.timeout",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "The command exceeded the Linux bwrap timeout and was killed.",
		timeoutMs,
	});
}

function backendError(message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "bash.exec",
		sanitizedTarget: "bwrap",
		matchedRule: "backend.exec",
		backend: "native",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Inspect the Linux bwrap backend error and retry after fixing the host setup.",
		backendMessage: message,
	});
}

const bwrapProbeControls = ["networkDeny", "fileWrite", "processIsolation", "fsPathResolution"] as const;

export const linuxBwrapCapability = {
	fileRead: true,
	fileWrite: true,
	fsPathResolution: "backend-mount-boundary",
	networkDeny: true,
	networkAllowlist: false,
	networkGateway: false,
	processIsolation: true,
	envScrub: true,
	stdoutCapture: "streaming",
	pathMapping: false,
	persistence: true,
	denialAttribution: true,
} satisfies BackendCapability;
