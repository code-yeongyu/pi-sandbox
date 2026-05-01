import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { access } from "node:fs/promises";
import path from "node:path";

import type { BackendCapability, SandboxControl } from "../../policy/capability.js";
import type { QemuBackendConfig } from "../../policy/desired.js";
import type { HealthResult, ProbeResult } from "../../policy/effective.js";
import type { SandboxBackend, SandboxExecOptions } from "../../sandbox/backend.js";
import type { PathMapper } from "../../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { runQemuDoctor } from "./doctor.js";
import { QEMU_SMOKE_FIXTURE, verifyFixture } from "./smoke-fixture.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const EXIT_MARKER = "__PI_SANDBOX_EXIT__:";

type QemuAssets = {
	readonly kernelPath: string;
	readonly initrdPath: string;
};

export async function createQemuBackend(
	config: QemuBackendConfig,
	sessionRoot: string,
): Promise<Result<SandboxBackend, SandboxFailure>> {
	return { ok: true, value: new QemuSandboxBackend(config, sessionRoot) };
}

class QemuSandboxBackend implements SandboxBackend {
	public readonly kind = "qemu" as const;
	public readonly capabilities: BackendCapability;
	public readonly pathMapper: PathMapper;
	public readonly lifecycle: QemuLifecycle;
	public readonly bash = { exec: this.exec.bind(this) };
	readonly #config: QemuBackendConfig;
	readonly #sessionRoot: string;
	#assets: QemuAssets | null = null;

	public constructor(config: QemuBackendConfig, sessionRoot: string) {
		this.#config = config;
		this.#sessionRoot = path.resolve(sessionRoot);
		this.pathMapper = new QemuPathMapper(this.#sessionRoot);
		this.capabilities = qemuCapability(config);
		this.lifecycle = new QemuLifecycle(this, config, this.#sessionRoot);
	}

	public setAssets(assets: QemuAssets): void {
		this.#assets = assets;
	}

	public async exec(
		command: string,
		options: SandboxExecOptions,
	): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
		const mappedCwd = this.pathMapper.hostToSandboxPath(options.cwd);
		if (!mappedCwd.ok) return { ok: false, error: pathMappingFailure(options.cwd, mappedCwd.error.kind) };
		const assets: Result<QemuAssets, SandboxFailure> =
			this.#assets === null ? await resolveAssets(this.#config, process.cwd()) : { ok: true, value: this.#assets };
		if (!assets.ok) return { ok: false, error: assets.error };

		const args = qemuArgs({
			config: this.#config,
			sessionRoot: this.#sessionRoot,
			assets: assets.value,
		});
		const child = spawn("qemu-system-x86_64", args, {
			detached: true,
			stdio: ["pipe", "pipe", "pipe"],
			env: minimalHostEnv(),
		});

		let output = "";
		let timedOut = false;
		let abortRequested = false;
		const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
		const timeout =
			timeoutMs > 0
				? setTimeout(() => {
						timedOut = true;
						killProcessGroup(child);
					}, timeoutMs)
				: undefined;
		const abort = (): void => {
			abortRequested = true;
			killProcessGroup(child);
		};
		if (options.signal?.aborted) abort();
		else options.signal?.addEventListener("abort", abort, { once: true });

		child.stdout.on("data", (data: Buffer) => {
			output += data.toString("utf8");
			options.onData?.(data);
		});
		child.stderr.on("data", (data: Buffer) => {
			output += data.toString("utf8");
			options.onData?.(data);
		});

		function writeGuestCommand(): void {
			const guestCommand = [
				`cd ${shellQuote(mappedCwd.ok ? mappedCwd.value : "/workspace")}`,
				`( ${command} )`,
				"pi_sandbox_exit=$?",
				`printf '\\n${EXIT_MARKER}%s\\n' "$pi_sandbox_exit"`,
				"poweroff -f",
			].join("; ");
			child.stdin.write(`${guestCommand}\n`);
		}

		setTimeout(writeGuestCommand, 250);
		const result = await waitForQemu(child, () => {
			if (timeout !== undefined) clearTimeout(timeout);
			options.signal?.removeEventListener("abort", abort);
		});
		if (!result.ok) return result;
		if (timedOut) return { ok: true, value: { exitCode: 124 } };
		if (abortRequested || options.signal?.aborted) return { ok: true, value: { exitCode: 130 } };
		const guestExit = guestExitCode(output);
		return { ok: true, value: { exitCode: guestExit ?? result.value.exitCode } };
	}
}

class QemuLifecycle {
	readonly #backend: QemuSandboxBackend;
	readonly #config: QemuBackendConfig;
	readonly #sessionRoot: string;

	public constructor(backend: QemuSandboxBackend, config: QemuBackendConfig, sessionRoot: string) {
		this.#backend = backend;
		this.#config = config;
		this.#sessionRoot = sessionRoot;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		const binary = await qemuVersion();
		if (!binary.ok) return binary;
		if (this.#config.shareMode.startsWith("virtiofs")) {
			return {
				ok: false,
				error: qemuFailure(
					"capability_unsupported",
					"lifecycle.init",
					this.#config.shareMode,
					"virtiofs requires a managed virtiofsd supervisor; use 9p-readonly for the smoke backend",
				),
			};
		}
		const assets = await resolveAssets(this.#config, process.cwd());
		if (!assets.ok) return assets;
		this.#backend.setAssets(assets.value);
		await runQemuDoctor(process.cwd());
		return { ok: true, value: undefined };
	}

	public async dispose(): Promise<void> {
		return undefined;
	}

	public async health(): Promise<HealthResult> {
		const startedAt = Date.now();
		const version = await qemuVersion();
		return version.ok
			? { healthy: true, backend: "qemu", latencyMs: Date.now() - startedAt, details: version.value }
			: { healthy: false, backend: "qemu", latencyMs: Date.now() - startedAt, details: version.error.remediation };
	}

	public async probe(controls: readonly SandboxControl[]): Promise<readonly ProbeResult[]> {
		const requested = new Set<SandboxControl>(controls);
		const probes: ProbeResult[] = [];
		if (requested.has("processIsolation"))
			probes.push({ kind: "passed", evidence: "qemu full VM boundary", control: "processIsolation" });
		if (requested.has("networkDeny") && this.#config.network === "none") {
			probes.push(await this.runExitProbe("networkDeny", "wget -T 2 -O - http://example.com >/dev/null 2>&1", true));
		}
		if (requested.has("fileWrite") && this.#config.shareMode.endsWith("readonly")) {
			probes.push(await this.runExitProbe("fileWrite", "touch /workspace/.pi-sandbox-qemu-probe 2>/dev/null", true));
		}
		if (requested.has("fsPathResolution")) {
			probes.push(await this.runExitProbe("fsPathResolution", "test ! -e /host && test ! -e /mnt/host", false));
		}
		return probes;
	}

	private async runExitProbe(control: SandboxControl, command: string, expectFailure: boolean): Promise<ProbeResult> {
		const result = await this.#backend.bash.exec(command, { cwd: this.#sessionRoot, timeoutMs: 20_000 });
		if (!result.ok) return failedProbe(control, command, null, result.error.remediation);
		const passed = expectFailure ? result.value.exitCode !== 0 : result.value.exitCode === 0;
		if (passed) return { kind: "passed", evidence: `qemu probe ${command} exit=${result.value.exitCode}`, control };
		return failedProbe(control, command, result.value.exitCode, "unexpected probe exit code");
	}
}

class QemuPathMapper implements PathMapper {
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
		return { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "outside /workspace" } };
	}

	public canRepresent(hostPath: string): boolean {
		return this.hostToSandboxPath(hostPath).ok;
	}
}

function qemuCapability(config: QemuBackendConfig): BackendCapability {
	return {
		fileRead: true,
		fileWrite: config.shareMode.endsWith("readwrite"),
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
	};
}

async function resolveAssets(config: QemuBackendConfig, root: string): Promise<Result<QemuAssets, SandboxFailure>> {
	if (config.assets.kind === "smoke") {
		const fixture = await verifyFixture(root);
		if (!fixture.ok) return fixture;
		if (config.assets.checksumSha256 !== "unset" && config.assets.checksumSha256 !== fixture.value.manifestSha256) {
			return {
				ok: false,
				error: qemuFailure(
					"backend_probe_failed",
					"qemu.fixture.config-checksum",
					config.assets.fixtureName,
					`expected ${config.assets.checksumSha256}, got ${fixture.value.manifestSha256}`,
				),
			};
		}
		return { ok: true, value: { kernelPath: fixture.value.kernelPath, initrdPath: fixture.value.initrdPath } };
	}
	const kernelPath = path.resolve(config.assets.kernelPath);
	const initrdPath = path.resolve(config.assets.initrdPath);
	for (const target of [kernelPath, initrdPath]) {
		try {
			await access(target);
		} catch {
			return {
				ok: false,
				error: qemuFailure("dependency_missing", "qemu.assets.user", target, "user QEMU asset missing"),
			};
		}
	}
	return { ok: true, value: { kernelPath, initrdPath } };
}

function qemuArgs(options: {
	readonly config: QemuBackendConfig;
	readonly sessionRoot: string;
	readonly assets: QemuAssets;
}): readonly string[] {
	const readonlyFlag = options.config.shareMode.endsWith("readonly") ? ",readonly=on" : "";
	const args = [
		"-m",
		String(options.config.memoryMb),
		"-smp",
		String(options.config.cpus),
		"-no-reboot",
		"-nographic",
		"-serial",
		"mon:stdio",
		"-kernel",
		options.assets.kernelPath,
		"-initrd",
		options.assets.initrdPath,
		"-append",
		QEMU_SMOKE_FIXTURE.recommendedAppend,
		"-virtfs",
		`local,path=${options.sessionRoot},mount_tag=workspace,security_model=mapped-xattr${readonlyFlag}`,
	];
	if (options.config.network === "none") args.push("-nic", "none");
	else args.push("-netdev", "user,id=net0", "-device", "virtio-net-pci,netdev=net0");
	if (options.config.snapshot) args.push("-snapshot");
	return args;
}

function waitForQemu(
	child: ChildProcessWithoutNullStreams,
	cleanup: () => void,
): Promise<Result<{ readonly exitCode: number | null }, SandboxFailure>> {
	return new Promise((resolve) => {
		child.once("error", (cause) => {
			cleanup();
			resolve({ ok: false, error: qemuFailure("sandbox_backend_error", "bash.exec", "qemu", errorMessage(cause)) });
		});
		child.once("close", (exitCode) => {
			cleanup();
			resolve({ ok: true, value: { exitCode } });
		});
	});
}

async function qemuVersion(): Promise<Result<string, SandboxFailure>> {
	return new Promise((resolve) => {
		const child = spawn("qemu-system-x86_64", ["--version"], { stdio: ["ignore", "pipe", "pipe"] });
		let output = "";
		child.stdout.on("data", (data: Buffer) => {
			output += data.toString("utf8");
		});
		child.stderr.on("data", (data: Buffer) => {
			output += data.toString("utf8");
		});
		child.once("error", (cause) => {
			resolve({
				ok: false,
				error: qemuFailure("dependency_missing", "qemu.version", "qemu-system-x86_64", errorMessage(cause)),
			});
		});
		child.once("close", (exitCode) => {
			if (exitCode === 0) resolve({ ok: true, value: output.split("\n")[0]?.trim() ?? "qemu-system-x86_64" });
			else
				resolve({
					ok: false,
					error: qemuFailure("dependency_missing", "qemu.version", "qemu-system-x86_64", output),
				});
		});
	});
}

function minimalHostEnv(): NodeJS.ProcessEnv {
	return {
		PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
		HOME: process.env.HOME ?? "/tmp",
		TERM: process.env.TERM ?? "dumb",
	};
}

function guestExitCode(output: string): number | null {
	const markerIndex = output.lastIndexOf(EXIT_MARKER);
	if (markerIndex < 0) return null;
	const rest = output.slice(markerIndex + EXIT_MARKER.length);
	const match = /^(?<code>\d+)/.exec(rest.trimStart());
	if (match?.groups?.code === undefined) return null;
	return Number.parseInt(match.groups.code, 10);
}

function killProcessGroup(child: ChildProcessWithoutNullStreams): void {
	if (child.pid === undefined) return;
	try {
		process.kill(-child.pid, "SIGKILL");
	} catch {
		child.kill("SIGKILL");
	}
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

function pathMappingFailure(target: string, kind: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "path_mapping_failed",
		policyArea: "backend",
		operation: "bash.cwd",
		sanitizedTarget: target,
		matchedRule: "qemu.path-mapper.session-root",
		backend: "qemu",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run QEMU backend commands from inside the mounted session root.",
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
		fixHint: "Inspect the QEMU smoke fixture, kernel 9p support, and backend command output.",
		control,
	};
}

function qemuFailure(
	code: "dependency_missing" | "backend_probe_failed" | "sandbox_backend_error" | "capability_unsupported",
	operation: string,
	target: string,
	message: string,
): SandboxFailure {
	return createBlock({
		version: 1,
		code,
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "qemu.adapter",
		backend: "qemu",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: message,
		...(code === "dependency_missing"
			? { dependency: target }
			: code === "capability_unsupported"
				? { control: "fsPathResolution" }
				: code === "backend_probe_failed"
					? { probeName: operation, probeOutput: message }
					: { backendMessage: message }),
	});
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
