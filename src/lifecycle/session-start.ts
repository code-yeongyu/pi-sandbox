// src/lifecycle/session-start.ts — init manager, register tools, set TUI status
import { createDockerBackend, dockerCapability } from "../backends/docker/adapter.js";
import { createJustbashBackend } from "../backends/justbash/adapter.js";
import {
	createDarwinSandboxExecBackend,
	darwinSandboxExecCapability,
	darwinSandboxExecEffectiveControls,
} from "../backends/native/darwin-sandbox-exec.js";
import { createLinuxBwrapBackend, linuxBwrapCapability } from "../backends/native/linux-bwrap.js";
import { createQemuBackend, qemuCapability } from "../backends/qemu/adapter.js";
import { createSshBackend, sshCapability } from "../backends/ssh/adapter.js";
import { loadFullConfig } from "../config/load.js";
import { normalizeConfig } from "../config/normalize.js";
import { SandboxConfigSchema, type SandboxRawConfig } from "../config/schema.js";
import { toTuiFooter, toTuiWidget } from "../explain/render-tui.js";
import type { ExtensionAPI, ExtensionContext } from "../pi/index.js";
import type { BackendCapability, SandboxControl } from "../policy/capability.js";
import type {
	BackendKind,
	DesiredBackendConfig,
	DockerBackendConfig,
	JustbashBackendConfig,
	NativeBackendConfig,
	QemuBackendConfig,
	SshBackendConfig,
} from "../policy/desired.js";
import type { EffectiveBackendState, EffectiveControls } from "../policy/effective.js";
import { BackendRegistry } from "../sandbox/backend-registry.js";
import { SandboxManager } from "../sandbox/manager.js";
import { createBlock, type Result, type SandboxFailure } from "../security/failure.js";

export async function onSessionStart(
	_pi: ExtensionAPI,
	ctx: ExtensionContext,
): Promise<Result<SandboxManager, SandboxFailure>> {
	const cwd = ctx.cwd ?? process.cwd();
	const loaded = await loadFullConfig(cwd);
	if (!loaded.ok) return { ok: false, error: loadFailure(loaded.error.kind) };
	const parsed = SandboxConfigSchema.parse(loaded.value.merged);
	const candidates = backendCandidates(
		resolveSessionBackendConfig(normalizeParsedBackendConfig(parsed.backend)),
		parsed.fallbackBackends,
	);
	let lastFailure: SandboxFailure | null = null;
	for (const backendConfig of candidates) {
		const started = await startManagerForBackend(backendConfig, loaded.value.merged, cwd);
		if (!started.ok) {
			lastFailure = started.error;
			continue;
		}
		const { manager, effectivePolicy } = started.value;
		ctx.ui.setStatus("sandbox", toTuiFooter(effectivePolicy, manager.getMode()));
		if (parsed.tui.detailsWidget !== "off")
			ctx.ui.setStatus("sandbox-detail", toTuiWidget(effectivePolicy, manager.getMode()).join(" | "));
		return { ok: true, value: manager };
	}
	if (lastFailure !== null) return { ok: false, error: lastFailure };
	return { ok: false, error: noBackendCandidateFailure() };
}

export function resolveSessionBackendConfig(
	config: DesiredBackendConfig,
): Exclude<DesiredBackendConfig, { readonly kind: "auto" }> {
	if (config.kind === "auto") return defaultJustbashConfig;
	return config;
}

export function registerBackendFactories(
	registry: BackendRegistry,
	cwd: string,
	envPolicy: Parameters<typeof createJustbashBackend>[2],
): void {
	registry.register("justbash", async (config) => {
		if (config.kind !== "justbash") return { ok: false, error: configMismatch(config.kind, "justbash") };
		return createJustbashBackend(config, cwd, envPolicy);
	});
	registry.register("docker", async (config) => {
		if (config.kind !== "docker") return { ok: false, error: configMismatch(config.kind, "docker") };
		return createDockerBackend(config, cwd);
	});
	registry.register("ssh", async (config) => {
		if (config.kind !== "ssh") return { ok: false, error: configMismatch(config.kind, "ssh") };
		return createSshBackend(config, cwd);
	});
	registry.register("qemu", async (config) => {
		if (config.kind !== "qemu") return { ok: false, error: configMismatch(config.kind, "qemu") };
		return createQemuBackend(config, cwd);
	});
	registry.register("native", async (config) => {
		if (config.kind !== "native") return { ok: false, error: configMismatch(config.kind, "native") };
		return createNativeBackend(config, cwd);
	});
}

function backendCandidates(
	primary: Exclude<DesiredBackendConfig, { readonly kind: "auto" }>,
	fallbackKinds: readonly BackendKind[],
): readonly Exclude<DesiredBackendConfig, { readonly kind: "auto" }>[] {
	const candidates: Exclude<DesiredBackendConfig, { readonly kind: "auto" }>[] = [primary];
	for (const kind of fallbackKinds) {
		if (kind === primary.kind) continue;
		candidates.push(defaultBackendConfigForKind(kind));
	}
	return candidates;
}

async function startManagerForBackend(
	backendConfig: Exclude<DesiredBackendConfig, { readonly kind: "auto" }>,
	mergedConfig: SandboxRawConfig,
	cwd: string,
): Promise<
	Result<
		{ readonly manager: SandboxManager; readonly effectivePolicy: ReturnType<typeof normalizeConfig> },
		SandboxFailure
	>
> {
	const merged = { ...mergedConfig, backend: backendConfig } satisfies SandboxRawConfig;
	const effectivePolicy = normalizeConfig(merged, backendStateForConfig(backendConfig));
	const registry = new BackendRegistry();
	registerBackendFactories(registry, cwd, effectivePolicy.env);
	const manager = new SandboxManager(registry, effectivePolicy, { backendConfig, cwd });
	const initialized = await manager.init();
	if (initialized.ok) return { ok: true, value: { manager, effectivePolicy } };
	await manager.dispose();
	return initialized;
}

function defaultBackendConfigForKind(kind: BackendKind): Exclude<DesiredBackendConfig, { readonly kind: "auto" }> {
	if (kind === "justbash") return defaultJustbashConfig;
	if (kind === "docker") return defaultDockerConfig;
	if (kind === "qemu") return defaultQemuConfig;
	if (kind === "ssh") return defaultSshConfig;
	return defaultNativeConfigForHost();
}

export function backendStateForConfig(
	config: Exclude<DesiredBackendConfig, { readonly kind: "auto" }>,
): EffectiveBackendState {
	if (config.kind === "justbash") return availableBackendState("justbash", justbashCapability);
	if (config.kind === "docker") return availableBackendState("docker", dockerCapability(config));
	if (config.kind === "ssh") return availableBackendState("ssh", sshCapability);
	if (config.kind === "qemu") return availableBackendState("qemu", qemuCapability(config));
	if (config.platform === "darwin") {
		return {
			kind: "native",
			status: "available",
			capabilities: darwinSandboxExecCapability,
			effectiveControls: darwinSandboxExecEffectiveControls,
			omittedControls: ["networkAllowlist", "pathMapping"],
			probeResults: [],
			diagnostics: [],
		};
	}
	if (config.platform === "linux") {
		return availableBackendState("native", linuxBwrapCapability);
	}
	return availableBackendState("native", linuxBwrapCapability);
}

const defaultJustbashConfig: JustbashBackendConfig = {
	kind: "justbash",
	fs: "read-write-root-locked",
	allowedBinaries: [],
	executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
};

const defaultDockerConfig: DockerBackendConfig = {
	kind: "docker",
	image: "node:22-alpine",
	networkMode: "none",
	readonlyRootfs: true,
	mounts: [],
	pullPolicy: "if-missing",
	capDrop: ["ALL"],
	securityOpt: ["no-new-privileges"],
	tmpfs: [],
};

const defaultQemuConfig: QemuBackendConfig = {
	kind: "qemu",
	assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
	cpus: 1,
	memoryMb: 512,
	shareMode: "9p-readonly",
	network: "none",
	snapshot: true,
};

const defaultSshConfig: SshBackendConfig = {
	kind: "ssh",
	host: "localhost",
	port: 22,
	username: "sandbox",
	auth: { kind: "kbi" },
	hostVerification: { strict: true },
	remoteRoot: "/tmp/pi-sandbox",
	proxyJump: [],
};

function defaultNativeConfigForHost(): NativeBackendConfig {
	if (process.platform === "darwin") return { kind: "native", platform: "darwin", mechanism: "sandbox-exec" };
	return { kind: "native", platform: "linux", mechanism: "bwrap" };
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

const sandboxControls = [
	"fileRead",
	"fileWrite",
	"fsPathResolution",
	"networkDeny",
	"networkAllowlist",
	"processIsolation",
	"envScrub",
	"stdoutCapture",
	"pathMapping",
	"persistence",
	"denialAttribution",
] as const satisfies readonly SandboxControl[];

type ParsedBackendConfig = ReturnType<typeof SandboxConfigSchema.parse>["backend"];
type ParsedDockerBackendConfig = Extract<ParsedBackendConfig, { readonly kind: "docker" }>;
type ParsedJustbashBackendConfig = Extract<ParsedBackendConfig, { readonly kind: "justbash" }>;
type ParsedQemuBackendConfig = Extract<ParsedBackendConfig, { readonly kind: "qemu" }>;
type ParsedSshBackendConfig = Extract<ParsedBackendConfig, { readonly kind: "ssh" }>;

function normalizeParsedBackendConfig(config: ParsedBackendConfig): DesiredBackendConfig {
	if (config.kind === "auto") return config;
	if (config.kind === "native") return config;
	if (config.kind === "docker") return normalizeDockerBackendConfig(config);
	if (config.kind === "justbash") return normalizeJustbashBackendConfig(config);
	if (config.kind === "qemu") return normalizeQemuBackendConfig(config);
	return normalizeSshBackendConfig(config);
}

function normalizeDockerBackendConfig(config: ParsedDockerBackendConfig): DockerBackendConfig {
	return {
		kind: "docker",
		image: config.image,
		networkMode: config.networkMode,
		readonlyRootfs: config.readonlyRootfs,
		mounts: config.mounts,
		pullPolicy: config.pullPolicy,
		...(config.memoryMb === undefined ? {} : { memoryMb: config.memoryMb }),
		...(config.cpuQuota === undefined ? {} : { cpuQuota: config.cpuQuota }),
		capDrop: config.capDrop,
		securityOpt: config.securityOpt,
		tmpfs: config.tmpfs,
	};
}

function normalizeJustbashBackendConfig(config: ParsedJustbashBackendConfig): JustbashBackendConfig {
	return {
		kind: "justbash",
		fs: config.fs,
		allowedBinaries: config.allowedBinaries,
		...(config.network === undefined ? {} : { network: config.network }),
		...(config.customCommands === undefined ? {} : { customCommands: config.customCommands }),
		executionLimits: config.executionLimits,
	};
}

function normalizeQemuBackendConfig(config: ParsedQemuBackendConfig): QemuBackendConfig {
	const assets: QemuBackendConfig["assets"] =
		config.assets.kind === "smoke"
			? config.assets
			: {
					kind: "user",
					kernelPath: config.assets.kernelPath,
					initrdPath: config.assets.initrdPath,
				};
	return {
		kind: "qemu",
		assets,
		cpus: config.cpus,
		memoryMb: config.memoryMb,
		shareMode: config.shareMode,
		network: config.network,
		snapshot: config.snapshot,
	};
}

function normalizeSshBackendConfig(config: ParsedSshBackendConfig): SshBackendConfig {
	return {
		kind: "ssh",
		host: config.host,
		port: config.port,
		username: config.username,
		auth: normalizeSshAuthConfig(config.auth),
		hostVerification: {
			strict: config.hostVerification.strict,
			...(config.hostVerification.hostHash === undefined ? {} : { hostHash: config.hostVerification.hostHash }),
			...(config.hostVerification.knownHostsPath === undefined
				? {}
				: { knownHostsPath: config.hostVerification.knownHostsPath }),
		},
		remoteRoot: config.remoteRoot,
		proxyJump: config.proxyJump.map(normalizeSshBackendConfig),
	};
}

function normalizeSshAuthConfig(auth: ParsedSshBackendConfig["auth"]): SshBackendConfig["auth"] {
	if (auth.kind === "kbi" || auth.kind === "v1") return auth;
	if (auth.kind === "agent") return { kind: "agent", ...(auth.sock === undefined ? {} : { sock: auth.sock }) };
	if (auth.kind === "password") return auth;
	if (auth.kind === "privateKey") {
		return {
			kind: "privateKey",
			keyPath: auth.keyPath,
			...(auth.passphrase === undefined ? {} : { passphrase: auth.passphrase }),
		};
	}
	return {
		kind: "hostbased",
		keyPath: auth.keyPath,
		localHostname: auth.localHostname,
		localUsername: auth.localUsername,
		...(auth.passphrase === undefined ? {} : { passphrase: auth.passphrase }),
	};
}

function createNativeBackend(
	config: NativeBackendConfig,
	cwd: string,
): ReturnType<typeof createDarwinSandboxExecBackend> {
	if (config.platform === "darwin") return createDarwinSandboxExecBackend(config, cwd);
	return createLinuxBwrapBackend(config, cwd);
}

function availableBackendState(
	kind: EffectiveBackendState["kind"],
	capabilities: BackendCapability,
): EffectiveBackendState {
	return {
		kind,
		status: "available",
		capabilities,
		effectiveControls: effectiveControlsForCapability(capabilities),
		omittedControls: omittedControlsForCapability(capabilities),
		probeResults: [],
		diagnostics: [],
	};
}

function effectiveControlsForCapability(capabilities: BackendCapability): EffectiveControls {
	return {
		fileRead: { state: capabilities.fileRead ? "enforced" : "omitted" },
		fileWrite: { state: capabilities.fileWrite ? "enforced" : "omitted" },
		fsPathResolution: { state: capabilities.fsPathResolution === "not-provided" ? "omitted" : "enforced" },
		networkDeny: { state: capabilities.networkDeny ? "enforced" : "omitted" },
		networkAllowlist: { state: capabilities.networkAllowlist ? "enforced" : "omitted" },
		processIsolation: { state: capabilities.processIsolation ? "enforced" : "omitted" },
		envScrub: { state: capabilities.envScrub ? "enforced" : "omitted" },
		stdoutCapture: { state: capabilities.stdoutCapture === "streaming" ? "enforced" : "omitted" },
		pathMapping: { state: capabilities.pathMapping ? "enforced" : "omitted" },
		persistence: { state: capabilities.persistence ? "enforced" : "omitted" },
		denialAttribution: { state: capabilities.denialAttribution ? "enforced" : "omitted" },
	};
}

function omittedControlsForCapability(capabilities: BackendCapability): readonly SandboxControl[] {
	return sandboxControls.filter(
		(control) => effectiveControlsForCapability(capabilities)[control].state === "omitted",
	);
}

function configMismatch(actual: string, expected: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "backend.resolve",
		sanitizedTarget: actual,
		matchedRule: "backend.factory.config-mismatch",
		backend: expected,
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: `Resolve ${expected} backend with a matching ${expected} config.`,
		availabilityReason: "factory-config-mismatch",
	});
}

function noBackendCandidateFailure(): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "backend.select",
		sanitizedTarget: "backend",
		matchedRule: "backend.candidates.empty",
		backend: "justbash",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Configure at least one concrete backend or use auto/default justbash.",
		availabilityReason: "no-backend-candidates",
	});
}

function loadFailure(kind: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "config.load",
		sanitizedTarget: kind,
		matchedRule: "config.load.failed",
		backend: "justbash",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Fix the sandbox config file and restart the session.",
		availabilityReason: kind,
	});
}
