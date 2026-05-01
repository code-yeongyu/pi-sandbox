// src/lifecycle/session-start.ts — init manager, register tools, set TUI status
import { createJustbashBackend } from "../backends/justbash/adapter.js";
import { loadFullConfig } from "../config/load.js";
import { normalizeConfig } from "../config/normalize.js";
import { SandboxConfigSchema, type SandboxRawConfig } from "../config/schema.js";
import { toTuiFooter, toTuiWidget } from "../explain/render-tui.js";
import type { ExtensionAPI, ExtensionContext } from "../pi/index.js";
import type { BackendCapability } from "../policy/capability.js";
import type { JustbashBackendConfig } from "../policy/desired.js";
import type { EffectiveBackendState } from "../policy/effective.js";
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
	const backendConfig =
		parsed.backend.kind === "justbash"
			? {
					kind: "justbash" as const,
					fs: parsed.backend.fs,
					allowedBinaries: parsed.backend.allowedBinaries,
					allowedLibraries: parsed.backend.allowedLibraries,
					...(parsed.backend.network === undefined ? {} : { network: parsed.backend.network }),
					...(parsed.backend.customCommands === undefined
						? {}
						: { customCommands: parsed.backend.customCommands }),
					executionLimits: parsed.backend.executionLimits,
				}
			: defaultJustbashConfig;
	const merged = { ...loaded.value.merged, backend: backendConfig } satisfies SandboxRawConfig;
	const effectivePolicy = normalizeConfig(merged, justbashBackendState);
	const registry = new BackendRegistry();
	registry.register("justbash", async () => createJustbashBackend(backendConfig, cwd, effectivePolicy.env));
	const manager = new SandboxManager(registry, effectivePolicy);
	const initialized = await manager.init();
	if (!initialized.ok) return initialized;
	ctx.ui.setStatus("sandbox", toTuiFooter(effectivePolicy, manager.getMode()));
	if (effectivePolicy.backend.kind === "justbash" && parsed.tui.detailsWidget !== "off")
		ctx.ui.setStatus("sandbox-detail", toTuiWidget(effectivePolicy, manager.getMode()).join(" | "));
	return { ok: true, value: manager };
}

const defaultJustbashConfig: JustbashBackendConfig = {
	kind: "justbash",
	fs: "read-write-root-locked",
	allowedBinaries: [],
	allowedLibraries: [],
	executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
};

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

const justbashBackendState = {
	kind: "justbash",
	status: "available",
	capabilities: justbashCapability,
	effectiveControls: {
		fileRead: { state: "enforced" },
		fileWrite: { state: "enforced" },
		fsPathResolution: { state: "enforced" },
		networkDeny: { state: "enforced" },
		networkAllowlist: { state: "enforced" },
		processIsolation: { state: "enforced" },
		envScrub: { state: "enforced" },
		stdoutCapture: { state: "enforced" },
		pathMapping: { state: "enforced" },
		persistence: { state: "enforced" },
		denialAttribution: { state: "enforced" },
	},
	unsupportedControls: [],
	probeResults: [{ kind: "passed", evidence: "justbash loaded", control: "processIsolation" }],
	diagnostics: [],
} satisfies EffectiveBackendState;

function loadFailure(kind: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_unavailable",
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
