import type { PromptHandler } from "../approvals/prompt.js";
import { parseTypedGrantRequestId, type TypedGrant } from "../approvals/store.js";
import { computeGrantHash, nextRevision } from "../config/hash.js";
import { loadFullConfig } from "../config/load.js";
import { normalizeConfig } from "../config/normalize.js";
import type { ApprovalDecision } from "../config/schema.js";
import { type Decision, decide, type SandboxOperation } from "../policy/decision.js";
import type { DesiredBackendConfig } from "../policy/desired.js";
import type { EffectivePolicy } from "../policy/effective.js";
import { createBlock, type Result, type SandboxFailure } from "../security/failure.js";
import type { StreamingRedactor } from "../security/redactor.js";
import { createStreamingRedactor } from "../security/redactor.js";
import type { SandboxBackend } from "./backend.js";
import type { BackendRegistry } from "./backend-registry.js";
import type { SandboxMode } from "./mode.js";

export class SandboxManager {
	readonly #registry: BackendRegistry;
	#effectivePolicy: EffectivePolicy;
	readonly #redactor: StreamingRedactor;
	#backend: SandboxBackend | null = null;
	readonly #backendConfig: DesiredBackendConfig;
	#promptHandler: PromptHandler | null;
	#blockHandler: ((block: SandboxFailure) => void) | null = null;
	#cwd: string | null;
	readonly #approvedRequestIds = new Set<string>();
	readonly #typedGrants: TypedGrant[] = [];
	readonly #recentBlocks: SandboxFailure[] = [];

	public constructor(
		registry: BackendRegistry,
		effectivePolicy: EffectivePolicy,
		options: {
			readonly promptHandler?: PromptHandler | null;
			readonly cwd?: string;
			readonly backendConfig?: DesiredBackendConfig;
		} = {},
	) {
		this.#registry = registry;
		this.#effectivePolicy = effectivePolicy;
		this.#backendConfig = options.backendConfig ?? defaultJustbashBackendConfig;
		this.#redactor = createStreamingRedactor(process.env);
		this.#promptHandler = options.promptHandler ?? null;
		this.#cwd = options.cwd ?? null;
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		const invariant = validateBackendConfigMatchesPolicy(this.#backendConfig, this.#effectivePolicy);
		if (!invariant.ok) return invariant;
		const capabilityInvariant = validatePolicyCapabilities(this.#effectivePolicy);
		if (!capabilityInvariant.ok) return capabilityInvariant;
		const result = await this.#registry.resolve(this.#backendConfig);
		if (!result.ok) return result;
		this.#backend = result.value;
		return result.value.lifecycle.init();
	}

	public getDesiredBackendConfig(): DesiredBackendConfig {
		return this.#backendConfig;
	}

	public async dispose(): Promise<void> {
		await this.#backend?.lifecycle.dispose();
		this.#backend = null;
	}

	public getBackend(): SandboxBackend {
		if (this.#backend === null) throw new Error("SandboxManager has not been initialized");
		return this.#backend;
	}

	public approveRequestId(requestId: string): void {
		this.#approvedRequestIds.add(requestId);
	}

	public setPromptHandler(handler: PromptHandler | null): void {
		this.#promptHandler = handler;
	}

	public setBlockHandler(handler: ((block: SandboxFailure) => void) | null): void {
		this.#blockHandler = handler;
	}

	public setCwd(cwd: string): void {
		this.#cwd = cwd;
	}

	public getRecentBlocks(): readonly SandboxFailure[] {
		return this.#recentBlocks;
	}

	public getRedactor(): StreamingRedactor {
		return this.#redactor;
	}

	public getEffectivePolicy(): EffectivePolicy {
		return this.#effectivePolicy;
	}

	public getCapability(): EffectivePolicy["backend"]["capabilities"] {
		return this.#effectivePolicy.backend.capabilities;
	}

	public getMode(): SandboxMode {
		return {
			kind: "enforcing",
			backend: this.#effectivePolicy.backend.kind,
			capabilities: this.#effectivePolicy.backend.capabilities,
		};
	}

	public async reloadEffectivePolicy(): Promise<Result<void, SandboxFailure>> {
		if (this.#cwd === null) return { ok: true, value: undefined };
		const loaded = await loadFullConfig(this.#cwd);
		if (!loaded.ok) return { ok: false, error: loadFailure(loaded.error.kind, this.#effectivePolicy) };
		const normalized = normalizeConfig(loaded.value.merged, this.#effectivePolicy.backend);
		this.#effectivePolicy = {
			...normalized,
			grantHash: computeGrantHash(loaded.value.grants),
			policyRevision: nextRevision(this.#effectivePolicy.policyRevision),
		};
		this.#loadGrantDecisions(loaded.value.grants);
		return { ok: true, value: undefined };
	}

	public async run<TValue>(
		operation: SandboxOperation,
		executor: (backend: SandboxBackend) => Promise<Result<TValue, SandboxFailure>>,
	): Promise<Result<TValue, SandboxFailure>> {
		const typedDecision = this.#decideTypedGrant(operation);
		if (typedDecision?.kind === "deny") return this.#blocked(typedDecision.block);
		if (typedDecision?.kind === "allow") return executor(this.getBackend());

		let decision = decide({
			operation,
			effectivePolicy: this.#effectivePolicy,
			approvedRequestIds: this.#approvedRequestIds,
		});
		if (decision.kind === "deny") return this.#blocked(decision.block);
		if (decision.kind === "prompt") {
			if (this.#promptHandler !== null && (await this.#promptHandler(decision))) {
				this.approveRequestId(decision.requestId);
				decision = decide({
					operation,
					effectivePolicy: this.#effectivePolicy,
					approvedRequestIds: this.#approvedRequestIds,
				});
				if (decision.kind === "allow") return executor(this.getBackend());
				if (decision.kind === "deny") return this.#blocked(decision.block);
			}
			return this.#blocked(createPromptBlock(decision, operation, this.#effectivePolicy));
		}
		return executor(this.getBackend());
	}

	#blocked<TValue>(block: SandboxFailure): Result<TValue, SandboxFailure> {
		this.#recentBlocks.push(block);
		if (this.#recentBlocks.length > 5) this.#recentBlocks.shift();
		this.#blockHandler?.(block);
		return { ok: false, error: block };
	}

	#loadGrantDecisions(grants: ReadonlyArray<ApprovalDecision>): void {
		this.#typedGrants.length = 0;
		for (const grant of grants) {
			const typedGrant = parseTypedGrantRequestId(grant.action, grant.requestId);
			if (typedGrant !== null) this.#typedGrants.push(typedGrant);
			else if (grant.action === "allow") this.#approvedRequestIds.add(grant.requestId);
		}
	}

	#decideTypedGrant(operation: SandboxOperation): Decision | null {
		const deny = this.#typedGrants.find((grant) => grant.action === "deny" && typedGrantMatches(grant, operation));
		if (deny !== undefined)
			return { kind: "deny", block: createTypedGrantBlock(deny, operation, this.#effectivePolicy) };
		if (this.#typedGrants.some((grant) => grant.action === "allow" && typedGrantMatches(grant, operation))) {
			return { kind: "allow" };
		}
		return null;
	}
}

function createPromptBlock(
	decision: Extract<Decision, { readonly kind: "prompt" }>,
	operation: SandboxOperation,
	effectivePolicy: EffectivePolicy,
): SandboxFailure {
	return createBlock({
		version: 1,
		code: "high_risk_approval_required",
		policyArea: policyAreaForPromptClass(decision.class),
		operation: operation.kind,
		sanitizedTarget: decision.sanitizedTarget,
		matchedRule: decision.matchedRule,
		backend: effectivePolicy.backend.kind,
		policyHash: effectivePolicy.desiredPolicyHash,
		policyRevision: effectivePolicy.policyRevision,
		approvalId: decision.requestId,
		remediation: "User declined approval; re-run with explicit allow.",
		riskClass: riskClassForPromptClass(decision.class),
	});
}

function loadFailure(kind: string, effectivePolicy: EffectivePolicy): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "config.load",
		sanitizedTarget: kind,
		matchedRule: "config.load.failed",
		backend: effectivePolicy.backend.kind,
		policyHash: effectivePolicy.desiredPolicyHash,
		policyRevision: effectivePolicy.policyRevision,
		remediation: "Fix the sandbox config file and reload sandbox policy.",
		availabilityReason: kind,
	});
}

function createTypedGrantBlock(
	grant: TypedGrant,
	operation: SandboxOperation,
	effectivePolicy: EffectivePolicy,
): SandboxFailure {
	return createBlock({
		version: 1,
		code: "permission_denied",
		policyArea: policyAreaForGrantClass(grant.class),
		operation: operation.kind,
		sanitizedTarget: targetForOperation(operation),
		matchedRule: `typedGrant.${grant.class}.deny`,
		backend: effectivePolicy.backend.kind,
		policyHash: effectivePolicy.desiredPolicyHash,
		policyRevision: effectivePolicy.policyRevision,
		remediation: "A project sandbox deny grant matched this operation.",
	});
}

const defaultJustbashBackendConfig: DesiredBackendConfig = {
	kind: "justbash",
	fs: "memory",
	allowedBinaries: [],
	executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
};

function validateBackendConfigMatchesPolicy(
	backendConfig: DesiredBackendConfig,
	effectivePolicy: EffectivePolicy,
): Result<void, SandboxFailure> {
	if (backendConfig.kind === "auto") {
		return {
			ok: false,
			error: backendConfigMismatchFailure("auto", effectivePolicy.backend.kind),
		};
	}
	if (backendConfig.kind === effectivePolicy.backend.kind) return { ok: true, value: undefined };
	return {
		ok: false,
		error: backendConfigMismatchFailure(backendConfig.kind, effectivePolicy.backend.kind),
	};
}

function validatePolicyCapabilities(effectivePolicy: EffectivePolicy): Result<void, SandboxFailure> {
	if (
		effectivePolicy.network.mode !== "restricted" ||
		(effectivePolicy.backend.capabilities.networkAllowlist && effectivePolicy.backend.capabilities.networkGateway)
	) {
		return { ok: true, value: undefined };
	}
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "capability_missing",
			policyArea: "network",
			operation: "backend.init",
			sanitizedTarget: "network.mode=restricted",
			matchedRule: "network.restricted.requires-gateway",
			backend: effectivePolicy.backend.kind,
			policyHash: effectivePolicy.desiredPolicyHash,
			policyRevision: effectivePolicy.policyRevision,
			remediation: "Use a backend with restricted network gateway support or change network.mode to deny/allow-all.",
			control: "networkAllowlist",
		}),
	};
}

function backendConfigMismatchFailure(actual: string, expected: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "backend_missing",
		policyArea: "backend",
		operation: "backend.init",
		sanitizedTarget: actual,
		matchedRule: "backend.config.policy-kind-mismatch",
		backend: expected,
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: `Initialize ${expected} with a matching concrete backend config.`,
		availabilityReason: "backend-config-policy-kind-mismatch",
	});
}

function policyAreaForPromptClass(promptClass: string): "file.write" | "network" | "process" {
	if (promptClass === "network") return "network";
	if (promptClass === "process") return "process";
	return "file.write";
}

function policyAreaForGrantClass(grantClass: TypedGrant["class"]): "file.read" | "file.write" | "network" | "process" {
	if (grantClass === "file.read") return "file.read";
	if (grantClass === "file.write") return "file.write";
	if (grantClass === "binary") return "process";
	return "network";
}

function typedGrantMatches(grant: TypedGrant, operation: SandboxOperation): boolean {
	if (grant.class === "file.read") return isFileReadOperation(operation) && operation.path.startsWith(grant.target);
	if (grant.class === "file.write") return isFileWriteOperation(operation) && operation.path.startsWith(grant.target);
	if (grant.class === "binary") return binaryForOperation(operation) === grant.target;
	if (grant.class === "domain") return urlsForOperation(operation).some((url) => hostForUrl(url) === grant.target);
	if (grant.class === "url-prefix") return urlsForOperation(operation).some((url) => url.startsWith(grant.target));
	return urlsForOperation(operation).some((url) => portForUrl(url) === Number(grant.target));
}

function isFileReadOperation(
	operation: SandboxOperation,
): operation is Extract<SandboxOperation, { readonly kind: "fs.read" | "fs.access" }> {
	return operation.kind === "fs.read" || operation.kind === "fs.access";
}

function isFileWriteOperation(
	operation: SandboxOperation,
): operation is Extract<SandboxOperation, { readonly kind: "fs.write" | "fs.mkdir" }> {
	return operation.kind === "fs.write" || operation.kind === "fs.mkdir";
}

function urlsForOperation(operation: SandboxOperation): readonly string[] {
	if (operation.kind === "network") return [operation.url];
	if (operation.kind === "bash")
		return [...operation.command.matchAll(/https?:\/\/[^\s'"<>]+/gi)].map((match) => match[0] ?? "");
	return [];
}

function hostForUrl(target: string): string | null {
	try {
		return new URL(target).hostname.toLowerCase();
	} catch {
		return null;
	}
}

function portForUrl(target: string): number | null {
	try {
		const url = new URL(target);
		if (url.port !== "") return Number(url.port);
		return url.protocol === "http:" ? 80 : 443;
	} catch {
		return null;
	}
}

function binaryForOperation(operation: SandboxOperation): string | null {
	if (operation.kind === "process.spawn") return operation.binary;
	if (operation.kind !== "bash") return null;
	const match = /^(?:env\s+)?([A-Za-z0-9_./-]+)/.exec(operation.command.trim());
	const value = match?.[1];
	if (value === undefined) return null;
	return value.split("/").at(-1) ?? value;
}

function targetForOperation(operation: SandboxOperation): string {
	if ("path" in operation) return operation.path;
	if (operation.kind === "network") return operation.url;
	if (operation.kind === "process.spawn") return operation.binary;
	return operation.command;
}

function riskClassForPromptClass(
	promptClass: string,
): "dotenv" | "ssh-key" | "git-hook" | "shell-rc" | "npm-script" | "executable" {
	if (promptClass === "ssh-key") return "ssh-key";
	if (promptClass === "git-hook") return "git-hook";
	if (promptClass === "shell-rc") return "shell-rc";
	if (promptClass === "npm-script") return "npm-script";
	if (promptClass === "executable") return "executable";
	return "dotenv";
}
