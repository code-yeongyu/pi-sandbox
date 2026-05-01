import { decide, type SandboxOperation } from "../policy/decision.js";
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
	readonly #effectivePolicy: EffectivePolicy;
	readonly #redactor: StreamingRedactor;
	#backend: SandboxBackend | null = null;
	readonly #approvedRequestIds = new Set<string>();

	public constructor(registry: BackendRegistry, effectivePolicy: EffectivePolicy) {
		this.#registry = registry;
		this.#effectivePolicy = effectivePolicy;
		this.#redactor = createStreamingRedactor(process.env);
	}

	public async init(): Promise<Result<void, SandboxFailure>> {
		const result = await this.#registry.resolve(defaultBackendConfig(this.#effectivePolicy.backend.kind));
		if (!result.ok) return result;
		this.#backend = result.value;
		return result.value.lifecycle.init();
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

	public async run<TValue>(
		operation: SandboxOperation,
		executor: (backend: SandboxBackend) => Promise<Result<TValue, SandboxFailure>>,
	): Promise<Result<TValue, SandboxFailure>> {
		const decision = decide({
			operation,
			effectivePolicy: this.#effectivePolicy,
			approvedRequestIds: this.#approvedRequestIds,
		});
		if (decision.kind === "deny") return { ok: false, error: decision.block };
		if (decision.kind === "prompt") {
			return {
				ok: false,
				error: createBlock({
					version: 1,
					code: "high_risk_approval_required",
					policyArea: policyAreaForPromptClass(decision.class),
					operation: operation.kind,
					sanitizedTarget: decision.sanitizedTarget,
					matchedRule: decision.matchedRule,
					backend: this.#effectivePolicy.backend.kind,
					policyHash: this.#effectivePolicy.desiredPolicyHash,
					policyRevision: this.#effectivePolicy.policyRevision,
					approvalId: decision.requestId,
					remediation: "Approval prompts are implemented in Wave 2d; deny until an approval is recorded.",
					riskClass: riskClassForPromptClass(decision.class),
				}),
			};
		}
		return executor(this.getBackend());
	}
}

function defaultBackendConfig(kind: EffectivePolicy["backend"]["kind"]): DesiredBackendConfig {
	if (kind === "justbash") {
		return {
			kind: "justbash",
			fs: "memory",
			allowedBinaries: [],
			allowedLibraries: [],
			executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
		};
	}
	if (kind === "docker") {
		return {
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
	}
	if (kind === "native") return { kind: "native", platform: "linux", mechanism: "bwrap" };
	if (kind === "qemu") {
		return {
			kind: "qemu",
			assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
			cpus: 1,
			memoryMb: 512,
			shareMode: "9p-readonly",
			network: "none",
			snapshot: true,
		};
	}
	return {
		kind: "ssh",
		host: "localhost",
		port: 22,
		username: "sandbox",
		auth: { kind: "kbi" },
		hostVerification: { strict: true },
		remoteRoot: "/tmp/pi-sandbox",
		sync: "sftp",
		proxyJump: [],
	};
}

function policyAreaForPromptClass(promptClass: string): "file.write" | "network" | "process" {
	if (promptClass === "network") return "network";
	if (promptClass === "process") return "process";
	return "file.write";
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
