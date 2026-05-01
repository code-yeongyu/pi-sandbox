import type { DesiredBackendConfig } from "../policy/desired.js";
import type { BackendKind } from "../policy/effective.js";
import { createBlock, type Result, type SandboxFailure } from "../security/failure.js";
import type { SandboxBackend } from "./backend.js";

export type BackendFactory = (config: DesiredBackendConfig) => Promise<Result<SandboxBackend, SandboxFailure>>;

export class BackendRegistry {
	readonly #factories = new Map<BackendKind, BackendFactory>();

	public register(kind: BackendKind, factory: BackendFactory): void {
		this.#factories.set(kind, factory);
	}

	public async resolve(config: DesiredBackendConfig): Promise<Result<SandboxBackend, SandboxFailure>> {
		if (config.kind === "auto") {
			return {
				ok: false,
				error: createBlock({
					version: 1,
					code: "backend_unavailable",
					policyArea: "backend",
					operation: "backend.resolve",
					sanitizedTarget: "auto",
					matchedRule: "backend.auto-unresolved",
					backend: "justbash",
					policyHash: "uninitialized",
					policyRevision: 0,
					remediation: "Select a concrete backend before resolving the registry.",
					availabilityReason: "auto-backend-not-resolved",
				}),
			};
		}
		const factory = this.#factories.get(config.kind);
		if (factory === undefined) {
			return {
				ok: false,
				error: createBlock({
					version: 1,
					code: "backend_unavailable",
					policyArea: "backend",
					operation: "backend.resolve",
					sanitizedTarget: config.kind,
					matchedRule: "backend.factory-missing",
					backend: config.kind,
					policyHash: "uninitialized",
					policyRevision: 0,
					remediation: "Register a backend factory for this backend kind.",
					availabilityReason: "factory-missing",
				}),
			};
		}
		return factory(config);
	}
}
