// src/tools/bash-adapter.ts — toBashOperations(driver) — streaming redaction wraps onData

import { toBashBlockedOutput } from "../explain/render-bash-output.js";
import type { BashOperations } from "../pi/index.js";
import type { SandboxOperation } from "../policy/decision.js";
import type { SandboxManager } from "../sandbox/manager.js";
import { createBlock } from "../security/failure.js";
import { wrapWithRedactor } from "../security/redactor.js";

export function toBashOperations(manager: SandboxManager): BashOperations {
	return {
		async exec(command, cwd, options) {
			const operation: SandboxOperation = { kind: "bash", command, cwd };
			const wrappedOnData = wrapWithRedactor(options.onData, manager.getRedactor());
			const result = await manager.run(operation, async (backend) => {
				if (backend.bash === undefined) {
					return {
						ok: false,
						error: createBlock({
							version: 1,
							code: "capability_unsupported",
							policyArea: "process",
							operation: "bash.exec",
							sanitizedTarget: "bash",
							matchedRule: "backend.bash=missing",
							backend: manager.getEffectivePolicy().backend.kind,
							policyHash: manager.getEffectivePolicy().desiredPolicyHash,
							policyRevision: manager.getEffectivePolicy().policyRevision,
							remediation: "Switch to a backend that supports bash execution.",
							control: "processIsolation",
						}),
					};
				}
				const environment = envMap(options.env);
				const execOptions = {
					cwd,
					...(options.signal === undefined ? {} : { signal: options.signal }),
					...(options.timeout === undefined ? {} : { timeoutMs: options.timeout }),
					...(environment === undefined ? {} : { env: environment }),
					onData: wrappedOnData,
				};
				return backend.bash.exec(command, execOptions);
			});
			if (result.ok) return result.value;
			const { stderr, exitCode } = toBashBlockedOutput(result.error);
			options.onData(Buffer.from(stderr, "utf8"));
			return { exitCode };
		},
	};
}

function envMap(env: NodeJS.ProcessEnv | undefined): ReadonlyMap<string, string> | undefined {
	if (env === undefined) return undefined;
	const entries = new Map<string, string>();
	for (const [key, value] of Object.entries(env)) {
		if (value !== undefined) entries.set(key, value);
	}
	return entries;
}
