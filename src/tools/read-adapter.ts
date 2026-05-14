import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { ReadOperations } from "../pi/index.js";
import type { SandboxBackend } from "../sandbox/backend.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxOperation } from "../sandbox/operation.js";
import { createBlock, type Result, type SandboxBlockV1, type SandboxFailure } from "../security/failure.js";

export function toReadOperations(manager: SandboxManager): ReadOperations {
	return {
		async readFile(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.read", path: absolutePath };
			const result = await manager.run<Buffer>(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.readFile(absolutePath);
				return missingReadFacet<Buffer>(backend, "read.readFile", absolutePath);
			});
			if (result.ok) return result.value;
			throwRenderedBlock(result.error);
		},
		async access(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.access", path: absolutePath };
			const result = await manager.run<void>(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.access(absolutePath);
				return missingReadFacet<void>(backend, "read.access", absolutePath);
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
	};
}

function missingReadFacet<TValue>(
	backend: SandboxBackend,
	operation: string,
	target: string,
): Result<TValue, SandboxFailure> {
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "capability_missing",
			policyArea: "file.read",
			operation,
			sanitizedTarget: target,
			matchedRule: "backend.read.facet-missing",
			backend: backend.kind,
			policyHash: "uninitialized",
			policyRevision: 0,
			remediation: "Select a backend with a read facet; pi-sandbox will not fall back to host filesystem reads.",
			control: "fileRead",
		}),
	};
}

function throwRenderedBlock(block: SandboxBlockV1): never {
	const [firstContent] = toToolResultBlock(block).content;
	throw new Error(firstContent?.text ?? block.remediation);
}
