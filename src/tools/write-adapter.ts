import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { WriteOperations } from "../pi/index.js";
import type { SandboxBackend } from "../sandbox/backend.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxOperation } from "../sandbox/operation.js";
import { createBlock, type Result, type SandboxBlockV1, type SandboxFailure } from "../security/failure.js";

export function toWriteOperations(manager: SandboxManager): WriteOperations {
	return {
		async writeFile(absolutePath, content) {
			const operation: SandboxOperation = { kind: "fs.write", path: absolutePath, content };
			const result = await manager.run<void>(operation, async (backend) => {
				if (backend.write !== undefined) return backend.write.writeFile(absolutePath, content);
				return missingWriteFacet<void>(backend, "write.writeFile", absolutePath);
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
		async mkdir(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.mkdir", path: absolutePath };
			const result = await manager.run<void>(operation, async (backend) => {
				if (backend.write !== undefined) return backend.write.mkdir(absolutePath);
				return missingWriteFacet<void>(backend, "write.mkdir", absolutePath);
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
	};
}

function missingWriteFacet<TValue>(
	backend: SandboxBackend,
	operation: string,
	target: string,
): Result<TValue, SandboxFailure> {
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "capability_missing",
			policyArea: "file.write",
			operation,
			sanitizedTarget: target,
			matchedRule: "backend.write.facet-missing",
			backend: backend.kind,
			policyHash: "uninitialized",
			policyRevision: 0,
			remediation: "Select a backend with a write facet; pi-sandbox will not fall back to host filesystem writes.",
			control: "fileWrite",
		}),
	};
}

function throwRenderedBlock(block: SandboxBlockV1): never {
	const [firstContent] = toToolResultBlock(block).content;
	throw new Error(firstContent?.text ?? block.remediation);
}
