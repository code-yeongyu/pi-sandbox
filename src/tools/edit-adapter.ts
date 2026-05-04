import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { EditOperations } from "../pi/index.js";
import type { SandboxOperation } from "../policy/decision.js";
import type { SandboxBackend } from "../sandbox/backend.js";
import type { SandboxManager } from "../sandbox/manager.js";
import { createBlock, type Result, type SandboxBlockV1, type SandboxFailure } from "../security/failure.js";

export function toEditOperations(manager: SandboxManager): EditOperations {
	return {
		async readFile(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.read", path: absolutePath };
			const result = await manager.run<Buffer>(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.readFile(absolutePath);
				return missingFileFacet<Buffer>(backend, "edit.readFile", absolutePath, "file.read", "fileRead");
			});
			if (result.ok) return result.value;
			throwRenderedBlock(result.error);
		},
		async writeFile(absolutePath, content) {
			const operation: SandboxOperation = { kind: "fs.write", path: absolutePath, content };
			const result = await manager.run<void>(operation, async (backend) => {
				if (backend.write !== undefined) return backend.write.writeFile(absolutePath, content);
				return missingFileFacet<void>(backend, "edit.writeFile", absolutePath, "file.write", "fileWrite");
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
		async access(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.access", path: absolutePath };
			const result = await manager.run<void>(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.access(absolutePath);
				return missingFileFacet<void>(backend, "edit.access", absolutePath, "file.read", "fileRead");
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
	};
}

function missingFileFacet<TValue>(
	backend: SandboxBackend,
	operation: string,
	target: string,
	policyArea: "file.read" | "file.write",
	control: "fileRead" | "fileWrite",
): Result<TValue, SandboxFailure> {
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "capability_missing",
			policyArea,
			operation,
			sanitizedTarget: target,
			matchedRule: `backend.${control}.facet-missing`,
			backend: backend.kind,
			policyHash: "uninitialized",
			policyRevision: 0,
			remediation: "Select a backend with file facets; pi-sandbox will not fall back to host filesystem access.",
			control,
		}),
	};
}

function throwRenderedBlock(block: SandboxBlockV1): never {
	const [firstContent] = toToolResultBlock(block).content;
	throw new Error(firstContent?.text ?? block.remediation);
}
