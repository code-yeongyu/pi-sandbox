import { mkdir, writeFile } from "node:fs/promises";

import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { WriteOperations } from "../pi/index.js";
import type { SandboxOperation } from "../policy/decision.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export function toWriteOperations(manager: SandboxManager): WriteOperations {
	return {
		async writeFile(absolutePath, content) {
			const operation: SandboxOperation = { kind: "fs.write", path: absolutePath, content };
			const result = await manager.run(operation, async (backend) => {
				if (backend.write !== undefined) return backend.write.writeFile(absolutePath, content);
				await writeFile(absolutePath, content, "utf8");
				return { ok: true, value: undefined };
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
		async mkdir(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.mkdir", path: absolutePath };
			const result = await manager.run(operation, async (backend) => {
				if (backend.write !== undefined) return backend.write.mkdir(absolutePath);
				await mkdir(absolutePath, { recursive: true });
				return { ok: true, value: undefined };
			});
			if (result.ok) return;
			throwRenderedBlock(result.error);
		},
	};
}

function throwRenderedBlock(block: SandboxBlockV1): never {
	const [firstContent] = toToolResultBlock(block).content;
	throw new Error(firstContent?.text ?? block.remediation);
}
