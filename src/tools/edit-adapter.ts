import { constants } from "node:fs";
import { access, readFile, writeFile } from "node:fs/promises";

import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { EditOperations } from "../pi/index.js";
import type { SandboxOperation } from "../policy/decision.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export function toEditOperations(manager: SandboxManager): EditOperations {
	return {
		async readFile(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.read", path: absolutePath };
			const result = await manager.run(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.readFile(absolutePath);
				return { ok: true, value: await readFile(absolutePath) };
			});
			if (result.ok) return result.value;
			throwRenderedBlock(result.error);
		},
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
		async access(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.access", path: absolutePath };
			const result = await manager.run(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.access(absolutePath);
				await access(absolutePath, constants.R_OK | constants.W_OK);
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
