import { constants } from "node:fs";
import { access, readFile } from "node:fs/promises";

import { toToolResultBlock } from "../explain/render-tool-result.js";
import type { ReadOperations } from "../pi/index.js";
import type { SandboxOperation } from "../policy/decision.js";
import type { SandboxManager } from "../sandbox/manager.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export function toReadOperations(manager: SandboxManager): ReadOperations {
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
		async access(absolutePath) {
			const operation: SandboxOperation = { kind: "fs.access", path: absolutePath };
			const result = await manager.run(operation, async (backend) => {
				if (backend.read !== undefined) return backend.read.access(absolutePath);
				await access(absolutePath, constants.R_OK);
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
