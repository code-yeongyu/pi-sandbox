import { access } from "node:fs/promises";
import path from "node:path";

import type { BackendKind } from "../policy/desired.js";
import type { SandboxBashFacet, SandboxReadFacet, SandboxWriteFacet } from "../sandbox/backend.js";
import type { PathMapper } from "../sandbox/path-mapper.js";
import { createBlock, type Result, type SandboxFailure } from "../security/failure.js";

export function createShellFileFacets(
	backend: BackendKind,
	pathMapper: PathMapper,
	bash: SandboxBashFacet,
): { readonly read: SandboxReadFacet; readonly write: SandboxWriteFacet } {
	return {
		read: {
			readFile: async (absolutePath) => {
				const mapped = pathMapper.hostToSandboxPath(absolutePath);
				if (!mapped.ok)
					return {
						ok: false,
						error: pathMappingFailure(backend, "read.readFile", absolutePath, mapped.error.kind),
					};
				const cwd = cwdForMappedPath(pathMapper, backend, "read.readFile", absolutePath, mapped.value);
				if (!cwd.ok) return cwd;
				const output: Buffer[] = [];
				const result = await bash.exec(`base64 < ${shellQuote(mapped.value)}`, {
					cwd: cwd.value,
					onData: (data) => output.push(data),
				});
				if (!result.ok) return result;
				if (result.value.exitCode !== 0)
					return {
						ok: false,
						error: shellFileFailure(backend, "read.readFile", absolutePath, result.value.exitCode),
					};
				return {
					ok: true,
					value: Buffer.from(Buffer.concat(output).toString("utf8").replace(/\s+/g, ""), "base64"),
				};
			},
			access: async (absolutePath) => {
				const mapped = pathMapper.hostToSandboxPath(absolutePath);
				if (!mapped.ok)
					return { ok: false, error: pathMappingFailure(backend, "read.access", absolutePath, mapped.error.kind) };
				const cwd = cwdForMappedPath(pathMapper, backend, "read.access", absolutePath, mapped.value);
				if (!cwd.ok) return cwd;
				const result = await bash.exec(`test -r ${shellQuote(mapped.value)}`, { cwd: cwd.value });
				if (!result.ok) return result;
				if (result.value.exitCode === 0) return { ok: true, value: undefined };
				return { ok: false, error: shellFileFailure(backend, "read.access", absolutePath, result.value.exitCode) };
			},
		},
		write: {
			writeFile: async (absolutePath, content) => {
				const mapped = pathMapper.hostToSandboxPath(absolutePath);
				if (!mapped.ok)
					return {
						ok: false,
						error: pathMappingFailure(backend, "write.writeFile", absolutePath, mapped.error.kind),
					};
				const cwd = await cwdForWriteMappedPath(pathMapper, backend, "write.writeFile", absolutePath, mapped.value);
				if (!cwd.ok) return cwd;
				const encoded = Buffer.isBuffer(content)
					? content.toString("base64")
					: Buffer.from(content).toString("base64");
				const target = shellQuote(mapped.value);
				const directory = shellQuote(path.posix.dirname(mapped.value));
				const payload = shellQuote(encoded);
				const command = [
					`mkdir -p ${directory}`,
					`(printf %s ${payload} | base64 -d > ${target} || printf %s ${payload} | base64 -D > ${target})`,
				].join(" && ");
				const result = await bash.exec(command, { cwd: cwd.value });
				if (!result.ok) return result;
				if (result.value.exitCode === 0) return { ok: true, value: undefined };
				return {
					ok: false,
					error: shellFileFailure(backend, "write.writeFile", absolutePath, result.value.exitCode),
				};
			},
			mkdir: async (absolutePath) => {
				const mapped = pathMapper.hostToSandboxPath(absolutePath);
				if (!mapped.ok)
					return { ok: false, error: pathMappingFailure(backend, "write.mkdir", absolutePath, mapped.error.kind) };
				const cwd = await cwdForWriteMappedPath(pathMapper, backend, "write.mkdir", absolutePath, mapped.value);
				if (!cwd.ok) return cwd;
				const result = await bash.exec(`mkdir -p ${shellQuote(mapped.value)}`, { cwd: cwd.value });
				if (!result.ok) return result;
				if (result.value.exitCode === 0) return { ok: true, value: undefined };
				return { ok: false, error: shellFileFailure(backend, "write.mkdir", absolutePath, result.value.exitCode) };
			},
		},
	};
}

function cwdForMappedPath(
	pathMapper: PathMapper,
	backend: BackendKind,
	operation: string,
	target: string,
	mappedPath: string,
): Result<string, SandboxFailure> {
	const mappedDirectory = pathMapper.sandboxToHostPath(path.posix.dirname(mappedPath));
	if (mappedDirectory.ok) return { ok: true, value: mappedDirectory.value };
	const mappedTarget = pathMapper.sandboxToHostPath(mappedPath);
	if (mappedTarget.ok) return { ok: true, value: mappedTarget.value };
	return { ok: false, error: pathMappingFailure(backend, operation, target, mappedDirectory.error.kind) };
}

async function cwdForWriteMappedPath(
	pathMapper: PathMapper,
	backend: BackendKind,
	operation: string,
	target: string,
	mappedPath: string,
): Promise<Result<string, SandboxFailure>> {
	const mappedTarget = pathMapper.sandboxToHostPath(mappedPath);
	if (!mappedTarget.ok)
		return { ok: false, error: pathMappingFailure(backend, operation, target, mappedTarget.error.kind) };
	let current = mappedTarget.value;
	while (true) {
		try {
			await access(current);
			return { ok: true, value: current };
		} catch {
			const next = path.dirname(current);
			if (next === current) {
				return { ok: false, error: pathMappingFailure(backend, operation, target, "non-representable") };
			}
			current = next;
		}
	}
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

function pathMappingFailure(backend: BackendKind, operation: string, target: string, kind: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "path_mapping_failed",
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "backend.file-facet.path-mapping",
		backend,
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run file tools inside paths representable by the selected sandbox backend.",
		pathEvidence: { kind, hostPath: target },
	});
}

function shellFileFailure(
	backend: BackendKind,
	operation: string,
	target: string,
	exitCode: number | null,
): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "backend.file-facet.shell-command",
		backend,
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "The selected backend failed the shell-backed file operation.",
		backendMessage: `exit=${exitCode ?? "signal"}`,
	});
}
