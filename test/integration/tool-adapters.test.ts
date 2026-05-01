import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import type { DesiredBackendConfig, FilePolicy } from "../../src/policy/desired.js";
import type { SandboxBackend } from "../../src/sandbox/backend.js";
import { BackendRegistry } from "../../src/sandbox/backend-registry.js";
import { SandboxManager } from "../../src/sandbox/manager.js";
import type { PathMapper } from "../../src/sandbox/path-mapper.js";
import type { Result, SandboxFailure } from "../../src/security/failure.js";
import { toEditOperations } from "../../src/tools/edit-adapter.js";
import { toReadOperations } from "../../src/tools/read-adapter.js";
import { toWriteOperations } from "../../src/tools/write-adapter.js";
import { fullCapability, makeEffectivePolicy } from "../unit/helpers/effective-policy.js";

const sessionRoots: string[] = [];

afterEach(async () => {
	await Promise.all(sessionRoots.splice(0).map((sessionRoot) => rm(sessionRoot, { recursive: true, force: true })));
});

describe("tool operation adapters", () => {
	it("#given read adapter and allowed root #when readFile is called #then it returns a Buffer through the policy gate", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "read.txt");
		await writeFile(filePath, "read-ok", "utf8");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: true, write: false, create: false }));
		const operations = toReadOperations(manager);

		await operations.access(filePath);
		const buffer = await operations.readFile(filePath);

		expect(Buffer.isBuffer(buffer)).toBe(true);
		expect(buffer.toString("utf8")).toBe("read-ok");
	});

	it("#given read adapter and denied root #when readFile is called #then it throws rendered sandbox block text", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "read-denied.txt");
		await writeFile(filePath, "blocked", "utf8");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: false, write: false, create: false }));
		const operations = toReadOperations(manager);

		await expect(operations.readFile(filePath)).rejects.toThrow("[pi-sandbox blocked]");
		await expect(operations.readFile(filePath)).rejects.toThrow("Rule: file.root.read=false");
	});

	it("#given write adapter and allowed root #when mkdir and writeFile are called #then content is written through the policy gate", async () => {
		const sessionRoot = await makeSessionRoot();
		const targetDirectory = path.join(sessionRoot, "nested");
		const filePath = path.join(targetDirectory, "write.txt");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: true, write: true, create: true }));
		const operations = toWriteOperations(manager);

		await operations.mkdir(targetDirectory);
		await operations.writeFile(filePath, "write-ok");

		expect(await readFile(filePath, "utf8")).toBe("write-ok");
	});

	it("#given write adapter and denied root #when writeFile is called #then it throws rendered sandbox block text", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "write-denied.txt");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: true, write: false, create: false }));
		const operations = toWriteOperations(manager);

		await expect(operations.writeFile(filePath, "blocked")).rejects.toThrow("[pi-sandbox blocked]");
		await expect(operations.writeFile(filePath, "blocked")).rejects.toThrow("Rule: file.root.write=false");
	});

	it("#given edit adapter and allowed root #when access readFile and writeFile are called #then file operations pass through policy gates", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "edit.txt");
		await writeFile(filePath, "edit-before", "utf8");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: true, write: true, create: false }));
		const operations = toEditOperations(manager);

		await operations.access(filePath);
		const before = await operations.readFile(filePath);
		await operations.writeFile(filePath, before.toString("utf8").replace("before", "after"));

		expect(await readFile(filePath, "utf8")).toBe("edit-after");
	});

	it("#given edit adapter and denied write root #when writeFile is called #then it throws rendered sandbox block text", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "edit-denied.txt");
		await writeFile(filePath, "edit-denied", "utf8");
		const manager = await makeManager(filePolicy({ root: sessionRoot, read: true, write: false, create: false }));
		const operations = toEditOperations(manager);

		await expect(operations.writeFile(filePath, "blocked")).rejects.toThrow("[pi-sandbox blocked]");
		await expect(operations.writeFile(filePath, "blocked")).rejects.toThrow("Rule: file.root.write=false");
	});
});

async function makeSessionRoot(): Promise<string> {
	const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-tool-adapter-test-"));
	sessionRoots.push(sessionRoot);
	return sessionRoot;
}

async function makeManager(file: FilePolicy): Promise<SandboxManager> {
	const manager = new SandboxManager(registryWithBackend(fakeBackend()), makeEffectivePolicy({ file }));
	const initialized = await manager.init();
	if (!initialized.ok) throw new Error(initialized.error.remediation);
	return manager;
}

function registryWithBackend(backend: SandboxBackend): BackendRegistry {
	const registry = new BackendRegistry();
	registry.register("justbash", async (_config: DesiredBackendConfig) => ok(backend));
	return registry;
}

function fakeBackend(): SandboxBackend {
	return {
		kind: "justbash",
		capabilities: fullCapability,
		pathMapper: fakePathMapper(),
		lifecycle: {
			init: async () => ok(undefined),
			dispose: async () => undefined,
			health: async () => ({ healthy: true, backend: "justbash", latencyMs: 1 }),
			probe: async () => [],
		},
		bash: { exec: async () => ok({ exitCode: 0 }) },
	};
}

function fakePathMapper(): PathMapper {
	return {
		hostToSandboxPath: (hostPath) => ({ ok: true, value: `/sandbox${hostPath}` }),
		sandboxToHostPath: (sandboxPath) => ({ ok: true, value: sandboxPath.replace(/^\/sandbox/, "") }),
		canRepresent: () => true,
	};
}

function ok<TValue>(value: TValue): Result<TValue, SandboxFailure> {
	return { ok: true, value };
}

function filePolicy(options: {
	readonly root: string;
	readonly read: boolean;
	readonly write: boolean;
	readonly create: boolean;
}): FilePolicy {
	return {
		defaultRead: "deny",
		defaultWrite: "deny",
		roots: [
			{
				path: options.root,
				read: options.read,
				write: options.write,
				create: options.create,
				delete: false,
				persist: "host",
				followSymlinks: false,
			},
		],
		denySpecialPaths: ["/proc", "/sys", "/dev"],
		denyMagicLinks: true,
		highRiskWriteClasses: ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"],
		maxReadBytes: 1024 * 1024,
	};
}
