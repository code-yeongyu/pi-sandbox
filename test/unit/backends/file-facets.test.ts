import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { dockerCapability } from "../../../src/backends/docker/adapter.js";
import { createQemuBackend, qemuCapability } from "../../../src/backends/qemu/adapter.js";
import { createShellFileFacets } from "../../../src/backends/shell-file-facets.js";
import { createSshBackend, sshCapability } from "../../../src/backends/ssh/adapter.js";
import type { DockerBackendConfig, QemuBackendConfig, SshBackendConfig } from "../../../src/policy/desired.js";
import type { PathMapper } from "../../../src/sandbox/path-mapper.js";
import type { Result, SandboxFailure } from "../../../src/security/failure.js";

const sessionRoots: string[] = [];

afterEach(async () => {
	await Promise.all(sessionRoots.splice(0).map((sessionRoot) => rm(sessionRoot, { recursive: true, force: true })));
});

describe("backend file facets", () => {
	it("#given mapper that rejects sandbox root #when shell read facet runs #then cwd uses mapped file dirname", async () => {
		const cwdValues: string[] = [];
		const facets = createShellFileFacets("qemu", dirnameOnlyPathMapper(), {
			exec: async (_command, options) => {
				cwdValues.push(options.cwd);
				options.onData?.(Buffer.from("ZGlybmFtZS1jd2Q=\n", "utf8"));
				return ok({ exitCode: 0 });
			},
		});

		const result = await facets.read.readFile("/host/project/file.txt");

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.error.remediation);
		expect(result.value.toString("utf8")).toBe("dirname-cwd");
		expect(cwdValues).toEqual(["/host/project"]);
	});

	it("#given mapper that rejects sandbox root #when shell access targets mapped root #then cwd falls back to mapped target", async () => {
		const sessionRoot = await makeSessionRoot();
		const cwdValues: string[] = [];
		const facets = createShellFileFacets("qemu", workspacePathMapper(sessionRoot), {
			exec: async (_command, options) => {
				cwdValues.push(options.cwd);
				return ok({ exitCode: 0 });
			},
		});

		const result = await facets.read.access(sessionRoot);

		expect(result.ok).toBe(true);
		expect(cwdValues).toEqual([sessionRoot]);
	});

	it("#given write target with missing parent #when shell write facet runs #then cwd uses existing mapped ancestor", async () => {
		const sessionRoot = await makeSessionRoot();
		const cwdValues: string[] = [];
		const facets = createShellFileFacets("qemu", workspacePathMapper(sessionRoot), {
			exec: async (_command, options) => {
				cwdValues.push(options.cwd);
				return ok({ exitCode: 0 });
			},
		});

		const result = await facets.write.writeFile(path.join(sessionRoot, "new", "file.txt"), "content");

		expect(result.ok).toBe(true);
		expect(cwdValues).toEqual([sessionRoot]);
	});

	it("#given write target with missing parents #when shell write facet runs #then cwd uses nearest existing ancestor", async () => {
		const root = await mkdtemp(path.join(tmpdir(), "pi-sandbox-file-facet-"));
		const cwdValues: string[] = [];
		try {
			const facets = createShellFileFacets("qemu", nestedWritePathMapper(root), {
				exec: async (_command, options) => {
					cwdValues.push(options.cwd);
					return ok({ exitCode: 0 });
				},
			});

			const result = await facets.write.writeFile(path.join(root, "new", "file.txt"), "content");

			expect(result.ok).toBe(true);
			expect(cwdValues).toEqual([root]);
		} finally {
			await rm(root, { recursive: true, force: true });
		}
	});

	it("#given ssh backend factory #when backend is created #then shell file facets are exposed", async () => {
		const backend = await createSshBackend(sshConfig, "/host/project");

		expect(sshCapability.fileRead).toBe(true);
		expect(sshCapability.fileWrite).toBe(true);
		expect(sshCapability.fsPathResolution).toBe("backend-mount-boundary");
		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		expect(backend.value.capabilities.fileRead).toBe(true);
		expect(backend.value.capabilities.fileWrite).toBe(true);
		expect(backend.value.read).toBeDefined();
		expect(backend.value.write).toBeDefined();
		const probes = await backend.value.lifecycle.probe(["processIsolation"]);
		expect(probes).toHaveLength(1);
		expect(probes[0]?.kind).toBe("failed");
	});

	it("#given qemu readonly config #when backend is created #then read facet exists and write facet is absent", async () => {
		const backend = await createQemuBackend(qemuConfig("9p-readonly"), "/host/project");

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		expect(backend.value.capabilities.fileRead).toBe(true);
		expect(backend.value.capabilities.fileWrite).toBe(false);
		expect(backend.value.read).toBeDefined();
		expect(backend.value.write).toBeUndefined();
	});

	it("#given qemu readwrite config #when backend is created #then write facet is exposed", async () => {
		const backend = await createQemuBackend(qemuConfig("9p-readwrite"), "/host/project");

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		expect(backend.value.capabilities.fileWrite).toBe(true);
		expect(backend.value.write).toBeDefined();
	});

	it("#given docker and qemu network modes #when capabilities are built #then network deny is config dependent", () => {
		expect(dockerCapability(dockerConfig("none")).networkDeny).toBe(true);
		expect(dockerCapability(dockerConfig("bridge")).networkDeny).toBe(false);
		expect(qemuCapability(qemuConfig("9p-readonly", "none")).networkDeny).toBe(true);
		expect(qemuCapability(qemuConfig("9p-readonly", "hostfwd")).networkDeny).toBe(false);
	});
});

function dirnameOnlyPathMapper(): PathMapper {
	return {
		hostToSandboxPath: (hostPath) => {
			const resolved = path.posix.normalize(hostPath);
			if (resolved === "/host/project/file.txt") return { ok: true, value: "/workspace/file.txt" };
			return { ok: false, error: { kind: "outside-sandbox", hostPath } };
		},
		sandboxToHostPath: (sandboxPath) => {
			const normalized = path.posix.normalize(sandboxPath);
			if (normalized === "/workspace") return { ok: true, value: "/host/project" };
			if (normalized === "/") {
				return { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "root rejected" } };
			}
			return { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "dirname only" } };
		},
		canRepresent: (hostPath) => path.posix.normalize(hostPath) === "/host/project/file.txt",
	};
}

function workspacePathMapper(sessionRoot: string): PathMapper {
	return {
		hostToSandboxPath: (hostPath) => {
			const resolved = path.resolve(hostPath);
			if (resolved === sessionRoot) return { ok: true, value: "/workspace" };
			if (resolved.startsWith(`${sessionRoot}${path.sep}`)) {
				return { ok: true, value: path.posix.join("/workspace", path.relative(sessionRoot, resolved)) };
			}
			return { ok: false, error: { kind: "outside-sandbox", hostPath } };
		},
		sandboxToHostPath: (sandboxPath) => {
			const normalized = path.posix.normalize(sandboxPath.startsWith("/") ? sandboxPath : `/${sandboxPath}`);
			if (normalized === "/workspace") return { ok: true, value: sessionRoot };
			if (normalized.startsWith("/workspace/"))
				return { ok: true, value: path.join(sessionRoot, normalized.slice(11)) };
			return {
				ok: false,
				error: { kind: "non-representable", hostPath: sandboxPath, reason: "outside /workspace" },
			};
		},
		canRepresent: (hostPath) => {
			const resolved = path.resolve(hostPath);
			return resolved === sessionRoot || resolved.startsWith(`${sessionRoot}${path.sep}`);
		},
	};
}

async function makeSessionRoot(): Promise<string> {
	const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-file-facets-test-"));
	sessionRoots.push(sessionRoot);
	return sessionRoot;
}

function nestedWritePathMapper(root: string): PathMapper {
	return {
		hostToSandboxPath: (hostPath) => {
			const resolved = path.resolve(hostPath);
			if (resolved === path.join(root, "new", "file.txt")) return { ok: true, value: "/workspace/new/file.txt" };
			return { ok: false, error: { kind: "outside-sandbox", hostPath } };
		},
		sandboxToHostPath: (sandboxPath) => {
			const normalized = path.posix.normalize(sandboxPath);
			if (normalized === "/workspace/new/file.txt") return { ok: true, value: path.join(root, "new", "file.txt") };
			if (normalized === "/workspace/new") return { ok: true, value: path.join(root, "new") };
			if (normalized === "/workspace") return { ok: true, value: root };
			return { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "outside root" } };
		},
		canRepresent: (hostPath) => path.resolve(hostPath) === path.join(root, "new", "file.txt"),
	};
}

function qemuConfig(
	shareMode: QemuBackendConfig["shareMode"],
	network: QemuBackendConfig["network"] = "none",
): QemuBackendConfig {
	return {
		kind: "qemu",
		assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
		cpus: 1,
		memoryMb: 512,
		shareMode,
		network,
		snapshot: true,
	};
}

function dockerConfig(networkMode: DockerBackendConfig["networkMode"]): DockerBackendConfig {
	return {
		kind: "docker",
		image: "node:22-alpine",
		networkMode,
		readonlyRootfs: true,
		mounts: [],
		pullPolicy: "never",
		capDrop: ["ALL"],
		securityOpt: ["no-new-privileges"],
		tmpfs: [],
	};
}

const sshConfig = {
	kind: "ssh",
	host: "example.invalid",
	port: 22,
	username: "user",
	auth: { kind: "password", password: "secret" },
	hostVerification: { strict: false },
	remoteRoot: "/tmp/pi-sandbox",
	proxyJump: [],
} satisfies SshBackendConfig;

function ok<TValue>(value: TValue): Result<TValue, SandboxFailure> {
	return { ok: true, value };
}
