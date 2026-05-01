import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import Dockerode from "dockerode";
import { describe, expect, it } from "vitest";

import { createDockerBackend } from "../../src/backends/docker/adapter.js";
import { buildDockerContainerOptions } from "../../src/backends/docker/host-config.js";
import type { DockerBackendConfig } from "../../src/policy/desired.js";
import type { SandboxBackend } from "../../src/sandbox/backend.js";

const dockerAvailable = await isDockerAvailable();

describe.skipIf(!dockerAvailable)("docker backend integration", () => {
	it("#given Docker daemon reachable #when bash hello world is run #then output is captured and exit 0", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-docker-"));
		try {
			const backend = await initializedBackend(sessionRoot);
			const chunks: Buffer[] = [];

			const result = await backend.bash?.exec("echo hello-docker", {
				cwd: sessionRoot,
				onData: (data: Buffer) => chunks.push(data),
			});

			expect(result).toEqual({ ok: true, value: { exitCode: 0 } });
			expect(Buffer.concat(chunks).toString("utf8")).toContain("hello-docker");
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});

	it("#given NetworkMode=none policy #when curl is attempted #then network denied", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-docker-"));
		try {
			const backend = await initializedBackend(sessionRoot);

			const result = await backend.bash?.exec(
				"node -e \"const net=require('node:net'); const socket=net.connect({host:'1.1.1.1',port:443,timeout:1000}); socket.on('connect',()=>process.exit(0)); socket.on('error',()=>process.exit(23)); socket.on('timeout',()=>process.exit(24));\"",
				{
					cwd: sessionRoot,
					timeoutMs: 3_000,
				},
			);

			expect(result?.ok).toBe(true);
			if (result?.ok) expect(result.value.exitCode).not.toBe(0);
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	}, 10_000);

	it("#given config tries to bind /var/run/docker.sock #when host-config built #then it is rejected with sandbox_backend_error", () => {
		const result = buildDockerContainerOptions(
			{
				...dockerConfig,
				mounts: [
					{
						hostPath: "/var/run/docker.sock",
						sandboxPath: "/docker.sock",
						mode: "readonly",
						persist: "host",
					},
				],
			},
			process.cwd(),
		);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("sandbox_backend_error");
	});

	it("#given readonly rootfs #when touch /readonly is attempted #then it fails", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-docker-"));
		try {
			const backend = await initializedBackend(sessionRoot);

			const result = await backend.bash?.exec("touch /readonly", { cwd: sessionRoot });

			expect(result?.ok).toBe(true);
			if (result?.ok) expect(result.value.exitCode).not.toBe(0);
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});

	it("#given cap-drop ALL #when capsh probe runs #then only minimal caps reported", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-docker-"));
		try {
			const backend = await initializedBackend(sessionRoot);
			const chunks: Buffer[] = [];

			const result = await backend.bash?.exec("grep CapEff /proc/self/status", {
				cwd: sessionRoot,
				onData: (data: Buffer) => chunks.push(data),
			});

			expect(result?.ok).toBe(true);
			if (result?.ok) expect(result.value.exitCode).toBe(0);
			expect(Buffer.concat(chunks).toString("utf8")).toContain("CapEff:\t0000000000000000");
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});

	it("#given hardened host config #when options are built #then adversarial safety controls are fixed", () => {
		const result = buildDockerContainerOptions(dockerConfig, process.cwd());

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.HostConfig).toMatchObject({
			Privileged: false,
			CapDrop: ["ALL"],
			SecurityOpt: ["no-new-privileges"],
			ReadonlyRootfs: true,
			NetworkMode: "none",
			AutoRemove: true,
		});
		expect(result.value.HostConfig?.PidMode).toBeUndefined();
		expect(result.value.HostConfig?.IpcMode).toBeUndefined();
		expect(result.value.HostConfig?.Binds?.some((bind) => bind.includes("/var/run/docker.sock"))).toBe(false);
	});
});

const dockerConfig: DockerBackendConfig = {
	kind: "docker",
	image: "node:22-alpine",
	networkMode: "none",
	readonlyRootfs: true,
	mounts: [],
	pullPolicy: "if-missing",
	capDrop: ["ALL"],
	securityOpt: ["no-new-privileges"],
	tmpfs: [],
};

async function initializedBackend(sessionRoot: string): Promise<SandboxBackend> {
	const result = await createDockerBackend(dockerConfig, sessionRoot);
	expect(result.ok).toBe(true);
	if (!result.ok) throw new Error(result.error.remediation);
	const initialized = await result.value.lifecycle.init();
	expect(initialized.ok).toBe(true);
	if (!initialized.ok) throw new Error(initialized.error.remediation);
	return result.value;
}

async function isDockerAvailable(): Promise<boolean> {
	try {
		await new Dockerode().ping();
		return true;
	} catch {
		return false;
	}
}
