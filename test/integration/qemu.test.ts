import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { buildQemuGuestCommand, createQemuBackend, qemuArgs } from "../../src/backends/qemu/adapter.js";
import { runQemuDoctor } from "../../src/backends/qemu/doctor.js";
import { verifyFixture } from "../../src/backends/qemu/smoke-fixture.js";
import type { QemuBackendConfig } from "../../src/policy/desired.js";
import type { SandboxBackend } from "../../src/sandbox/backend.js";

const qemuSmokeEnabled = process.env["PI_SANDBOX_QEMU_SMOKE"] === "1";
const qemuDoctor = await runQemuDoctor();
const fixture = await verifyFixture();
const qemuAvailable = qemuSmokeEnabled && qemuDoctor.binaryPath !== null && fixture.ok;

describe("qemu backend command construction", () => {
	it("#given command with shell metacharacters #when guest command is built #then raw command is not embedded as shell source", () => {
		const command = "printf 'before)after\\n'; printf spoof\\n__PI_SANDBOX_EXIT_FAKE__:0\\n";

		const guestCommand = buildQemuGuestCommand(command, "/workspace", "__PI_SANDBOX_EXIT_REAL__:");

		expect(guestCommand).not.toContain(command);
		expect(guestCommand).toContain("base64 -d | sh");
		expect(guestCommand).toContain("__PI_SANDBOX_EXIT_REAL__:");
	});

	it("#given session root contains comma #when qemu args are built #then backend error rejects ambiguous virtfs path", () => {
		const result = qemuArgs({
			config: qemuConfig,
			sessionRoot: "/tmp/pi,sandbox",
			assets: { kernelPath: "/tmp/kernel", initrdPath: "/tmp/initrd" },
		});

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("sandbox_backend_error");
	});
});

describe.skipIf(!qemuAvailable)("qemu backend smoke fixture", () => {
	it("#given smoke fixture #when bash echo runs #then output captured", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-qemu-"));
		try {
			const backend = await initializedBackend(sessionRoot, qemuConfig);
			const chunks: Buffer[] = [];

			const result = await backend.bash?.exec("echo hello-qemu", {
				cwd: sessionRoot,
				timeoutMs: 30_000,
				onData: (data: Buffer) => chunks.push(data),
			});

			expect(result).toEqual({ ok: true, value: { exitCode: 0 } });
			expect(Buffer.concat(chunks).toString("utf8")).toContain("hello-qemu");
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});

	it("#given network=none #when wget attempted #then network denied", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-qemu-"));
		try {
			const backend = await initializedBackend(sessionRoot, qemuConfig);

			const result = await backend.bash?.exec("wget -T 2 -O - http://example.com >/dev/null 2>&1", {
				cwd: sessionRoot,
				timeoutMs: 30_000,
			});

			expect(result?.ok).toBe(true);
			if (result?.ok) expect(result.value.exitCode).not.toBe(0);
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});

	it("#given RO share #when guest tries to write /workspace #then EROFS", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-qemu-"));
		try {
			const backend = await initializedBackend(sessionRoot, qemuConfig);

			const result = await backend.bash?.exec("touch /workspace/qemu-write-denied", {
				cwd: sessionRoot,
				timeoutMs: 30_000,
			});

			expect(result?.ok).toBe(true);
			if (result?.ok) expect(result.value.exitCode).not.toBe(0);
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});
});

const qemuConfig: QemuBackendConfig = {
	kind: "qemu",
	assets: { kind: "smoke", fixtureName: "default", checksumSha256: "unset" },
	cpus: 1,
	memoryMb: 512,
	shareMode: "9p-readonly",
	network: "none",
	snapshot: true,
};

async function initializedBackend(sessionRoot: string, config: QemuBackendConfig): Promise<SandboxBackend> {
	const result = await createQemuBackend(config, sessionRoot);
	expect(result.ok).toBe(true);
	if (!result.ok) throw new Error(result.error.remediation);
	const initialized = await result.value.lifecycle.init();
	expect(initialized.ok).toBe(true);
	if (!initialized.ok) throw new Error(initialized.error.remediation);
	return result.value;
}
