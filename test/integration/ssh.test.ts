import { spawnSync } from "node:child_process";

import { describe, expect, it } from "vitest";

import { createSshBackend } from "../../src/backends/ssh/adapter.js";
import type { SshBackendConfig } from "../../src/policy/desired.js";

type SshTestEnv =
	| {
			readonly available: true;
			readonly host: string;
			readonly port: number;
			readonly username: string;
			readonly keyPath: string;
	  }
	| { readonly available: false; readonly reason: string };

const sshTestEnv = readSshTestEnv();
const describeSsh = sshTestEnv.available ? describe : describe.skip;

describeSsh("ssh backend integration", () => {
	it("#given valid key auth #when bash ls runs #then output captured + exit 0", async () => {
		if (!sshTestEnv.available) throw new Error(sshTestEnv.reason);
		const backendResult = await createSshBackend(baseConfig(sshTestEnv, { strict: false }), process.cwd());
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const init = await backendResult.value.lifecycle.init();
		expect(init.ok).toBe(true);
		try {
			const output: Buffer[] = [];
			const result = await backendResult.value.bash?.exec("ls -1 .", {
				cwd: process.cwd(),
				onData: (data) => output.push(data),
				timeoutMs: 10_000,
			});
			expect(result?.ok).toBe(true);
			if (result?.ok !== true) throw new Error("ssh ls did not return ok result");
			expect(result.value.exitCode).toBe(0);
			expect(Buffer.concat(output).toString("utf8").length).toBeGreaterThan(0);
		} finally {
			await backendResult.value.lifecycle.dispose();
		}
	});

	it("#given wrong host fingerprint #when client connects #then connection rejected", async () => {
		if (!sshTestEnv.available) throw new Error(sshTestEnv.reason);
		const backendResult = await createSshBackend(
			baseConfig(sshTestEnv, { strict: true, hostHash: "SHA256:not-a-real-fingerprint" }),
			process.cwd(),
		);
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const init = await backendResult.value.lifecycle.init();
		expect(init.ok).toBe(false);
		await backendResult.value.lifecycle.dispose();
	});

	it("#given strict host verification #when no key matches #then auth rejected", async () => {
		if (!sshTestEnv.available) throw new Error(sshTestEnv.reason);
		const backendResult = await createSshBackend(baseConfig(sshTestEnv, { strict: true }), process.cwd());
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const init = await backendResult.value.lifecycle.init();
		expect(init.ok).toBe(false);
		await backendResult.value.lifecycle.dispose();
	});

	it("#given agent forwarding default #when remote env checked #then SSH_AUTH_SOCK not present", async () => {
		if (!sshTestEnv.available) throw new Error(sshTestEnv.reason);
		const backendResult = await createSshBackend(baseConfig(sshTestEnv, { strict: false }), process.cwd());
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const init = await backendResult.value.lifecycle.init();
		expect(init.ok).toBe(true);
		try {
			const output: Buffer[] = [];
			const result = await backendResult.value.bash?.exec("printf '%s' \"$" + '{SSH_AUTH_SOCK-unset}"', {
				cwd: process.cwd(),
				onData: (data) => output.push(data),
				timeoutMs: 10_000,
			});
			expect(result?.ok).toBe(true);
			expect(Buffer.concat(output).toString("utf8")).toBe("unset");
		} finally {
			await backendResult.value.lifecycle.dispose();
		}
	});
});

function baseConfig(
	env: Extract<SshTestEnv, { readonly available: true }>,
	hostVerification: SshBackendConfig["hostVerification"],
): SshBackendConfig {
	return {
		kind: "ssh",
		host: env.host,
		port: env.port,
		username: env.username,
		auth: { kind: "privateKey", keyPath: env.keyPath },
		hostVerification,
		remoteRoot: "/tmp",
		sync: "sftp",
		proxyJump: [],
	};
}

function readSshTestEnv(): SshTestEnv {
	const openSsh = spawnSync("ssh", ["-V"], { encoding: "utf8" });
	const hasOpenSsh = openSsh.status === 0 || openSsh.stderr.includes("OpenSSH") || openSsh.stdout.includes("OpenSSH");
	if (!hasOpenSsh) return { available: false, reason: "OpenSSH client is not installed" };
	const { SSH_TEST_HOST, SSH_TEST_PORT, SSH_TEST_USER, SSH_TEST_KEY } = process.env;
	if (SSH_TEST_HOST === undefined || SSH_TEST_USER === undefined || SSH_TEST_KEY === undefined) {
		return { available: false, reason: "SSH_TEST_HOST, SSH_TEST_USER, and SSH_TEST_KEY are required" };
	}
	return {
		available: true,
		host: SSH_TEST_HOST,
		port: SSH_TEST_PORT === undefined ? 22 : Number.parseInt(SSH_TEST_PORT, 10),
		username: SSH_TEST_USER,
		keyPath: SSH_TEST_KEY,
	};
}
