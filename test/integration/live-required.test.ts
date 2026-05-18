import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { describe, expect, it } from "vitest";

import { createJustbashBackend } from "../../src/backends/justbash/adapter.js";
import type { EnvPolicy, JustbashBackendConfig } from "../../src/policy/desired.js";

const requireLive = process.env["PI_SANDBOX_REQUIRE_LIVE"] === "1";
const describeLive = requireLive ? describe : describe.skip;

describeLive("required live backend smoke", () => {
	it("#given PI_SANDBOX_REQUIRE_LIVE #when integration suite runs #then at least one backend smoke executes", async () => {
		const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-live-"));
		try {
			const backendResult = await createJustbashBackend(justbashConfig, sessionRoot, envPolicy);
			expect(backendResult.ok).toBe(true);
			if (!backendResult.ok) throw new Error(backendResult.error.remediation);
			const initialized = await backendResult.value.lifecycle.init();
			expect(initialized.ok).toBe(true);
			if (!initialized.ok) throw new Error(initialized.error.remediation);

			const chunks: Buffer[] = [];
			const result = await backendResult.value.bash?.exec("echo live-justbash", {
				cwd: sessionRoot,
				onData: (data: Buffer) => chunks.push(data),
			});

			expect(result).toEqual({ ok: true, value: { exitCode: 0 } });
			expect(Buffer.concat(chunks).toString("utf8")).toContain("live-justbash");
		} finally {
			await rm(sessionRoot, { recursive: true, force: true });
		}
	});
});

const justbashConfig: JustbashBackendConfig = {
	kind: "justbash",
	fs: "memory",
	allowedBinaries: [],
	executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 },
};

const envPolicy: EnvPolicy = {
	clearenv: true,
	allowlist: ["PATH", "HOME", "TERM", "LANG"],
	denyPatterns: ["*_TOKEN", "*_SECRET", "*_PASSWORD", "SSH_AUTH_SOCK"],
	scrubProxyEnv: true,
};
