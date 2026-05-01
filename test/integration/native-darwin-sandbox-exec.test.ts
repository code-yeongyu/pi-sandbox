import { spawn, spawnSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createDarwinSandboxExecBackend } from "../../src/backends/native/darwin-sandbox-exec.js";
import { generateSbplProfile } from "../../src/backends/native/darwin-sbpl.js";
import type { FilePolicy } from "../../src/policy/desired.js";

const canRunSandboxExec = process.platform === "darwin" && spawnSync("which", ["sandbox-exec"]).status === 0;
const describeIfSandboxExec = canRunSandboxExec ? describe : describe.skip;

type RunResult = {
	readonly exitCode: number | null;
	readonly signal: NodeJS.Signals | null;
	readonly stdout: string;
	readonly stderr: string;
};

const sessionRoots: string[] = [];

afterEach(async () => {
	await Promise.all(sessionRoots.splice(0).map((sessionRoot) => rm(sessionRoot, { recursive: true, force: true })));
});

describeIfSandboxExec("native darwin sandbox-exec backend", () => {
	it("#given network=deny policy #when curl is attempted #then network denied", async () => {
		const sessionRoot = await makeSessionRoot();
		const backendResult = await createDarwinSandboxExecBackend(
			{ kind: "native", platform: "darwin", mechanism: "sandbox-exec" },
			sessionRoot,
		);
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const initialized = await backendResult.value.lifecycle.init();
		if (!initialized.ok) throw new Error(JSON.stringify(initialized.error));
		expect(initialized.ok).toBe(true);

		const probes = await backendResult.value.lifecycle.probe(["networkDeny"]);

		expect(probes).toHaveLength(1);
		expect(probes[0]).toMatchObject({ kind: "passed", control: "networkDeny" });
	});

	it("#given file write policy denying $HOME #when sandbox writes to $HOME/escape #then it fails", async () => {
		const sessionRoot = await makeSessionRoot();
		const target = path.join(process.env.HOME ?? tmpdir(), "escape");
		const profile = generateSbplProfile({
			network: { mode: "deny" },
			file: filePolicy({ root: sessionRoot, write: true, denyPaths: [process.env.HOME ?? tmpdir()] }),
			cwd: sessionRoot,
			allowedExecutables: ["/bin/sh", "/bin/bash"],
		});

		const result = await runSandboxExec(
			["-p", profile, "/bin/sh", "-c", `echo x > ${shellQuote(target)}`],
			sessionRoot,
		);

		expect(result.exitCode ?? signalExitCode(result.signal)).not.toBe(0);
	});

	it("#given file read allowed under sessionRoot #when reading sessionRoot/file.txt #then read succeeds", async () => {
		const sessionRoot = await makeSessionRoot();
		const filePath = path.join(sessionRoot, "file.txt");
		await writeFile(filePath, "seatbelt-ok", "utf8");
		const backendResult = await createDarwinSandboxExecBackend(
			{ kind: "native", platform: "darwin", mechanism: "sandbox-exec" },
			sessionRoot,
		);
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const initialized = await backendResult.value.lifecycle.init();
		if (!initialized.ok) throw new Error(JSON.stringify(initialized.error));
		expect(initialized.ok).toBe(true);
		const output: Buffer[] = [];

		const result = await backendResult.value.bash?.exec(`read line < ${shellQuote(filePath)}; printf '%s' "$line"`, {
			cwd: sessionRoot,
			onData: (data) => output.push(data),
		});

		expect(result).toMatchObject({ ok: true, value: { exitCode: 0 } });
		expect(Buffer.concat(output).toString("utf8")).toContain("seatbelt-ok");
	});

	it("#given a stale profile file #when sandbox-exec runs #then exit code is captured correctly", async () => {
		const sessionRoot = await makeSessionRoot();
		await writeFile(path.join(sessionRoot, "darwin-sandbox-stale.sb"), "(version 1)\n(deny default)\n", "utf8");
		const backendResult = await createDarwinSandboxExecBackend(
			{ kind: "native", platform: "darwin", mechanism: "sandbox-exec" },
			sessionRoot,
		);
		expect(backendResult.ok).toBe(true);
		if (!backendResult.ok) throw new Error(backendResult.error.remediation);
		const initialized = await backendResult.value.lifecycle.init();
		if (!initialized.ok) throw new Error(JSON.stringify(initialized.error));
		expect(initialized.ok).toBe(true);

		const result = await backendResult.value.bash?.exec("exit 42", { cwd: sessionRoot });

		expect(result).toMatchObject({ ok: true, value: { exitCode: 42 } });
	});
});

async function makeSessionRoot(): Promise<string> {
	const sessionRoot = await mkdtemp(path.join(tmpdir(), "pi-sandbox-darwin-test-"));
	sessionRoots.push(sessionRoot);
	return sessionRoot;
}

function filePolicy(options: {
	readonly root: string;
	readonly write: boolean;
	readonly denyPaths: readonly string[];
}): FilePolicy {
	return {
		defaultRead: "deny",
		defaultWrite: "deny",
		roots: [
			{
				path: options.root,
				read: true,
				write: options.write,
				create: options.write,
				delete: false,
				persist: "host",
				followSymlinks: false,
			},
		],
		denySpecialPaths: options.denyPaths,
		denyMagicLinks: true,
		highRiskWriteClasses: ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"],
		maxReadBytes: 1024 * 1024,
	};
}

function runSandboxExec(args: readonly string[], cwd: string): Promise<RunResult> {
	return new Promise((resolve, reject) => {
		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		const child = spawn("sandbox-exec", [...args], {
			cwd,
			env: minimalEnvironment(),
			stdio: ["ignore", "pipe", "pipe"],
		});
		child.stdout.on("data", (chunk: Buffer) => stdoutChunks.push(chunk));
		child.stderr.on("data", (chunk: Buffer) => stderrChunks.push(chunk));
		child.once("error", reject);
		child.once("close", (exitCode, signal) => {
			resolve({
				exitCode,
				signal,
				stdout: Buffer.concat(stdoutChunks).toString("utf8"),
				stderr: Buffer.concat(stderrChunks).toString("utf8"),
			});
		});
	});
}

function minimalEnvironment(): NodeJS.ProcessEnv {
	return {
		PATH: process.env.PATH ?? "/usr/bin:/bin:/usr/sbin:/sbin",
		HOME: process.env.HOME ?? tmpdir(),
		TERM: process.env.TERM ?? "dumb",
		LANG: process.env.LANG ?? "C.UTF-8",
	};
}

function shellQuote(value: string): string {
	return `'${value.replaceAll("'", "'\\''")}'`;
}

function signalExitCode(signal: NodeJS.Signals | null): number {
	return signal === null ? 0 : 128;
}
