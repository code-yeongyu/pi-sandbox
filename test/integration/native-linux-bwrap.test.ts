import { spawn } from "node:child_process";

import { describe, expect, it } from "vitest";

const bwrapAvailability = await checkBwrapAvailability();
const describeWhenBwrapAvailable = bwrapAvailability.available ? describe : describe.skip;

describeWhenBwrapAvailable("native linux bwrap integration", () => {
	it("#given network deny #when curl attempted #then non-zero exit", async () => {
		const result = await runBwrap([
			"--die-with-parent",
			"--unshare-user",
			"--unshare-pid",
			"--unshare-net",
			"--ro-bind-try",
			"/usr",
			"/usr",
			"--ro-bind-try",
			"/bin",
			"/bin",
			"--proc",
			"/proc",
			"/bin/sh",
			"-c",
			"curl -m 2 https://example.com",
		]);

		expect(result.exitCode).not.toBe(0);
	});

	it("#given /etc readonly bind #when sh tries to write /etc/passwd #then EROFS", async () => {
		const result = await runBwrap([
			"--die-with-parent",
			"--unshare-user",
			"--unshare-pid",
			"--ro-bind",
			"/etc",
			"/etc",
			"--ro-bind-try",
			"/usr",
			"/usr",
			"--ro-bind-try",
			"/bin",
			"/bin",
			"--proc",
			"/proc",
			"/bin/sh",
			"-c",
			"echo x >> /etc/passwd",
		]);

		expect(result.exitCode).not.toBe(0);
		expect(result.stderr).toMatch(/Read-only file system|Permission denied|Operation not permitted/i);
	});

	it("#given pid namespace #when ps -ef runs #then no host processes visible", async () => {
		const result = await runBwrap([
			"--die-with-parent",
			"--unshare-user",
			"--unshare-pid",
			"--ro-bind-try",
			"/usr",
			"/usr",
			"--ro-bind-try",
			"/bin",
			"/bin",
			"--proc",
			"/proc",
			"/bin/sh",
			"-c",
			"ps -eo pid=",
		]);

		expect(result.exitCode).toBe(0);
		expect(processListLooksIsolated(result.stdout)).toBe(true);
	});

	it("#given /proc magic-link defense #when reading /proc/self/mem #then access denied", async () => {
		const result = await runBwrap([
			"--die-with-parent",
			"--unshare-user",
			"--unshare-pid",
			"--ro-bind-try",
			"/usr",
			"/usr",
			"--ro-bind-try",
			"/bin",
			"/bin",
			"--proc",
			"/proc",
			"/bin/sh",
			"-c",
			"cat /proc/self/mem >/dev/null",
		]);

		expect(result.exitCode).not.toBe(0);
		expect(result.stderr).toMatch(/Permission denied|Input\/output error|Operation not permitted/i);
	});
});

type CommandResult = {
	readonly exitCode: number | null;
	readonly signal: NodeJS.Signals | null;
	readonly stdout: string;
	readonly stderr: string;
};

type BwrapAvailability =
	| { readonly available: true }
	| { readonly available: false; readonly reason: "not-linux" | "missing-or-blocked" };

async function checkBwrapAvailability(): Promise<BwrapAvailability> {
	if (process.platform !== "linux") return { available: false, reason: "not-linux" };
	const smoke = await runBwrap([
		"--unshare-user",
		"--unshare-pid",
		"--die-with-parent",
		"--ro-bind",
		"/usr",
		"/usr",
		"--proc",
		"/proc",
		"/bin/true",
	]);
	return smoke.exitCode === 0 ? { available: true } : { available: false, reason: "missing-or-blocked" };
}

function runBwrap(args: readonly string[]): Promise<CommandResult> {
	return new Promise((resolve) => {
		const child = spawn("bwrap", args, { stdio: ["ignore", "pipe", "pipe"] });
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		child.stdout.on("data", (data: Buffer) => stdout.push(data));
		child.stderr.on("data", (data: Buffer) => stderr.push(data));
		child.on("error", (cause) => {
			resolve({ exitCode: 127, signal: null, stdout: "", stderr: cause.message });
		});
		child.on("close", (exitCode, signal) => {
			resolve({ exitCode, signal, stdout: joinBuffers(stdout), stderr: joinBuffers(stderr) });
		});
	});
}

function processListLooksIsolated(stdout: string): boolean {
	const processIds = stdout
		.split(/\s+/)
		.map((entry) => Number.parseInt(entry, 10))
		.filter((processId) => Number.isInteger(processId));
	return processIds.length > 0 && processIds.every((processId) => processId > 0 && processId <= 20);
}

function joinBuffers(buffers: readonly Buffer[]): string {
	return Buffer.concat(buffers).toString("utf8");
}
