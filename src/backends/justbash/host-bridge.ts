// src/backends/justbash/host-bridge.ts — defineCommand bridges (host binaries) — env scrubbed
import { spawn } from "node:child_process";

import { type Command, defineCommand } from "just-bash";

import type { EnvPolicy } from "../../policy/desired.js";
import { buildEnv } from "../../security/env-policy.js";

export function createHostBinaryBridges(names: readonly string[], envPolicy: EnvPolicy): readonly Command[] {
	return names.map((name) =>
		defineCommand(name, async (args, ctx) => {
			const result = await runHostBinary({ name, args, cwd: ctx.cwd, envPolicy, stdin: ctx.stdin });
			return { stdout: result.stdout, stderr: result.stderr, exitCode: result.exitCode };
		}),
	);
}

async function runHostBinary(options: {
	readonly name: string;
	readonly args: readonly string[];
	readonly cwd: string;
	readonly envPolicy: EnvPolicy;
	readonly stdin: string;
}): Promise<{ readonly stdout: string; readonly stderr: string; readonly exitCode: number }> {
	return new Promise((resolve) => {
		const child = spawn(options.name, [...options.args], {
			cwd: options.cwd,
			env: Object.fromEntries(buildEnv(options.envPolicy, process.env)),
			stdio: ["pipe", "pipe", "pipe"],
		});
		const stdout: Buffer[] = [];
		const stderr: Buffer[] = [];
		child.stdout.on("data", (chunk: Buffer) => stdout.push(chunk));
		child.stderr.on("data", (chunk: Buffer) => stderr.push(chunk));
		child.on("error", (error) => {
			resolve({ stdout: "", stderr: `${options.name}: ${error.message}\n`, exitCode: 127 });
		});
		child.on("close", (code, signal) => {
			resolve({
				stdout: Buffer.concat(stdout).toString("utf8"),
				stderr: Buffer.concat(stderr).toString("utf8"),
				exitCode: signal === null ? (code ?? 1) : 130,
			});
		});
		child.stdin.end(options.stdin);
	});
}
