// src/backends/ssh/auth.ts — privateKey + passphrase + password + agent + kbi + hostbased
import { readFileSync } from "node:fs";
import { createInterface } from "node:readline/promises";

import type { ConnectConfig, Prompt } from "ssh2";

import type { SshBackendConfig } from "../../policy/desired.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";

export function buildConnectConfig(backendConfig: SshBackendConfig): Result<ConnectConfig, SandboxFailure> {
	const base = {
		host: backendConfig.host,
		port: backendConfig.port,
		username: backendConfig.username,
		agentForward: false,
		readyTimeout: 20_000,
		keepaliveInterval: 15_000,
		keepaliveCountMax: 3,
	} satisfies ConnectConfig;

	try {
		switch (backendConfig.auth.kind) {
			case "privateKey":
				if (backendConfig.auth.passphrase === undefined) {
					return { ok: true, value: { ...base, privateKey: readFileSync(backendConfig.auth.keyPath) } };
				}
				return {
					ok: true,
					value: {
						...base,
						privateKey: readFileSync(backendConfig.auth.keyPath),
						passphrase: backendConfig.auth.passphrase,
					},
				};
			case "password":
				return { ok: true, value: { ...base, password: backendConfig.auth.password } };
			case "agent": {
				const agent = backendConfig.auth.sock ?? process.env.SSH_AUTH_SOCK;
				if (agent === undefined || agent.length === 0) {
					return {
						ok: false,
						error: invalidConfig(
							"ssh-agent-socket-missing",
							"Set SSH_AUTH_SOCK or configure backend.auth.sock for SSH agent authentication.",
						),
					};
				}
				return { ok: true, value: { ...base, agent } };
			}
			case "kbi":
				if (!process.stdin.isTTY) {
					return {
						ok: false,
						error: invalidConfig(
							"ssh-keyboard-interactive-requires-tty",
							"Use password/privateKey/agent auth in non-interactive sessions.",
						),
					};
				}
				return {
					ok: true,
					value: {
						...base,
						tryKeyboard: true,
					},
				};
			case "hostbased":
				if (backendConfig.auth.passphrase === undefined) {
					return {
						ok: true,
						value: {
							...base,
							privateKey: readFileSync(backendConfig.auth.keyPath),
							localHostname: backendConfig.auth.localHostname,
							localUsername: backendConfig.auth.localUsername,
							authHandler: ["hostbased"],
						},
					};
				}
				return {
					ok: true,
					value: {
						...base,
						privateKey: readFileSync(backendConfig.auth.keyPath),
						passphrase: backendConfig.auth.passphrase,
						localHostname: backendConfig.auth.localHostname,
						localUsername: backendConfig.auth.localUsername,
						authHandler: ["hostbased"],
					},
				};
			case "v1":
				return {
					ok: false,
					error: invalidConfig(
						"ssh-v1-unsupported-insecure",
						"SSHv1 is unsupported because it is cryptographically insecure; use SSHv2.",
					),
				};
		}
	} catch (cause) {
		return {
			ok: false,
			error: invalidConfig(cause instanceof Error ? cause.message : String(cause), "Fix SSH authentication config."),
		};
	}
}

export async function answerKeyboardInteractivePrompts(
	name: string,
	instructions: string,
	_lang: string,
	prompts: Prompt[],
	finish: (responses: string[]) => void,
): Promise<void> {
	const readline = createInterface({ input: process.stdin, output: process.stderr });
	try {
		if (name.length > 0) process.stderr.write(`${name}\n`);
		if (instructions.length > 0) process.stderr.write(`${instructions}\n`);
		const responses: string[] = [];
		for (const prompt of prompts) responses.push(await readline.question(prompt.prompt));
		finish(responses);
	} finally {
		readline.close();
	}
}

function invalidConfig(reason: string, remediation: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "ssh.auth",
		sanitizedTarget: "ssh",
		matchedRule: `invalid-config:${reason}`,
		backend: "ssh",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation,
		backendMessage: reason,
	});
}
