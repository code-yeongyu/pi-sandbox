// src/backends/ssh/proxy-jump.ts — chained forwardOut for ProxyJump
import type { Duplex } from "node:stream";

import { Client, type ClientChannel, type ConnectConfig } from "ssh2";

import type { SshBackendConfig } from "../../policy/desired.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";
import { buildConnectConfig } from "./auth.js";
import { buildHostVerifier } from "./host-verify.js";

export async function buildProxyJumpChain(
	target: SshBackendConfig,
): Promise<Result<{ readonly socket: Duplex; readonly close: () => void }, SandboxFailure>> {
	const clients: Client[] = [];
	try {
		let socket: Duplex | undefined;
		for (const [index, hop] of target.proxyJump.entries()) {
			const hopConfig = buildConnectConfig(hop);
			if (!hopConfig.ok) return hopConfig;
			const client = await connectClient(withSocketAndVerifier(hopConfig.value, hop, socket));
			clients.push(client);
			const next = target.proxyJump[index + 1] ?? target;
			socket = await forwardOut(client, next.host, next.port);
		}
		if (socket === undefined) return { ok: false, error: proxyFailure("proxyJump is empty") };
		return { ok: true, value: { socket, close: () => closeAll(clients, socket) } };
	} catch (cause) {
		closeAll(clients, undefined);
		return { ok: false, error: proxyFailure(cause instanceof Error ? cause.message : String(cause)) };
	}
}

function withSocketAndVerifier(
	config: ConnectConfig,
	hop: SshBackendConfig,
	socket: Duplex | undefined,
): ConnectConfig {
	return {
		...config,
		...(socket === undefined ? {} : { sock: socket }),
		hostVerifier: buildHostVerifier(hop.hostVerification),
	};
}

function connectClient(config: ConnectConfig): Promise<Client> {
	return new Promise((resolve, reject) => {
		const client = new Client();
		client.once("ready", () => resolve(client));
		client.once("error", reject);
		client.connect(config);
	});
}

function forwardOut(client: Client, host: string, port: number): Promise<ClientChannel> {
	return new Promise((resolve, reject) => {
		client.forwardOut("127.0.0.1", 0, host, port, (error, channel) => {
			if (error !== undefined) reject(error);
			else resolve(channel);
		});
	});
}

function closeAll(clients: readonly Client[], socket: Duplex | undefined): void {
	socket?.destroy();
	for (const client of [...clients].reverse()) client.end();
}

function proxyFailure(message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation: "ssh.proxyJump",
		sanitizedTarget: "ssh",
		matchedRule: "proxy-jump",
		backend: "ssh",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Verify each ProxyJump host, authentication method, and host-key fingerprint.",
		backendMessage: message,
	});
}
