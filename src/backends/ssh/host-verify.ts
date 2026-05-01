// src/backends/ssh/host-verify.ts — hostHash + hostVerifier (NEVER MITM-allowing)
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";

import type { SshHostVerificationConfig } from "../../policy/desired.js";

export function buildHostVerifier(verification: SshHostVerificationConfig): (key: Buffer) => boolean {
	const acceptedFingerprints = new Set<string>();
	if (verification.hostHash !== undefined) acceptedFingerprints.add(normalizeFingerprint(verification.hostHash));
	for (const fingerprint of readKnownHostsFingerprints(verification.knownHostsPath)) {
		acceptedFingerprints.add(fingerprint);
	}

	return (key: Buffer): boolean => {
		if (!verification.strict) return true;
		if (acceptedFingerprints.size === 0) return false;
		return acceptedFingerprints.has(sha256Fingerprint(key));
	};
}

export function sha256Fingerprint(key: Buffer): string {
	return createHash("sha256").update(key).digest("base64").replace(/=+$/u, "");
}

function readKnownHostsFingerprints(knownHostsPath: string | undefined): readonly string[] {
	if (knownHostsPath === undefined || !existsSync(knownHostsPath)) return [];
	const content = readFileSync(knownHostsPath, "utf8");
	const fingerprints: string[] = [];
	for (const line of content.split(/\r?\n/u)) {
		const trimmed = line.trim();
		if (trimmed.length === 0 || trimmed.startsWith("#")) continue;
		const parts = trimmed.split(/\s+/u);
		const keyData = parts.at(0)?.startsWith("@") ? parts.at(3) : parts.at(2);
		if (keyData === undefined) continue;
		try {
			fingerprints.push(sha256Fingerprint(Buffer.from(keyData, "base64")));
		} catch {}
	}
	return fingerprints;
}

function normalizeFingerprint(value: string): string {
	const trimmed = value.trim();
	if (trimmed.toUpperCase().startsWith("SHA256:")) return trimmed.slice("SHA256:".length).replace(/=+$/u, "");
	if (/^[0-9a-f]{64}$/iu.test(trimmed)) return Buffer.from(trimmed, "hex").toString("base64").replace(/=+$/u, "");
	return trimmed.replace(/=+$/u, "");
}
