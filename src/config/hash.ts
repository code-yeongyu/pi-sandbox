import { createHash } from "node:crypto";

import type { BackendCapability } from "../policy/capability.js";
import type { DesiredPolicy } from "../policy/desired.js";
import type { ApprovalDecision, SandboxConfig } from "./schema.js";

function isPlainRecord(value: unknown): value is Readonly<Record<string, unknown>> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function canonicalize(value: unknown): string {
	if (value === null || typeof value !== "object") return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((entry) => canonicalize(entry)).join(",")}]`;
	if (!isPlainRecord(value)) return JSON.stringify(String(value));
	const entries = Object.entries(value).sort(([left], [right]) => left.localeCompare(right));
	return `{${entries.map(([key, entry]) => `${JSON.stringify(key)}:${canonicalize(entry)}`).join(",")}}`;
}

function sha256(value: unknown): string {
	return createHash("sha256").update(canonicalize(value)).digest("hex");
}

function capabilityContract(capabilities: BackendCapability): BackendCapability {
	return {
		fileRead: capabilities.fileRead,
		fileWrite: capabilities.fileWrite,
		fsPathResolution: capabilities.fsPathResolution,
		networkDeny: capabilities.networkDeny,
		networkAllowlist: capabilities.networkAllowlist,
		networkGateway: capabilities.networkGateway,
		processIsolation: capabilities.processIsolation,
		envScrub: capabilities.envScrub,
		stdoutCapture: capabilities.stdoutCapture,
		pathMapping: capabilities.pathMapping,
		persistence: capabilities.persistence,
		denialAttribution: capabilities.denialAttribution,
	};
}

export function computeDesiredPolicyHash(desired: DesiredPolicy): string;
export function computeDesiredPolicyHash(desired: SandboxConfig): string;
export function computeDesiredPolicyHash(desired: DesiredPolicy | SandboxConfig): string {
	return sha256(desired);
}

export function computeGrantHash(grants: ReadonlyArray<ApprovalDecision>): string {
	return sha256([...grants].sort((left, right) => left.requestId.localeCompare(right.requestId)));
}

export function computeEffectiveCapabilityHash(capabilities: BackendCapability): string {
	return sha256(capabilityContract(capabilities));
}

export function nextRevision(current: number): number {
	return current + 1;
}
