import { resolve } from "node:path";

import type { BackendKind } from "../policy/desired.js";
import type { SandboxRawConfig } from "./schema.js";

export type ConfigLayerName = "global" | "project" | "session";

export type ConfigLayer = {
	readonly name: ConfigLayerName;
	readonly config: SandboxRawConfig;
};

type MutableRawConfig = { -readonly [TKey in keyof SandboxRawConfig]: SandboxRawConfig[TKey] };
type FileRoot = { readonly path: string };
type DockerMount = { readonly hostPath: string; readonly sandboxPath: string };

function cloneRawConfig(config: SandboxRawConfig): SandboxRawConfig {
	return structuredClone(config);
}

function dedupeStrings(
	values: ReadonlyArray<string>,
	key: (value: string) => string = (value) => value,
): readonly string[] {
	const seen = new Set<string>();
	const result: string[] = [];
	for (const value of values) {
		const stableKey = key(value);
		if (seen.has(stableKey)) continue;
		seen.add(stableKey);
		result.push(value);
	}
	return result;
}

function canonicalPath(path: string): string {
	return resolve(path);
}

function isPathEqualOrInside(path: string, deniedPath: string): boolean {
	const canonical = canonicalPath(path);
	const denied = canonicalPath(deniedPath);
	return canonical === denied || canonical.startsWith(`${denied}/`);
}

function dedupeRoots<TRoot extends FileRoot>(
	roots: ReadonlyArray<TRoot>,
	denySpecialPaths: ReadonlyArray<string>,
): readonly TRoot[] {
	const byPath = new Map<string, TRoot>();
	for (const root of roots) byPath.set(canonicalPath(root.path), root);
	return [...byPath.values()].filter(
		(root) => !denySpecialPaths.some((deniedPath) => isPathEqualOrInside(root.path, deniedPath)),
	);
}

function dedupeMounts<TMount extends DockerMount>(mounts: ReadonlyArray<TMount>): readonly TMount[] {
	const byTuple = new Map<string, TMount>();
	for (const mount of mounts) byTuple.set(`${canonicalPath(mount.hostPath)}\0${mount.sandboxPath}`, mount);
	return [...byTuple.values()];
}

function mergeNetwork(
	current: SandboxRawConfig["network"],
	next: SandboxRawConfig["network"],
): SandboxRawConfig["network"] {
	if (!next) return current;
	if (!current || current.mode !== "restricted" || next.mode !== "restricted") return structuredClone(next);
	const denyDomains = dedupeStrings([...(current.denyDomains ?? []), ...(next.denyDomains ?? [])], (domain) =>
		domain.toLowerCase(),
	);
	const deniedDomains = new Set(denyDomains.map((domain) => domain.toLowerCase()));
	return {
		...current,
		...next,
		default: next.default ?? current.default ?? "deny",
		allowDomains: dedupeStrings([...(current.allowDomains ?? []), ...(next.allowDomains ?? [])], (domain) =>
			domain.toLowerCase(),
		).filter((domain) => !deniedDomains.has(domain.toLowerCase())),
		denyDomains,
		allowUrlPrefixes: dedupeStrings([...(current.allowUrlPrefixes ?? []), ...(next.allowUrlPrefixes ?? [])]),
		allowPorts: [...new Set([...(current.allowPorts ?? []), ...(next.allowPorts ?? [])])],
		allowCidrs: dedupeStrings([...(current.allowCidrs ?? []), ...(next.allowCidrs ?? [])]),
		denyPrivateNetworks: next.denyPrivateNetworks ?? current.denyPrivateNetworks ?? true,
		denyMetadata: next.denyMetadata ?? current.denyMetadata ?? true,
		allowUnixSockets: next.allowUnixSockets ?? current.allowUnixSockets ?? false,
		scrubProxyEnv: next.scrubProxyEnv ?? current.scrubProxyEnv ?? true,
		dns: next.dns ?? current.dns ?? "deny",
	};
}

function mergeFile(current: SandboxRawConfig["file"], next: SandboxRawConfig["file"]): SandboxRawConfig["file"] {
	if (!next) return current;
	if (!current) return structuredClone(next);
	const denySpecialPaths = dedupeStrings(
		[...(current.denySpecialPaths ?? []), ...(next.denySpecialPaths ?? [])],
		canonicalPath,
	);
	return {
		...current,
		...next,
		defaultRead: next.defaultRead ?? current.defaultRead ?? "deny",
		defaultWrite: next.defaultWrite ?? current.defaultWrite ?? "deny",
		roots: dedupeRoots([...(current.roots ?? []), ...(next.roots ?? [])], denySpecialPaths),
		denySpecialPaths,
		denyMagicLinks: next.denyMagicLinks ?? current.denyMagicLinks ?? true,
		highRiskWriteClasses: [
			...new Set([...(current.highRiskWriteClasses ?? []), ...(next.highRiskWriteClasses ?? [])]),
		],
		maxReadBytes: next.maxReadBytes ?? current.maxReadBytes ?? 10 * 1024 * 1024,
	};
}

function mergeEnv(current: SandboxRawConfig["env"], next: SandboxRawConfig["env"]): SandboxRawConfig["env"] {
	if (!next) return current;
	if (!current) return structuredClone(next);
	return {
		...current,
		...next,
		clearenv: next.clearenv ?? current.clearenv ?? true,
		allowlist: dedupeStrings([...(current.allowlist ?? []), ...(next.allowlist ?? [])]),
		denyPatterns: dedupeStrings([...(current.denyPatterns ?? []), ...(next.denyPatterns ?? [])]),
		scrubProxyEnv: next.scrubProxyEnv ?? current.scrubProxyEnv ?? true,
	};
}

function mergeBackend(
	current: SandboxRawConfig["backend"],
	next: SandboxRawConfig["backend"],
): SandboxRawConfig["backend"] {
	if (!next) return current;
	if (current?.kind === "docker" && next.kind === "docker") {
		return { ...current, ...next, mounts: dedupeMounts([...(current.mounts ?? []), ...(next.mounts ?? [])]) };
	}
	return structuredClone(next);
}

function compact(config: SandboxRawConfig): SandboxRawConfig {
	const result: MutableRawConfig = {};
	if (config.backend !== undefined) result.backend = config.backend;
	if (config.fallbackBackends !== undefined && config.fallbackBackends.length > 0)
		result.fallbackBackends = config.fallbackBackends;
	if (config.backendMissing !== undefined) result.backendMissing = config.backendMissing;
	if (config.network !== undefined) result.network = config.network;
	if (config.file !== undefined) result.file = config.file;
	if (config.process !== undefined) result.process = config.process;
	if (config.env !== undefined) result.env = config.env;
	if (config.approvals !== undefined) result.approvals = config.approvals;
	if (config.tui !== undefined) result.tui = config.tui;
	if (config.agentAwareness !== undefined) result.agentAwareness = config.agentAwareness;
	if (config.audit !== undefined) result.audit = config.audit;
	return result;
}

export function mergeConfigs(layers: ReadonlyArray<ConfigLayer>): SandboxRawConfig {
	let merged: SandboxRawConfig = {};
	for (const layer of layers) {
		const next = cloneRawConfig(layer.config);
		const fallbackBackends = dedupeStrings(
			[...(merged.fallbackBackends ?? []), ...(next.fallbackBackends ?? [])].filter(
				(backend): backend is BackendKind => backend !== undefined,
			),
		) as readonly BackendKind[];
		merged = compact({
			...merged,
			backend: mergeBackend(merged.backend, next.backend),
			fallbackBackends,
			backendMissing: next.backendMissing ?? merged.backendMissing,
			network: mergeNetwork(merged.network, next.network),
			file: mergeFile(merged.file, next.file),
			process: next.process ?? merged.process,
			env: mergeEnv(merged.env, next.env),
			approvals: next.approvals ?? merged.approvals,
			tui: next.tui ?? merged.tui,
			agentAwareness: next.agentAwareness ?? merged.agentAwareness,
			audit: next.audit ?? merged.audit,
		});
	}
	return merged;
}
