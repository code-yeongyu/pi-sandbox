import { join } from "node:path";

import type { EnvPolicy } from "../policy/desired.js";

const PROXY_KEYS = new Set([
	"HTTP_PROXY",
	"HTTPS_PROXY",
	"ALL_PROXY",
	"NO_PROXY",
	"http_proxy",
	"https_proxy",
	"all_proxy",
	"no_proxy",
	"npm_config_proxy",
	"npm_config_https_proxy",
]);

const SECRET_NAME_PATTERN =
	/(_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD|^SSH_AUTH_SOCK$|^AWS_.+|^GCP_.+|^GOOGLE_APPLICATION_CREDENTIALS$)/i;

export function buildEnv(policy: EnvPolicy, parentEnv: NodeJS.ProcessEnv): ReadonlyMap<string, string> {
	const entries = new Map<string, string>();
	const denyPatterns = compilePolicyPatterns(policy.denyPatterns);
	if (!policy.clearenv) {
		for (const [name, value] of Object.entries(parentEnv)) {
			if (value !== undefined) entries.set(name, value);
		}
	}

	for (const [name, value] of Object.entries(parentEnv)) {
		if (value === undefined) continue;
		if (!policy.allowlist.includes(name)) continue;
		if (matchesAnyPolicyPattern(name, denyPatterns)) continue;
		entries.set(name, value);
	}

	if (policy.scrubProxyEnv) {
		for (const key of PROXY_KEYS) entries.delete(key);
	}

	entries.set("PATH", parentEnv.PATH ?? sandboxPath());
	entries.set("HOME", join(process.cwd(), ".pi", "sandbox-home"));
	entries.set("TERM", parentEnv.TERM ?? "dumb");
	entries.set("LANG", parentEnv.LANG ?? "C.UTF-8");

	return Object.freeze(entries);
}

export function filterExplicitEnv(
	policy: EnvPolicy,
	explicitEnv: ReadonlyMap<string, string>,
	defaultEnv: NodeJS.ProcessEnv = process.env,
): ReadonlyMap<string, string> {
	const entries = new Map<string, string>();
	const denyPatterns = compilePolicyPatterns(policy.denyPatterns);
	for (const [name, value] of explicitEnv) {
		if (matchesAnyPolicyPattern(name, denyPatterns)) continue;
		if (policy.scrubProxyEnv && PROXY_KEYS.has(name)) continue;
		entries.set(name, value);
	}

	entries.set("PATH", defaultEnv.PATH ?? sandboxPath());
	entries.set("HOME", join(process.cwd(), ".pi", "sandbox-home"));
	entries.set("TERM", defaultEnv.TERM ?? "dumb");
	entries.set("LANG", defaultEnv.LANG ?? "C.UTF-8");

	return Object.freeze(entries);
}

export function classifySecret(name: string, value: string): boolean {
	return value.length > 0 && SECRET_NAME_PATTERN.test(name);
}

function sandboxPath(): string {
	return ["/usr/local/bin", "/usr/bin", "/bin"].join(":");
}

function matchesAnyPolicyPattern(name: string, patterns: readonly RegExp[]): boolean {
	return patterns.some((pattern) => pattern.test(name));
}

function compilePolicyPatterns(patterns: readonly string[]): readonly RegExp[] {
	return patterns.map(wildcardPatternToRegExp);
}

function wildcardPatternToRegExp(pattern: string): RegExp {
	const escaped = pattern.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replaceAll("*", ".*");
	return new RegExp(`^${escaped}$`, "i");
}
