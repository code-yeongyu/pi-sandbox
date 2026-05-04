import { createHash } from "node:crypto";
import { isAbsolute, normalize, resolve, sep } from "node:path";
import { createBlock, type SandboxBlockV1 } from "../security/failure.js";
import type { EffectivePolicy } from "./effective.js";

export type SandboxOperation =
	| { readonly kind: "bash"; readonly command: string; readonly cwd: string }
	| { readonly kind: "fs.read"; readonly path: string }
	| { readonly kind: "fs.write"; readonly path: string; readonly content: string | Buffer }
	| { readonly kind: "fs.access"; readonly path: string }
	| { readonly kind: "fs.mkdir"; readonly path: string }
	| { readonly kind: "process.spawn"; readonly binary: string; readonly args: readonly string[]; readonly cwd: string }
	| { readonly kind: "network"; readonly method: string; readonly url: string };

export type DecisionRequest = {
	readonly operation: SandboxOperation;
	readonly effectivePolicy: EffectivePolicy;
	readonly approvedRequestIds: ReadonlySet<string>;
};

export type Decision =
	| { readonly kind: "allow" }
	| { readonly kind: "deny"; readonly block: SandboxBlockV1 }
	| {
			readonly kind: "prompt";
			readonly requestId: string;
			readonly class: string;
			readonly sanitizedTarget: string;
			readonly matchedRule: string;
	  };

type FilePermission = "read" | "write" | "create";
type NetworkCheck = { readonly allowed: boolean; readonly rule: string };

const URL_PATTERN = /https?:\/\/[^\s'"<>]+/gi;
const HOST_BRIDGE_BINARIES = new Set(["npm", "pnpm", "yarn", "npx", "node", "git", "curl", "wget"]);
const NETWORK_REQUIRED_BINARIES = new Set(["npm", "pnpm", "yarn", "npx", "curl", "wget"]);

export function decide(request: DecisionRequest): Decision {
	const operation = request.operation;
	if (operation.kind === "bash") return decideBash(request);
	if (operation.kind === "network") return decideNetworkOperation(request);
	if (operation.kind === "process.spawn") return decideProcessSpawn(request);
	return decideFileOperation(request);
}

function decideBash(request: DecisionRequest): Decision {
	const { effectivePolicy, operation } = request;
	if (operation.kind !== "bash") return { kind: "allow" };

	const urls = extractUrls(operation.command);
	if (effectivePolicy.network.mode === "deny" && urls.length > 0) {
		return deny(
			effectivePolicy,
			"permission_denied",
			"network",
			"bash",
			sanitizeUrl(urls[0] ?? "https://redacted.invalid"),
			"network.mode=deny",
			"Remove the network URL or request a network grant.",
		);
	}
	if (
		effectivePolicy.network.mode === "restricted" &&
		!effectivePolicy.backend.capabilities.networkGateway &&
		urls.length > 0
	) {
		return denyCapability(
			effectivePolicy,
			"bash",
			sanitizeUrl(urls[0] ?? "https://redacted.invalid"),
			"networkGateway",
		);
	}
	for (const url of urls) {
		const check = checkNetworkUrl(effectivePolicy, url);
		if (!check.allowed) {
			return deny(
				effectivePolicy,
				"permission_denied",
				"network",
				"bash",
				sanitizeUrl(url),
				check.rule,
				"Request a domain or URL-prefix grant, or remove the network access.",
			);
		}
	}

	const binary = firstShellWord(operation.command);
	if (binary !== null && HOST_BRIDGE_BINARIES.has(binary)) {
		const processDecision = processDecisionForBinary(request, binary, `bash:${binary}`);
		if (processDecision.kind !== "allow") return processDecision;
		if (NETWORK_REQUIRED_BINARIES.has(binary) && effectivePolicy.network.mode === "deny") {
			return deny(
				effectivePolicy,
				"permission_denied",
				"network",
				"bash",
				binary,
				"host-bridge-requires-network",
				"Use an offline command or request a network grant for this host bridge.",
			);
		}
	}

	return { kind: "allow" };
}

function decideNetworkOperation(request: DecisionRequest): Decision {
	const { effectivePolicy, operation } = request;
	if (operation.kind !== "network") return { kind: "allow" };
	if (effectivePolicy.network.mode === "deny") {
		return deny(
			effectivePolicy,
			"permission_denied",
			"network",
			"network",
			sanitizeUrl(operation.url),
			"network.mode=deny",
			"Request a network grant before making this request.",
		);
	}
	if (effectivePolicy.network.mode === "restricted" && !effectivePolicy.backend.capabilities.networkGateway) {
		return denyCapability(effectivePolicy, "network", sanitizeUrl(operation.url), "networkGateway");
	}
	const check = checkNetworkUrl(effectivePolicy, operation.url);
	if (!check.allowed) {
		const requestId = stableRequestId(operation, check.rule, effectivePolicy.policyRevision);
		if (request.approvedRequestIds.has(requestId)) return { kind: "allow" };
		return {
			kind: "prompt",
			requestId,
			class: "network",
			sanitizedTarget: sanitizeUrl(operation.url),
			matchedRule: check.rule,
		};
	}
	return { kind: "allow" };
}

function decideProcessSpawn(request: DecisionRequest): Decision {
	const { operation } = request;
	if (operation.kind !== "process.spawn") return { kind: "allow" };
	return processDecisionForBinary(request, operation.binary, "process.spawn");
}

function decideFileOperation(request: DecisionRequest): Decision {
	const { effectivePolicy, operation } = request;
	if (!isFileOperation(operation)) return { kind: "allow" };
	const path = operation.path;
	const canonical = canonicalizeLexical(path);

	if (effectivePolicy.file.denyMagicLinks && traversesProcSelfFd(canonical)) {
		return denyMagicLink(effectivePolicy, operation.kind, sanitizePath(canonical));
	}

	const permission = permissionForOperation(operation.kind);
	const root = effectivePolicy.file.roots.find((candidate) =>
		pathWithinRoot(canonical, canonicalizeLexical(candidate.path)),
	);
	if (root === undefined) {
		const matchedRule = `file.roots.${permission}=missing`;
		if (defaultAllows(effectivePolicy, permission)) return { kind: "allow" };
		return deny(
			effectivePolicy,
			"permission_denied",
			policyAreaForFilePermission(permission),
			operation.kind,
			sanitizePath(canonical),
			matchedRule,
			"Move the target under an allowed sandbox root or request a file grant.",
		);
	}

	if (!rootAllows(root, permission)) {
		return deny(
			effectivePolicy,
			"permission_denied",
			policyAreaForFilePermission(permission),
			operation.kind,
			sanitizePath(canonical),
			`file.root.${permission}=false`,
			"Request a file grant for this path or choose a permitted root.",
		);
	}

	if (permission !== "read") {
		const riskClass = classifyHighRiskWrite(canonical, effectivePolicy.file.highRiskWriteClasses);
		if (riskClass !== null) {
			const requestId = stableRequestId(operation, riskClass, effectivePolicy.policyRevision);
			if (request.approvedRequestIds.has(requestId)) return { kind: "allow" };
			return {
				kind: "prompt",
				requestId,
				class: riskClass,
				sanitizedTarget: sanitizePath(canonical),
				matchedRule: `highRiskWriteClasses.${riskClass}`,
			};
		}
	}

	return { kind: "allow" };
}

function isFileOperation(
	operation: SandboxOperation,
): operation is Extract<SandboxOperation, { readonly kind: "fs.read" | "fs.write" | "fs.access" | "fs.mkdir" }> {
	return (
		operation.kind === "fs.read" ||
		operation.kind === "fs.write" ||
		operation.kind === "fs.access" ||
		operation.kind === "fs.mkdir"
	);
}

function processDecisionForBinary(request: DecisionRequest, binary: string, operationName: string): Decision {
	const { effectivePolicy } = request;
	if (effectivePolicy.process.isolation) return { kind: "allow" };
	const requestId = stableRequestId(
		{ kind: "process.spawn", binary, args: [], cwd: "" },
		"process.isolation=false",
		effectivePolicy.policyRevision,
	);
	if (request.approvedRequestIds.has(requestId)) return { kind: "allow" };
	return {
		kind: "prompt",
		requestId,
		class: "process",
		sanitizedTarget: binary,
		matchedRule: operationName,
	};
}

function extractUrls(command: string): readonly string[] {
	return [...command.matchAll(URL_PATTERN)].map((match) => match[0] ?? "");
}

function firstShellWord(command: string): string | null {
	const trimmed = command.trim();
	const match = /^(?:env\s+)?([A-Za-z0-9_./-]+)/.exec(trimmed);
	const value = match?.[1];
	if (value === undefined) return null;
	const parts = value.split("/");
	return parts.at(-1) ?? value;
}

function checkNetworkUrl(effectivePolicy: EffectivePolicy, target: string): NetworkCheck {
	const policy = effectivePolicy.network;
	if (policy.mode === "allow-all") return { allowed: true, rule: "network.mode=allow-all" };
	if (policy.mode === "deny") return { allowed: false, rule: "network.mode=deny" };
	const parsed = parseUrl(target);
	if (parsed === null) return { allowed: false, rule: "network.url=invalid" };
	const host = parsed.hostname.toLowerCase();
	if (policy.denyDomains.some((domain) => domainMatches(host, domain))) {
		return { allowed: false, rule: "network.denyDomains" };
	}
	if (policy.allowUrlPrefixes.some((prefix) => target.startsWith(prefix))) {
		return { allowed: true, rule: "network.allowUrlPrefixes" };
	}
	if (policy.allowDomains.some((domain) => domainMatches(host, domain))) {
		return { allowed: true, rule: "network.allowDomains" };
	}
	const port = parsed.port === "" ? defaultPort(parsed.protocol) : Number(parsed.port);
	if (policy.allowPorts.includes(port)) return { allowed: true, rule: "network.allowPorts" };
	return { allowed: policy.default === "allow", rule: `network.restricted.default=${policy.default}` };
}

function parseUrl(target: string): URL | null {
	try {
		return new URL(target);
	} catch {
		return null;
	}
}

function defaultPort(protocol: string): number {
	return protocol === "http:" ? 80 : 443;
}

function domainMatches(host: string, domain: string): boolean {
	const normalizedDomain = domain.toLowerCase();
	return host === normalizedDomain || host.endsWith(`.${normalizedDomain}`);
}

function canonicalizeLexical(path: string): string {
	return normalize(isAbsolute(path) ? path : resolve(path));
}

function pathWithinRoot(path: string, root: string): boolean {
	return path === root || path.startsWith(root.endsWith(sep) ? root : `${root}${sep}`);
}

function traversesProcSelfFd(path: string): boolean {
	return /(?:^|\/)proc\/self\/fd(?:\/|$)/.test(path);
}

function permissionForOperation(kind: SandboxOperation["kind"]): FilePermission {
	if (kind === "fs.read" || kind === "fs.access") return "read";
	if (kind === "fs.mkdir") return "create";
	return "write";
}

function defaultAllows(effectivePolicy: EffectivePolicy, permission: FilePermission): boolean {
	if (permission === "read") return effectivePolicy.file.defaultRead === "allow";
	return effectivePolicy.file.defaultWrite === "allow";
}

function rootAllows(root: EffectivePolicy["file"]["roots"][number], permission: FilePermission): boolean {
	if (permission === "read") return root.read;
	if (permission === "create") return root.create;
	return root.write;
}

function policyAreaForFilePermission(permission: FilePermission): "file.read" | "file.write" {
	return permission === "read" ? "file.read" : "file.write";
}

function classifyHighRiskWrite(path: string, enabled: readonly string[]): string | null {
	const basename = path.split(sep).at(-1) ?? path;
	const checks: ReadonlyArray<readonly [string, boolean]> = [
		["dotenv", basename === ".env" || basename.startsWith(".env.")],
		["ssh-key", path.includes(`${sep}.ssh${sep}`) || /(?:^|[_-])id_(?:rsa|dsa|ecdsa|ed25519)$/.test(basename)],
		["git-hook", path.includes(`${sep}.git${sep}hooks${sep}`)],
		["shell-rc", [".bashrc", ".zshrc", ".profile", ".zprofile"].includes(basename)],
		["npm-script", basename === "package.json"],
		["executable", [".sh", ".bash", ".zsh", ".fish", ".command"].some((suffix) => basename.endsWith(suffix))],
	];
	const found = checks.find(([name, matches]) => matches && enabled.includes(name));
	return found?.[0] ?? null;
}

function stableRequestId(operation: SandboxOperation, matchedRule: string, policyRevision: number): string {
	const hash = createHash("sha256");
	hash.update(stableOperationString(operation));
	hash.update("\0");
	hash.update(matchedRule);
	hash.update("\0");
	hash.update(String(policyRevision));
	return `sandbox-${hash.digest("hex").slice(0, 24)}`;
}

function stableOperationString(operation: SandboxOperation): string {
	if (operation.kind === "fs.write")
		return `${operation.kind}:${operation.path}:${Buffer.byteLength(operation.content)}`;
	if (operation.kind === "process.spawn")
		return `${operation.kind}:${operation.binary}:${operation.args.join("\0")}:${operation.cwd}`;
	return Object.entries(operation)
		.map(([key, value]) => `${key}=${String(value)}`)
		.sort()
		.join(";");
}

function sanitizePath(path: string): string {
	const home = process.env.HOME;
	if (home !== undefined && path === home) return "~";
	if (home !== undefined && path.startsWith(`${home}${sep}`)) return `~${path.slice(home.length)}`;
	return path;
}

function sanitizeUrl(target: string): string {
	const parsed = parseUrl(target);
	if (parsed === null) return target;
	return `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
}

function deny(
	effectivePolicy: EffectivePolicy,
	code: "permission_denied",
	policyArea: "file.read" | "file.write" | "network" | "process" | "env" | "backend",
	operation: string,
	sanitizedTarget: string,
	matchedRule: string,
	remediation: string,
): Decision {
	return {
		kind: "deny",
		block: createBlock({
			version: 1,
			code,
			policyArea,
			operation,
			sanitizedTarget,
			matchedRule,
			backend: effectivePolicy.backend.kind,
			policyHash: effectivePolicy.desiredPolicyHash,
			policyRevision: effectivePolicy.policyRevision,
			remediation,
		}),
	};
}

function denyMagicLink(effectivePolicy: EffectivePolicy, operation: string, sanitizedTarget: string): Decision {
	return {
		kind: "deny",
		block: createBlock({
			version: 1,
			code: "magic_link_denied",
			policyArea: "file.read",
			operation,
			sanitizedTarget,
			matchedRule: "file.denyMagicLinks=true",
			backend: effectivePolicy.backend.kind,
			policyHash: effectivePolicy.desiredPolicyHash,
			policyRevision: effectivePolicy.policyRevision,
			remediation: "Use a normal filesystem path; /proc/self/fd magic links are blocked.",
			pathEvidence: { kind: "magic-link", path: sanitizedTarget },
		}),
	};
}

function denyCapability(
	effectivePolicy: EffectivePolicy,
	operation: string,
	sanitizedTarget: string,
	matchedRule: string,
): Decision {
	return {
		kind: "deny",
		block: createBlock({
			version: 1,
			code: "capability_missing",
			policyArea: "network",
			operation,
			sanitizedTarget,
			matchedRule,
			backend: effectivePolicy.backend.kind,
			policyHash: effectivePolicy.desiredPolicyHash,
			policyRevision: effectivePolicy.policyRevision,
			remediation: "Switch to a backend with networkGateway support or change network policy to deny/allow-all.",
			control: "networkAllowlist",
		}),
	};
}
