import { z } from "zod";

import type { DesiredPolicy, SshBackendConfig } from "../policy/desired.js";

export type Result<TValue, TError> =
	| { readonly ok: true; readonly value: TValue }
	| { readonly ok: false; readonly error: TError };

export type SandboxConfigParseIssue = {
	readonly path: ReadonlyArray<string | number>;
	readonly message: string;
	readonly code: string;
};

export type SandboxConfigParseError = {
	readonly issues: ReadonlyArray<SandboxConfigParseIssue>;
};

export const SandboxConfigTopLevelKeys = new Set([
	"network",
	"file",
	"process",
	"env",
	"approvals",
	"tui",
	"agentAwareness",
	"audit",
	"backend",
	"fallbackBackends",
	"backendUnavailable",
]);

const backendKinds = ["native", "docker", "justbash", "qemu", "ssh"] as const;
const highRiskWriteClasses = ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"] as const;

const NetworkPolicySchema = z.discriminatedUnion("mode", [
	z.object({ mode: z.literal("deny").default("deny") }).strict(),
	z.object({ mode: z.literal("allow-all") }).strict(),
	z
		.object({
			mode: z.literal("restricted"),
			default: z.enum(["deny", "allow"]).default("deny"),
			allowDomains: z.array(z.string()).readonly().default([]),
			denyDomains: z.array(z.string()).readonly().default([]),
			allowUrlPrefixes: z.array(z.string()).readonly().default([]),
			allowPorts: z.array(z.number().int().nonnegative()).readonly().default([]),
			allowCidrs: z.array(z.string()).readonly().default([]),
			denyPrivateNetworks: z.boolean().default(true),
			denyMetadata: z.boolean().default(true),
			allowUnixSockets: z.boolean().default(false),
			scrubProxyEnv: z.boolean().default(true),
			dns: z
				.union([
					z.literal("deny"),
					z.literal("system"),
					z.object({ servers: z.array(z.string()).readonly().default([]) }).strict(),
				])
				.default("deny"),
		})
		.strict(),
]);

const FileRootSchema = z
	.object({
		path: z.string(),
		read: z.boolean().default(true),
		write: z.boolean().default(false),
		create: z.boolean().default(false),
		delete: z.boolean().default(false),
		persist: z.enum(["ephemeral", "host"]).default("ephemeral"),
		followSymlinks: z.boolean().default(false),
	})
	.strict();

const FilePolicySchema = z
	.object({
		defaultRead: z.enum(["deny", "allow"]).default("deny"),
		defaultWrite: z.enum(["deny", "allow"]).default("deny"),
		roots: z.array(FileRootSchema).readonly().default([]),
		denySpecialPaths: z.array(z.string()).readonly().default(["/proc", "/sys", "/dev"]),
		denyMagicLinks: z.boolean().default(true),
		highRiskWriteClasses: z
			.array(z.enum(highRiskWriteClasses))
			.readonly()
			.default([...highRiskWriteClasses]),
		maxReadBytes: z
			.number()
			.int()
			.nonnegative()
			.default(10 * 1024 * 1024),
	})
	.strict();

const ProcessPolicySchema = z
	.object({
		isolation: z.boolean().default(true),
		gitHooks: z.enum(["deny", "allow", "prompt"]).default("prompt"),
		seccompProfile: z.string().optional(),
		capDrop: z.array(z.string()).readonly().default([]),
	})
	.strict();

const EnvPolicySchema = z
	.object({
		clearenv: z.boolean().default(true),
		allowlist: z.array(z.string()).readonly().default(["PATH", "HOME", "TERM", "LANG", "LC_ALL"]),
		denyPatterns: z
			.array(z.string())
			.readonly()
			.default(["*_KEY", "*_TOKEN", "*_SECRET", "*_PASSWORD", "SSH_AUTH_SOCK", "AWS_*", "GCP_*"]),
		scrubProxyEnv: z.boolean().default(true),
	})
	.strict();

const ApprovalConfigSchema = z
	.object({
		interactive: z.boolean().default(true),
		defaultOnNoUi: z.enum(["deny", "allow"]).default("deny"),
		rememberSession: z.boolean().default(true),
		allowProjectWrites: z.boolean().default(true),
		allowGlobalWrites: z.boolean().default(false),
		batchWindowMs: z.number().int().nonnegative().default(250),
	})
	.strict();

const TuiConfigSchema = z
	.object({
		statusLine: z.boolean().default(true),
		detailsWidget: z.enum(["off", "always", "on-change", "on-block"]).default("on-block"),
		promptStyle: z.enum(["compact", "verbose"]).default("compact"),
	})
	.strict();

const AgentAwarenessConfigSchema = z
	.object({
		injectSystemPrompt: z.boolean().default(true),
		decorateBlockedToolResults: z.boolean().default(true),
		includeAllowedPaths: z.boolean().default(true),
		includeAllowedDomains: z.boolean().default(false),
		includeAllowedBinaries: z.boolean().default(true),
	})
	.strict();

const AuditConfigSchema = z
	.object({
		enabled: z.boolean().default(true),
		path: z.string().default(".pi/sandbox-audit.jsonl"),
		includeToolArgs: z.enum(["raw", "redacted", "omit"]).default("redacted"),
	})
	.strict();

const SandboxMountSchema = z
	.object({
		hostPath: z.string(),
		sandboxPath: z.string(),
		mode: z.enum(["readonly", "readwrite"]).default("readonly"),
		persist: z.enum(["ephemeral", "host"]).default("host"),
	})
	.strict();

const DockerBackendConfigSchema = z
	.object({
		kind: z.literal("docker"),
		image: z.string().default("node:22-alpine"),
		networkMode: z.enum(["none", "bridge", "host"]).default("none"),
		readonlyRootfs: z.boolean().default(true),
		mounts: z.array(SandboxMountSchema).readonly().default([]),
		pullPolicy: z.enum(["always", "if-missing", "never"]).default("if-missing"),
		memoryMb: z.number().int().positive().optional(),
		cpuQuota: z.number().int().positive().optional(),
		capDrop: z.array(z.string()).readonly().default(["ALL"]),
		securityOpt: z.array(z.string()).readonly().default(["no-new-privileges"]),
		tmpfs: z.array(z.string()).readonly().default([]),
	})
	.strict();

const JustbashBackendConfigSchema = z
	.object({
		kind: z.literal("justbash"),
		fs: z.enum(["memory", "overlay", "read-write-root-locked"]).default("memory"),
		allowedBinaries: z.array(z.string()).readonly().default([]),
		allowedLibraries: z.array(z.string()).readonly().default([]),
		network: NetworkPolicySchema.optional(),
		customCommands: z
			.record(
				z.string(),
				z
					.object({ description: z.string(), hostBinary: z.string(), args: z.array(z.string()).readonly() })
					.strict(),
			)
			.optional(),
		executionLimits: z
			.object({
				maxOutputBytes: z
					.number()
					.int()
					.nonnegative()
					.default(1024 * 1024),
				maxRuntimeMs: z.number().int().nonnegative().default(30_000),
			})
			.strict()
			.default({ maxOutputBytes: 1024 * 1024, maxRuntimeMs: 30_000 }),
	})
	.strict();

const NativeBackendConfigSchema = z.discriminatedUnion("platform", [
	z
		.object({ kind: z.literal("native"), platform: z.literal("darwin"), mechanism: z.literal("sandbox-exec") })
		.strict(),
	z
		.object({
			kind: z.literal("native"),
			platform: z.literal("linux"),
			mechanism: z.enum(["bwrap", "landlock-experimental"]),
		})
		.strict(),
	z
		.object({
			kind: z.literal("native"),
			platform: z.literal("win32"),
			mechanism: z.enum(["appcontainer", "wsl2-bwrap"]),
		})
		.strict(),
]);

const QemuBackendConfigSchema = z
	.object({
		kind: z.literal("qemu"),
		assets: z
			.discriminatedUnion("kind", [
				z.object({ kind: z.literal("smoke"), fixtureName: z.string(), checksumSha256: z.string() }).strict(),
				z
					.object({
						kind: z.literal("user"),
						kernelPath: z.string(),
						initrdPath: z.string(),
						rootImagePath: z.string().optional(),
					})
					.strict(),
			])
			.default({ kind: "smoke", fixtureName: "default", checksumSha256: "unset" }),
		cpus: z.number().int().positive().default(1),
		memoryMb: z.number().int().positive().default(512),
		shareMode: z
			.enum(["virtiofs-readonly", "virtiofs-readwrite", "9p-readonly", "9p-readwrite"])
			.default("9p-readonly"),
		network: z.enum(["none", "hostfwd"]).default("none"),
		snapshot: z.boolean().default(true),
	})
	.strict();

const SshAuthConfigSchema = z.discriminatedUnion("kind", [
	z.object({ kind: z.literal("privateKey"), keyPath: z.string(), passphrase: z.string().optional() }).strict(),
	z.object({ kind: z.literal("password"), password: z.string() }).strict(),
	z.object({ kind: z.literal("agent"), sock: z.string().optional() }).strict(),
	z.object({ kind: z.literal("kbi") }).strict(),
	z.object({ kind: z.literal("hostbased") }).strict(),
]);

const SshHostVerificationConfigSchema = z
	.object({ strict: z.boolean(), hostHash: z.string().optional(), knownHostsPath: z.string().optional() })
	.strict();

const SshBackendConfigSchema: z.ZodType<SshBackendConfig> = z.lazy(() =>
	z
		.object({
			kind: z.literal("ssh"),
			host: z.string(),
			port: z.number().int().positive().default(22),
			username: z.string(),
			auth: SshAuthConfigSchema,
			hostVerification: SshHostVerificationConfigSchema,
			remoteRoot: z.string(),
			sync: z.enum(["rsync", "sftp"]).default("rsync"),
			proxyJump: z.array(SshBackendConfigSchema).readonly().default([]),
		})
		.strict(),
);

const BackendConfigSchema = z.union([
	z.object({ kind: z.literal("auto") }).strict(),
	NativeBackendConfigSchema,
	DockerBackendConfigSchema,
	JustbashBackendConfigSchema,
	QemuBackendConfigSchema,
	SshBackendConfigSchema,
]);

export const ApprovalDecisionSchema = z
	.object({
		requestId: z.string().min(1),
		action: z.enum(["allow", "deny"]),
		scope: z.enum(["once", "session", "project", "global"]),
		mutationTarget: z.enum(["project-config", "global-config"]).optional(),
	})
	.strict()
	.readonly();

export const SandboxConfigSchema = z
	.object({
		backend: BackendConfigSchema.default({ kind: "auto" }),
		fallbackBackends: z.array(z.enum(backendKinds)).readonly().default([]),
		backendUnavailable: z.enum(["fail", "prompt", "disabled-by-user"]).default("prompt"),
		network: NetworkPolicySchema.default({ mode: "deny" }),
		file: FilePolicySchema.default({
			defaultRead: "deny",
			defaultWrite: "deny",
			roots: [],
			denySpecialPaths: ["/proc", "/sys", "/dev"],
			denyMagicLinks: true,
			highRiskWriteClasses: [...highRiskWriteClasses],
			maxReadBytes: 10 * 1024 * 1024,
		}),
		process: ProcessPolicySchema.default({ isolation: true, gitHooks: "prompt", capDrop: [] }),
		env: EnvPolicySchema.default({
			clearenv: true,
			allowlist: ["PATH", "HOME", "TERM", "LANG", "LC_ALL"],
			denyPatterns: ["*_KEY", "*_TOKEN", "*_SECRET", "*_PASSWORD", "SSH_AUTH_SOCK", "AWS_*", "GCP_*"],
			scrubProxyEnv: true,
		}),
		approvals: ApprovalConfigSchema.default({
			interactive: true,
			defaultOnNoUi: "deny",
			rememberSession: true,
			allowProjectWrites: true,
			allowGlobalWrites: false,
			batchWindowMs: 250,
		}),
		tui: TuiConfigSchema.default({ statusLine: true, detailsWidget: "on-block", promptStyle: "compact" }),
		agentAwareness: AgentAwarenessConfigSchema.default({
			injectSystemPrompt: true,
			decorateBlockedToolResults: true,
			includeAllowedPaths: true,
			includeAllowedDomains: false,
			includeAllowedBinaries: true,
		}),
		audit: AuditConfigSchema.default({ enabled: true, path: ".pi/sandbox-audit.jsonl", includeToolArgs: "redacted" }),
	})
	.strict();

export const SandboxRawConfigSchema = SandboxConfigSchema.partial().strict();

export type ApprovalDecision = z.infer<typeof ApprovalDecisionSchema>;
export type SandboxConfig = DesiredPolicy;
export type SandboxRawConfig = {
	readonly [TKey in keyof DesiredPolicy]?: Partial<DesiredPolicy[TKey]> | DesiredPolicy[TKey] | undefined;
};

function issuePath(path: ReadonlyArray<PropertyKey>): ReadonlyArray<string | number> {
	return path.filter(
		(segment): segment is string | number => typeof segment === "string" || typeof segment === "number",
	);
}

export function parseSandboxConfig(value: unknown): Result<SandboxConfig, SandboxConfigParseError> {
	const result = SandboxConfigSchema.safeParse(value);
	if (result.success) return { ok: true, value: result.data };
	return {
		ok: false,
		error: {
			issues: result.error.issues.map((issue) => ({
				path: issuePath(issue.path),
				message: issue.message,
				code: issue.code,
			})),
		},
	};
}
