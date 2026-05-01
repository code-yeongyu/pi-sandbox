// src/policy/desired.ts — DesiredPolicy types (NetworkPolicy, FilePolicy, ProcessPolicy, EnvPolicy)
import { z } from "zod";

export const BackendKindSchema = z.enum(["native", "docker", "justbash", "qemu", "ssh"]);

export const NetworkPolicySchema = z.discriminatedUnion("mode", [
	z
		.object({ mode: z.literal("deny") })
		.strict()
		.readonly(),
	z
		.object({ mode: z.literal("allow-all") })
		.strict()
		.readonly(),
	z
		.object({
			mode: z.literal("restricted"),
			default: z.enum(["deny", "allow"]),
			allowDomains: z.array(z.string()).readonly(),
			denyDomains: z.array(z.string()).readonly(),
			allowUrlPrefixes: z.array(z.string()).readonly(),
			allowPorts: z.array(z.number().int().nonnegative()).readonly(),
			allowCidrs: z.array(z.string()).readonly(),
			denyPrivateNetworks: z.boolean(),
			denyMetadata: z.boolean(),
			allowUnixSockets: z.boolean(),
			scrubProxyEnv: z.boolean(),
			dns: z.union([
				z.literal("deny"),
				z.literal("system"),
				z
					.object({ servers: z.array(z.string()).readonly() })
					.strict()
					.readonly(),
			]),
		})
		.strict()
		.readonly(),
]);
// Restricted network policy requires an active backend capability: BackendCapability.networkGateway === true.

export const FileRootSchema = z
	.object({
		path: z.string(),
		read: z.boolean(),
		write: z.boolean(),
		create: z.boolean(),
		delete: z.boolean(),
		persist: z.enum(["ephemeral", "host"]),
		followSymlinks: z.boolean(),
	})
	.strict()
	.readonly();

export const HighRiskWriteClassSchema = z.enum([
	"dotenv",
	"ssh-key",
	"git-hook",
	"shell-rc",
	"npm-script",
	"executable",
]);

export const FilePolicySchema = z
	.object({
		defaultRead: z.enum(["deny", "allow"]),
		defaultWrite: z.enum(["deny", "allow"]),
		roots: z.array(FileRootSchema).readonly(),
		denySpecialPaths: z.array(z.string()).readonly(),
		denyMagicLinks: z.boolean(),
		highRiskWriteClasses: z.array(HighRiskWriteClassSchema).readonly(),
		maxReadBytes: z.number().int().nonnegative(),
	})
	.strict()
	.readonly();

export const ProcessPolicySchema = z
	.object({
		isolation: z.boolean(),
		gitHooks: z.enum(["deny", "allow", "prompt"]),
		seccompProfile: z.string().optional(),
		capDrop: z.array(z.string()).readonly(),
	})
	.strict()
	.readonly();

export const EnvPolicySchema = z
	.object({
		clearenv: z.boolean(),
		allowlist: z.array(z.string()).readonly(),
		denyPatterns: z.array(z.string()).readonly(),
		scrubProxyEnv: z.boolean(),
	})
	.strict()
	.readonly();

export const ApprovalConfigSchema = z
	.object({
		interactive: z.boolean(),
		defaultOnNoUi: z.enum(["deny", "allow"]),
		rememberSession: z.boolean(),
		allowProjectWrites: z.boolean(),
		allowGlobalWrites: z.boolean(),
		batchWindowMs: z.number().int().nonnegative(),
	})
	.strict()
	.readonly();

export const SandboxMountSchema = z
	.object({
		hostPath: z.string(),
		sandboxPath: z.string(),
		mode: z.enum(["readonly", "readwrite"]),
		persist: z.enum(["ephemeral", "host"]),
	})
	.strict()
	.readonly();

export const JustbashCustomCommandSchema = z
	.object({
		description: z.string(),
		hostBinary: z.string(),
		args: z.array(z.string()).readonly(),
	})
	.strict()
	.readonly();

export const QemuSmokeConfigSchema = z
	.object({
		kind: z.literal("smoke"),
		fixtureName: z.string(),
		checksumSha256: z.string(),
	})
	.strict()
	.readonly();

export const QemuUserConfigSchema = z
	.object({
		kind: z.literal("user"),
		kernelPath: z.string(),
		initrdPath: z.string(),
		rootImagePath: z.string().optional(),
	})
	.strict()
	.readonly();

export const QemuAssetConfigSchema = z.discriminatedUnion("kind", [QemuSmokeConfigSchema, QemuUserConfigSchema]);

export const SshAuthConfigSchema = z.discriminatedUnion("kind", [
	z
		.object({
			kind: z.literal("privateKey"),
			keyPath: z.string(),
			passphrase: z.string().optional(),
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("password"),
			password: z.string(),
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("agent"),
			sock: z.string().optional(),
		})
		.strict()
		.readonly(),
	z
		.object({ kind: z.literal("kbi") })
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("hostbased"),
			keyPath: z.string(),
			localHostname: z.string(),
			localUsername: z.string(),
			passphrase: z.string().optional(),
		})
		.strict()
		.readonly(),
	z
		.object({ kind: z.literal("v1") })
		.strict()
		.readonly(),
]);

export const SshHostVerificationConfigSchema = z
	.object({
		strict: z.boolean(),
		hostHash: z.string().optional(),
		knownHostsPath: z.string().optional(),
	})
	.strict()
	.readonly();

export type BackendKind = z.infer<typeof BackendKindSchema>;
export type NetworkPolicy = z.infer<typeof NetworkPolicySchema>;
export type FileRoot = z.infer<typeof FileRootSchema>;
export type HighRiskWriteClass = z.infer<typeof HighRiskWriteClassSchema>;
export type FilePolicy = z.infer<typeof FilePolicySchema>;
export type ProcessPolicy = z.infer<typeof ProcessPolicySchema>;
export type EnvPolicy = z.infer<typeof EnvPolicySchema>;
export type ApprovalConfig = z.infer<typeof ApprovalConfigSchema>;
export type SandboxMount = z.infer<typeof SandboxMountSchema>;
export type JustbashCustomCommand = z.infer<typeof JustbashCustomCommandSchema>;
export type QemuSmokeConfig = z.infer<typeof QemuSmokeConfigSchema>;
export type QemuUserConfig = z.infer<typeof QemuUserConfigSchema>;
export type SshAuthConfig = z.infer<typeof SshAuthConfigSchema>;
export type SshHostVerificationConfig = z.infer<typeof SshHostVerificationConfigSchema>;

export type NativeBackendConfig =
	| { readonly kind: "native"; readonly platform: "darwin"; readonly mechanism: "sandbox-exec" }
	| { readonly kind: "native"; readonly platform: "linux"; readonly mechanism: "bwrap" | "landlock-experimental" }
	| { readonly kind: "native"; readonly platform: "win32"; readonly mechanism: "appcontainer" | "wsl2-bwrap" };

export type DockerBackendConfig = {
	readonly kind: "docker";
	readonly image: string;
	readonly networkMode: "none" | "bridge" | "host";
	readonly readonlyRootfs: boolean;
	readonly mounts: readonly SandboxMount[];
	readonly pullPolicy: "always" | "if-missing" | "never";
	readonly memoryMb?: number;
	readonly cpuQuota?: number;
	readonly capDrop: readonly string[];
	readonly securityOpt: readonly string[];
	readonly tmpfs: readonly string[];
};

export type JustbashBackendConfig = {
	readonly kind: "justbash";
	readonly fs: "memory" | "overlay" | "read-write-root-locked";
	readonly allowedBinaries: readonly string[];
	readonly allowedLibraries: readonly string[];
	readonly network?: NetworkPolicy;
	readonly customCommands?: Readonly<Record<string, JustbashCustomCommand>>;
	readonly executionLimits: { readonly maxOutputBytes: number; readonly maxRuntimeMs: number };
};

export type QemuBackendConfig = {
	readonly kind: "qemu";
	readonly assets: QemuSmokeConfig | QemuUserConfig;
	readonly cpus: number;
	readonly memoryMb: number;
	readonly shareMode: "virtiofs-readonly" | "virtiofs-readwrite" | "9p-readonly" | "9p-readwrite";
	readonly network: "none" | "hostfwd";
	readonly snapshot: boolean;
};

export type SshBackendConfig = {
	readonly kind: "ssh";
	readonly host: string;
	readonly port: number;
	readonly username: string;
	readonly auth: SshAuthConfig;
	readonly hostVerification: SshHostVerificationConfig;
	readonly remoteRoot: string;
	readonly sync: "rsync" | "sftp";
	readonly proxyJump: readonly SshBackendConfig[];
};

export type DesiredBackendConfig =
	| { readonly kind: "auto" }
	| NativeBackendConfig
	| DockerBackendConfig
	| JustbashBackendConfig
	| QemuBackendConfig
	| SshBackendConfig;

const NativeBackendConfigSchema = z.discriminatedUnion("platform", [
	z
		.object({
			kind: z.literal("native"),
			platform: z.literal("darwin"),
			mechanism: z.literal("sandbox-exec"),
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("native"),
			platform: z.literal("linux"),
			mechanism: z.enum(["bwrap", "landlock-experimental"]),
		})
		.strict()
		.readonly(),
	z
		.object({
			kind: z.literal("native"),
			platform: z.literal("win32"),
			mechanism: z.enum(["appcontainer", "wsl2-bwrap"]),
		})
		.strict()
		.readonly(),
]);

const DockerBackendConfigSchema = z
	.object({
		kind: z.literal("docker"),
		image: z.string(),
		networkMode: z.enum(["none", "bridge", "host"]),
		readonlyRootfs: z.boolean(),
		mounts: z.array(SandboxMountSchema).readonly(),
		pullPolicy: z.enum(["always", "if-missing", "never"]),
		memoryMb: z.number().int().positive().optional(),
		cpuQuota: z.number().int().positive().optional(),
		capDrop: z.array(z.string()).readonly(),
		securityOpt: z.array(z.string()).readonly(),
		tmpfs: z.array(z.string()).readonly(),
	})
	.strict()
	.readonly();

const JustbashBackendConfigSchema = z
	.object({
		kind: z.literal("justbash"),
		fs: z.enum(["memory", "overlay", "read-write-root-locked"]),
		allowedBinaries: z.array(z.string()).readonly(),
		allowedLibraries: z.array(z.string()).readonly(),
		network: NetworkPolicySchema.optional(),
		customCommands: z.record(z.string(), JustbashCustomCommandSchema).readonly().optional(),
		executionLimits: z
			.object({
				maxOutputBytes: z.number().int().nonnegative(),
				maxRuntimeMs: z.number().int().nonnegative(),
			})
			.strict()
			.readonly(),
	})
	.strict()
	.readonly();

const QemuBackendConfigSchema = z
	.object({
		kind: z.literal("qemu"),
		assets: QemuAssetConfigSchema,
		cpus: z.number().int().positive(),
		memoryMb: z.number().int().positive(),
		shareMode: z.enum(["virtiofs-readonly", "virtiofs-readwrite", "9p-readonly", "9p-readwrite"]),
		network: z.enum(["none", "hostfwd"]),
		snapshot: z.boolean(),
	})
	.strict()
	.readonly();

export const SshBackendConfigSchema: z.ZodType<SshBackendConfig> = z.lazy(() =>
	z
		.object({
			kind: z.literal("ssh"),
			host: z.string(),
			port: z.number().int().positive(),
			username: z.string(),
			auth: SshAuthConfigSchema,
			hostVerification: SshHostVerificationConfigSchema,
			remoteRoot: z.string(),
			sync: z.enum(["rsync", "sftp"]),
			proxyJump: z.array(SshBackendConfigSchema).readonly(),
		})
		.strict()
		.readonly(),
);

export const DesiredBackendConfigSchema = z.union([
	z
		.object({ kind: z.literal("auto") })
		.strict()
		.readonly(),
	NativeBackendConfigSchema,
	DockerBackendConfigSchema,
	JustbashBackendConfigSchema,
	QemuBackendConfigSchema,
	SshBackendConfigSchema,
]);

export const TuiConfigSchema = z
	.object({
		statusLine: z.boolean(),
		detailsWidget: z.enum(["off", "always", "on-change", "on-block"]),
		promptStyle: z.enum(["compact", "verbose"]),
	})
	.strict()
	.readonly();

export const AgentAwarenessConfigSchema = z
	.object({
		injectSystemPrompt: z.boolean(),
		decorateBlockedToolResults: z.boolean(),
		includeAllowedPaths: z.boolean(),
		includeAllowedDomains: z.boolean(),
		includeAllowedBinaries: z.boolean(),
	})
	.strict()
	.readonly();

export const AuditConfigSchema = z
	.object({
		enabled: z.boolean(),
		path: z.string(),
		includeToolArgs: z.enum(["raw", "redacted", "omit"]),
	})
	.strict()
	.readonly();

export const DesiredPolicySchema = z
	.object({
		backend: DesiredBackendConfigSchema,
		fallbackBackends: z.array(BackendKindSchema).readonly(),
		backendUnavailable: z.enum(["fail", "prompt", "disabled-by-user"]),
		network: NetworkPolicySchema,
		file: FilePolicySchema,
		process: ProcessPolicySchema,
		env: EnvPolicySchema,
		approvals: ApprovalConfigSchema,
		tui: TuiConfigSchema,
		agentAwareness: AgentAwarenessConfigSchema,
		audit: AuditConfigSchema,
	})
	.strict()
	.readonly();

export type TuiConfig = z.infer<typeof TuiConfigSchema>;
export type AgentAwarenessConfig = z.infer<typeof AgentAwarenessConfigSchema>;
export type AuditConfig = z.infer<typeof AuditConfigSchema>;
export type DesiredPolicy = z.infer<typeof DesiredPolicySchema>;
