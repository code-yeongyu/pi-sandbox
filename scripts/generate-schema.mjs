#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";

const stringArray = { type: "array", items: { type: "string" }, default: [] };
const networkPolicy = {
	oneOf: [
		{
			type: "object",
			required: ["mode"],
			additionalProperties: false,
			properties: { mode: { const: "deny", default: "deny" } },
		},
		{
			type: "object",
			required: ["mode"],
			additionalProperties: false,
			properties: { mode: { const: "allow-all" } },
		},
		{
			type: "object",
			required: ["mode"],
			additionalProperties: false,
			properties: {
				mode: { const: "restricted" },
				default: { enum: ["deny", "allow"], default: "deny" },
				allowDomains: stringArray,
				denyDomains: stringArray,
				allowUrlPrefixes: stringArray,
				allowPorts: { type: "array", items: { type: "integer", minimum: 0 }, default: [] },
				allowCidrs: stringArray,
				denyPrivateNetworks: { type: "boolean", default: true },
				denyMetadata: { type: "boolean", default: true },
				allowUnixSockets: { type: "boolean", default: false },
				scrubProxyEnv: { type: "boolean", default: true },
				dns: {
					oneOf: [
						{ const: "deny" },
						{ const: "system" },
						{
							type: "object",
							additionalProperties: false,
							properties: { servers: stringArray },
						},
					],
					default: "deny",
				},
			},
		},
	],
};

const sandboxMount = {
	type: "object",
	required: ["hostPath", "sandboxPath"],
	additionalProperties: false,
	properties: {
		hostPath: { type: "string" },
		sandboxPath: { type: "string" },
		mode: { enum: ["readonly", "readwrite"], default: "readonly" },
		persist: { enum: ["ephemeral", "host"], default: "host" },
	},
};

const backendConfig = {
	oneOf: [
		{ type: "object", required: ["kind"], additionalProperties: false, properties: { kind: { const: "auto" } } },
		{
			type: "object",
			required: ["kind", "platform", "mechanism"],
			additionalProperties: false,
			properties: {
				kind: { const: "native" },
				platform: { const: "darwin" },
				mechanism: { const: "sandbox-exec" },
			},
		},
		{
			type: "object",
			required: ["kind", "platform", "mechanism"],
			additionalProperties: false,
			properties: { kind: { const: "native" }, platform: { const: "linux" }, mechanism: { const: "bwrap" } },
		},
		{
			type: "object",
			required: ["kind"],
			additionalProperties: false,
			properties: {
				kind: { const: "docker" },
				image: { type: "string", default: "node:22-alpine" },
				networkMode: { enum: ["none", "bridge", "host"], default: "none" },
				readonlyRootfs: { type: "boolean", default: true },
				mounts: { type: "array", items: sandboxMount, default: [] },
				pullPolicy: { enum: ["always", "if-missing", "never"], default: "if-missing" },
				memoryMb: { type: "integer", minimum: 1 },
				cpuQuota: { type: "integer", minimum: 1 },
				capDrop: { ...stringArray, default: ["ALL"] },
				securityOpt: { ...stringArray, default: ["no-new-privileges"] },
				tmpfs: stringArray,
			},
		},
		{
			type: "object",
			required: ["kind"],
			additionalProperties: false,
			properties: {
				kind: { const: "justbash" },
				fs: { enum: ["memory", "overlay", "read-write-root-locked"], default: "memory" },
				allowedBinaries: stringArray,
				network: networkPolicy,
				customCommands: { type: "object", additionalProperties: true },
				executionLimits: {
					type: "object",
					additionalProperties: false,
					properties: {
						maxOutputBytes: { type: "integer", minimum: 0, default: 1048576 },
						maxRuntimeMs: { type: "integer", minimum: 0, default: 30000 },
					},
				},
			},
		},
		{
			type: "object",
			required: ["kind"],
			additionalProperties: false,
			properties: {
				kind: { const: "qemu" },
				assets: { type: "object", additionalProperties: true },
				cpus: { type: "integer", minimum: 1, default: 1 },
				memoryMb: { type: "integer", minimum: 1, default: 512 },
				shareMode: { enum: ["virtiofs-readonly", "virtiofs-readwrite", "9p-readonly", "9p-readwrite"] },
				network: { enum: ["none", "hostfwd"], default: "none" },
				snapshot: { type: "boolean", default: true },
			},
		},
		{
			type: "object",
			required: ["kind", "host", "username", "auth", "hostVerification", "remoteRoot"],
			additionalProperties: false,
			properties: {
				kind: { const: "ssh" },
				host: { type: "string" },
				port: { type: "integer", minimum: 1, default: 22 },
				username: { type: "string" },
				auth: { type: "object", required: ["kind"], properties: { kind: { type: "string" } }, additionalProperties: true },
				hostVerification: {
					type: "object",
					required: ["strict"],
					additionalProperties: false,
					properties: {
						strict: { type: "boolean" },
						hostHash: { type: "string" },
						knownHostsPath: { type: "string" },
					},
				},
				remoteRoot: { type: "string" },
				proxyJump: { type: "array", items: { type: "object" }, default: [] },
			},
		},
	],
};

const schema = {
	$schema: "http://json-schema.org/draft-07/schema#",
	$id: "https://github.com/code-yeongyu/pi-sandbox/schema/sandbox.schema.json",
	title: "pi-sandbox configuration",
	type: "object",
	additionalProperties: false,
	properties: {
		backend: backendConfig,
		fallbackBackends: { type: "array", items: { enum: ["native", "docker", "justbash", "qemu", "ssh"] }, default: [] },
		backendMissing: { enum: ["fail", "prompt", "disabled-by-user"], default: "prompt" },
		network: networkPolicy,
		file: {
			type: "object",
			additionalProperties: false,
			properties: {
				defaultRead: { enum: ["deny", "allow"], default: "deny" },
				defaultWrite: { enum: ["deny", "allow"], default: "deny" },
				roots: {
					type: "array",
					items: {
						type: "object",
						required: ["path"],
						additionalProperties: false,
						properties: {
							path: { type: "string" },
							read: { type: "boolean", default: true },
							write: { type: "boolean", default: false },
							create: { type: "boolean", default: false },
							delete: { type: "boolean", default: false },
							persist: { enum: ["ephemeral", "host"], default: "ephemeral" },
							followSymlinks: { type: "boolean", default: false },
						},
					},
					default: [],
				},
				denySpecialPaths: { ...stringArray, default: ["/proc", "/sys", "/dev"] },
				denyMagicLinks: { type: "boolean", default: true },
				highRiskWriteClasses: { type: "array", items: { enum: ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"] } },
				maxReadBytes: { type: "integer", minimum: 0, default: 10485760 },
			},
		},
		process: {
			type: "object",
			additionalProperties: false,
			properties: {
				isolation: { type: "boolean", default: true },
				gitHooks: { enum: ["deny", "allow", "prompt"], default: "prompt" },
				seccompProfile: { type: "string" },
				capDrop: stringArray,
			},
		},
		env: { type: "object", additionalProperties: false },
		approvals: { type: "object", additionalProperties: false },
		tui: { type: "object", additionalProperties: false },
		agentAwareness: { type: "object", additionalProperties: false },
		audit: { type: "object", additionalProperties: false },
	},
};

const outputPath = resolve("schema", "sandbox.schema.json");
await mkdir(dirname(outputPath), { recursive: true });
await writeFile(outputPath, `${JSON.stringify(schema, null, "\t")}\n`);
console.log(`Wrote ${outputPath}`);
