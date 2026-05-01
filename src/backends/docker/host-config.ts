import path from "node:path";

import type Dockerode from "dockerode";

import type { DockerBackendConfig, SandboxMount } from "../../policy/desired.js";
import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";

const WORKSPACE_PATH = "/workspace";
const DEFAULT_TMPFS = "rw,noexec,nosuid,size=512m";
const UNSAFE_EXACT_HOST_PATHS = new Set(["/", "/var/run/docker.sock", "/proc", "/sys"]);
const UNSAFE_HOST_PREFIXES = ["/var/run/", "/proc/", "/sys/", "/dev/"] as const;

export type DockerHostConfigOverrides = {
	readonly command?: readonly string[];
	readonly workingDir?: string;
	readonly env?: ReadonlyMap<string, string>;
	readonly extraBinds?: readonly string[];
};

export function buildDockerContainerOptions(
	config: DockerBackendConfig,
	sessionRoot: string,
	overrides: DockerHostConfigOverrides = {},
): Result<Dockerode.ContainerCreateOptions, SandboxFailure> {
	const binds = buildBinds(config.mounts, sessionRoot, overrides.extraBinds ?? []);
	if (!binds.ok) return binds;
	const options: Dockerode.ContainerCreateOptions = {
		Image: config.image,
		AttachStdout: true,
		AttachStderr: true,
		Tty: false,
		OpenStdin: false,
		StdinOnce: false,
		NetworkDisabled: config.networkMode === "none",
		WorkingDir: overrides.workingDir ?? WORKSPACE_PATH,
		HostConfig: {
			Privileged: false,
			CapDrop: ["ALL"],
			SecurityOpt: ["no-new-privileges"],
			ReadonlyRootfs: true,
			Tmpfs: buildTmpfs(config.tmpfs),
			NetworkMode: config.networkMode,
			AutoRemove: true,
			Binds: binds.value,
			MaskedPaths: ["/proc/kcore", "/proc/keys", "/proc/timer_list", "/proc/sched_debug"],
			ReadonlyPaths: ["/proc/asound", "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"],
			...(config.memoryMb === undefined ? {} : { Memory: config.memoryMb * 1024 * 1024 }),
			...(config.cpuQuota === undefined ? {} : { CpuQuota: config.cpuQuota }),
		},
		...(overrides.command === undefined ? {} : { Cmd: [...overrides.command] }),
		...(overrides.env === undefined ? {} : { Env: envMapToDocker(overrides.env) }),
	};
	return { ok: true, value: options };
}

function buildBinds(
	mounts: readonly SandboxMount[],
	sessionRoot: string,
	extraBinds: readonly string[],
): Result<string[], SandboxFailure> {
	const sessionBind = bindFromParts(path.resolve(sessionRoot), WORKSPACE_PATH, "readwrite");
	const configuredBinds: string[] = [sessionBind];
	for (const mount of mounts) {
		const safety = validateMount(mount.hostPath, mount.sandboxPath);
		if (!safety.ok) return safety;
		configuredBinds.push(bindFromParts(path.resolve(mount.hostPath), mount.sandboxPath, mount.mode));
	}
	for (const bind of extraBinds) {
		const safety = validateBindString(bind);
		if (!safety.ok) return safety;
		configuredBinds.push(bind);
	}
	return { ok: true, value: configuredBinds };
}

function buildTmpfs(configuredTmpfs: readonly string[]): { readonly [directory: string]: string } {
	const tmpfs: Record<string, string> = { "/tmp": DEFAULT_TMPFS };
	for (const entry of configuredTmpfs) {
		const separatorIndex = entry.indexOf(":");
		if (separatorIndex <= 0) continue;
		const directory = path.posix.normalize(entry.slice(0, separatorIndex));
		if (!directory.startsWith("/")) continue;
		tmpfs[directory] = entry.slice(separatorIndex + 1);
	}
	return tmpfs;
}

function validateMount(hostPath: string, sandboxPath: string): Result<void, SandboxFailure> {
	const resolvedHostPath = path.resolve(hostPath);
	if (isUnsafeHostPath(resolvedHostPath)) return unsafeBindFailure(resolvedHostPath);
	if (sandboxPath === "/" || sandboxPath === "/Users" || sandboxPath.startsWith("/Users/")) {
		return unsafeBindFailure(`${resolvedHostPath}:${sandboxPath}`);
	}
	return { ok: true, value: undefined };
}

function validateBindString(bind: string): Result<void, SandboxFailure> {
	const hostPath = bind.split(":")[0] ?? "";
	return validateMount(hostPath, bind.split(":")[1] ?? "/");
}

function isUnsafeHostPath(resolvedHostPath: string): boolean {
	if (UNSAFE_EXACT_HOST_PATHS.has(resolvedHostPath)) return true;
	if (resolvedHostPath === "/var/run") return true;
	if (resolvedHostPath === "/dev") return true;
	if (resolvedHostPath === "/Users") return true;
	return UNSAFE_HOST_PREFIXES.some((prefix) => resolvedHostPath.startsWith(prefix));
}

function bindFromParts(hostPath: string, sandboxPath: string, mode: SandboxMount["mode"]): string {
	const access = mode === "readonly" ? "ro" : "rw";
	return `${hostPath}:${path.posix.normalize(sandboxPath)}:${access}`;
}

function envMapToDocker(env: ReadonlyMap<string, string>): string[] {
	return [...env.entries()].map(([name, value]) => `${name}=${value}`);
}

function unsafeBindFailure(target: string): Result<void, SandboxFailure> {
	return {
		ok: false,
		error: createBlock({
			version: 1,
			code: "sandbox_backend_error",
			policyArea: "backend",
			operation: "docker.host-config",
			sanitizedTarget: target,
			matchedRule: "docker.binds.safe-host-paths",
			backend: "docker",
			policyHash: "uninitialized",
			policyRevision: 0,
			remediation:
				"Remove unsafe Docker bind mounts such as docker.sock, /var/run, /proc, /sys, /dev, /, or /Users.",
			backendMessage: `unsafe Docker bind rejected: ${target}`,
		}),
	};
}
