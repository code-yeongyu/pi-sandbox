import path from "node:path";

import type { FilePolicy, NetworkPolicy } from "../../policy/desired.js";

export type BwrapPolicy = {
	readonly network: NetworkPolicy;
	readonly file: FilePolicy;
	readonly cwd: string;
	readonly env: ReadonlyMap<string, string>;
	readonly allowedExecutables: readonly string[];
	readonly sessionRoot: string;
};

const BASE_SYSTEM_BINDS = ["/usr", "/bin", "/sbin", "/lib", "/lib64"] as const;
const PROC_MAGIC_LINK_PATTERN = /^\/proc\/(?:self|thread-self|\d+)(?:\/|$)/;
const UNSAFE_EXACT_BIND_ROOTS = new Set(["/", "/proc", "/sys", "/dev", "/var/run"]);

export function buildBwrapArgs(policy: BwrapPolicy): readonly string[] {
	assertSafePath(policy.cwd, policy.file.denyMagicLinks, "cwd");
	assertSafePath(policy.sessionRoot, policy.file.denyMagicLinks, "sessionRoot");

	const args: string[] = ["--die-with-parent", "--unshare-pid", "--unshare-user", "--unshare-uts", "--unshare-ipc"];

	if (policy.network.mode === "deny") args.push("--unshare-net");

	args.push("--proc", "/proc", "--dev", "/dev");

	for (const systemPath of BASE_SYSTEM_BINDS) args.push("--ro-bind-try", systemPath, systemPath);

	args.push("--bind", normalizeAbsolutePath(policy.sessionRoot), normalizeAbsolutePath(policy.sessionRoot));

	for (const root of policy.file.roots) {
		assertSafePath(root.path, policy.file.denyMagicLinks, "file root");
		const normalizedRoot = normalizeAbsolutePath(root.path);
		args.push(root.write ? "--bind" : "--ro-bind", normalizedRoot, normalizedRoot);
	}

	for (const executable of policy.allowedExecutables) {
		assertSafePath(executable, policy.file.denyMagicLinks, "allowed executable");
		const normalizedExecutable = normalizeAbsolutePath(executable);
		args.push("--ro-bind-try", normalizedExecutable, normalizedExecutable);
	}

	args.push("--clearenv");
	for (const [key, value] of policy.env) args.push("--setenv", key, value);
	args.push("--chdir", normalizeAbsolutePath(policy.cwd));

	return Object.freeze(args);
}

function normalizeAbsolutePath(input: string): string {
	return path.resolve(input);
}

function assertSafePath(input: string, denyMagicLinks: boolean, label: string): void {
	const normalized = normalizeAbsolutePath(input);
	if (UNSAFE_EXACT_BIND_ROOTS.has(normalized)) {
		throw new Error(`Refusing to bind unsafe ${label} root: ${normalized}`);
	}
	if (denyMagicLinks && (normalized === "/proc" || PROC_MAGIC_LINK_PATTERN.test(normalized))) {
		throw new Error(`Refusing to bind ${label} through proc magic-link path: ${normalized}`);
	}
}
