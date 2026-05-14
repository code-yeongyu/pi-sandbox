import type { FilePolicy, NetworkPolicy } from "../../policy/desired.js";

export type DarwinSbplPolicy = {
	readonly network: NetworkPolicy;
	readonly file: FilePolicy;
	readonly cwd: string;
	readonly allowedExecutables: readonly string[];
};

export function generateSbplProfile(policy: DarwinSbplPolicy): string {
	const lines = [
		"(version 1)",
		"(deny default)",
		"(allow process-fork)",
		"(allow signal (target self))",
		platformReadRule(),
		"(allow file-read-metadata)",
	];

	const rootsByPath = new Map(policy.file.roots.map((entry) => [entry.path, entry]));
	for (const root of dedupe([policy.cwd, ...rootsByPath.keys()])) {
		const escapedRoot = sbplString(root);
		const matchingRoot = rootsByPath.get(root);
		const canRead = root === policy.cwd || policy.file.defaultRead === "allow" || matchingRoot?.read === true;
		const canWrite = policy.file.defaultWrite === "allow" || matchingRoot?.write === true;
		if (canRead) lines.push(`(allow file-read* (subpath ${escapedRoot}))`);
		if (canWrite) lines.push(`(allow file-write* (subpath ${escapedRoot}))`);
	}

	for (const deniedPath of policy.file.denySpecialPaths) {
		const escapedDeniedPath = sbplString(deniedPath);
		lines.push(`(deny file-read* (subpath ${escapedDeniedPath}))`);
		lines.push(`(deny file-write* (subpath ${escapedDeniedPath}))`);
	}

	for (const executable of dedupe(policy.allowedExecutables)) {
		lines.push(`(allow process-exec (literal ${sbplString(executable)}))`);
	}

	if (policy.network.mode === "allow-all") lines.push("(allow network*)");
	else lines.push("(deny network*)");

	return `${lines.join("\n")}\n`;
}

function platformReadRule(): string {
	return [
		"(allow file-read*",
		'(subpath "/usr")',
		'(subpath "/bin")',
		'(subpath "/sbin")',
		'(subpath "/System")',
		'(subpath "/private/etc"))',
	].join(" ");
}

function sbplString(value: string): string {
	return `"${value.replaceAll("\\", "\\\\").replaceAll('"', '\\"')}"`;
}

function dedupe(values: readonly string[]): readonly string[] {
	return [...new Set(values.filter((value) => value.length > 0))];
}
