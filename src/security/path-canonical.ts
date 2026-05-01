import type { Stats } from "node:fs";
import { lstat, readlink, realpath } from "node:fs/promises";
import { dirname, isAbsolute, resolve } from "node:path";

import type { PathMappingError } from "../sandbox/path-mapper.js";
import type { Result } from "./failure.js";

export type CanonicalizationResult = {
	readonly canonical: string;
	readonly followedSymlinks: boolean;
	readonly residualToctoeRisk: boolean;
};

export async function canonicalizePath(
	path: string,
	options: { readonly followSymlinks: boolean },
): Promise<Result<CanonicalizationResult, PathMappingError>> {
	const absolutePath = isAbsolute(path) ? path : resolve(path);
	if (options.followSymlinks) return canonicalizeFollowingSymlinks(absolutePath);
	return canonicalizeWithoutFollowingSymlinks(absolutePath);
}

async function canonicalizeFollowingSymlinks(path: string): Promise<Result<CanonicalizationResult, PathMappingError>> {
	try {
		return { ok: true, value: { canonical: await realpath(path), followedSymlinks: true, residualToctoeRisk: true } };
	} catch {
		return { ok: false, error: { kind: "non-representable", hostPath: path, reason: "realpath-failed" } };
	}
}

async function canonicalizeWithoutFollowingSymlinks(
	path: string,
): Promise<Result<CanonicalizationResult, PathMappingError>> {
	let stat: Stats;
	try {
		stat = await lstat(path);
	} catch {
		return { ok: false, error: { kind: "non-representable", hostPath: path, reason: "path-missing" } };
	}
	if (stat.isSymbolicLink()) {
		let target: string;
		try {
			target = await readlink(path);
		} catch {
			return { ok: false, error: { kind: "non-representable", hostPath: path, reason: "readlink-failed" } };
		}
		const resolvedTarget = resolve(dirname(path), target);
		if (resolvedTarget === path) return { ok: false, error: { kind: "symlink-loop", hostPath: path } };
		return {
			ok: false,
			error: { kind: "non-representable", hostPath: path, reason: `symlink-not-allowed:${resolvedTarget}` },
		};
	}
	return { ok: true, value: { canonical: await realpath(path), followedSymlinks: false, residualToctoeRisk: true } };
}
