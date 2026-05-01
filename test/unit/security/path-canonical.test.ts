import { mkdir, mkdtemp, realpath, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { canonicalizePath } from "../../../src/security/path-canonical.js";

async function fixtureRoot(): Promise<string> {
	return mkdtemp(join(tmpdir(), "pi-sandbox-canonical-"));
}

describe("canonicalizePath", () => {
	it("#given existing file and follow symlinks #when canonicalized #then realpath is returned", async () => {
		const root = await fixtureRoot();
		const file = join(root, "file.txt");
		await writeFile(file, "ok");
		const result = await canonicalizePath(file, { followSymlinks: true });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.residualToctoeRisk).toBe(true);
	});

	it("#given symlink and follow disabled #when canonicalized #then non representable is returned", async () => {
		const root = await fixtureRoot();
		const target = join(root, "target.txt");
		const link = join(root, "link.txt");
		await writeFile(target, "ok");
		await symlink(target, link);
		const result = await canonicalizePath(link, { followSymlinks: false });
		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.kind).toBe("non-representable");
	});

	it("#given symlink and follow enabled #when canonicalized #then target is followed", async () => {
		const root = await fixtureRoot();
		const target = join(root, "target.txt");
		const link = join(root, "link.txt");
		await writeFile(target, "ok");
		await symlink(target, link);
		const result = await canonicalizePath(link, { followSymlinks: true });
		expect(result.ok).toBe(true);
	});

	it("#given missing path #when canonicalized #then error is returned", async () => {
		const result = await canonicalizePath(join(await fixtureRoot(), "missing"), { followSymlinks: false });
		expect(result.ok).toBe(false);
	});

	it("#given nested directory #when canonicalized without following #then same path is returned", async () => {
		const root = await fixtureRoot();
		const nested = join(root, "a", "b");
		await mkdir(nested, { recursive: true });
		const result = await canonicalizePath(nested, { followSymlinks: false });
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.canonical).toBe(await realpath(nested));
	});

	it("#given relative path #when canonicalized #then absolute path is evaluated", async () => {
		const result = await canonicalizePath("package.json", { followSymlinks: false });
		expect(result.ok).toBe(true);
	});
});
