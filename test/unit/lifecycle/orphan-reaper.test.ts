import { access, mkdir, mkdtemp, readdir, rm, utimes } from "node:fs/promises";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mockedTmpdir = vi.hoisted(() => ({ value: "" }));
const realTmpdir = vi.hoisted(() => ({ value: "" }));

vi.mock("node:os", async (importOriginal) => {
	const actual = await importOriginal<typeof import("node:os")>();
	realTmpdir.value = actual.tmpdir();
	return {
		...actual,
		tmpdir: () => mockedTmpdir.value,
	};
});

import { reapOrphans } from "../../../src/lifecycle/orphan-reaper.js";

let sandboxRoot: string;

beforeEach(async () => {
	sandboxRoot = await mkdtemp(join(realTmpdir.value, "pi-sandbox-reaper-test-"));
	mockedTmpdir.value = sandboxRoot;
});

afterEach(async () => {
	await rm(sandboxRoot, { recursive: true, force: true });
});

describe("reapOrphans", () => {
	it("#given missing sandbox root #when reaping #then it exits without throwing", async () => {
		// given
		const missingRoot = join(sandboxRoot, "pi-sandbox");
		await rm(missingRoot, { recursive: true, force: true });

		// when / then
		await expect(reapOrphans(new Date("2026-05-06T12:00:00.000Z"))).resolves.toBeUndefined();
	});

	it("#given stale recent and non-session entries #when reaping #then only stale session roots are removed", async () => {
		// given
		const root = join(sandboxRoot, "pi-sandbox");
		const staleSession = join(root, "sess-stale");
		const recentSession = join(root, "sess-recent");
		const unrelatedEntry = join(root, "cache-stale");
		await Promise.all([
			mkdir(staleSession, { recursive: true }),
			mkdir(recentSession, { recursive: true }),
			mkdir(unrelatedEntry, { recursive: true }),
		]);
		await Promise.all([
			setModifiedTime(staleSession, "2026-05-05T23:00:00.000Z"),
			setModifiedTime(recentSession, "2026-05-06T06:00:00.000Z"),
			setModifiedTime(unrelatedEntry, "2026-05-05T23:00:00.000Z"),
		]);

		// when
		await reapOrphans(new Date("2026-05-06T12:00:00.000Z"));

		// then
		await expect(access(staleSession)).rejects.toThrow();
		await expect(access(recentSession)).resolves.toBeUndefined();
		await expect(access(unrelatedEntry)).resolves.toBeUndefined();
		expect(await readdir(root)).toEqual(["cache-stale", "sess-recent"]);
	});
});

async function setModifiedTime(filePath: string, isoDate: string): Promise<void> {
	const date = new Date(isoDate);
	await utimes(filePath, date, date);
}
