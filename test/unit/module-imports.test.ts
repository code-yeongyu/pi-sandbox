import { readdir } from "node:fs/promises";
import { dirname, relative, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

import { describe, expect, it } from "vitest";

type SourceModule = {
	readonly absolutePath: string;
	readonly relativePath: string;
	readonly importSpecifier: string;
};

type ExcludedSourceModule = {
	readonly relativePath: string;
	readonly reason: string;
};

const sourceRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../src");

const excludedSourceModules = [
	{
		relativePath: "types/just-bash.d.ts",
		reason: "Type declaration file only; it has no runtime JavaScript module to import.",
	},
] satisfies readonly ExcludedSourceModule[];

async function collectSourceModules(directory: string): Promise<readonly SourceModule[]> {
	const entries = await readdir(directory, { withFileTypes: true });
	const collectedModules = await Promise.all(
		entries.map(async (entry): Promise<readonly SourceModule[]> => {
			const absolutePath = resolve(directory, entry.name);
			if (entry.isDirectory()) return collectSourceModules(absolutePath);
			if (!entry.isFile() || !entry.name.endsWith(".ts")) return [];

			const relativePath = toSourceRelativePath(absolutePath);
			return [
				{
					absolutePath,
					relativePath,
					importSpecifier: pathToFileURL(absolutePath).href,
				},
			];
		}),
	);

	return collectedModules.flat().sort((left, right) => left.relativePath.localeCompare(right.relativePath));
}

function toSourceRelativePath(absolutePath: string): string {
	return relative(sourceRoot, absolutePath).split(sep).join("/");
}

const allSourceModules = await collectSourceModules(sourceRoot);
const excludedSourceModulePaths = new Set(excludedSourceModules.map((module) => module.relativePath));
const importableSourceModules = allSourceModules.filter(
	(module) => !excludedSourceModulePaths.has(module.relativePath),
);

describe("src module dynamic imports", () => {
	it("#given documented exclusions #when test data is checked #then only non-runtime files are excluded", () => {
		const allSourceModulePaths = new Set(allSourceModules.map((module) => module.relativePath));

		for (const excludedSourceModule of excludedSourceModules) {
			expect(excludedSourceModule.reason).not.toHaveLength(0);
			expect(allSourceModulePaths.has(excludedSourceModule.relativePath)).toBe(true);
			expect(excludedSourceModule.relativePath.endsWith(".d.ts")).toBe(true);
		}
	});

	it("#given src modules #when enumerated #then runtime modules are covered", () => {
		expect(importableSourceModules.length).toBeGreaterThan(0);
		expect(importableSourceModules.some((module) => module.relativePath === "backends/qemu/adapter.ts")).toBe(true);
		expect(importableSourceModules.some((module) => module.relativePath === "index.ts")).toBe(true);
	});

	it.each(
		importableSourceModules,
	)("#given src module $relativePath #when dynamically imported #then module loads", async (sourceModule) => {
		await expect(import(sourceModule.importSpecifier)).resolves.toBeDefined();
	});
});
