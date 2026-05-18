import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { loadFullConfig, loadGlobalConfig, loadGrantsFile, loadProjectConfig } from "../../../src/config/load.js";

let testHome: string;
let testProject: string;
let originalHome: string | undefined;

async function writeText(path: string, text: string): Promise<void> {
	await mkdir(join(path, ".."), { recursive: true });
	await writeFile(path, text);
}

describe("config loading", () => {
	beforeEach(async () => {
		originalHome = process.env["HOME"];
		testHome = await mkdtemp(join(tmpdir(), "pi-sandbox-home-"));
		testProject = await mkdtemp(join(tmpdir(), "pi-sandbox-project-"));
		process.env["HOME"] = testHome;
	});

	afterEach(async () => {
		if (originalHome === undefined) delete process.env["HOME"];
		else process.env["HOME"] = originalHome;
		await rm(testHome, { recursive: true, force: true });
		await rm(testProject, { recursive: true, force: true });
	});

	it("#given missing project config #when loaded #then empty config is returned", async () => {
		const result = await loadProjectConfig(testProject);

		expect(result).toEqual({ ok: true, value: {} });
	});

	it("#given missing global config #when loaded #then empty config is returned", async () => {
		const result = await loadGlobalConfig();

		expect(result).toEqual({ ok: true, value: {} });
	});

	it("#given legacy global config #when primary missing #then legacy config is loaded", async () => {
		await writeText(join(testHome, ".pi", "agent", "sandbox.json"), '{ "backendMissing": "fail" }');

		const result = await loadGlobalConfig();

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.backendMissing).toBe("fail");
	});

	it("#given primary global config #when legacy exists #then primary config wins", async () => {
		await writeText(join(testHome, ".pi", "sandbox.json"), '{ "backendMissing": "prompt" }');
		await writeText(join(testHome, ".pi", "agent", "sandbox.json"), '{ "backendMissing": "fail" }');

		const result = await loadGlobalConfig();

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.backendMissing).toBe("prompt");
	});

	it("#given valid project config #when loaded #then project config is parsed", async () => {
		await writeText(join(testProject, ".pi", "sandbox.json"), '{ "network": { "mode": "deny" } }');

		const result = await loadProjectConfig(testProject);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.network).toEqual({ mode: "deny" });
	});

	it("#given valid global and project configs #when full config loaded #then configs are merged", async () => {
		await writeText(join(testHome, ".pi", "sandbox.json"), '{ "backendMissing": "prompt" }');
		await writeText(join(testProject, ".pi", "sandbox.json"), '{ "backendMissing": "fail" }');

		const result = await loadFullConfig(testProject);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.merged.backendMissing).toBe("fail");
	});

	it("#given parse error #when project config loaded #then parse load error is returned", async () => {
		await writeText(join(testProject, ".pi", "sandbox.json"), '{ "network": }');

		const result = await loadProjectConfig(testProject);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.kind).toBe("parse");
	});

	it("#given schema validation error #when project config loaded #then validation load error is returned", async () => {
		await writeText(join(testProject, ".pi", "sandbox.json"), '{ "network": { "mode": "bad" } }');

		const result = await loadProjectConfig(testProject);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.kind).toBe("validation");
	});

	it("#given unknown top-level section #when project config loaded #then parse load error is returned", async () => {
		await writeText(join(testProject, ".pi", "sandbox.json"), '{ "grants": [] }');

		const result = await loadProjectConfig(testProject);

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.kind).toBe("parse");
	});

	it("#given project grants file #when loaded #then grants are returned separately", async () => {
		await writeText(
			join(testProject, ".pi", "sandbox.grants.jsonc"),
			'[{ "requestId": "request-1", "action": "allow", "scope": "project" }]',
		);

		const result = await loadGrantsFile(testProject, "project");

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value[0]?.requestId).toBe("request-1");
	});

	it("#given global grants file #when full config loaded #then grants are included", async () => {
		await writeText(
			join(testHome, ".pi", "sandbox.grants.jsonc"),
			'[{ "requestId": "global-1", "action": "deny", "scope": "global" }]',
		);

		const result = await loadFullConfig(testProject);

		expect(result.ok).toBe(true);
		if (!result.ok) return;
		expect(result.value.grants[0]?.requestId).toBe("global-1");
	});
});
