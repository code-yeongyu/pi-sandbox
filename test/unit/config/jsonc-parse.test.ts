import { describe, expect, it } from "vitest";

import { modifyJsonc, parseJsonc } from "../../../src/config/jsonc-parse.js";

describe("parseJsonc", () => {
	it("#given jsonc comments #when parsed #then comments are accepted", () => {
		const result = parseJsonc('{ // comment\n "network": { "mode": "deny" }\n}');

		expect(result.ok).toBe(true);
	});

	it("#given block comments #when parsed #then comments are accepted", () => {
		const result = parseJsonc('{ /* comment */ "file": {} }');

		expect(result.ok).toBe(true);
	});

	it("#given trailing comma #when parsed #then trailing comma is accepted", () => {
		const result = parseJsonc('{ "fallbackBackends": ["docker",], }');

		expect(result.ok).toBe(true);
	});

	it("#given bom #when parsed #then bom input is accepted", () => {
		const result = parseJsonc('\uFEFF{ "network": { "mode": "deny" } }');

		expect(result.ok).toBe(true);
	});

	it("#given empty input #when parsed #then empty object is returned", () => {
		const result = parseJsonc("   \n// only comment");

		expect(result).toEqual({ ok: true, value: {} });
	});

	it("#given syntax error #when parsed #then line and column are reported", () => {
		const result = parseJsonc('{\n  "network": \n}');

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error[0]?.line).toBeGreaterThanOrEqual(2);
		expect(result.error[0]?.column).toBeGreaterThanOrEqual(1);
	});

	it("#given duplicate root key #when parsed #then duplicate is rejected", () => {
		const result = parseJsonc('{ "network": {}, "network": {} }');

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error.some((error) => error.message.includes("Duplicate"))).toBe(true);
	});

	it("#given duplicate nested key #when parsed #then duplicate is rejected", () => {
		const result = parseJsonc('{ "network": { "mode": "deny", "mode": "allow-all" } }');

		expect(result.ok).toBe(false);
	});

	it("#given unknown top-level section #when parsed with allowed keys #then section is rejected", () => {
		const result = parseJsonc('{ "grants": [] }', new Set(["network"]));

		expect(result.ok).toBe(false);
		if (result.ok) return;
		expect(result.error[0]?.message).toContain("Unknown top-level section");
	});

	it("#given known top-level section #when parsed with allowed keys #then section is accepted", () => {
		const result = parseJsonc('{ "network": { "mode": "deny" } }', new Set(["network"]));

		expect(result.ok).toBe(true);
	});

	it("#given jsonc text #when modified #then existing comments are preserved", () => {
		const text = '{\n\t// network policy\n\t"network": { "mode": "deny" }\n}\n';

		const modified = modifyJsonc(text, ["backendUnavailable"], "fail");

		expect(modified).toContain("// network policy");
		expect(modified).toContain("backendUnavailable");
	});

	it("#given jsonc text #when modified #then output parses without duplicate keys", () => {
		const modified = modifyJsonc('{\n\t"network": { "mode": "deny" }\n}\n', ["network", "mode"], "allow-all");

		const parsed = parseJsonc(modified);

		expect(parsed.ok).toBe(true);
	});
});
