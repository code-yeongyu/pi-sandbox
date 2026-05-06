import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { parseGrantArgs, persistProjectGrant } from "../../../src/commands/grants.js";

describe("grant command helpers", () => {
	it("#given grant args with whitespace target #when parsed #then typed class and full target are preserved", () => {
		expect(parseGrantArgs(" file.write   /tmp/path with spaces ")).toEqual({
			class: "file.write",
			target: "/tmp/path with spaces",
		});
	});

	it("#given port grants #when parsed #then only numeric port range is accepted", () => {
		expect(parseGrantArgs("port 443")).toEqual({ class: "port", target: "443" });
		expect(parseGrantArgs("port 65536")).toBeNull();
		expect(parseGrantArgs("port not-a-port")).toBeNull();
	});

	it("#given existing grant #when persisted with opposite action #then file contains replacement not duplicate", async () => {
		const directory = await mkdtemp(join(tmpdir(), "pi-sandbox-grants-"));
		const grant = { class: "domain", target: "example.com" } as const;

		const allowed = await persistProjectGrant(directory, grant, "allow");
		const denied = await persistProjectGrant(directory, grant, "deny");

		expect(allowed.ok).toBe(true);
		expect(denied.ok).toBe(true);
		const content = await readFile(join(directory, ".pi", "sandbox.grants.jsonc"), "utf8");
		expect(content).toContain('"action": "deny"');
		expect(content).not.toContain('"action": "allow"');
		expect(content.match(/typed:domain:example.com/gu)).toHaveLength(1);
	});
});
