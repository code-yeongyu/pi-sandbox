import { describe, expect, it } from "vitest";

import type { EnvPolicy } from "../../../src/policy/desired.js";
import { buildEnv, classifySecret } from "../../../src/security/env-policy.js";

const basePolicy: EnvPolicy = {
	clearenv: true,
	allowlist: ["SAFE", "HTTP_PROXY", "PATH"],
	denyPatterns: ["*_TOKEN"],
	scrubProxyEnv: true,
};

describe("env-policy", () => {
	it("#given clearenv policy #when env is built #then non allowlisted values are omitted", () => {
		const env = buildEnv(basePolicy, { SAFE: "1", HIDDEN: "2", PATH: "/bin" });
		expect(env.get("SAFE")).toBe("1");
		expect(env.has("HIDDEN")).toBe(false);
	});

	it("#given deny pattern matching allowlisted key #when env is built #then denied key is omitted", () => {
		const env = buildEnv({ ...basePolicy, allowlist: ["API_TOKEN"] }, { API_TOKEN: "secretsecret" });
		expect(env.has("API_TOKEN")).toBe(false);
	});

	it("#given proxy scrub enabled #when env is built #then proxy variables are removed", () => {
		const env = buildEnv(basePolicy, { HTTP_PROXY: "http://proxy", PATH: "/bin" });
		expect(env.has("HTTP_PROXY")).toBe(false);
	});

	it("#given parent term absent #when env is built #then TERM defaults to dumb", () => {
		const env = buildEnv(basePolicy, { PATH: "/bin" });
		expect(env.get("TERM")).toBe("dumb");
	});

	it("#given parent lang absent #when env is built #then LANG defaults to C UTF8", () => {
		const env = buildEnv(basePolicy, { PATH: "/bin" });
		expect(env.get("LANG")).toBe("C.UTF-8");
	});

	it("#given clearenv false #when env is built #then parent values are retained unless scrubbed", () => {
		const env = buildEnv({ ...basePolicy, clearenv: false, scrubProxyEnv: false }, { EXTRA: "x", PATH: "/bin" });
		expect(env.get("EXTRA")).toBe("x");
	});

	it("#given AWS env name #when classified #then secret is detected", () => {
		expect(classifySecret("AWS_ACCESS_KEY_ID", "longvalue")).toBe(true);
	});

	it("#given normal env name #when classified #then secret is not detected", () => {
		expect(classifySecret("SAFE", "longvalue")).toBe(false);
	});
});
