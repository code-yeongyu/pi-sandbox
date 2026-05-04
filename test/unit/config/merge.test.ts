import { describe, expect, it } from "vitest";

import { type ConfigLayer, mergeConfigs } from "../../../src/config/merge.js";
import type { SandboxRawConfig } from "../../../src/config/schema.js";

function layer(name: ConfigLayer["name"], config: SandboxRawConfig): ConfigLayer {
	return { name, config };
}

function freezeConfig(config: SandboxRawConfig): SandboxRawConfig {
	Object.freeze(config);
	for (const value of Object.values(config)) {
		if (typeof value === "object" && value !== null) Object.freeze(value);
	}
	return config;
}

describe("mergeConfigs", () => {
	it("#given no layers #when merged #then empty config is returned", () => {
		expect(mergeConfigs([])).toEqual({});
	});

	it("#given empty layer #when merged #then empty config is returned", () => {
		expect(mergeConfigs([layer("global", {})])).toEqual({});
	});

	it("#given scalar backendMissing #when project overrides global #then later wins", () => {
		const merged = mergeConfigs([
			layer("global", { backendMissing: "prompt" }),
			layer("project", { backendMissing: "fail" }),
		]);

		expect(merged.backendMissing).toBe("fail");
	});

	it("#given session scalar #when merged after project #then session wins", () => {
		const merged = mergeConfigs([
			layer("project", { process: { isolation: true, gitHooks: "deny", capDrop: [] } }),
			layer("session", { process: { isolation: false, gitHooks: "allow", capDrop: ["CAP_SYS_PTRACE"] } }),
		]);

		expect(merged.process?.gitHooks).toBe("allow");
		expect(merged.process?.isolation).toBe(false);
	});

	it("#given allow and deny domains #when merged #then deny removes allow case-insensitively", () => {
		const merged = mergeConfigs([
			layer("global", {
				network: { mode: "restricted", allowDomains: ["Example.com"], denyDomains: [] },
			}),
			layer("project", { network: { mode: "restricted", denyDomains: ["example.COM"] } }),
		]);

		expect(merged.network?.mode).toBe("restricted");
		if (merged.network?.mode !== "restricted") return;
		expect(merged.network.allowDomains).toEqual([]);
		expect(merged.network.denyDomains).toEqual(["example.COM"]);
	});

	it("#given duplicate allow domains #when merged #then domain dedup is case-insensitive", () => {
		const merged = mergeConfigs([
			layer("global", { network: { mode: "restricted", allowDomains: ["Example.com"] } }),
			layer("project", { network: { mode: "restricted", allowDomains: ["example.com"] } }),
		]);

		if (merged.network?.mode !== "restricted") return;
		expect(merged.network.allowDomains).toEqual(["Example.com"]);
	});

	it("#given url prefixes #when merged #then exact duplicate is removed", () => {
		const merged = mergeConfigs([
			layer("global", { network: { mode: "restricted", allowUrlPrefixes: ["https://a"] } }),
			layer("project", { network: { mode: "restricted", allowUrlPrefixes: ["https://a", "https://b"] } }),
		]);

		if (merged.network?.mode !== "restricted") return;
		expect(merged.network.allowUrlPrefixes).toEqual(["https://a", "https://b"]);
	});

	it("#given ports #when merged #then duplicate ports are removed", () => {
		const merged = mergeConfigs([
			layer("global", { network: { mode: "restricted", allowPorts: [443] } }),
			layer("project", { network: { mode: "restricted", allowPorts: [443, 8443] } }),
		]);

		if (merged.network?.mode !== "restricted") return;
		expect(merged.network.allowPorts).toEqual([443, 8443]);
	});

	it("#given conflicting network mode #when later layer differs #then later network wins", () => {
		const merged = mergeConfigs([
			layer("global", { network: { mode: "allow-all" } }),
			layer("project", { network: { mode: "deny" } }),
		]);

		expect(merged.network).toEqual({ mode: "deny" });
	});

	it("#given duplicate roots #when merged #then roots dedupe by canonical path with later value", () => {
		const merged = mergeConfigs([
			layer("global", {
				file: {
					roots: [
						{
							path: "/tmp/a",
							read: true,
							write: false,
							create: false,
							delete: false,
							persist: "host",
							followSymlinks: false,
						},
					],
				},
			}),
			layer("project", {
				file: {
					roots: [
						{
							path: "/tmp/./a",
							read: true,
							write: true,
							create: false,
							delete: false,
							persist: "host",
							followSymlinks: false,
						},
					],
				},
			}),
		]);

		expect(merged.file?.roots).toHaveLength(1);
		expect(merged.file?.roots?.[0]?.write).toBe(true);
	});

	it("#given denied path #when root is inside deny path #then root is removed", () => {
		const merged = mergeConfigs([
			layer("global", {
				file: {
					roots: [
						{
							path: "/tmp/secrets/app",
							read: true,
							write: false,
							create: false,
							delete: false,
							persist: "host",
							followSymlinks: false,
						},
					],
				},
			}),
			layer("project", { file: { denySpecialPaths: ["/tmp/secrets"] } }),
		]);

		expect(merged.file?.roots).toEqual([]);
	});

	it("#given deny special paths #when merged #then paths are unioned", () => {
		const merged = mergeConfigs([
			layer("global", { file: { denySpecialPaths: ["/proc"] } }),
			layer("project", { file: { denySpecialPaths: ["/sys", "/proc"] } }),
		]);

		expect(merged.file?.denySpecialPaths).toEqual(["/proc", "/sys"]);
	});

	it("#given high-risk classes #when merged #then classes are unioned", () => {
		const merged = mergeConfigs([
			layer("global", { file: { highRiskWriteClasses: ["dotenv"] } }),
			layer("project", { file: { highRiskWriteClasses: ["dotenv", "ssh-key"] } }),
		]);

		expect(merged.file?.highRiskWriteClasses).toEqual(["dotenv", "ssh-key"]);
	});

	it("#given env arrays #when merged #then env allow and deny patterns are deduped", () => {
		const merged = mergeConfigs([
			layer("global", { env: { allowlist: ["PATH"], denyPatterns: ["*_TOKEN"] } }),
			layer("project", { env: { allowlist: ["PATH", "TERM"], denyPatterns: ["*_TOKEN", "SSH_AUTH_SOCK"] } }),
		]);

		expect(merged.env?.allowlist).toEqual(["PATH", "TERM"]);
		expect(merged.env?.denyPatterns).toEqual(["*_TOKEN", "SSH_AUTH_SOCK"]);
	});

	it("#given fallback backends #when merged #then fallback list is deduped", () => {
		const merged = mergeConfigs([
			layer("global", { fallbackBackends: ["docker", "justbash"] }),
			layer("project", { fallbackBackends: ["docker", "ssh"] }),
		]);

		expect(merged.fallbackBackends).toEqual(["docker", "justbash", "ssh"]);
	});

	it("#given docker mounts #when merged #then mounts dedupe by host and sandbox path", () => {
		const merged = mergeConfigs([
			layer("global", {
				backend: {
					kind: "docker",
					mounts: [{ hostPath: "/tmp/a", sandboxPath: "/work", mode: "readonly", persist: "host" }],
				},
			}),
			layer("project", {
				backend: {
					kind: "docker",
					mounts: [{ hostPath: "/tmp/./a", sandboxPath: "/work", mode: "readwrite", persist: "host" }],
				},
			}),
		]);

		expect(merged.backend?.kind).toBe("docker");
		if (merged.backend?.kind !== "docker") return;
		expect(merged.backend.mounts).toHaveLength(1);
		expect(merged.backend.mounts?.[0]?.mode).toBe("readwrite");
	});

	it("#given conflicting backend kinds #when merged #then later backend wins", () => {
		const merged = mergeConfigs([
			layer("global", { backend: { kind: "docker" } }),
			layer("project", { backend: { kind: "justbash" } }),
		]);

		expect(merged.backend).toEqual({ kind: "justbash" });
	});

	it("#given frozen inputs #when merged #then inputs are not mutated", () => {
		const global = freezeConfig({ network: { mode: "restricted", allowDomains: ["a.test"] } });
		const project = freezeConfig({ network: { mode: "restricted", denyDomains: ["b.test"] } });

		mergeConfigs([layer("global", global), layer("project", project)]);

		expect(global).toEqual({ network: { mode: "restricted", allowDomains: ["a.test"] } });
		expect(project).toEqual({ network: { mode: "restricted", denyDomains: ["b.test"] } });
	});

	it("#given project and session roots #when merged #then session can override project root", () => {
		const merged = mergeConfigs([
			layer("project", {
				file: {
					roots: [
						{
							path: "/tmp/project",
							read: true,
							write: false,
							create: false,
							delete: false,
							persist: "host",
							followSymlinks: false,
						},
					],
				},
			}),
			layer("session", {
				file: {
					roots: [
						{
							path: "/tmp/project",
							read: true,
							write: true,
							create: true,
							delete: false,
							persist: "host",
							followSymlinks: false,
						},
					],
				},
			}),
		]);

		expect(merged.file?.roots?.[0]?.write).toBe(true);
		expect(merged.file?.roots?.[0]?.create).toBe(true);
	});
});
