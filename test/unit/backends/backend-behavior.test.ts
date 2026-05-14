import { mkdtemp, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

import { afterEach, describe, expect, it } from "vitest";

import { createDockerBackend } from "../../../src/backends/docker/adapter.js";
import { createJustbashBackend } from "../../../src/backends/justbash/adapter.js";
import { toJustbashNetworkConfig } from "../../../src/backends/justbash/network.js";
import { generateSbplProfile } from "../../../src/backends/native/darwin-sbpl.js";
import { createQemuBackend, qemuArgs } from "../../../src/backends/qemu/adapter.js";
import { createSshBackend } from "../../../src/backends/ssh/adapter.js";
import { buildConnectConfig } from "../../../src/backends/ssh/auth.js";
import { buildHostVerifier, sha256Fingerprint } from "../../../src/backends/ssh/host-verify.js";
import type {
	DockerBackendConfig,
	EnvPolicy,
	FilePolicy,
	JustbashBackendConfig,
	NetworkPolicy,
	QemuBackendConfig,
	SshBackendConfig,
} from "../../../src/policy/desired.js";

const temporaryRoots: string[] = [];

afterEach(async () => {
	await Promise.all(temporaryRoots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("backend module no-live-infra behavior", () => {
	it("#given docker backend factory #when paths are mapped and invalid cwd execs #then behavior is enforced before Docker is touched", async () => {
		const sessionRoot = await makeTemporaryRoot("pi-sandbox-docker-unit-");
		const backend = await createDockerBackend(dockerConfig, sessionRoot);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		expect(backend.value.pathMapper.hostToSandboxPath(sessionRoot)).toEqual({ ok: true, value: "/workspace" });
		expect(backend.value.pathMapper.hostToSandboxPath(path.join(sessionRoot, "child.txt"))).toEqual({
			ok: true,
			value: "/workspace/child.txt",
		});
		expect(backend.value.pathMapper.sandboxToHostPath("/")).toEqual({ ok: true, value: sessionRoot });

		const result = await backend.value.bash?.exec("echo should-not-run", { cwd: path.dirname(sessionRoot) });

		expect(result?.ok).toBe(false);
		if (result?.ok === false) expect(result.error.code).toBe("path_mapping_failed");
	});

	it("#given qemu backend factory #when readonly and readwrite configs are created #then file facets and path failures are behavioral", async () => {
		const sessionRoot = await makeTemporaryRoot("pi-sandbox-qemu-unit-");
		const readonlyBackend = await createQemuBackend(qemuConfig("9p-readonly"), sessionRoot);
		const readwriteBackend = await createQemuBackend(qemuConfig("9p-readwrite"), sessionRoot);

		expect(readonlyBackend.ok).toBe(true);
		expect(readwriteBackend.ok).toBe(true);
		if (!readonlyBackend.ok) throw new Error(readonlyBackend.error.remediation);
		if (!readwriteBackend.ok) throw new Error(readwriteBackend.error.remediation);
		expect(readonlyBackend.value.read).toBeDefined();
		expect(readonlyBackend.value.write).toBeUndefined();
		expect(readwriteBackend.value.write).toBeDefined();
		expect(readonlyBackend.value.pathMapper.sandboxToHostPath("/workspace/nested/file.txt")).toEqual({
			ok: true,
			value: path.join(sessionRoot, "nested", "file.txt"),
		});

		const result = await readonlyBackend.value.bash?.exec("echo should-not-run", { cwd: path.dirname(sessionRoot) });

		expect(result?.ok).toBe(false);
		if (result?.ok === false) expect(result.error.code).toBe("path_mapping_failed");
	});

	it("#given qemu hostfwd config #when args are built #then user networking is explicit without requiring QEMU", () => {
		const result = qemuArgs({
			config: qemuConfig("9p-readwrite", "hostfwd"),
			sessionRoot: "/tmp/pi-sandbox-qemu",
			assets: { kernelPath: "/tmp/kernel", initrdPath: "/tmp/initrd" },
		});

		expect(result.ok).toBe(true);
		if (!result.ok) throw new Error(result.error.remediation);
		expect(result.value).toContain("-netdev");
		expect(result.value).toContain("user,id=net0");
		expect(result.value).not.toContain("-nic");
		expect(result.value).not.toContain("none");
	});

	it("#given ssh backend factory #when paths and non-live probes are exercised #then remoteRoot mapping and transport limits are explicit", async () => {
		const sessionRoot = await makeTemporaryRoot("pi-sandbox-ssh-unit-");
		const backend = await createSshBackend(sshConfig, sessionRoot);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		expect(backend.value.pathMapper.hostToSandboxPath(path.join(sessionRoot, "nested", "file.txt"))).toEqual({
			ok: true,
			value: "/remote/root/nested/file.txt",
		});
		expect(backend.value.pathMapper.sandboxToHostPath("nested/file.txt")).toEqual({
			ok: true,
			value: path.join(sessionRoot, "nested", "file.txt"),
		});

		const probes = await backend.value.lifecycle.probe(["pathMapping", "processIsolation"]);
		const result = await backend.value.bash?.exec("echo should-not-run", { cwd: path.dirname(sessionRoot) });

		expect(probes).toEqual([
			{ kind: "passed", evidence: "SSH host path maps to configured remoteRoot", control: "pathMapping" },
			{
				kind: "failed",
				command: "probe-unverified-control",
				exitCode: null,
				reason: "ssh-control-unverified-until-remote-guard",
				fixHint: "Install a remote guard before treating SSH controls as enforced.",
				control: "processIsolation",
			},
		]);
		expect(result?.ok).toBe(false);
		if (result?.ok === false) expect(result.error.code).toBe("path_mapping_failed");
	});

	it("#given ssh auth and host verification helpers #when configured locally #then secrets and strict fingerprints are handled without connecting", () => {
		const connectConfig = buildConnectConfig(sshConfig);
		const key = Buffer.from("host-key", "utf8");
		const verifier = buildHostVerifier({ strict: true, hostHash: `SHA256:${sha256Fingerprint(key)}` });
		const nonStrictVerifier = buildHostVerifier({ strict: false });

		expect(connectConfig.ok).toBe(true);
		if (!connectConfig.ok) throw new Error(connectConfig.error.remediation);
		expect(connectConfig.value.agentForward).toBe(false);
		expect(connectConfig.value.password).toBe("secret");
		expect(verifier(key)).toBe(true);
		expect(verifier(Buffer.from("other-key", "utf8"))).toBe(false);
		expect(nonStrictVerifier(key)).toBe(false);
	});

	it("#given justbash root-locked backend #when symlink escapes are read or written #then realpath guard denies them", async () => {
		const projectRoot = await makeTemporaryRoot("pi-sandbox-justbash-project-");
		const outsideRoot = await makeTemporaryRoot("pi-sandbox-justbash-outside-");
		await writeFile(path.join(outsideRoot, "secret.txt"), "secret", "utf8");
		await symlink(outsideRoot, path.join(projectRoot, "escape"));
		const backend = await createJustbashBackend(justbashRootLockedConfig, projectRoot, envPolicy);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		const readResult = await backend.value.read?.readFile(path.join(projectRoot, "escape", "secret.txt"));
		const writeResult = await backend.value.write?.writeFile(path.join(projectRoot, "escape", "new.txt"), "blocked");

		expect(readResult?.ok).toBe(false);
		if (readResult?.ok === false) expect(readResult.error.code).toBe("permission_denied");
		expect(writeResult?.ok).toBe(false);
		if (writeResult?.ok === false) expect(writeResult.error.code).toBe("permission_denied");
	});

	it("#given justbash command references blocked host path #when exec denies #then actual path is reported", async () => {
		const projectRoot = await makeTemporaryRoot("pi-sandbox-justbash-deny-path-");
		const backend = await createJustbashBackend(justbashRootLockedConfig, projectRoot, envPolicy);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		const result = await backend.value.bash?.exec("cat /private/secret-token", { cwd: projectRoot });

		expect(result?.ok).toBe(false);
		if (result?.ok === false) expect(result.error.sanitizedTarget).toBe("/private/secret-token");
	});

	it("#given justbash command exceeds timeout #when exec returns #then timeout is a failure result", async () => {
		const projectRoot = await makeTemporaryRoot("pi-sandbox-justbash-timeout-");
		const backend = await createJustbashBackend(justbashRootLockedConfig, projectRoot, envPolicy);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		const result = await backend.value.bash?.exec("sleep 1", { cwd: projectRoot, timeoutMs: 1 });

		expect(result?.ok).toBe(false);
		if (result?.ok === false) expect(result.error.code).toBe("timeout");
	});

	it("#given justbash backend #when real controls are probed #then probe results are returned", async () => {
		const projectRoot = await makeTemporaryRoot("pi-sandbox-justbash-probe-");
		const backend = await createJustbashBackend(justbashRootLockedConfig, projectRoot, envPolicy);

		expect(backend.ok).toBe(true);
		if (!backend.ok) throw new Error(backend.error.remediation);
		const probes = await backend.value.lifecycle.probe(["pathMapping", "networkAllowlist"]);

		expect(probes).toEqual([
			{ kind: "passed", evidence: "justbash maps host paths into its virtual filesystem", control: "pathMapping" },
			{
				kind: "failed",
				command: "probe-unsupported-control",
				exitCode: null,
				reason: "justbash does not enforce this control",
				fixHint: "Use a backend that supports the requested control.",
				control: "networkAllowlist",
			},
		]);
	});

	it("#given justbash restricted network with non-url-prefix controls #when network config is converted #then capability gap is explicit", () => {
		const result = toJustbashNetworkConfig({
			mode: "restricted",
			default: "deny",
			allowDomains: ["example.com"],
			denyDomains: [],
			allowUrlPrefixes: [],
			allowPorts: [],
			allowCidrs: [],
			denyPrivateNetworks: true,
			denyMetadata: true,
			allowUnixSockets: false,
			scrubProxyEnv: true,
			dns: "deny",
		} satisfies NetworkPolicy);

		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.error.code).toBe("capability_missing");
	});

	it("#given darwin SBPL policy #when generated without sandbox-exec #then deny rules, escapes, and dedupe are deterministic", () => {
		const profile = generateSbplProfile({
			network: { mode: "deny" },
			file: filePolicy("/tmp/pi sandbox/root", ["/Users/me/Secrets"]),
			cwd: "/tmp/pi sandbox/root",
			allowedExecutables: ["/bin/sh", "/bin/sh", '/tmp/quote"bin'],
		});

		expect(profile).toContain("(deny network*)");
		expect(profile).toContain('(allow file-read* (subpath "/tmp/pi sandbox/root"))');
		expect(profile).toContain('(allow file-write* (subpath "/tmp/pi sandbox/root"))');
		expect(profile).toContain('(deny file-read* (subpath "/Users/me/Secrets"))');
		expect(profile).toContain('(allow process-exec (literal "/tmp/quote\\"bin"))');
		expect(countOccurrences(profile, '(allow process-exec (literal "/bin/sh"))')).toBe(1);
	});
});

async function makeTemporaryRoot(prefix: string): Promise<string> {
	const root = await mkdtemp(path.join(tmpdir(), prefix));
	temporaryRoots.push(root);
	return root;
}

function qemuConfig(
	shareMode: QemuBackendConfig["shareMode"],
	network: QemuBackendConfig["network"] = "none",
): QemuBackendConfig {
	return {
		kind: "qemu",
		assets: { kind: "user", kernelPath: "/tmp/kernel", initrdPath: "/tmp/initrd" },
		cpus: 1,
		memoryMb: 512,
		shareMode,
		network,
		snapshot: true,
	};
}

function filePolicy(root: string, denySpecialPaths: readonly string[]): FilePolicy {
	return {
		defaultRead: "deny",
		defaultWrite: "deny",
		roots: [
			{
				path: root,
				read: true,
				write: true,
				create: true,
				delete: false,
				persist: "host",
				followSymlinks: false,
			},
		],
		denySpecialPaths,
		denyMagicLinks: true,
		highRiskWriteClasses: [],
		maxReadBytes: 1024,
	};
}

function countOccurrences(input: string, needle: string): number {
	return input.split(needle).length - 1;
}

const dockerConfig = {
	kind: "docker",
	image: "node:22-alpine",
	networkMode: "none",
	readonlyRootfs: true,
	mounts: [],
	pullPolicy: "never",
	capDrop: ["ALL"],
	securityOpt: ["no-new-privileges"],
	tmpfs: [],
} satisfies DockerBackendConfig;

const sshConfig = {
	kind: "ssh",
	host: "example.invalid",
	port: 22,
	username: "user",
	auth: { kind: "password", password: "secret" },
	hostVerification: { strict: false },
	remoteRoot: "/remote/root",
	proxyJump: [],
} satisfies SshBackendConfig;

const justbashRootLockedConfig = {
	kind: "justbash",
	fs: "read-write-root-locked",
	allowedBinaries: [],
	network: { mode: "deny" },
	executionLimits: { maxOutputBytes: 1024 * 1024, maxRuntimeMs: 5_000 },
} satisfies JustbashBackendConfig;

const envPolicy = {
	clearenv: true,
	allowlist: ["PATH"],
	denyPatterns: [".*SECRET.*", ".*TOKEN.*", ".*KEY.*"],
	scrubProxyEnv: true,
} satisfies EnvPolicy;
