import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, readFile } from "node:fs/promises";
import path from "node:path";

import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";

export const QEMU_SMOKE_FIXTURE = {
	fixtureName: "default",
	directory: "qemu-fixtures",
	kernelFile: "bzImage",
	initrdFile: "initrd.cpio.gz",
	manifestFile: "MANIFEST.sha256",
	recommendedAppend: "console=ttyS0 init=/init quiet",
	recommendedArgs: ["-no-reboot", "-nographic", "-serial", "mon:stdio"],
} as const;

export type SmokeFixturePaths = {
	readonly kernelPath: string;
	readonly initrdPath: string;
};

export type SmokeFixtureHashes = {
	readonly kernelSha256: string;
	readonly initrdSha256: string;
	readonly manifestSha256: string;
};

export type SmokeFixtureVerification = SmokeFixturePaths & SmokeFixtureHashes;

export function smokeFixturePaths(root: string = process.cwd()): SmokeFixturePaths & { readonly manifestPath: string } {
	const fixtureRoot = path.resolve(root, QEMU_SMOKE_FIXTURE.directory);
	return {
		kernelPath: path.join(fixtureRoot, QEMU_SMOKE_FIXTURE.kernelFile),
		initrdPath: path.join(fixtureRoot, QEMU_SMOKE_FIXTURE.initrdFile),
		manifestPath: path.join(fixtureRoot, QEMU_SMOKE_FIXTURE.manifestFile),
	};
}

export async function verifyFixture(
	root: string = process.cwd(),
): Promise<Result<SmokeFixtureVerification, SandboxFailure>> {
	const fixture = smokeFixturePaths(root);
	const existence = await requireFixtureFiles(fixture.kernelPath, fixture.initrdPath, fixture.manifestPath);
	if (!existence.ok) return existence;

	const [kernelSha256, initrdSha256, manifest] = await Promise.all([
		sha256File(fixture.kernelPath),
		sha256File(fixture.initrdPath),
		readManifest(fixture.manifestPath),
	]);
	if (!kernelSha256.ok) return kernelSha256;
	if (!initrdSha256.ok) return initrdSha256;
	if (!manifest.ok) return manifest;

	const expectedKernel = manifest.value.get(QEMU_SMOKE_FIXTURE.kernelFile);
	const expectedInitrd = manifest.value.get(QEMU_SMOKE_FIXTURE.initrdFile);
	if (expectedKernel !== kernelSha256.value) {
		return {
			ok: false,
			error: fixtureFailure(
				"backend_probe_failed",
				"qemu.fixture.kernel-checksum",
				QEMU_SMOKE_FIXTURE.kernelFile,
				`expected ${expectedKernel ?? "missing"}, got ${kernelSha256.value}`,
			),
		};
	}
	if (expectedInitrd !== initrdSha256.value) {
		return {
			ok: false,
			error: fixtureFailure(
				"backend_probe_failed",
				"qemu.fixture.initrd-checksum",
				QEMU_SMOKE_FIXTURE.initrdFile,
				`expected ${expectedInitrd ?? "missing"}, got ${initrdSha256.value}`,
			),
		};
	}

	const manifestSha256 = createHash("sha256")
		.update(`${kernelSha256.value}\n${initrdSha256.value}\n`, "utf8")
		.digest("hex");
	return {
		ok: true,
		value: {
			kernelPath: fixture.kernelPath,
			initrdPath: fixture.initrdPath,
			kernelSha256: kernelSha256.value,
			initrdSha256: initrdSha256.value,
			manifestSha256,
		},
	};
}

async function requireFixtureFiles(
	kernelPath: string,
	initrdPath: string,
	manifestPath: string,
): Promise<Result<void, SandboxFailure>> {
	for (const target of [kernelPath, initrdPath, manifestPath]) {
		try {
			await access(target);
		} catch {
			return {
				ok: false,
				error: fixtureFailure("dependency_missing", "qemu.fixture.exists", target, "fixture file missing"),
			};
		}
	}
	return { ok: true, value: undefined };
}

async function readManifest(manifestPath: string): Promise<Result<ReadonlyMap<string, string>, SandboxFailure>> {
	try {
		const content = await readFile(manifestPath, "utf8");
		const entries = new Map<string, string>();
		for (const line of content.split("\n")) {
			const trimmed = line.trim();
			if (trimmed.length === 0) continue;
			const match = /^(?<hash>[a-fA-F0-9]{64})[ \t]+\*?(?<file>[^\s]+)$/.exec(trimmed);
			if (match?.groups === undefined) {
				return {
					ok: false,
					error: fixtureFailure(
						"backend_probe_failed",
						"qemu.fixture.manifest",
						manifestPath,
						"invalid manifest line",
					),
				};
			}
			entries.set(path.basename(match.groups.file ?? ""), (match.groups.hash ?? "").toLowerCase());
		}
		return { ok: true, value: entries };
	} catch (cause) {
		return {
			ok: false,
			error: fixtureFailure("backend_probe_failed", "qemu.fixture.manifest", manifestPath, errorMessage(cause)),
		};
	}
}

export async function sha256File(filePath: string): Promise<Result<string, SandboxFailure>> {
	return new Promise((resolve) => {
		const hash = createHash("sha256");
		const stream = createReadStream(filePath);
		stream.once("error", (cause) => {
			resolve({
				ok: false,
				error: fixtureFailure("backend_probe_failed", "qemu.fixture.sha256", filePath, errorMessage(cause)),
			});
		});
		stream.on("data", (chunk: Buffer) => hash.update(chunk));
		stream.once("end", () => resolve({ ok: true, value: hash.digest("hex") }));
	});
}

function fixtureFailure(
	code: "dependency_missing" | "backend_probe_failed",
	operation: string,
	target: string,
	message: string,
): SandboxFailure {
	return createBlock({
		version: 1,
		code,
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "qemu.smoke-fixture",
		backend: "qemu",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Run scripts/qemu-smoke-fixture-build.sh before enabling PI_SANDBOX_QEMU_SMOKE.",
		...(code === "dependency_missing" ? { dependency: target } : { probeName: operation, probeOutput: message }),
	});
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
