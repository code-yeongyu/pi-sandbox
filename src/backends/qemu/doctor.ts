import { execFile } from "node:child_process";
import { access } from "node:fs/promises";
import { promisify } from "node:util";

import { verifyFixture } from "./smoke-fixture.js";

const execFileAsync = promisify(execFile);

export type QemuDoctorCheck = {
	readonly name: string;
	readonly status: "pass" | "warn" | "fail";
	readonly details: string;
};

export type QemuDoctorReport = {
	readonly backend: "qemu";
	readonly available: boolean;
	readonly binaryPath: string | null;
	readonly version: string | null;
	readonly accelerator: "kvm" | "hvf" | "tcg";
	readonly fixture: {
		readonly present: boolean;
		readonly checksumMatch: boolean;
		readonly kernelPath: string | null;
		readonly initrdPath: string | null;
		readonly manifestSha256: string | null;
	};
	readonly checks: readonly QemuDoctorCheck[];
};

export async function runQemuDoctor(root: string = process.cwd()): Promise<QemuDoctorReport> {
	const checks: QemuDoctorCheck[] = [];
	const binary = await qemuBinary();
	if (binary.path === null) {
		checks.push({ name: "qemu-system-x86_64", status: "fail", details: binary.details });
	} else {
		checks.push({ name: "qemu-system-x86_64", status: "pass", details: binary.details });
	}

	const accelerator = await detectAccelerator();
	checks.push({
		name: "accelerator",
		status: accelerator === "tcg" ? "warn" : "pass",
		details:
			accelerator === "tcg" ? "KVM/HVF not active; QEMU will use software emulation" : `${accelerator} available`,
	});

	const fixture = await verifyFixture(root);
	if (!fixture.ok) {
		checks.push({ name: "smoke-fixture", status: "fail", details: fixture.error.remediation });
	} else {
		checks.push({
			name: "smoke-fixture",
			status: "pass",
			details: `kernel=${fixture.value.kernelSha256} initrd=${fixture.value.initrdSha256}`,
		});
	}

	return {
		backend: "qemu",
		available: binary.path !== null && fixture.ok,
		binaryPath: binary.path,
		version: binary.version,
		accelerator,
		fixture: fixture.ok
			? {
					present: true,
					checksumMatch: true,
					kernelPath: fixture.value.kernelPath,
					initrdPath: fixture.value.initrdPath,
					manifestSha256: fixture.value.manifestSha256,
				}
			: { present: false, checksumMatch: false, kernelPath: null, initrdPath: null, manifestSha256: null },
		checks,
	};
}

async function qemuBinary(): Promise<{
	readonly path: string | null;
	readonly version: string | null;
	readonly details: string;
}> {
	try {
		const located = await execFileAsync("sh", ["-c", "command -v qemu-system-x86_64"]);
		const binaryPath = located.stdout.trim();
		const version = await execFileAsync(binaryPath, ["--version"]);
		const firstLine = version.stdout.split("\n")[0]?.trim() ?? "qemu-system-x86_64 version unknown";
		return { path: binaryPath, version: firstLine, details: firstLine };
	} catch (cause) {
		return { path: null, version: null, details: errorMessage(cause) };
	}
}

async function detectAccelerator(): Promise<"kvm" | "hvf" | "tcg"> {
	if (process.platform === "linux") {
		try {
			await access("/dev/kvm");
			return "kvm";
		} catch {
			return "tcg";
		}
	}
	if (process.platform === "darwin") {
		try {
			const result = await execFileAsync("sysctl", ["-n", "kern.hv_support"]);
			return result.stdout.trim() === "1" ? "hvf" : "tcg";
		} catch {
			return "tcg";
		}
	}
	return "tcg";
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}
