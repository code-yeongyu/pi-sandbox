import type Docker from "dockerode";

import { createBlock, type Result, type SandboxFailure } from "../../security/failure.js";

export async function ensureImage(
	docker: Docker,
	image: string,
	pullPolicy: "always" | "if-missing" | "never",
): Promise<Result<void, SandboxFailure>> {
	try {
		if (pullPolicy === "never") return { ok: true, value: undefined };
		if (pullPolicy === "if-missing") {
			const present = await imageExists(docker, image);
			if (present.ok && present.value) return { ok: true, value: undefined };
			if (!present.ok && pullPolicy === "if-missing") return present;
		}
		const stream = await docker.pull(image, {});
		await drainPullStream(stream);
		return { ok: true, value: undefined };
	} catch (cause) {
		return { ok: false, error: dockerFailure("docker.image.pull", image, errorMessage(cause)) };
	}
}

async function imageExists(docker: Docker, image: string): Promise<Result<boolean, SandboxFailure>> {
	try {
		await docker.getImage(image).inspect();
		return { ok: true, value: true };
	} catch (cause) {
		if (isDockerNotFound(cause)) return { ok: true, value: false };
		return { ok: false, error: dockerFailure("docker.image.inspect", image, errorMessage(cause)) };
	}
}

async function drainPullStream(stream: NodeJS.ReadableStream): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		stream.on("data", () => undefined);
		stream.once("error", reject);
		stream.once("end", resolve);
	});
}

function isDockerNotFound(cause: unknown): boolean {
	if (typeof cause !== "object" || cause === null) return false;
	if (!("statusCode" in cause)) return false;
	return cause.statusCode === 404;
}

function errorMessage(cause: unknown): string {
	return cause instanceof Error ? cause.message : String(cause);
}

function dockerFailure(operation: string, target: string, message: string): SandboxFailure {
	return createBlock({
		version: 1,
		code: "sandbox_backend_error",
		policyArea: "backend",
		operation,
		sanitizedTarget: target,
		matchedRule: "docker.image",
		backend: "docker",
		policyHash: "uninitialized",
		policyRevision: 0,
		remediation: "Check Docker daemon connectivity and image availability.",
		backendMessage: message,
	});
}
