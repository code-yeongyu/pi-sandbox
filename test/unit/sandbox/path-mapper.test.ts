import { expectTypeOf } from "expect-type";
import { describe, expect, it } from "vitest";
import type { PathMapper, PathMappingError } from "../../../src/sandbox/path-mapper.js";
import type { Result } from "../../../src/security/failure.js";

describe("PathMapper", () => {
	it("#given path mapper interface #when implemented #then methods return result-wrapped mapped paths", () => {
		// given
		const mapper: PathMapper = {
			hostToSandboxPath(hostPath: string): Result<string, PathMappingError> {
				return hostPath.startsWith("/repo")
					? { ok: true, value: hostPath.replace("/repo", "/workspace") }
					: { ok: false, error: { kind: "outside-sandbox", hostPath } };
			},
			sandboxToHostPath(sandboxPath: string): Result<string, PathMappingError> {
				return sandboxPath.startsWith("/workspace")
					? { ok: true, value: sandboxPath.replace("/workspace", "/repo") }
					: { ok: false, error: { kind: "non-representable", hostPath: sandboxPath, reason: "outside mount" } };
			},
			canRepresent(hostPath: string): boolean {
				return hostPath.startsWith("/repo");
			},
		};

		// when
		const result = mapper.hostToSandboxPath("/repo/file.txt");

		// then
		expect(result).toEqual({ ok: true, value: "/workspace/file.txt" });
		expectTypeOf<PathMappingError>().toExtend<
			| { readonly kind: "outside-sandbox"; readonly hostPath: string }
			| { readonly kind: "non-representable"; readonly hostPath: string; readonly reason: string }
			| { readonly kind: "case-collision"; readonly hostPath: string }
			| { readonly kind: "symlink-loop"; readonly hostPath: string }
		>();
	});
});
