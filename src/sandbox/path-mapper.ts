// src/sandbox/path-mapper.ts — PathMapper interface
import type { Result } from "../security/failure.js";

export type PathMappingError =
	| { readonly kind: "outside-sandbox"; readonly hostPath: string }
	| { readonly kind: "non-representable"; readonly hostPath: string; readonly reason: string }
	| { readonly kind: "case-collision"; readonly hostPath: string }
	| { readonly kind: "symlink-loop"; readonly hostPath: string };

export interface PathMapper {
	hostToSandboxPath(hostPath: string): Result<string, PathMappingError>;
	sandboxToHostPath(sandboxPath: string): Result<string, PathMappingError>;
	canRepresent(hostPath: string): boolean;
}
