// src/sandbox/path-mapper.ts — PathMapper interface
export type PathRepresentationResult =
	| { ok: true; sandboxPath: string }
	| { ok: false; reason: "outside-root" | "unsupported-path" | "case-conflict" | "symlink-unrepresentable" };

export interface PathMapper {
	hostToSandboxPath(hostPath: string): PathRepresentationResult;
	sandboxToHostPath(sandboxPath: string): PathRepresentationResult;
	canRepresent(hostPath: string): boolean;
}
