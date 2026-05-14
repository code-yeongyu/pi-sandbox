export type SandboxOperation =
	| { readonly kind: "bash"; readonly command: string; readonly cwd: string }
	| { readonly kind: "fs.read"; readonly path: string }
	| { readonly kind: "fs.write"; readonly path: string; readonly content: string | Buffer }
	| { readonly kind: "fs.access"; readonly path: string }
	| { readonly kind: "fs.mkdir"; readonly path: string }
	| { readonly kind: "process.spawn"; readonly binary: string; readonly args: readonly string[]; readonly cwd: string }
	| { readonly kind: "network"; readonly method: string; readonly url: string };
