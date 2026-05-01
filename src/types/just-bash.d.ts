declare module "just-bash" {
	export type CommandContext = {
		readonly cwd: string;
		readonly stdin: string;
	};

	export type CommandResult = {
		readonly stdout: string;
		readonly stderr: string;
		readonly exitCode: number;
	};

	export type Command = {
		readonly name: string;
	};

	export interface IFileSystem {}

	export type NetworkConfig = {
		readonly dangerouslyAllowFullInternetAccess?: boolean;
		readonly allowedUrlPrefixes?: readonly string[];
		readonly denyPrivateRanges?: boolean;
	};

	export function defineCommand(
		name: string,
		handler: (args: readonly string[], ctx: CommandContext) => Promise<CommandResult>,
	): Command;

	export class ReadWriteFs implements IFileSystem {
		public constructor(options: {
			readonly root: string;
			readonly allowSymlinks: boolean;
			readonly maxFileReadSize: number;
		});
	}

	export class Bash {
		public constructor(options: {
			readonly fs: IFileSystem;
			readonly cwd: string;
			readonly env: Readonly<Record<string, string>>;
			readonly customCommands: readonly Command[];
			readonly executionLimits: { readonly maxCommandCount: number };
			readonly network?: NetworkConfig;
		});

		public exec(
			command: string,
			options: { readonly signal: AbortSignal },
		): Promise<{
			readonly stdout: string;
			readonly stderr: string;
			readonly exitCode: number;
		}>;
	}
}
