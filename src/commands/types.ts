export type CommandNotificationType = "info" | "error";

export type SandboxCommandContext = {
	readonly cwd?: string;
	readonly ui: {
		readonly notify: (message: string, type: CommandNotificationType) => void;
	};
};

export type SandboxCommandOptions = {
	readonly description: string;
	readonly handler: (args: string, ctx: SandboxCommandContext) => Promise<void>;
};

export type CommandRegistrar = {
	readonly registerCommand: (name: string, options: SandboxCommandOptions) => void;
};
