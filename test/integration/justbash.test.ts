import { describe, expect, it } from "vitest";

import piSandboxExtension from "../../src/index.js";

type Handler<TEvent, TResult = undefined> = (
	event: TEvent,
	ctx: HarnessContext,
) => Promise<TResult | undefined> | TResult | undefined;
type RegisteredHandler = (event: object, ctx: HarnessContext) => Promise<object | undefined> | object | undefined;
type ToolDefinition = {
	readonly name: string;
	execute(
		toolCallId: string,
		params: { readonly command: string; readonly timeout?: number },
		signal?: AbortSignal,
		onUpdate?: (result: ToolResult) => void,
		ctx?: HarnessContext,
	): Promise<ToolResult>;
};
type ToolResult = {
	readonly content: ReadonlyArray<{ readonly type: "text"; readonly text: string }>;
	readonly details?: unknown;
	readonly isError?: boolean;
};
type CommandDefinition = {
	readonly description?: string;
	handler(args: string, ctx: HarnessContext): Promise<void>;
};
type BeforeAgentStartEvent = {
	readonly type: "before_agent_start";
	readonly prompt: string;
	readonly systemPrompt: string;
};
type SessionStartEvent = { readonly type: "session_start"; readonly reason: "startup" };
type HarnessContext = {
	readonly ui: {
		notify(message: string, type?: "info" | "warning" | "error"): void;
		setStatus(key: string, text: string | undefined): void;
		setWidget(key: string, content: string[] | undefined): void;
	};
	readonly hasUI: boolean;
	readonly cwd: string;
};

class Harness {
	readonly tools = new Map<string, ToolDefinition>();
	readonly commands = new Map<string, CommandDefinition>();
	readonly notifications: string[] = [];
	readonly statuses: string[] = [];
	readonly widgets: string[] = [];
	readonly sessionStartHandlers: Handler<SessionStartEvent>[] = [];
	readonly beforeAgentStartHandlers: Handler<BeforeAgentStartEvent, { readonly systemPrompt?: string }>[] = [];
	readonly ctx: HarnessContext;
	readonly api: object;

	public constructor(cwd: string) {
		const ui = {
			notify: (message: string, type?: "info" | "warning" | "error") =>
				this.notifications.push(`${type ?? "info"}:${message}`),
			setStatus: (key: string, text: string | undefined) => this.statuses.push(`${key}=${text ?? "unset"}`),
			setWidget: (key: string, content: string[] | undefined) =>
				this.widgets.push(`${key}=${content?.join("|") ?? "unset"}`),
			setWorkingMessage: () => undefined,
			setWorkingVisible: () => undefined,
			setTitle: () => undefined,
		};
		this.ctx = {
			ui,
			hasUI: true,
			cwd,
		};
		this.api = {
			on: (event: string, handler: RegisteredHandler) => {
				if (event === "session_start") {
					this.sessionStartHandlers.push(async (sessionEvent, context) => {
						await handler(sessionEvent, context);
						return undefined;
					});
				}
				if (event === "before_agent_start") {
					this.beforeAgentStartHandlers.push(async (agentEvent, context) => {
						const result = await handler(agentEvent, context);
						return isSystemPromptResult(result) ? result : undefined;
					});
				}
			},
			registerTool: (tool: ToolDefinition) => {
				this.tools.set(tool.name, tool);
			},
			registerCommand: (name: string, command: CommandDefinition) => {
				this.commands.set(name, command);
			},
		};
	}

	public async start(): Promise<void> {
		for (const handler of this.sessionStartHandlers)
			await handler({ type: "session_start", reason: "startup" }, this.ctx);
	}

	public async executeBash(command: string): Promise<{ readonly text: string; readonly result: ToolResult }> {
		const tool = this.tools.get("bash");
		expect(tool).toBeDefined();
		if (tool === undefined) throw new Error("bash tool was not registered");
		try {
			const result = await tool.execute("call-1", { command }, undefined, undefined, this.ctx);
			return { text: result.content.map((entry) => entry.text).join("\n"), result };
		} catch (cause) {
			const message = cause instanceof Error ? cause.message : String(cause);
			return {
				text: message,
				result: { content: [{ type: "text", text: message }], details: { exitCode: 126 }, isError: true },
			};
		}
	}

	public async beforeAgentStart(): Promise<string> {
		let systemPrompt = "base prompt";
		for (const handler of this.beforeAgentStartHandlers) {
			const result = await handler({ type: "before_agent_start", prompt: "hello", systemPrompt }, this.ctx);
			if (result?.systemPrompt !== undefined) systemPrompt = result.systemPrompt;
		}
		return systemPrompt;
	}
}

function isSystemPromptResult(value: object | undefined): value is { readonly systemPrompt?: string } {
	return value !== undefined && (!("systemPrompt" in value) || typeof value.systemPrompt === "string");
}

describe("justbash backend end-to-end", () => {
	it("#given enabled justbash backend #when bash exec is called #then output is sandboxed and redacted", async () => {
		const harness = new Harness(process.cwd());
		const extension = piSandboxExtension as (api: Harness["api"]) => void;
		extension(harness.api);

		await harness.start();
		const { text, result } = await harness.executeBash("echo hello-sandbox");

		expect(text).toContain("hello-sandbox");
		expect(result.isError).not.toBe(true);
		expect(harness.statuses.some((status) => status.startsWith("sandbox=sandbox enforcing justbash"))).toBe(true);
	});

	it("#given an attempt to access /etc/passwd #when bash exec is called #then it fails with structured permission_denied", async () => {
		const harness = new Harness(process.cwd());
		const extension = piSandboxExtension as (api: Harness["api"]) => void;
		extension(harness.api);

		await harness.start();
		const { text, result } = await harness.executeBash("cat /etc/passwd");

		expect(text).toContain("pi-sandbox blocked");
		expect(result.details).toMatchObject({ exitCode: 126 });
	});

	it("#given before_agent_start fires #when manager is active #then systemPrompt includes <pi_sandbox> block", async () => {
		const harness = new Harness(process.cwd());
		const extension = piSandboxExtension as (api: Harness["api"]) => void;
		extension(harness.api);

		await harness.start();
		const systemPrompt = await harness.beforeAgentStart();

		expect(systemPrompt).toContain('<pi_sandbox active="true"');
	});

	it("#given sandbox is enabled #when /sandbox-status is invoked #then status output is rendered", async () => {
		const harness = new Harness(process.cwd());
		const extension = piSandboxExtension as (api: Harness["api"]) => void;
		extension(harness.api);

		await harness.start();
		const command = harness.commands.get("sandbox-status");
		expect(command).toBeDefined();
		if (command === undefined) throw new Error("sandbox-status command was not registered");
		await command.handler("", harness.ctx);

		expect(harness.notifications.some((notification) => notification.includes("pi-sandbox status"))).toBe(true);
	});
});
