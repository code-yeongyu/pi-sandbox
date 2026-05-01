// src/pi/index.ts — pi public contract boundary barrel

export type {
	BeforeAgentStartEvent,
	BeforeAgentStartEventResult,
	PiToolResultEventResult,
	SessionShutdownEvent,
	SessionStartEvent,
	ToolCallEvent,
	ToolCallEventResult,
	ToolResultEvent,
	UserBashEvent,
	UserBashEventResult,
} from "./events.js";
export type { ExtensionAPI, ExtensionContext, ExtensionUIContext } from "./extension-api.js";
export type { BashOperations, EditOperations, ReadOperations, WriteOperations } from "./operations.js";
export {
	createBashToolDefinition,
	createEditToolDefinition,
	createReadToolDefinition,
	createWriteToolDefinition,
	getAgentDir,
	isToolCallEventType,
} from "./tools.js";
