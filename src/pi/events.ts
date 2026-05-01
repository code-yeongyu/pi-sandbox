// src/pi/events.ts — public pi event contract boundary re-exports
export type {
	BeforeAgentStartEvent,
	BeforeAgentStartEventResult,
	SessionShutdownEvent,
	SessionStartEvent,
	ToolCallEvent,
	ToolCallEventResult,
	ToolResultEvent,
	UserBashEvent,
	UserBashEventResult,
} from "@mariozechner/pi-coding-agent";

import type { ToolResultEvent } from "@mariozechner/pi-coding-agent";

// ToolResultEventResult is present in pi-mono source but not exported from the public package root.
export type PiToolResultEventResult = {
	content?: ToolResultEvent["content"];
	details?: unknown;
	isError?: boolean;
};
