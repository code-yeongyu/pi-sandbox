import { describe, expect, it } from "vitest";

import { toAgentContextBlock } from "../../../src/explain/render-agent-context.js";
import { toSandboxStatus, toTuiFooter, toTuiWidget } from "../../../src/explain/render-tui.js";
import type { SandboxMode } from "../../../src/sandbox/mode.js";
import { fullCapability, makeBlock, makeEffectivePolicy } from "../helpers/effective-policy.js";

const mode: SandboxMode = { kind: "enforcing", backend: "justbash", capabilities: fullCapability };

describe("agent and tui renderers", () => {
	it("#given effective policy #when agent context renders #then sandbox tag is present", () => {
		expect(toAgentContextBlock(makeEffectivePolicy(), fullCapability)).toContain('<pi_sandbox active="true"');
	});

	it("#given effective policy #when agent context renders #then raw project path is not included", () => {
		expect(toAgentContextBlock(makeEffectivePolicy(), fullCapability)).not.toContain(process.cwd());
	});

	it("#given capability #when agent context renders #then mechanism is summarized", () => {
		expect(toAgentContextBlock(makeEffectivePolicy(), fullCapability)).toContain("network=gateway");
	});

	it("#given footer inputs #when rendered #then backend and revision are compact", () => {
		const footer = toTuiFooter(makeEffectivePolicy(), mode);
		expect(footer).toContain("justbash");
		expect(footer).toContain("rev=7:");
	});

	it("#given disabled mode #when footer renders #then disabled is visible", () => {
		const footer = toTuiFooter(makeEffectivePolicy(), {
			kind: "disabled-by-user",
			approvalId: "a",
			scope: "session",
			visibleReason: "test",
		});
		expect(footer).toContain("disabled-by-user");
	});

	it("#given widget without block #when rendered #then unsupported controls line is present", () => {
		expect(toTuiWidget(makeEffectivePolicy(), mode).join("\n")).toContain("unsupported controls: none");
	});

	it("#given widget with block #when rendered #then last block is included", () => {
		expect(toTuiWidget(makeEffectivePolicy(), mode, makeBlock()).join("\n")).toContain("last block: network");
	});

	it("#given status inputs #when rendered #then probe results are shown", () => {
		const status = toSandboxStatus(
			makeEffectivePolicy(),
			mode,
			[{ kind: "passed", control: "networkDeny", evidence: "namespace" }],
			[],
		);
		expect(status).toContain("probe networkDeny: passed");
	});

	it("#given env inputs #when status renders #then only name class and presence are shown", () => {
		const status = toSandboxStatus(
			makeEffectivePolicy(),
			mode,
			[],
			[{ name: "SSH_AUTH_SOCK", class: "socket-path", present: true }],
		);
		expect(status).toContain("SSH_AUTH_SOCK: present/socket-path/redacted");
	});

	it("#given failed probe #when status renders #then failure reason is shown", () => {
		const status = toSandboxStatus(
			makeEffectivePolicy(),
			mode,
			[{ kind: "failed", control: "fileRead", command: "probe", exitCode: 1, reason: "denied" }],
			[],
		);
		expect(status).toContain("reason=denied");
	});
});
