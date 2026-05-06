import { describe, expect, it } from "vitest";
import { installFooter } from "../../../src/tui/footer.js";
import { renderPermissionPrompt } from "../../../src/tui/permission-prompt.js";
import { installWidget } from "../../../src/tui/widget.js";
import { makeBlock, makeEffectivePolicy } from "../helpers/effective-policy.js";

type MinimalManager = Parameters<typeof installWidget>[1];

function createManager(): MinimalManager {
	return {
		getEffectivePolicy: () => makeEffectivePolicy(),
		getMode: () => ({
			kind: "enforcing",
			backend: "justbash",
			capabilities: makeEffectivePolicy().backend.capabilities,
		}),
	} as MinimalManager;
}

describe("tui installers and prompt renderer", () => {
	it("#given permission decision #when prompt renders #then request metadata is visible", () => {
		expect(
			renderPermissionPrompt({
				requestId: "request-1",
				class: "file.write",
				sanitizedTarget: "<project>/.env",
				matchedRule: "high-risk dotenv",
			}),
		).toEqual({
			title: "pi-sandbox approval required",
			message: [
				"sandbox-prompt",
				"class: file.write",
				"target: <project>/.env",
				"matchedRule: high-risk dotenv",
				"requestId: request-1",
				"Allow this request for the current session?",
			].join("\n"),
		});
	});

	it("#given pi without ui #when widget and footer install #then no-op disposers are returned", () => {
		const pi = {};

		expect(() => installWidget(pi, createManager()).update(makeBlock())).not.toThrow();
		expect(() => installFooter(pi, createManager())()).not.toThrow();
	});

	it("#given ui-capable pi #when widget updates and disposes #then sandbox widget is set and cleared", () => {
		const calls: Array<readonly [string, string[] | undefined]> = [];
		const ui = {
			setWidget: (name: string, lines: string[] | undefined): void => {
				calls.push([name, lines]);
			},
		};
		const widget = installWidget({ ui }, createManager());

		widget.update(makeBlock());
		widget.dispose();

		expect(calls[0]?.[0]).toBe("sandbox");
		expect(calls[0]?.[1]?.join("\n")).toContain("last block: network");
		expect(calls[1]).toEqual(["sandbox", undefined]);
	});

	it("#given ui-capable pi #when footer installs and disposes #then footer provider renders sandbox status", () => {
		let renderedFooter = "";
		let cleared = false;
		const ui = {
			setFooter: (factory: (() => { readonly render: () => string[] }) | undefined) => {
				if (factory === undefined) {
					cleared = true;
					return;
				}
				renderedFooter = factory().render().join("\n");
			},
		};

		const dispose = installFooter({ ui }, createManager());
		dispose();

		expect(renderedFooter).toContain("sandbox enforcing justbash");
		expect(cleared).toBe(true);
	});
});
