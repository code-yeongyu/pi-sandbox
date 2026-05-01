import { describe, expect, it } from "vitest";

import piSandboxExtension from "../../src/index.js";

describe("piSandboxExtension", () => {
	it("#given extension entrypoint #when imported #then default export is a function", () => {
		// given
		const extensionFactory = piSandboxExtension;

		// when
		const extensionType = typeof extensionFactory;

		// then
		expect(extensionType).toBe("function");
	});
});
