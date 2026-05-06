import { describe, expect, it } from "vitest";

import {
	ApprovalStore,
	parseGrantClass,
	parseTypedGrantRequestId,
	typedGrantRequestId,
} from "../../../src/approvals/store.js";

describe("approval store helpers", () => {
	it("#given typed grant target with spaces and URL separators #when request id round-trips #then original target is preserved", () => {
		const target = "https://example.com/a path?token=redacted&x=1";
		const requestId = typedGrantRequestId("url-prefix", target);

		expect(parseTypedGrantRequestId("allow", requestId)).toEqual({
			action: "allow",
			class: "url-prefix",
			target,
		});
	});

	it("#given malformed typed request id #when parsed #then null is returned instead of throwing", () => {
		expect(parseTypedGrantRequestId("deny", "typed:file.read:%E0%A4%A")).toBeNull();
		expect(parseTypedGrantRequestId("allow", "manual:file.read:/tmp/a")).toBeNull();
		expect(parseTypedGrantRequestId("allow", "typed:not-a-class:/tmp/a")).toBeNull();
	});

	it("#given grant class text #when parsed #then only supported classes are accepted", () => {
		expect(parseGrantClass("binary")).toBe("binary");
		expect(parseGrantClass("network")).toBeNull();
	});

	it("#given grants added out of order #when listed #then insertion storage is sorted by added time", () => {
		const store = new ApprovalStore();

		store.add({ requestId: "later", class: "file.read", target: "/tmp/later", addedAt: 20 });
		store.add({ requestId: "earlier", class: "file.write", target: "/tmp/earlier", addedAt: 10 });

		expect(store.list().map((grant) => grant.requestId)).toEqual(["earlier", "later"]);
	});
});
