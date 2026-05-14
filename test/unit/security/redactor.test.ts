import { describe, expect, it } from "vitest";

import {
	createStreamingRedactor,
	flushCarryover,
	makeDefaultPatterns,
	type RedactionState,
	redactChunk,
} from "../../../src/security/redactor.js";

function emptyState(): RedactionState {
	return { buffer: Buffer.alloc(0) };
}

describe("redactor", () => {
	it("#given split chunk secret #when chunks are redacted #then final output redacts secret", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret" });
		const first = redactChunk(Buffer.from("prefix super"), emptyState(), patterns);
		const second = redactChunk(Buffer.from("secret suffix"), { buffer: first.carryover }, patterns);
		const output = Buffer.concat([
			first.output,
			second.output,
			flushCarryover({ buffer: second.carryover }, patterns),
		]);
		expect(output.toString("utf8")).toContain("[REDACTED:API_TOKEN]");
		expect(output.toString("utf8")).not.toContain("supersecret");
	});

	it("#given streaming secret split across chunks #when chunks are redacted #then secret is not emitted", () => {
		const redactor = createStreamingRedactor({ API_TOKEN: "sk-12345" });

		const output = Buffer.concat([redactor.redact(Buffer.from("sk-1")), redactor.redact(Buffer.from("2345"))]);

		expect(output.toString("utf8")).toContain("[REDACTED:API_TOKEN]");
		expect(output.toString("utf8")).not.toContain("sk-12345");
	});

	it("#given multiple secret patterns #when chunk is redacted #then all patterns are replaced", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret", AWS_SECRET: "awssecret" });
		const chunk = redactChunk(Buffer.from("supersecret and awssecret"), emptyState(), patterns);
		const text = Buffer.concat([chunk.output, flushCarryover({ buffer: chunk.carryover }, patterns)]).toString(
			"utf8",
		);
		expect(text).toContain("[REDACTED:API_TOKEN]");
		expect(text).toContain("[REDACTED:AWS_SECRET]");
	});

	it("#given ANSI escapes around secret #when redacted #then escape bytes do not prevent redaction", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret" });
		const chunk = redactChunk(Buffer.from("\u001b[31msupersecret\u001b[0m"), emptyState(), patterns);
		const text = Buffer.concat([chunk.output, flushCarryover({ buffer: chunk.carryover }, patterns)]).toString(
			"utf8",
		);
		expect(text).toContain("\u001b[31m[REDACTED:API_TOKEN]\u001b[0m");
	});

	it("#given base64 encoded secret #when redacted #then encoded form remains as known limitation", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret" });
		const chunk = redactChunk(Buffer.from("c3VwZXJzZWNyZXQ="), emptyState(), patterns);
		const text = Buffer.concat([chunk.output, flushCarryover({ buffer: chunk.carryover }, patterns)]).toString(
			"utf8",
		);
		expect(text).toBe("c3VwZXJzZWNyZXQ=");
	});

	it("#given concurrent states #when chunks differ #then carryover is isolated", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret" });
		const left = redactChunk(Buffer.from("super"), emptyState(), patterns);
		const right = redactChunk(Buffer.from("ordinary"), emptyState(), patterns);
		const completeLeft = redactChunk(Buffer.from("secret"), { buffer: left.carryover }, patterns);
		expect(
			Buffer.concat([completeLeft.output, flushCarryover({ buffer: completeLeft.carryover }, patterns)]).toString(
				"utf8",
			),
		).toContain("[REDACTED:API_TOKEN]");
		expect(
			Buffer.concat([right.output, flushCarryover({ buffer: right.carryover }, patterns)]).toString("utf8"),
		).toBe("ordinary");
	});

	it("#given short secret env value #when default patterns are made #then value is ignored", () => {
		expect(makeDefaultPatterns({ API_TOKEN: "short" })).toHaveLength(0);
	});

	it("#given non secret env name #when default patterns are made #then value is ignored", () => {
		expect(makeDefaultPatterns({ USERNAME: "long-enough-value" })).toHaveLength(0);
	});

	it("#given regex metacharacters in secret #when redacted #then literal value is matched", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "a.b+c[d]" });
		const chunk = redactChunk(Buffer.from("a.b+c[d]"), emptyState(), patterns);
		const text = Buffer.concat([chunk.output, flushCarryover({ buffer: chunk.carryover }, patterns)]).toString(
			"utf8",
		);
		expect(text).toBe("[REDACTED:API_TOKEN]");
	});

	it("#given repeated secret #when redacted #then counter records both replacements", () => {
		const patterns = makeDefaultPatterns({ API_TOKEN: "supersecret" });
		const chunk = redactChunk(Buffer.from("supersecret supersecret"), emptyState(), patterns);
		expect(chunk.redactionsApplied).toBe(2);
	});

	it("#given no patterns #when redacted #then output is unchanged", () => {
		const chunk = redactChunk(Buffer.from("plain text"), emptyState(), []);
		expect(Buffer.concat([chunk.output, chunk.carryover]).toString("utf8")).toBe("plain text");
	});
});
