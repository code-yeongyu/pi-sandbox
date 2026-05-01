export type RedactionState = {
	readonly buffer: Buffer;
	readonly redactedSpans: ReadonlyArray<{
		readonly start: number;
		readonly end: number;
		readonly replacement: string;
	}>;
};

export type SecretPattern = {
	readonly name: string;
	readonly pattern: RegExp;
	readonly replacement: string;
};

export type RedactedChunk = {
	readonly output: Buffer;
	readonly carryover: Buffer;
	readonly redactionsApplied: number;
};

export interface StreamingRedactor {
	redact(data: Buffer): Buffer;
}

const SECRET_NAME_PATTERN =
	/(?:_KEY|_TOKEN|_SECRET|_PASSWORD|_PASSWD|^SSH_AUTH_SOCK$|^AWS_.+|^GCP_.+|^GOOGLE_APPLICATION_CREDENTIALS$)/i;

export function makeDefaultPatterns(
	envSnapshot: Readonly<Record<string, string | undefined>>,
): readonly SecretPattern[] {
	return Object.entries(envSnapshot)
		.filter(([name, value]) => value !== undefined && value.length >= 8 && SECRET_NAME_PATTERN.test(name))
		.map(([name, value]) => ({
			name,
			pattern: new RegExp(escapeRegExp(value ?? ""), "g"),
			replacement: `[REDACTED:${name}]`,
		}));
}

export function redactChunk(input: Buffer, state: RedactionState, patterns: readonly SecretPattern[]): RedactedChunk {
	const combined = Buffer.concat([state.buffer, input]);
	if (patterns.length > 0) {
		return {
			output: Buffer.alloc(0),
			carryover: combined,
			redactionsApplied: applyPatterns(combined.toString("utf8"), patterns).count,
		};
	}
	const redacted = applyPatterns(combined.toString("utf8"), patterns);
	return {
		output: Buffer.from(redacted.text, "utf8"),
		carryover: Buffer.alloc(0),
		redactionsApplied: redacted.count,
	};
}

export function flushCarryover(state: RedactionState, patterns: readonly SecretPattern[]): Buffer {
	return Buffer.from(applyPatterns(state.buffer.toString("utf8"), patterns).text, "utf8");
}

export function createStreamingRedactor(envSnapshot: Readonly<Record<string, string | undefined>>): StreamingRedactor {
	const patterns = makeDefaultPatterns(envSnapshot);
	let state: RedactionState = { buffer: Buffer.alloc(0), redactedSpans: [] };
	return {
		redact(data: Buffer): Buffer {
			const redacted = redactChunk(data, state, patterns);
			state = { buffer: redacted.carryover, redactedSpans: [] };
			if (redacted.output.length > 0) return redacted.output;
			const flushed = flushCarryover(state, patterns);
			state = { buffer: Buffer.alloc(0), redactedSpans: [] };
			return flushed;
		},
	};
}

export function wrapWithRedactor(onData: (data: Buffer) => void, redactor: StreamingRedactor): (data: Buffer) => void {
	return (data) => onData(redactor.redact(data));
}

function applyPatterns(
	input: string,
	patterns: readonly SecretPattern[],
): { readonly text: string; readonly count: number } {
	let text = input;
	let count = 0;
	for (const pattern of patterns) {
		if (!pattern.pattern.global) {
			throw new Error(`Secret pattern ${pattern.name} must have global flag`);
		}
		pattern.pattern.lastIndex = 0;
		const matches = [...text.matchAll(pattern.pattern)];
		if (matches.length === 0) continue;
		count += matches.length;
		pattern.pattern.lastIndex = 0;
		text = text.replace(pattern.pattern, pattern.replacement);
	}
	return { text, count };
}

function escapeRegExp(value: string): string {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
