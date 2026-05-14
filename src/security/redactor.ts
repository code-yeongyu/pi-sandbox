export type RedactionState = {
	readonly buffer: Buffer;
};

export type SecretPattern = {
	readonly name: string;
	readonly pattern: RegExp;
	readonly replacement: string;
	readonly secretLength?: number;
	readonly secretValue?: string;
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
	return Object.entries(envSnapshot).flatMap(([name, value]) => {
		if (value === undefined || value.length < 8 || !SECRET_NAME_PATTERN.test(name)) return [];
		return [
			{
				name,
				pattern: new RegExp(escapeRegExp(value), "g"),
				replacement: `[REDACTED:${name}]`,
				secretLength: value.length,
				secretValue: value,
			},
		];
	});
}

export function redactChunk(input: Buffer, state: RedactionState, patterns: readonly SecretPattern[]): RedactedChunk {
	const combined = Buffer.concat([state.buffer, input]);
	const carryoverLength = carryoverLengthForInput(combined.toString("utf8"), patterns);
	let safeOutputLength = carryoverLength === 0 ? combined.length : Math.max(0, combined.length - carryoverLength);
	safeOutputLength = includeCompleteMatches(combined.toString("utf8"), safeOutputLength, patterns);
	safeOutputLength = adjustSafeOutputLength(combined.toString("utf8"), safeOutputLength, patterns);
	if (safeOutputLength === 0) {
		const redacted = applyPatterns(combined.toString("utf8"), patterns);
		if (redacted.count > 0) {
			return {
				output: Buffer.from(redacted.text, "utf8"),
				carryover: Buffer.alloc(0),
				redactionsApplied: redacted.count,
			};
		}
		return {
			output: Buffer.alloc(0),
			carryover: combined,
			redactionsApplied: 0,
		};
	}
	const output = combined.subarray(0, safeOutputLength);
	const carryover = combined.subarray(safeOutputLength);
	const redacted = applyPatterns(output.toString("utf8"), patterns);
	return {
		output: Buffer.from(redacted.text, "utf8"),
		carryover,
		redactionsApplied: redacted.count,
	};
}

export function flushCarryover(state: RedactionState, patterns: readonly SecretPattern[]): Buffer {
	return Buffer.from(applyPatterns(state.buffer.toString("utf8"), patterns).text, "utf8");
}

export function createStreamingRedactor(envSnapshot: Readonly<Record<string, string | undefined>>): StreamingRedactor {
	const patterns = makeDefaultPatterns(envSnapshot);
	let state: RedactionState = { buffer: Buffer.alloc(0) };
	return {
		redact(data: Buffer): Buffer {
			const redacted = redactChunk(data, state, patterns);
			state = { buffer: redacted.carryover };
			if (redacted.output.length > 0) return redacted.output;
			return Buffer.alloc(0);
		},
	};
}

export function wrapWithRedactor(onData: (data: Buffer) => void, redactor: StreamingRedactor): (data: Buffer) => void {
	return (data) => onData(redactor.redact(data));
}

function carryoverLengthForInput(input: string, patterns: readonly SecretPattern[]): number {
	return patterns.reduce((maxLength, pattern) => {
		if (pattern.secretValue === undefined) return Math.max(maxLength, pattern.secretLength ?? 64);
		return Math.max(maxLength, secretPrefixSuffixLength(input, pattern.secretValue));
	}, 0);
}

function secretPrefixSuffixLength(input: string, secretValue: string): number {
	const maxLength = Math.min(input.length, secretValue.length - 1);
	for (let length = maxLength; length > 0; length -= 1) {
		if (input.endsWith(secretValue.slice(0, length))) return length;
	}
	return 0;
}

function includeCompleteMatches(input: string, safeOutputLength: number, patterns: readonly SecretPattern[]): number {
	let adjusted = safeOutputLength;
	for (const pattern of patterns) {
		pattern.pattern.lastIndex = 0;
		for (const match of input.matchAll(pattern.pattern)) {
			const start = match.index;
			const matchedText = match[0];
			if (start !== undefined && start <= adjusted && start + matchedText.length > adjusted) {
				adjusted = start + matchedText.length;
			}
		}
	}
	return adjusted;
}

function adjustSafeOutputLength(input: string, safeOutputLength: number, patterns: readonly SecretPattern[]): number {
	let adjusted = safeOutputLength;
	for (const pattern of patterns) {
		pattern.pattern.lastIndex = 0;
		for (const match of input.matchAll(pattern.pattern)) {
			const start = match.index;
			const matchedText = match[0];
			if (start !== undefined && start < adjusted && start + matchedText.length > adjusted) adjusted = start;
		}
	}
	return adjusted;
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
