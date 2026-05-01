import {
	applyEdits,
	type FormattingOptions,
	type JSONPath,
	modify,
	type ParseError,
	parse,
	printParseErrorCode,
	visit,
} from "jsonc-parser";

import type { Result } from "./schema.js";

export type JsoncParseError = {
	line: number;
	column: number;
	offset: number;
	message: string;
	severity: "error" | "warning";
};

type ObjectFrame = {
	path: JSONPath;
	keys: Set<string>;
};

const parseOptions = { allowTrailingComma: true, allowEmptyContent: true } as const;

function toJsoncParseError(text: string, error: ParseError): JsoncParseError {
	const position = offsetToPosition(text, error.offset);
	return {
		line: position.line,
		column: position.column,
		offset: error.offset,
		message: printParseErrorCode(error.error),
		severity: "error",
	};
}

function offsetToPosition(text: string, offset: number): { line: number; column: number } {
	let line = 1;
	let column = 1;
	for (let index = 0; index < offset && index < text.length; index += 1) {
		if (text[index] === "\n") {
			line += 1;
			column = 1;
		} else {
			column += 1;
		}
	}
	return { line, column };
}

function validateJsoncAst(text: string, topLevelKeys?: ReadonlySet<string>): ReadonlyArray<JsoncParseError> {
	const errors: JsoncParseError[] = [];
	const stack: ObjectFrame[] = [];
	visit(
		text,
		{
			onObjectBegin: (_offset, _length, _startLine, _startCharacter, pathSupplier) => {
				stack.push({ path: pathSupplier(), keys: new Set() });
			},
			onObjectProperty: (property, offset, _length, startLine, startCharacter) => {
				const frame = stack[stack.length - 1];
				if (!frame) return;
				if (frame.keys.has(property)) {
					errors.push({
						line: startLine + 1,
						column: startCharacter + 1,
						offset,
						message: `Duplicate object key "${property}"`,
						severity: "error",
					});
				}
				frame.keys.add(property);
				if (frame.path.length === 0 && topLevelKeys && !topLevelKeys.has(property)) {
					errors.push({
						line: startLine + 1,
						column: startCharacter + 1,
						offset,
						message: `Unknown top-level section "${property}"`,
						severity: "error",
					});
				}
			},
			onObjectEnd: () => {
				stack.pop();
			},
		},
		parseOptions,
	);
	return errors;
}

export function parseJsonc(
	text: string,
	topLevelKeys?: ReadonlySet<string>,
): Result<unknown, ReadonlyArray<JsoncParseError>> {
	const parseText = text.charCodeAt(0) === 0xfeff ? text.slice(1) : text;
	const syntaxErrors: ParseError[] = [];
	const value: unknown = parse(parseText, syntaxErrors, parseOptions);
	const errors = [
		...syntaxErrors.map((error) => toJsoncParseError(parseText, error)),
		...validateJsoncAst(parseText, topLevelKeys),
	];
	if (errors.length > 0) return { ok: false, error: errors };
	return { ok: true, value: value ?? {} };
}

export function modifyJsonc(
	text: string,
	path: ReadonlyArray<string | number>,
	value: unknown,
	options?: { formattingOptions?: FormattingOptions },
): string {
	const edits = modify(text, [...path], value, options ?? { formattingOptions: { insertSpaces: false, tabSize: 3 } });
	const nextText = applyEdits(text, edits);
	const validation = parseJsonc(nextText);
	if (!validation.ok) {
		throw new Error(validation.error.map((error) => error.message).join("; "));
	}
	return nextText;
}
