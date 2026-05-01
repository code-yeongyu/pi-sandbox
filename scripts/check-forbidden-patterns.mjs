#!/usr/bin/env node
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative, sep } from "node:path";
import ts from "typescript";

const root = process.cwd();
const targetRoots = ["src", "test", "vitest.config.ts"].map((entry) => join(root, entry));
const violations = [];

function isTypeScriptFile(path) {
	return path.endsWith(".ts") && !path.endsWith(".d.ts");
}

function collectFiles(path) {
	const stats = statSync(path);
	if (stats.isFile()) return isTypeScriptFile(path) ? [path] : [];
	if (!stats.isDirectory()) return [];
	return readdirSync(path).flatMap((entry) => collectFiles(join(path, entry)));
}

function report(sourceFile, node, message) {
	const start = node.getStart(sourceFile);
	const position = sourceFile.getLineAndCharacterOfPosition(start);
	violations.push(`${relative(root, sourceFile.fileName)}:${position.line + 1}:${position.character + 1} ${message}`);
}

function sourceText(sourceFile, node) {
	return sourceFile.text.slice(node.getStart(sourceFile), node.getEnd());
}

function isJsonParseCall(node) {
	return (
		ts.isCallExpression(node) &&
		ts.isPropertyAccessExpression(node.expression) &&
		node.expression.expression.getText() === "JSON" &&
		node.expression.name.text === "parse"
	);
}

function visit(sourceFile, node) {
	if (ts.isEnumDeclaration(node)) report(sourceFile, node, "enum declarations are forbidden");
	if (ts.isThrowStatement(node) && node.expression && ts.isStringLiteralLike(node.expression)) {
		report(sourceFile, node, "thrown strings are forbidden");
	}
	if (ts.isCallExpression(node) && ts.isPropertyAccessExpression(node.expression)) {
		if (node.expression.expression.getText() === "Object" && node.expression.name.text === "assign") {
			report(sourceFile, node, "Object.assign is forbidden for config-sensitive code");
		}
	}
	if (isJsonParseCall(node) && !relative(root, sourceFile.fileName).split(sep).join("/").endsWith("src/config/jsonc-parse.ts")) {
		report(sourceFile, node, "raw JSON.parse is forbidden outside src/config/jsonc-parse.ts");
	}
	if (ts.isAsExpression(node)) {
		const text = sourceText(sourceFile, node).replace(/\s+/g, " ");
		if (/ as unknown as /.test(text)) report(sourceFile, node, "as unknown as double casts are forbidden");
	}
	ts.forEachChild(node, (child) => visit(sourceFile, child));
}

for (const file of targetRoots.flatMap((entry) => collectFiles(entry))) {
	const sourceFile = ts.createSourceFile(file, readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
	visit(sourceFile, sourceFile);
}

if (violations.length > 0) {
	console.error("Forbidden patterns found:");
	for (const violation of violations) console.error(`- ${violation}`);
	process.exit(1);
}

console.log("Forbidden pattern check passed.");
