import { readFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { type JsoncParseError, parseJsonc } from "./jsonc-parse.js";
import { mergeConfigs } from "./merge.js";
import {
	type ApprovalDecision,
	ApprovalDecisionSchema,
	type Result,
	type SandboxConfigParseIssue,
	SandboxConfigTopLevelKeys,
	type SandboxRawConfig,
	SandboxRawConfigSchema,
} from "./schema.js";

export type LoadError =
	| { kind: "io"; path: string; cause: string }
	| { kind: "parse"; path: string; issues: ReadonlyArray<JsoncParseError> }
	| { kind: "validation"; path: string; issues: ReadonlyArray<SandboxConfigParseIssue> };

type LoadedConfig = {
	path: string;
	config: SandboxRawConfig;
};

const primaryGlobalConfigPath = (): string => join(homedir(), ".pi", "sandbox.json");
const legacyGlobalConfigPath = (): string => join(homedir(), ".pi", "agent", "sandbox.json");
const globalGrantsPath = (): string => join(homedir(), ".pi", "sandbox.grants.jsonc");
const projectConfigPath = (cwd: string): string => join(cwd, ".pi", "sandbox.json");
const projectGrantsPath = (cwd: string): string => join(cwd, ".pi", "sandbox.grants.jsonc");

function issueFromZod(issue: {
	path: ReadonlyArray<PropertyKey>;
	message: string;
	code: string;
}): SandboxConfigParseIssue {
	return {
		path: issue.path.filter(
			(segment): segment is string | number => typeof segment === "string" || typeof segment === "number",
		),
		message: issue.message,
		code: issue.code,
	};
}

function causeString(cause: unknown): string {
	if (cause instanceof Error) return cause.message;
	return String(cause);
}

function isMissingFile(cause: unknown): boolean {
	return typeof cause === "object" && cause !== null && "code" in cause && cause.code === "ENOENT";
}

async function readOptionalText(path: string): Promise<Result<string | null, LoadError>> {
	try {
		return { ok: true, value: await readFile(path, "utf8") };
	} catch (cause) {
		if (isMissingFile(cause)) return { ok: true, value: null };
		return { ok: false, error: { kind: "io", path, cause: causeString(cause) } };
	}
}

function validateRawConfig(path: string, value: unknown): Result<SandboxRawConfig, LoadError> {
	const result = SandboxRawConfigSchema.safeParse(value);
	if (result.success) return { ok: true, value: result.data };
	return { ok: false, error: { kind: "validation", path, issues: result.error.issues.map(issueFromZod) } };
}

function validateGrants(path: string, value: unknown): Result<ReadonlyArray<ApprovalDecision>, LoadError> {
	const result = ApprovalDecisionSchema.array().readonly().safeParse(value);
	if (result.success) return { ok: true, value: result.data };
	return { ok: false, error: { kind: "validation", path, issues: result.error.issues.map(issueFromZod) } };
}

async function loadConfigFile(path: string): Promise<Result<LoadedConfig, LoadError>> {
	const text = await readOptionalText(path);
	if (!text.ok) return text;
	if (text.value === null) return { ok: true, value: { path, config: {} } };
	const parsed = parseJsonc(text.value, SandboxConfigTopLevelKeys);
	if (!parsed.ok) return { ok: false, error: { kind: "parse", path, issues: parsed.error } };
	const validated = validateRawConfig(path, parsed.value);
	if (!validated.ok) return validated;
	return { ok: true, value: { path, config: validated.value } };
}

export async function loadGlobalConfig(): Promise<Result<SandboxRawConfig, LoadError>> {
	const primary = await loadConfigFile(primaryGlobalConfigPath());
	if (!primary.ok) return primary;
	if (Object.keys(primary.value.config).length > 0) return { ok: true, value: primary.value.config };
	const legacy = await loadConfigFile(legacyGlobalConfigPath());
	if (!legacy.ok) return legacy;
	return { ok: true, value: legacy.value.config };
}

export async function loadProjectConfig(cwd: string): Promise<Result<SandboxRawConfig, LoadError>> {
	const loaded = await loadConfigFile(projectConfigPath(cwd));
	if (!loaded.ok) return loaded;
	return { ok: true, value: loaded.value.config };
}

export async function loadGrantsFile(
	cwd: string,
	scope: "project" | "global",
): Promise<Result<ReadonlyArray<ApprovalDecision>, LoadError>> {
	const path = scope === "project" ? projectGrantsPath(cwd) : globalGrantsPath();
	const text = await readOptionalText(path);
	if (!text.ok) return text;
	if (text.value === null) return { ok: true, value: [] };
	const parsed = parseJsonc(text.value);
	if (!parsed.ok) return { ok: false, error: { kind: "parse", path, issues: parsed.error } };
	return validateGrants(path, parsed.value);
}

export async function loadFullConfig(
	cwd: string,
): Promise<Result<{ merged: SandboxRawConfig; grants: ReadonlyArray<ApprovalDecision> }, LoadError>> {
	const globalConfig = await loadGlobalConfig();
	if (!globalConfig.ok) return globalConfig;
	const projectConfig = await loadProjectConfig(cwd);
	if (!projectConfig.ok) return projectConfig;
	const globalGrants = await loadGrantsFile(cwd, "global");
	if (!globalGrants.ok) return globalGrants;
	const projectGrants = await loadGrantsFile(cwd, "project");
	if (!projectGrants.ok) return projectGrants;
	return {
		ok: true,
		value: {
			merged: mergeConfigs([
				{ name: "global", config: globalConfig.value },
				{ name: "project", config: projectConfig.value },
			]),
			grants: [...globalGrants.value, ...projectGrants.value],
		},
	};
}
