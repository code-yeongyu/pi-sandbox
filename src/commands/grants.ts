import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { type GrantClass, parseGrantClass, typedGrantRequestId } from "../approvals/store.js";
import { loadGrantsFile } from "../config/load.js";
import type { ApprovalDecision } from "../config/schema.js";

export type ParsedGrantArgs = {
	readonly class: GrantClass;
	readonly target: string;
};

export function parseGrantArgs(args: string): ParsedGrantArgs | null {
	const [rawClass, ...targetParts] = args
		.trim()
		.split(/\s+/)
		.filter((part) => part.length > 0);
	if (rawClass === undefined || targetParts.length === 0) return null;
	const grantClass = parseGrantClass(rawClass);
	if (grantClass === null) return null;
	const target = targetParts.join(" ");
	if (!validTarget(grantClass, target)) return null;
	return { class: grantClass, target };
}

export async function persistProjectGrant(
	cwd: string,
	grant: ParsedGrantArgs,
	action: "allow" | "deny",
): Promise<{ readonly ok: true; readonly requestId: string } | { readonly ok: false; readonly message: string }> {
	const requestId = typedGrantRequestId(grant.class, grant.target);
	const loaded = await loadGrantsFile(cwd, "project");
	if (!loaded.ok) return { ok: false, message: `Failed to load grants: ${loaded.error.kind}` };
	const nextGrant: ApprovalDecision = {
		requestId,
		action,
		scope: "project",
		mutationTarget: "project-config",
	};
	const withoutExisting = loaded.value.filter((entry) => entry.requestId !== requestId);
	await writeProjectGrants(cwd, [...withoutExisting, nextGrant]);
	return { ok: true, requestId };
}

async function writeProjectGrants(cwd: string, grants: ReadonlyArray<ApprovalDecision>): Promise<void> {
	const directory = join(cwd, ".pi");
	await mkdir(directory, { recursive: true });
	await writeFile(join(directory, "sandbox.grants.jsonc"), `${JSON.stringify(grants, null, "\t")}\n`, "utf8");
}

function validTarget(grantClass: GrantClass, target: string): boolean {
	if (target.length === 0) return false;
	if (grantClass === "port") {
		const port = Number(target);
		return Number.isInteger(port) && port >= 0 && port <= 65_535;
	}
	return true;
}
