import type { ApprovalStore } from "../approvals/store.js";
import { toTuiWidget } from "../explain/render-tui.js";
import type { EffectivePolicy } from "../policy/effective.js";
import type { SandboxMode } from "../sandbox/mode.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export type SandboxStatusManager = {
	readonly getEffectivePolicy: () => EffectivePolicy;
	readonly getMode: () => SandboxMode;
	readonly getRecentBlocks: () => readonly SandboxBlockV1[];
};

export function formatSandboxStatus(manager: SandboxStatusManager, store: ApprovalStore): string {
	const effectivePolicy = manager.getEffectivePolicy();
	const recentBlocks = manager.getRecentBlocks();
	return [
		"pi-sandbox status",
		...toTuiWidget(effectivePolicy, manager.getMode(), recentBlocks.at(-1)),
		`policy hash prefix: ${effectivePolicy.desiredPolicyHash.slice(0, 8)}`,
		`grant hash prefix: ${effectivePolicy.grantHash.slice(0, 8)}`,
		`approvals: ${store.list().length}`,
		...formatApprovals(store),
		`recent blocks: ${recentBlocks.length}`,
		...recentBlocks.map(formatBlock),
	].join("\n");
}

function formatApprovals(store: ApprovalStore): readonly string[] {
	const grants = store.list();
	if (grants.length === 0) return ["approval none: none"];
	return grants.map((grant) => `approval ${grant.class}: ${grant.target} (${grant.requestId})`);
}

function formatBlock(block: SandboxBlockV1): string {
	return `block ${block.code}: ${block.policyArea} ${block.sanitizedTarget} ${block.matchedRule}`;
}
