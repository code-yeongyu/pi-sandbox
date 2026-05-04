import type { EffectivePolicy, ProbeResult } from "../policy/effective.js";
import type { SandboxMode } from "../sandbox/mode.js";
import type { SandboxBlockV1 } from "../security/failure.js";

export type EnvInput = {
	readonly name: string;
	readonly class: "secret" | "config" | "binary-path" | "socket-path";
	readonly present: boolean;
};

export function toTuiFooter(effectivePolicy: EffectivePolicy, mode: SandboxMode): string {
	const backend =
		mode.kind === "enforcing" ? mode.backend : mode.kind === "missing" ? (mode.backend ?? "missing") : "disabled";
	const omitted = effectivePolicy.backend.omittedControls.length;
	const shortRevision = `${effectivePolicy.policyRevision}:${effectivePolicy.desiredPolicyHash.slice(0, 8)}`;
	return `sandbox ${mode.kind} ${backend} fs=${effectivePolicy.backend.capabilities.fsPathResolution} net=${networkLabel(effectivePolicy)} omitted=${omitted} grants=${effectivePolicy.grantHash.slice(0, 8)} rev=${shortRevision}`;
}

export function toTuiWidget(
	effectivePolicy: EffectivePolicy,
	mode: SandboxMode,
	lastBlock?: SandboxBlockV1,
): readonly string[] {
	const lines = [
		`pi-sandbox: ${mode.kind}`,
		`backend: ${effectivePolicy.backend.kind} (${effectivePolicy.backend.status})`,
		`file: read=${stateFor(effectivePolicy, "fileRead")} write=${stateFor(effectivePolicy, "fileWrite")}`,
		`network: ${networkLabel(effectivePolicy)} allowlist=${stateFor(effectivePolicy, "networkAllowlist")}`,
		`omitted controls: ${effectivePolicy.backend.omittedControls.join(",") || "none"}`,
		`policy: ${effectivePolicy.desiredPolicyHash} revision=${effectivePolicy.policyRevision}`,
	];
	if (lastBlock !== undefined)
		lines.push(`last block: ${lastBlock.policyArea} ${lastBlock.sanitizedTarget} ${lastBlock.matchedRule}`);
	return lines;
}

export function toSandboxStatus(
	effectivePolicy: EffectivePolicy,
	mode: SandboxMode,
	probeResults: readonly ProbeResult[],
	envInputs: readonly EnvInput[],
): string {
	const probeLines = probeResults.map((probe) => {
		if (probe.kind === "passed") return `probe ${probe.control}: passed (${probe.evidence})`;
		const stderr = probe.stderrExcerpt === undefined ? "" : ` stderr=${probe.stderrExcerpt}`;
		return `probe ${probe.control}: failed command=${probe.command} exit=${probe.exitCode} reason=${probe.reason}${stderr}`;
	});
	const envLines = envInputs.map(
		(input) => `${input.name}: ${input.present ? "present" : "absent"}/${input.class}/redacted`,
	);
	return [
		"pi-sandbox status",
		`mode: ${mode.kind}`,
		`backend: ${effectivePolicy.backend.kind}`,
		`enforcement: ${effectivePolicy.backend.status}`,
		`policyHash: ${effectivePolicy.desiredPolicyHash}`,
		`grantHash: ${effectivePolicy.grantHash}`,
		`effectiveCapabilityHash: ${effectivePolicy.effectiveCapabilityHash}`,
		`omittedControls: ${effectivePolicy.backend.omittedControls.join(",") || "none"}`,
		"probes:",
		...(probeLines.length === 0 ? ["probe none: not-run"] : probeLines),
		"env:",
		...(envLines.length === 0 ? ["env none: absent/config/redacted"] : envLines),
	].join("\n");
}

function stateFor(
	effectivePolicy: EffectivePolicy,
	control: keyof EffectivePolicy["backend"]["effectiveControls"],
): string {
	return effectivePolicy.backend.effectiveControls[control].state;
}

function networkLabel(effectivePolicy: EffectivePolicy): string {
	if (effectivePolicy.network.mode === "restricted") return "restricted";
	return effectivePolicy.network.mode;
}
