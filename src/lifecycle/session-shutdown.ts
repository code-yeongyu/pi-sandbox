// src/lifecycle/session-shutdown.ts — release session root, close docker/ssh/qemu, restore env
import type { ExtensionContext } from "../pi/index.js";
import type { SandboxManager } from "../sandbox/manager.js";

export async function onSessionShutdown(manager: SandboxManager, ctx: ExtensionContext): Promise<void> {
	await manager.dispose();
	ctx.ui.setStatus("sandbox", undefined);
	ctx.ui.setWidget("sandbox", undefined);
}
