// src/lifecycle/orphan-reaper.ts — on startup, sweep stale per-session sandbox roots > TTL
import { readdir, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";

const ORPHAN_TTL_MS = 12 * 60 * 60 * 1000;

export async function reapOrphans(now: Date = new Date()): Promise<void> {
	const root = path.join(tmpdir(), "pi-sandbox");
	let entries: readonly string[];
	try {
		entries = await readdir(root);
	} catch {
		return;
	}
	await Promise.all(
		entries
			.filter((entry) => entry.startsWith("sess-"))
			.map(async (entry) => {
				const fullPath = path.join(root, entry);
				try {
					const info = await stat(fullPath);
					if (now.getTime() - info.mtimeMs > ORPHAN_TTL_MS) await rm(fullPath, { recursive: true, force: true });
				} catch {
					// best effort
				}
			}),
	);
}
