export type PromptBatcher = {
	readonly run: (requestId: string, prompt: () => Promise<boolean>) => Promise<boolean>;
	readonly clear: () => void;
};

type CachedPrompt = {
	readonly createdAt: number;
	readonly result: Promise<boolean>;
};

export function createPromptBatcher(windowMs: number, now: () => number = () => Date.now()): PromptBatcher {
	const prompts = new Map<string, CachedPrompt>();

	return {
		run(requestId, prompt) {
			const current = now();
			const cached = prompts.get(requestId);
			if (cached !== undefined && current - cached.createdAt <= windowMs) return cached.result;
			const result = prompt().finally(() => {
				const stored = prompts.get(requestId);
				if (stored?.result === result && now() - stored.createdAt > windowMs) prompts.delete(requestId);
			});
			prompts.set(requestId, { createdAt: current, result });
			return result;
		},
		clear() {
			prompts.clear();
		},
	};
}
