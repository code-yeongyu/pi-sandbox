export type GrantClass = "file.read" | "file.write" | "domain" | "url-prefix" | "port" | "binary";

export type Grant = {
	readonly requestId: string;
	readonly class: GrantClass;
	readonly target: string;
	readonly addedAt: number;
};

export type TypedGrantAction = "allow" | "deny";

export type TypedGrant = {
	readonly action: TypedGrantAction;
	readonly class: GrantClass;
	readonly target: string;
};

export const GRANT_CLASSES = ["file.read", "file.write", "domain", "url-prefix", "port", "binary"] as const;

export function parseGrantClass(value: string): GrantClass | null {
	for (const grantClass of GRANT_CLASSES) {
		if (value === grantClass) return grantClass;
	}
	return null;
}

export function typedGrantRequestId(grantClass: GrantClass, target: string): string {
	return `typed:${grantClass}:${encodeURIComponent(target)}`;
}

export function parseTypedGrantRequestId(action: TypedGrantAction, requestId: string): TypedGrant | null {
	if (!requestId.startsWith("typed:")) return null;
	const [, rawClass, encodedTarget] = requestId.split(":", 3);
	if (rawClass === undefined || encodedTarget === undefined) return null;
	const grantClass = parseGrantClass(rawClass);
	if (grantClass === null) return null;
	try {
		return { action, class: grantClass, target: decodeURIComponent(encodedTarget) };
	} catch {
		return null;
	}
}

export class ApprovalStore {
	readonly #grants = new Map<string, Grant>();

	public add(grant: Grant): void {
		this.#grants.set(grant.requestId, grant);
	}

	public has(requestId: string): boolean {
		return this.#grants.has(requestId);
	}

	public list(): readonly Grant[] {
		return [...this.#grants.values()].sort((left, right) => left.addedAt - right.addedAt);
	}

	public remove(requestId: string): void {
		this.#grants.delete(requestId);
	}

	public clear(): void {
		this.#grants.clear();
	}
}
