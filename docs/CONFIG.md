# Configuration reference

pi-sandbox policy is expressed in JSONC (JSON with comments) and loaded from two layers: global user config and project config. Grants (approvals) are stored in separate JSONC files.

## File locations

| File | Location | Purpose |
|------|----------|---------|
| Project policy | `.pi/sandbox.jsonc` | Per-project sandbox policy |
| Global policy | `~/.pi/sandbox.json` or `~/.pi/agent/sandbox.json` (legacy) | User-wide defaults |
| Project grants | `.pi/sandbox.grants.jsonc` | Per-project approval decisions |
| Global grants | `~/.pi/sandbox.grants.jsonc` | User-wide approval decisions |

All config files are optional. Missing files are treated as empty configs.

## Top-level schema

The config object supports these top-level keys (defined in [src/config/schema.ts](../src/config/schema.ts)):

| Key | Type | Default |
|-----|------|---------|
| `backend` | BackendConfig | `{ kind: "auto" }` |
| `fallbackBackends` | BackendKind[] | `[]` |
| `backendMissing` | `"fail" \| "prompt" \| "disabled-by-user"` | `"prompt"` |
| `network` | NetworkPolicy | `{ mode: "deny" }` |
| `file` | FilePolicy | see below |
| `process` | ProcessPolicy | `{ isolation: true, gitHooks: "prompt", capDrop: [] }` |
| `env` | EnvPolicy | see below |
| `approvals` | ApprovalConfig | see below |
| `tui` | TuiConfig | `{ statusLine: true, detailsWidget: "on-block", promptStyle: "compact" }` |
| `agentAwareness` | AgentAwarenessConfig | see below |
| `audit` | AuditConfig | `{ enabled: true, path: ".pi/sandbox-audit.jsonl", includeToolArgs: "redacted" }` |

`backend.kind: "auto"` resolves to `justbash` with `fs: "read-write-root-locked"` for normal session startup. That default keeps file tools working against the project root while still routing operations through the sandbox policy gates.

## Complete annotated example

```jsonc
{
	// Backend selection
	"backend": {
		"kind": "docker",
		"image": "node:22-alpine",
		"networkMode": "none",
		"readonlyRootfs": true,
		"mounts": [
			{ "hostPath": "/host/data", "sandboxPath": "/data", "mode": "readonly", "persist": "host" }
		],
		"pullPolicy": "if-missing",
		"capDrop": ["ALL"],
		"securityOpt": ["no-new-privileges"],
		"tmpfs": []
	},
	"fallbackBackends": ["justbash", "native"],
	"backendMissing": "prompt",

	// Network policy
	"network": {
		"mode": "restricted",
		"default": "deny",
		"allowDomains": ["registry.npmjs.org", "github.com"],
		"denyDomains": ["evil.example"],
		"allowUrlPrefixes": ["https://api.github.com/repos/code-yeongyu/"],
		"allowPorts": [443, 8080],
		"allowCidrs": ["10.0.0.0/8"],
		"denyPrivateNetworks": true,
		"denyMetadata": true,
		"allowUnixSockets": false,
		"scrubProxyEnv": true,
		"dns": "deny"
	},

	// File policy
	"file": {
		"defaultRead": "deny",
		"defaultWrite": "deny",
		"roots": [
			{
				"path": ".",
				"read": true,
				"write": true,
				"create": true,
				"delete": false,
				"persist": "host",
				"followSymlinks": false
			}
		],
		"denySpecialPaths": ["/proc", "/sys", "/dev"],
		"denyMagicLinks": true,
		"highRiskWriteClasses": ["dotenv", "ssh-key", "git-hook", "shell-rc", "npm-script", "executable"],
		"maxReadBytes": 10485760
	},

	// Process policy
	"process": {
		"isolation": true,
		"gitHooks": "prompt",
		"seccompProfile": "",
		"capDrop": []
	},

	// Environment policy
	"env": {
		"clearenv": true,
		"allowlist": ["PATH", "HOME", "TERM", "LANG", "LC_ALL"],
		"denyPatterns": ["*_KEY", "*_TOKEN", "*_SECRET", "*_PASSWORD", "SSH_AUTH_SOCK", "AWS_*", "GCP_*"],
		"scrubProxyEnv": true
	},

	// Approval settings
	"approvals": {
		"interactive": true,
		"defaultOnNoUi": "deny",
		"rememberSession": true,
		"allowProjectWrites": true,
		"allowGlobalWrites": false,
		"batchWindowMs": 250
	},

	// TUI settings
	"tui": {
		"statusLine": true,
		"detailsWidget": "on-block",
		"promptStyle": "compact"
	},

	// Agent awareness
	"agentAwareness": {
		"injectSystemPrompt": true,
		"decorateBlockedToolResults": true,
		"includeAllowedPaths": true,
		"includeAllowedDomains": false,
		"includeAllowedBinaries": true
	},

	// Audit logging
	"audit": {
		"enabled": true,
		"path": ".pi/sandbox-audit.jsonl",
		"includeToolArgs": "redacted"
	}
}
```

## Merge semantics

Config is loaded from two layers and merged in this order:

1. Global config (`~/.pi/sandbox.json`)
2. Project config (`.pi/sandbox.jsonc`)

Project config takes precedence over global config. The merge rules per section:

- **Backend**: project config completely replaces global config. For Docker backends, mounts are deduplicated by `(hostPath, sandboxPath)` tuple.
- **Fallback backends**: concatenated and deduplicated in order.
- **Network (restricted mode)**: `denyDomains` are unioned; `allowDomains` are unioned then filtered against denied domains; `allowUrlPrefixes`, `allowPorts`, `allowCidrs` are unioned; booleans and enums take the project value if present.
- **File**: `denySpecialPaths` are unioned and deduplicated; `roots` are deduplicated by canonical path and filtered against `denySpecialPaths`; `highRiskWriteClasses` are unioned; defaults take the project value.
- **Env**: `allowlist` and `denyPatterns` are unioned and deduplicated; booleans take the project value.
- **Process, approvals, TUI, agentAwareness, audit**: project config completely replaces global config.

### Deny overrides allow

If a domain appears in both `allowDomains` and `denyDomains`, the deny wins. This is enforced during merge by filtering allowed domains against the denied set.

### Narrower overrides broader

Not explicitly implemented; the merge uses simple union and precedence. For fine-grained overrides, use project-specific `roots` with narrower paths.

## Hash bindings

Three hashes are computed during policy normalization and used to invalidate approvals when policy changes:

| Hash | Source | Invalidates when |
|------|--------|-----------------|
| `desiredPolicyHash` | SHA-256 of the merged `DesiredPolicy` (backend, network, file, process, env, approvals, TUI, agentAwareness, audit) | Any top-level policy key changes |
| `grantHash` | SHA-256 of the sorted grant decisions array | Any grant is added, removed, or changed |
| `effectiveCapabilityHash` | SHA-256 of the backend capability contract | Backend kind or capability values change |

The `stableRequestId(operation, rule, policyRevision)` function incorporates `policyRevision` (incremented on every reload) into the request ID. This means approvals granted under a previous policy revision are automatically invalidated when the policy is reloaded.

## Grant classes

Grants are typed approval decisions stored in `.pi/sandbox.grants.jsonc`. Each grant has a `class` and `target`:

| Class | Target format | Example |
|-------|--------------|---------|
| `file.read` | Absolute or relative path prefix | `"/home/user/project/src"` |
| `file.write` | Absolute or relative path prefix | `"/home/user/project/src"` |
| `domain` | Hostname | `"github.com"` |
| `url-prefix` | URL prefix | `"https://api.github.com/repos/code-yeongyu/"` |
| `port` | Port number (0-65535) | `"8080"` |
| `binary` | Binary name | `"node"` |

### Grant file format

```jsonc
[
	{
		"requestId": "typed:domain:github.com",
		"action": "allow",
		"scope": "project",
		"mutationTarget": "project-config"
	},
	{
		"requestId": "typed:file.write:%2Fhome%2Fuser%2Fproject%2Fsrc",
		"action": "deny",
		"scope": "project",
		"mutationTarget": "project-config"
	}
]
```

Grants are evaluated before the interactive prompt. A deny grant blocks immediately; an allow grant bypasses the prompt.

## Schema reference

The canonical JSON Schema is generated to [schema/sandbox.schema.json](../schema/sandbox.schema.json) by `npm run generate:schema`. The schema covers all top-level keys, backend variants, and policy sub-objects.
