# pi-sandbox

[![ci](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/pi-sandbox.svg)](https://www.npmjs.com/package/pi-sandbox)
[![license](https://img.shields.io/npm/l/pi-sandbox.svg)](https://github.com/code-yeongyu/pi-sandbox/blob/main/LICENSE)

Policy-aware sandboxing extension for [pi-mono](https://github.com/mariozechner/pi-mono) that intercepts `bash`, `read`, `write`, and `edit` tool operations and enforces per-project sandbox policy across five isolation backends.

## Quick start

```bash
# 1. Install the extension
npm install pi-sandbox

# 2. Create a project policy
mkdir -p .pi && cat > .pi/sandbox.jsonc <<'EOF'
{
	"backend": { "kind": "docker", "image": "node:22-alpine" },
	"network": { "mode": "deny" },
	"file": {
		"defaultRead": "allow",
		"defaultWrite": "deny",
		"roots": [{ "path": ".", "read": true, "write": true }]
	}
}
EOF

# 3. Load into pi
pi -e ./node_modules/pi-sandbox/src/index.ts
```

## Feature matrix

| Control | justbash | docker | native (darwin) | native (linux) | qemu | ssh |
|---------|:--------:|:------:|:---------------:|:--------------:|:----:|:---:|
| fileRead | yes | no | yes | yes | yes | no |
| fileWrite | yes | no | yes | yes | rw only | no |
| fsPathResolution | mount-boundary | mount-boundary | realpath+toctou | mount-boundary | mount-boundary | unsupported |
| networkDeny | yes | yes | yes | yes | yes | no |
| networkAllowlist | yes | no | no | no | no | no |
| processIsolation | yes | yes | simulated | yes | yes | no |
| envScrub | yes | yes | yes | yes | yes | yes |
| stdoutCapture | streaming | streaming | streaming | streaming | streaming | streaming |
| pathMapping | yes | yes | no | no | yes | yes |
| persistence | no | no | yes | yes | no | yes |
| denialAttribution | yes | yes | yes | yes | yes | no |

See [docs/BACKENDS.md](docs/BACKENDS.md) for per-backend capability tables, probe semantics, and honest "unsupported" listings.

## Configuration

Policy lives in JSONC files:

- `.pi/sandbox.jsonc` — project policy
- `~/.pi/sandbox.json` — global user policy (lower precedence)
- `.pi/sandbox.grants.jsonc` — project approval grants
- `~/.pi/sandbox.grants.jsonc` — global approval grants

See [docs/CONFIG.md](docs/CONFIG.md) for the full schema, merge semantics, hash bindings, and annotated examples.

## TUI and slash commands

The extension registers a TUI footer and widget showing the active backend, control states, and recent blocks. Five slash commands are available:

| Command | Description |
|---------|-------------|
| `/sandbox` | Help and status summary |
| `/sandbox-status` | Full status with policy hashes and approvals |
| `/sandbox-switch <backend>` | Validate a backend kind switch |
| `/sandbox-allow <class> <target>` | Persist a typed allow grant |
| `/sandbox-deny <class> <target>` | Persist a typed deny grant |

See [docs/SECURITY.md](docs/SECURITY.md) for the threat model, block codes, and approval flow.

## Architecture

```
+--------------------------------------------------+
|  pi-mono session                                  |
|  +---------------------------------------------+  |
|  |  pi-sandbox extension                        |  |
|  |  +----------------+  +--------------------+  |  |
|  |  | SandboxManager |->| SandboxBackend     |  |  |
|  |  |  - decide()    |  |  - bash.exec()     |  |  |
|  |  |  - run()       |  |  - lifecycle       |  |  |
|  |  +----------------+  +--------------------+  |  |
|  |         ^                ^                  |  |
|  |         |                |                  |  |
|  |  +----------------+  +--------------------+  |  |
|  |  | EffectivePolicy|  | PathMapper         |  |  |
|  |  |  - backend     |  |  - hostToSandbox   |  |  |
|  |  |  - file        |  |  - sandboxToHost   |  |  |
|  |  |  - network     |  +--------------------+  |  |
|  |  +----------------+                         |  |
|  |         ^                                    |  |
|  |         |                                    |  |
|  |  +----------------+  +--------------------+  |  |
|  |  | ConfigLoader   |  | ApprovalStore      |  |  |
|  |  |  - merge       |  |  - typed grants    |  |  |
|  |  |  - normalize   |  +--------------------+  |  |
|  |  +----------------+                         |  |
|  +---------------------------------------------+  |
+--------------------------------------------------+
```

## Documentation

- [docs/BACKENDS.md](docs/BACKENDS.md) — backend reference
- [docs/CONFIG.md](docs/CONFIG.md) — configuration reference
- [docs/SECURITY.md](docs/SECURITY.md) — security model and threat model
- [CHANGELOG.md](CHANGELOG.md) — release history

## License

MIT. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
