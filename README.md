# pi-sandbox

[![ci](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/pi-sandbox.svg)](https://www.npmjs.com/package/pi-sandbox)
[![license](https://img.shields.io/npm/l/pi-sandbox.svg)](https://github.com/code-yeongyu/pi-sandbox/blob/main/LICENSE)

Policy-aware sandboxing extension for [pi-mono](https://github.com/mariozechner/pi-mono) that intercepts `bash`, `read`, `write`, and `edit` tool operations and enforces per-project sandbox policy across native, Docker, justbash, and QEMU sandbox backends. SSH is a remote transport profile with file facets and env scrub semantics.

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

| Control | justbash | docker | native (darwin) | native (linux) | qemu | ssh transport |
|---------|:--------:|:------:|:---------------:|:--------------:|:----:|:-------------:|
| fileRead | host-root | bind mount | host-root | host-root | shared root | remoteRoot |
| fileWrite | host-root | bind mount | host-root | host-root | share mode | remoteRoot |
| fsPathResolution | mount-boundary | mount-boundary | realpath+toctou | mount-boundary | mount-boundary | mount-boundary |
| networkDeny | virtual shell | network none | sandbox-exec | bwrap | network none | transport only |
| restricted network | config error | config error | config error | config error | config error | config error |
| processIsolation | virtual shell | container | seatbelt policy | bwrap | VM | transport only |
| envScrub | local | container | local | local | guest | remote |
| stdoutCapture | streaming | streaming | streaming | streaming | streaming | streaming |
| pathMapping | host-root | bind mount | identity | identity | shared root | remoteRoot |
| persistence | ephemeral | ephemeral | yes | yes | ephemeral | remoteRoot lifecycle |
| denialAttribution | structured | structured | structured | structured | structured | generic |

See [docs/BACKENDS.md](docs/BACKENDS.md) for per-backend capability tables, probe semantics, and operational limits.

## Configuration

Policy lives in JSONC files:

- `.pi/sandbox.jsonc` — project policy
- `~/.pi/sandbox.json` — global user policy (lower precedence)
- `.pi/sandbox.grants.jsonc` — project approval grants
- `~/.pi/sandbox.grants.jsonc` — global approval grants

See [docs/CONFIG.md](docs/CONFIG.md) for the full schema, merge semantics, hash bindings, and annotated examples.

CI release gates can require one backend smoke with `npm run test:live-required`; it sets `PI_SANDBOX_REQUIRE_LIVE=1` and fails if the live smoke cannot execute.

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
