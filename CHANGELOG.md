# Changelog

All notable changes to this project are documented in this file.

## [0.0.1] - 2026-05-01

### Added

- Five sandbox backends: `justbash` (virtual shell), `docker` (container per command), `native` (darwin `sandbox-exec` and linux `bwrap`), `qemu` (full VM), `ssh` (remote execution)
- Backend registry with availability probing and fallback chain resolution
- `SandboxManager` orchestrating policy decisions, backend lifecycle, and operation execution
- Policy decision engine with support for file, network, process, and bash operations
- 12 stable `SandboxBlockV1` error codes with typed Zod schemas
- Effective policy normalization with capability hash binding and control state taxonomy (`enforced`, `simulated`, `unverified`, `unsupported`)
- JSONC config loader with project/global merge semantics and grant file support
- TUI footer and widget showing backend status, control states, and recent blocks
- Five slash commands: `/sandbox`, `/sandbox-status`, `/sandbox-switch`, `/sandbox-allow`, `/sandbox-deny`
- Approval store with typed grants (`file.read`, `file.write`, `domain`, `url-prefix`, `port`, `binary`)
- Prompt batcher to deduplicate approval requests within a 250ms window
- Streaming secret redactor for stdout/stderr output
- Environment scrub with allowlist, deny patterns, and proxy key removal
- Magic-link defense blocking `/proc/self/fd` traversal
- Path canonicalization with TOCTOU defense notes
- Tool adapters for `bash`, `read`, `write`, and `edit` operations
- Agent awareness injection into system prompts
- Audit logging to `.pi/sandbox-audit.jsonl`
- CI workflow with typecheck, lint, forbidden-pattern checks, unit tests, integration tests, and package dry-run

### Security

- Defined threat model covering RCE defense, exfiltration prevention, and destructive write protection
- Documented what pi-sandbox does not defend against (kernel exploits, hypervisor escapes, pi-mono bugs)
- SSH backend enforces strict host key verification and env scrub by default
- High-risk write classification for `.env`, `.ssh/*`, git hooks, shell rc files, `package.json`, and executables

### Documentation

- Added README.md with quick start, feature matrix, and architecture diagram
- Added docs/BACKENDS.md with per-backend capability tables and probe semantics
- Added docs/CONFIG.md with schema reference, merge semantics, and hash bindings
- Added docs/SECURITY.md with threat model, block codes, and control state taxonomy
- Added CHANGELOG.md (this file)
