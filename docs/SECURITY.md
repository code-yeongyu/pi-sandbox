# Security model

## Threat model

### What pi-sandbox defends against

1. **Untrusted-prompt RCE on host** — LLM-generated bash commands are intercepted and routed through a sandbox backend with filesystem, network, and process restrictions.
2. **Exfiltration via shell** — Network policy (`deny`, `restricted`, or `allow-all`) blocks or restricts outbound URLs in bash commands. Secret redaction scrubs env values from stdout/stderr streams.
3. **Accidental destructive writes** — File policy denies writes outside configured roots. High-risk write classes (`.env`, `.ssh/*`, git hooks, shell rc files, `package.json`, executables) trigger interactive approval prompts.
4. **Magic-link traversal** — `denyMagicLinks: true` blocks paths traversing `/proc/self/fd` and other procfs magic links that can escape sandbox boundaries.
5. **Secret leakage in tool output** — Streaming redactor replaces env values matching secret patterns with `[REDACTED:name]` in real-time.

### What pi-sandbox does NOT defend against

1. **Kernel exploits** — Backends like bwrap and Docker rely on Linux kernel namespaces. A kernel vulnerability can escape these boundaries.
2. **Hypervisor escapes** — QEMU backend relies on the host hypervisor. A hypervisor bug could compromise the host.
3. **Bugs in pi-mono itself** — If the pi-mono runtime has a vulnerability that bypasses extension hooks, pi-sandbox cannot intercept it.
4. **Social engineering of the user** — Approval prompts ask the user to allow/deny; a user can always choose "allow".
5. **Side-channel exfiltration** — Timing, CPU usage, or other covert channels are not mitigated.

## SandboxBlockV1 codes

pi-sandbox uses 12 stable block codes defined in [src/security/failure.ts](../src/security/failure.ts). Each code has a Zod schema with additional typed fields.

| Code | Policy area | Meaning | When it fires | User action |
|------|-------------|---------|---------------|-------------|
| `permission_denied` | file.read, file.write, network, process | Operation violates policy | File outside roots, network URL denied, binary not allowed | Adjust policy or request a grant |
| `backend_unavailable` | backend | Backend cannot start | Missing binary, wrong platform, daemon down | Install dependency or switch backend |
| `dependency_missing` | backend | Required host binary missing | `bwrap`, `sandbox-exec`, `qemu-system-x86_64` not found | Install the missing dependency |
| `capability_unsupported` | backend | Backend lacks capability for requested control | Restricted network on backend without `networkGateway` | Switch backend or simplify policy |
| `backend_probe_failed` | backend | Runtime probe did not pass | Docker container lacks `capsh`, bwrap namespace not working | Inspect probe output and fix host setup |
| `path_mapping_failed` | backend | Path cannot be mapped into sandbox | Path outside project root on mapped backend | Run from inside the project root |
| `policy_hash_mismatch` | backend | Effective policy hash does not match expected | Config reloaded but operation cached old hash | Retry the operation |
| `secret_denied` | env | Operation tried to access a secret env key | Env scrub blocked access to `*_KEY`, `*_TOKEN`, etc. | Do not rely on secret env in sandbox |
| `magic_link_denied` | file.read | Path traverses a procfs magic link | `/proc/self/fd/...` or similar path detected | Use normal filesystem paths |
| `high_risk_approval_required` | file.write, network, process | Operation needs user approval | Writing `.env`, accessing new domain, spawning binary | Approve via TUI prompt or add a grant |
| `timeout` | process | Command exceeded timeout | Backend killed command after `timeoutMs` | Increase timeout or simplify command |
| `sandbox_backend_error` | backend | Generic backend failure | Unexpected error from backend adapter | Inspect backend logs and retry |

## Control state taxonomy

Each control in `EffectivePolicy.backend.effectiveControls` has a `state` field:

| State | Meaning | Example backend/control |
|-------|---------|------------------------|
| `enforced` | Active runtime enforcement | docker `networkDeny` with `networkMode: "none"` |
| `simulated` | Policy checks exist but no hard kernel/container boundary | darwin `processIsolation` (seatbelt is not a PID namespace) |
| `unverified` | Capability claims true but no probe has run yet | ssh `envScrub` before first probe |
| `unsupported` | Backend cannot implement this control | docker `networkAllowlist` |

Controls listed in `EffectivePolicy.backend.unsupportedControls` are permanently unsupported for the current backend and policy combination. The `normalizeConfig` function may downgrade `restricted` network to `deny` and add `networkAllowlist` to `unsupportedControls` when the backend lacks `networkGateway`.

## Path canonicalization

The decision engine uses `canonicalizeLexical(path)` (Node `path.normalize` + `path.resolve`) to compute a stable path before checking roots. This defends against basic traversal (`../`) but has residual TOCTOU risk because the canonicalization happens in the Node process, not at the kernel openat2 level. Backends with `fsPathResolution: "backend-mount-boundary"` rely on mount/bind restrictions rather than path strings.

## Magic-link defense

When `file.denyMagicLinks` is true, any path matching `/(^|\/)proc\/self\/fd(\/|$)/` is blocked with code `magic_link_denied`. This prevents procfs-based path traversal attacks that can open arbitrary file descriptors.

## Secret redaction streaming

The `StreamingRedactor` scans stdout/stderr chunks for values of env keys matching secret patterns (`*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `SSH_AUTH_SOCK`, `AWS_*`, `GCP_*`, `GOOGLE_APPLICATION_CREDENTIALS`). Matches are replaced with `[REDACTED:name]` in real-time. The redactor is applied to:

- SSH backend stdout/stderr
- justbash backend stdout/stderr

## Environment scrub

The `buildEnv` function constructs a sandbox environment:

1. If `clearenv: true`, start with an empty env.
2. Add only keys in `allowlist` that do not match `denyPatterns`.
3. If `scrubProxyEnv: true`, remove all proxy-related keys (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, and lowercase variants, plus npm proxy config).
4. Force-set `PATH`, `HOME` (to `.pi/sandbox-home`), `TERM`, and `LANG`.

## SSH-specific notes

- **Agent forwarding**: Off by default. The remote command is prefixed with `env -i` and only non-secret env assignments are forwarded.
- **Strict host key verification**: Enabled by default. The `hostVerification.strict` option controls this. A probe verifies that mismatched fingerprints are rejected.
- **Env scrub on remote**: The SSH backend runs `scrubbedCommand` which wraps the remote command in `env -i` with a filtered env. The `probeEnvScrub` probe checks that `SSH_AUTH_SOCK` and secret keys are not present in remote `printenv` output.
- **SSHv1 unsupported**: The schema includes `auth.kind: "v1"` for completeness but SSHv1 is not recommended and may not work with modern servers.
- **Proxy jump**: Supported via `proxyJump` array. Each hop is an `SshBackendConfig` connected in sequence.

## Approval flow

When an operation is not explicitly allowed or denied by policy, the decision engine computes a deterministic request ID:

```
stableRequestId = sha256(stableOperationString(operation) + "\0" + matchedRule + "\0" + policyRevision).slice(0, 24)
```

The `policyRevision` is incremented every time `reloadEffectivePolicy()` runs. This means:

- Approvals are scoped to a specific policy revision.
- Changing the config invalidates previous approvals (they get a new `policyRevision`).
- Grants persisted to `.pi/sandbox.grants.jsonc` survive policy reloads because they are reloaded as part of the new effective policy.

The approval prompt is batched via `PromptBatcher` with a 250ms window to avoid duplicate prompts for the same operation.

## Per-backend control matrix

See [BACKENDS.md](BACKENDS.md) for the full per-backend capability tables and probe details.

## Reporting security issues

Please use [GitHub Security Advisories](https://github.com/code-yeongyu/pi-sandbox/security/advisories) to report vulnerabilities. Do not open public issues for security bugs.
