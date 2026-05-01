# Backend reference

pi-sandbox supports five backends. Each section lists the actual capability values from the source, required host dependencies, network model, process isolation primitive, path mapping strategy, probes, limitations, and a minimal config snippet to enable it.

## justbash

A pure-JavaScript virtual shell using the `just-bash` library. No external binaries required. Filesystem is either in-memory or an overlay on a temp directory. Intended for lightweight, cross-platform sandboxing where native OS primitives are unavailable.

### Required dependencies

- Node.js >= 20
- `just-bash` npm package (declared dependency)

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | true |
| fileWrite | true |
| fsPathResolution | `backend-mount-boundary` |
| networkDeny | true |
| networkAllowlist | true |
| networkGateway | true |
| processIsolation | true |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | true |
| persistence | false |
| denialAttribution | true |

### Network model

`proxy` — just-bash network requests are routed through a configurable `NetworkConfig` proxy/allowlist layer inside the JS runtime. No host network namespace is used.

### Process isolation

Namespace — each `new Bash()` instance runs in an isolated JS execution context with its own filesystem, env, and command counter. There is no OS-level PID namespace.

### Path mapping

Mount — host paths under the project root are mapped to `/` inside the sandbox temp directory. Paths outside the project root are rejected with `path_mapping_failed`.

### Probes

The justbash backend accepts a probe control list but currently returns it unchanged (no runtime probes are executed). Health always returns `healthy: true`.

### Known limitations

- No real OS filesystem isolation: the sandbox root is a temp directory on the host filesystem.
- No persistence: sandbox temp directory is deleted on dispose.
- `networkAllowlist` and `networkGateway` are true at the capability level, but the actual network enforcement depends on the `NetworkConfig` passed to `just-bash`.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "justbash",
		"fs": "memory",
		"allowedBinaries": [],
		"allowedLibraries": [],
		"executionLimits": { "maxOutputBytes": 1048576, "maxRuntimeMs": 30000 }
	}
}
```

## docker

Docker container backend. Each bash invocation creates a fresh container from a configured image, runs the command, and removes the container. Intended for environments where Docker is available and strong container isolation is desired.

### Required dependencies

- Docker daemon running on the host
- `dockerode` npm package (declared dependency)

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | false |
| fileWrite | false |
| fsPathResolution | `backend-mount-boundary` |
| networkDeny | true |
| networkAllowlist | false |
| networkGateway | false |
| processIsolation | true |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | true |
| persistence | false |
| denialAttribution | true |

### Network model

`host-bridge` — Docker network mode is configurable (`none`, `bridge`, `host`). `networkDeny` is enforced when `networkMode: "none"`.

### Process isolation

Namespace — each command runs in a fresh Docker container with its own PID namespace, rootfs, and capabilities.

### Path mapping

Mount — the project root is mounted as `/workspace` inside the container. Paths outside the project root are rejected.

### Probes

| Control | Command | Expected result |
|---------|---------|-----------------|
| networkDeny | `curl -m 2 https://example.com` | exit != 0 (when networkMode=none) |
| fsPathResolution | `ls /Users 2>/dev/null \|\| true` | output == "" |
| processIsolation | `capsh --print 2>/dev/null \|\| true` | output contains "Current:" |
| fileWrite | `touch /test-ro >/dev/null 2>&1` | exit != 0 (when readonlyRootfs=true) |

### Known limitations

- `fileRead` and `fileWrite` are false at the capability level because the Docker backend only exposes `bash.exec`; direct file read/write facets are not implemented.
- `networkAllowlist` and `networkGateway` are false; restricted network policy with domain allowlists is not supported.
- No persistence: containers are ephemeral.
- Each command incurs container create/start/remove overhead.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "docker",
		"image": "node:22-alpine",
		"networkMode": "none",
		"readonlyRootfs": true,
		"mounts": [],
		"pullPolicy": "if-missing",
		"capDrop": ["ALL"],
		"securityOpt": ["no-new-privileges"],
		"tmpfs": []
	}
}
```

## native (darwin sandbox-exec)

macOS native sandboxing using the `sandbox-exec` binary and SBPL (Sandbox Profile Language). Intended for macOS hosts where seatbelt profiles provide sufficient isolation.

### Required dependencies

- macOS with `sandbox-exec` binary available (ships with macOS)
- Apple Silicon or Intel Mac; Linux and Windows are unsupported

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | true |
| fileWrite | true |
| fsPathResolution | `realpath-canonical-residual-toctou` |
| networkDeny | true |
| networkAllowlist | false |
| networkGateway | false |
| processIsolation | false |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | false |
| persistence | true |
| denialAttribution | true |

### Network model

`firewalled` — SBPL `network*` deny rules block outbound connections. No domain allowlist support.

### Process isolation

Sandbox-exec — seatbelt profiles limit file and network access but do not provide PID or mount namespace isolation. Process isolation is `simulated`.

### Path mapping

Identity — macOS native paths are used as-is. No sandbox path translation.

### Probes

| Control | Command | Expected result |
|---------|---------|-----------------|
| networkDeny | `sandbox-exec curl https://example.com` | exit != 0 |
| fileWrite | `sandbox-exec sh -c "echo x > probe"` | exit != 0 (when write denied) |
| processIsolation | — | simulated: seatbelt limits process access but does not provide namespace isolation |

### Known limitations

- `networkAllowlist` and `networkGateway` are unsupported. Restricted network policy falls back to `deny`.
- `processIsolation` is false at capability level; isolation is `simulated`.
- `pathMapping` is unsupported; paths are identity-mapped.
- `sandbox-exec` is deprecated by Apple but still functional on current macOS versions.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "native",
		"platform": "darwin",
		"mechanism": "sandbox-exec"
	}
}
```

## native (linux bwrap)

Linux native sandboxing using `bubblewrap` (`bwrap`). Creates unprivileged user namespaces with unshared PID, network, and mount namespaces. Intended for Linux hosts where bwrap is available.

### Required dependencies

- Linux host with `bwrap` binary installed
- Unprivileged user namespaces enabled (most modern distributions)

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | true |
| fileWrite | true |
| fsPathResolution | `backend-mount-boundary` |
| networkDeny | true |
| networkAllowlist | false |
| networkGateway | false |
| processIsolation | true |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | false |
| persistence | true |
| denialAttribution | true |

### Network model

`host-bridge` — `--unshare-net` creates a private network namespace with no connectivity. `networkDeny` is enforced when the namespace is unshared.

### Process isolation

Namespace — `--unshare-user`, `--unshare-pid`, and `--unshare-net` create isolated namespaces. `--die-with-parent` ensures cleanup.

### Path mapping

Identity — Linux native paths are used as-is. Bind mounts are used to expose only required host paths.

### Probes

| Control | Command | Expected result |
|---------|---------|-----------------|
| networkDeny | `bwrap --unshare-net curl https://example.com` | exit != 0 |
| fileWrite | `bwrap --ro-bind /tmp /tmp sh -c "echo x > /tmp/probe"` | exit != 0 |
| processIsolation | `bwrap --unshare-pid ps -eo pid=` | low PID count (isolated namespace) |
| fsPathResolution | `bwrap cat /proc/self/mem` | exit != 0 (magic-link defense) |

### Known limitations

- `networkAllowlist` and `networkGateway` are unsupported. Restricted network policy falls back to `deny`.
- `pathMapping` is unsupported; paths are identity-mapped.
- Requires `bwrap` binary on the host PATH.
- Windows AppContainer and WSL2-bwrap are planned but not implemented.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "native",
		"platform": "linux",
		"mechanism": "bwrap"
	}
}
```

## qemu

Full VM isolation using QEMU system emulation. Each command boots a minimal Linux guest, runs the command, and powers off. Intended for maximum isolation where container or namespace isolation is insufficient.

### Required dependencies

- `qemu-system-x86_64` binary on the host PATH
- Smoke fixture assets (kernel + initrd) or user-provided assets

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | true |
| fileWrite | depends on shareMode |
| fsPathResolution | `backend-mount-boundary` |
| networkDeny | true |
| networkAllowlist | false |
| networkGateway | false |
| processIsolation | true |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | true |
| persistence | false |
| denialAttribution | true |

`fileWrite` is true only when `shareMode` ends with `readwrite` (e.g., `9p-readwrite`, `virtiofs-readwrite`).

### Network model

`none` / `hostfwd` — `-nic none` disables all networking. `-netdev user` enables user-mode networking with host forwarding.

### Process isolation

VM — full hardware virtualization boundary. Each command runs in a separate guest OS instance.

### Path mapping

Mount — project root is shared via 9p or virtiofs as `/workspace` inside the guest.

### Probes

| Control | Command | Expected result |
|---------|---------|-----------------|
| processIsolation | — | passed: QEMU full VM boundary |
| networkDeny | `wget -T 2 -O - http://example.com` | exit != 0 (when network=none) |
| fileWrite | `touch /workspace/.pi-sandbox-qemu-probe` | exit != 0 (when shareMode ends with readonly) |
| fsPathResolution | `test ! -e /host && test ! -e /mnt/host` | exit == 0 |

### Known limitations

- `virtiofs` share modes are unsupported in the smoke backend because they require a `virtiofsd` supervisor. Use `9p-readonly` or `9p-readwrite` instead.
- `networkAllowlist` and `networkGateway` are unsupported.
- Each command incurs full VM boot overhead (seconds, not milliseconds).
- No persistence: guest state is ephemeral unless snapshot is disabled.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "qemu",
		"assets": { "kind": "smoke", "fixtureName": "default", "checksumSha256": "unset" },
		"cpus": 1,
		"memoryMb": 512,
		"shareMode": "9p-readonly",
		"network": "none",
		"snapshot": true
	}
}
```

## ssh

Remote execution backend using `ssh2`. Commands run on a remote host via SSH. Intended for offloading sandboxed execution to a dedicated remote machine.

### Required dependencies

- `ssh2` npm package (declared dependency)
- Remote SSH server reachable from the host
- Valid SSH credentials (private key, password, agent, or keyboard-interactive)

### BackendCapability

| Control | Value |
|---------|-------|
| fileRead | false |
| fileWrite | false |
| fsPathResolution | `unsupported` |
| networkDeny | false |
| networkAllowlist | false |
| networkGateway | false |
| processIsolation | false |
| envScrub | true |
| stdoutCapture | `streaming` |
| pathMapping | true |
| persistence | true |
| denialAttribution | false |

### Network model

`proxy` — the remote host's network is used. No local network controls are enforced.

### Process isolation

None — remote host process isolation depends on the remote machine's configuration. SSH backend does not create namespaces or sandboxes on the remote side.

### Path mapping

SFTP / rsync — local project root is mapped to `remoteRoot` on the remote host. File sync happens via `rsync` or `sftp` before/after commands.

### Probes

| Control | Command | Expected result |
|---------|---------|-----------------|
| processIsolation | — | passed: strict host verifier rejects mismatched SHA-256 fingerprint |
| envScrub | `printenv` on remote | no `SSH_AUTH_SOCK` or secret env keys leaked |
| pathMapping | — | passed: SSH host path maps to configured remoteRoot |

Other controls return `failed` with reason `ssh-control-unverified-until-remote-guard`.

### Known limitations

- `fileRead`, `fileWrite`, `fsPathResolution`, `networkDeny`, `networkAllowlist`, `networkGateway`, and `processIsolation` are unsupported at the capability level.
- `denialAttribution` is false; SSH backend errors are reported generically.
- SSHv1 authentication is unsupported (schema allows it but it is not recommended).
- Agent forwarding is off by default; the remote env is scrubbed of `SSH_AUTH_SOCK` and secret patterns.
- Strict host key verification is enforced by default.

### Minimum config

```jsonc
{
	"backend": {
		"kind": "ssh",
		"host": "localhost",
		"port": 22,
		"username": "sandbox",
		"auth": { "kind": "kbi" },
		"hostVerification": { "strict": true },
		"remoteRoot": "/tmp/pi-sandbox",
		"sync": "sftp",
		"proxyJump": []
	}
}
```

## Platform support summary

| Platform | Supported backends | Notes |
|----------|-------------------|-------|
| macOS | justbash, docker, native (sandbox-exec), qemu, ssh | sandbox-exec requires macOS host |
| Linux | justbash, docker, native (bwrap), qemu, ssh | bwrap requires binary on host |
| Windows | justbash, docker, qemu, ssh | AppContainer/WSL2-bwrap planned, not implemented |
