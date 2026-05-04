# Backend reference

pi-sandbox 1.0 exposes four sandbox backend families plus an SSH remote transport profile. Backend capability objects remain the source of truth for enforcement state; this page describes how to choose and operate each profile.

## Selection summary

| Profile | Best fit | Isolation primitive | Network model | Persistence |
|---------|----------|---------------------|---------------|-------------|
| `justbash` | local fast path and tests | virtual shell + root lock | deny or allow-all | ephemeral by default |
| `docker` | containerized commands | Docker container per command | Docker network mode | ephemeral container |
| `native` on macOS | local macOS command execution | `sandbox-exec` seatbelt | deny via sandbox profile | host workspace |
| `native` on Linux | local Linux command execution | `bwrap` namespaces | deny via bwrap args | host workspace |
| `qemu` | VM boundary smoke runs | QEMU guest | disabled or hostfwd | snapshot by default |
| `ssh` | remote execution transport | remote host policy | remote host policy | remoteRoot lifecycle |

Restricted network policies require a backend with both `networkGateway` and `networkAllowlist`. The 1.0 backend capability set omits that pair, so `network.mode: "restricted"` is a configuration error at manager initialization. Use `network.mode: "deny"` or `"allow-all"` for the 1.0 release surface.

## justbash

`justbash` runs commands through the `just-bash` interpreter with a locked project root or temporary root.

```jsonc
{
	"backend": { "kind": "justbash", "fs": "read-write-root-locked" },
	"network": { "mode": "deny" }
}
```

Operational notes:

- File operations map through the configured root and reject escapes after realpath checks.
- `allow-all` maps to `dangerouslyAllowFullInternetAccess` in `just-bash`.
- URL-prefix restricted network wiring remains backend-local, but the public capability is conservative because full restricted fields are broader than URL prefixes.

## docker

Docker creates a container per command with hardened host config defaults.

```jsonc
{
	"backend": {
		"kind": "docker",
		"image": "node:22-alpine",
		"networkMode": "none",
		"readonlyRootfs": true
	}
}
```

Operational notes:

- `networkMode: "none"` is the deny-network mode.
- Mounts are explicit and reject ambiguous bind syntax and Docker socket binds.
- Containers use `CapDrop: ["ALL"]` and `no-new-privileges` by default.

## native macOS

macOS native uses `/usr/bin/sandbox-exec` and generated SBPL.

```jsonc
{
	"backend": { "kind": "native", "platform": "darwin", "mechanism": "sandbox-exec" }
}
```

Operational notes:

- File reads and writes are mediated by generated profile rules.
- Network deny is represented in the SBPL profile.
- Path mapping is identity because commands run on the host.

## native Linux

Linux native uses `bwrap`.

```jsonc
{
	"backend": { "kind": "native", "platform": "linux", "mechanism": "bwrap" }
}
```

Operational notes:

- `bwrap` must be present on PATH and able to run the smoke command.
- Commands execute with namespace isolation and a generated bind layout.
- Path mapping is identity because requested host paths remain representable through the bwrap policy.

## qemu

QEMU runs commands through a guest fixture or user-provided kernel/initrd assets.

```jsonc
{
	"backend": {
		"kind": "qemu",
		"assets": { "kind": "smoke", "fixtureName": "default", "checksumSha256": "unset" },
		"network": "none",
		"snapshot": true
	}
}
```

Operational notes:

- `network: "none"` is the deny-network mode.
- `snapshot: true` keeps guest state ephemeral.
- Share mode controls read/write behavior for file facets.

## ssh remote transport profile

SSH is a transport profile backed by `ssh2`. It runs commands on a configured remote host and maps file facets under `remoteRoot`.

```jsonc
{
	"backend": {
		"kind": "ssh",
		"host": "sandbox.example.com",
		"port": 22,
		"username": "sandbox",
		"auth": { "kind": "agent" },
		"hostVerification": { "strict": true },
		"remoteRoot": "/srv/pi-sandbox",
		"proxyJump": []
	}
}
```

Operational notes:

- Host key verification is strict by default.
- Remote env is scrubbed before command execution.
- File facets operate below `remoteRoot`.
- Process and network isolation are properties of the remote host profile you connect to; the SSH transport capability object marks those controls as transport-only.

## Live release smoke

Local tests keep optional heavy backends skippable. CI can require a live smoke with:

```bash
npm run test:live-required
```

The script sets `PI_SANDBOX_REQUIRE_LIVE=1` and runs a backend smoke that fails the release gate if no backend command executes.
