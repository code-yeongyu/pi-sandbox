# pi-sandbox

[![ci](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml/badge.svg)](https://github.com/code-yeongyu/pi-sandbox/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/pi-sandbox.svg)](https://www.npmjs.com/package/pi-sandbox)

`pi-sandbox` is a pi-mono extension scaffold for policy-aware sandboxing of `bash`, `read`, `write`, and `edit` tool operations.

Planned backends:

- native OS sandboxing: macOS `sandbox-exec`, Linux `bwrap`/Landlock, Windows AppContainer/WSL2
- Docker containers
- justbash virtual shell
- QEMU guest isolation
- SSH remote execution

This repository is at Wave 1 scaffold status. Enforcement implementations land in later waves.
