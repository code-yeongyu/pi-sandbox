#!/usr/bin/env bash
set -euo pipefail

busybox_version="${PI_SANDBOX_BUSYBOX_VERSION:-1.21.1}"
busybox_url="${PI_SANDBOX_BUSYBOX_URL:-https://busybox.net/downloads/binaries/${busybox_version}/busybox-x86_64}"
kernel_url="${PI_SANDBOX_QEMU_KERNEL_URL:-https://github.com/cirosantilli/linux-kernel-module-cheat/releases/download/v3.0/bzImage}"

repo_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
fixture_dir="${repo_root}/qemu-fixtures"
cache_dir="${PI_SANDBOX_QEMU_CACHE:-${fixture_dir}/.cache}"
manifest="${fixture_dir}/MANIFEST.sha256"
kernel="${fixture_dir}/bzImage"
initrd="${fixture_dir}/initrd.cpio.gz"

sha256_one() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{print $1}'
	else
		shasum -a 256 "$1" | awk '{print $1}'
	fi
}

download() {
	url="$1"
	target="$2"
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$url" -o "$target"
	elif command -v wget >/dev/null 2>&1; then
		wget -O "$target" "$url"
	else
		printf '%s\n' "curl or wget is required" >&2
		exit 1
	fi
}

manifest_valid() {
	[ -f "$kernel" ] || return 1
	[ -f "$initrd" ] || return 1
	[ -f "$manifest" ] || return 1
	kernel_hash="$(sha256_one "$kernel")"
	initrd_hash="$(sha256_one "$initrd")"
	grep "^${kernel_hash}  bzImage$" "$manifest" >/dev/null 2>&1 || return 1
	grep "^${initrd_hash}  initrd.cpio.gz$" "$manifest" >/dev/null 2>&1 || return 1
}

build_initrd() {
	busybox="$1"
	output="$2"
	staging="$(mktemp -d "${TMPDIR:-/tmp}/pi-qemu-initrd.XXXXXX")"
	trap 'rm -rf "$staging"' EXIT HUP INT TERM
	mkdir -p "$staging/bin" "$staging/dev" "$staging/proc" "$staging/tmp" "$staging/workspace"
	cp "$busybox" "$staging/bin/busybox"
	chmod 0755 "$staging/bin/busybox"
	ln -s busybox "$staging/bin/sh"
	ln -s busybox "$staging/bin/mount"
	ln -s busybox "$staging/bin/mkdir"
	ln -s busybox "$staging/bin/poweroff"
	ln -s busybox "$staging/bin/wget"
	ln -s busybox "$staging/bin/ls"
	ln -s busybox "$staging/bin/touch"
	ln -s busybox "$staging/bin/cat"
	ln -s busybox "$staging/bin/printf"
	cat >"$staging/init" <<'INIT'
#!/bin/sh
export PATH=/bin
mount -t proc proc /proc 2>/dev/null || true
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mkdir -p /workspace
mount -t 9p -o trans=virtio,version=9p2000.L,msize=1048576 workspace /workspace 2>/dev/null || true
cd /workspace 2>/dev/null || cd /
exec /bin/sh
INIT
	chmod 0755 "$staging/init"
	(
		cd "$staging"
		find . | cpio -o -H newc 2>/dev/null
	) | gzip -n >"$output"
}

if manifest_valid; then
	printf '%s\n' "qemu smoke fixture already valid: ${fixture_dir}"
	exit 0
fi

mkdir -p "$fixture_dir" "$cache_dir"
busybox_cache="${cache_dir}/busybox-x86_64-${busybox_version}"
kernel_cache="${cache_dir}/bzImage"

if [ ! -f "$busybox_cache" ]; then
	download "$busybox_url" "$busybox_cache"
	chmod 0755 "$busybox_cache"
fi

if [ ! -f "$kernel_cache" ]; then
	download "$kernel_url" "$kernel_cache"
fi

tmp_kernel="${kernel}.tmp"
tmp_initrd="${initrd}.tmp"
cp "$kernel_cache" "$tmp_kernel"
build_initrd "$busybox_cache" "$tmp_initrd"
mv "$tmp_kernel" "$kernel"
mv "$tmp_initrd" "$initrd"

{
	printf '%s  %s\n' "$(sha256_one "$kernel")" "bzImage"
	printf '%s  %s\n' "$(sha256_one "$initrd")" "initrd.cpio.gz"
} >"${manifest}.tmp"
mv "${manifest}.tmp" "$manifest"

printf '%s\n' "qemu smoke fixture built: ${fixture_dir}"
