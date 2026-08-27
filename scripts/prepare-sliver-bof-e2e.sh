#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "${SLIVER_BOF_E2E_PHASE:-}" != plan ||
      -n "${SLIVER_BOF_E2E_TARGET:-}" ||
      -n "${SLIVER_BOF_E2E_OS:-}" ||
      -n "${SLIVER_BOF_E2E_ARCH:-}" ]]; then
    echo "error: this preparation script only supports the Sliver BOF E2E plan phase" >&2
    exit 2
fi
if [[ -z "${RUNNER_TEMP:-}" ]]; then
    echo "error: RUNNER_TEMP is required" >&2
    exit 2
fi
if [[ "$(uname -s)" != Linux || "$(uname -m)" != x86_64 ]]; then
    echo "error: the reusable workflow plan must run on Linux x86_64" >&2
    exit 2
fi

for tool in curl file jq node sha256sum tar uname; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "error: required runner tool is unavailable: $tool" >&2
        exit 1
    fi
done

zig_version=0.14.0
# Official checksum from https://ziglang.org/download/index.json.
zig_sha256=473ec26806133cf4d1918caf1a410f8403a13d979726a9045b421b685031a982
zig_url="https://ziglang.org/download/${zig_version}/zig-linux-x86_64-${zig_version}.tar.xz"
zig_root="${RUNNER_TEMP}/situational-awareness-zig-${zig_version}"
zig_archive="${RUNNER_TEMP}/zig-linux-x86_64-${zig_version}.tar.xz"

if [[ ! -x "${zig_root}/zig" ]]; then
    mkdir -p "$zig_root"
    curl --fail --location --proto '=https' --tlsv1.2 \
        --retry 3 --retry-all-errors \
        --output "$zig_archive" "$zig_url"
    printf '%s  %s\n' "$zig_sha256" "$zig_archive" | sha256sum --check --strict
    tar -xJf "$zig_archive" -C "$zig_root" --strip-components=1
fi
if [[ "$("${zig_root}/zig" version)" != "$zig_version" ]]; then
    echo "error: prepared Zig version does not match $zig_version" >&2
    exit 1
fi

llvm_nm="$(command -v llvm-nm-18 || command -v llvm-nm || true)"
llvm_objdump="$(command -v llvm-objdump-18 || command -v llvm-objdump || true)"
if [[ -z "$llvm_nm" || -z "$llvm_objdump" ]]; then
    echo "error: LLVM nm and objdump are required on the planning runner" >&2
    exit 1
fi

export ZIG="${zig_root}/zig"
export LLVM_NM="$llvm_nm"
export NM="$llvm_nm"
export OBJDUMP="$llvm_objdump"
export ZIG_GLOBAL_CACHE_DIR="${RUNNER_TEMP}/situational-awareness-zig-cache/global"
export ZIG_LOCAL_CACHE_DIR="${RUNNER_TEMP}/situational-awareness-zig-cache/local"

./scripts/build-matrix.sh
