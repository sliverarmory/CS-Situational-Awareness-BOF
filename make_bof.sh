#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 ]]; then
    echo "usage: $0 <src/SA source-directory name>" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

version="${ARMORY_VERSION:-}"
if [[ -z "$version" ]]; then
    version="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || printf 'v0.0.0-dev')"
fi
output="${ARMORY_OUTPUT_DIR:-packages}"

# The shared matrix build is authoritative even for a single Armory package.
# This prevents the compatibility wrapper from drifting to another compiler or
# artifact layout.
"$repo_root/scripts/build-matrix.sh"

package_args=(
    build
    --version "$version"
    --output "$output"
    --package "$1"
)
if [[ -n "${ARMORY_SOURCE_DATE_EPOCH:-}" ]]; then
    package_args+=(--source-date-epoch "$ARMORY_SOURCE_DATE_EPOCH")
fi
if [[ -n "${ARMORY_SIGNING_KEY:-}" ]]; then
    package_args+=(
        --signing-key "$ARMORY_SIGNING_KEY"
        --minisign "${MINISIGN:-minisign}"
    )
fi

python3 "$repo_root/packaging/armory_packages.py" "${package_args[@]}"
