#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$repo_root"

version="${ARMORY_VERSION:-}"
if [[ -z "$version" ]]; then
    version="$(git describe --tags --exact-match --match 'v[0-9]*' 2>/dev/null || printf 'v0.0.0-dev')"
fi
output="${ARMORY_OUTPUT_DIR:-packages}"

"$repo_root/scripts/build-matrix.sh"

package_args=(
    build
    --version "$version"
    --output "$output"
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
