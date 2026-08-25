#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

while IFS=$'\t' read -r goos goarch; do
    "$repo_root/scripts/build-target.sh" "$goos" "$goarch"
done < <(jq -er '.targets[] | [.goos, .goarch] | @tsv' portable/manifest.json | tr -d '\r')

"$repo_root/scripts/verify-matrix.sh"
