#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

# Native Windows jq.exe emits CRLF under Git Bash; normalize JSON-derived lines.
portable_commands=()
while IFS= read -r command; do
    portable_commands+=("$command")
done < <(jq -er '.command_sets.portable[]' portable/manifest.json | tr -d '\r')
windows_commands=()
while IFS= read -r command; do
    windows_commands+=("$command")
done < <(find src/SA -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | LC_ALL=C sort)
target_specs=()
while IFS=$'\t' read -r goos goarch command_set; do
    target_specs+=("$goos/$goarch:$command_set")
done < <(jq -er '.targets[] | [.goos, .goarch, .commands] | @tsv' \
    portable/manifest.json | tr -d '\r')

if [[ -n "${NM:-}" ]]; then
    nm_bin="$NM"
elif command -v llvm-nm >/dev/null 2>&1; then
    nm_bin=llvm-nm
else
    nm_bin=nm
fi
if ! command -v "$nm_bin" >/dev/null 2>&1; then
    echo "error: nm is required to verify BOF entry symbols (set NM=/path/to/llvm-nm)" >&2
    exit 1
fi
if [[ -n "${OBJDUMP:-}" ]]; then
    objdump_bin="$OBJDUMP"
elif command -v llvm-objdump >/dev/null 2>&1; then
    objdump_bin=llvm-objdump
else
    objdump_bin=objdump
fi
if ! command -v "$objdump_bin" >/dev/null 2>&1; then
    echo "error: objdump is required to verify Darwin/arm64 register use (set OBJDUMP=/path/to/llvm-objdump)" >&2
    exit 1
fi

failures=0
read_le_u32() {
    local artifact="$1"
    local offset="$2"
    local byte0 byte1 byte2 byte3
    read -r byte0 byte1 byte2 byte3 < <(od -An -tu1 -j "$offset" -N4 "$artifact")
    if [[ -z "${byte0:-}" || -z "${byte1:-}" || -z "${byte2:-}" || -z "${byte3:-}" ]]; then
        return 1
    fi
    printf '%u\n' "$((byte0 | (byte1 << 8) | (byte2 << 16) | (byte3 << 24)))"
}

verify_artifact() {
    local target="$1"
    local command="$2"
    local goos="${target%/*}"
    local goarch="${target#*/}"
    local artifact="dist/$target/$command.o"
    local description
    local expected=
    local expected_machine=
    local expected_macho_cpu=
    local flags
    local symbols
    local entry_address
    local last_digit
    local disassembly
    local undefined_symbols
    if [[ ! -s "$artifact" ]]; then
        echo "missing: $artifact" >&2
        failures=$((failures + 1))
        return
    fi
    description="$(file -b "$artifact")"
    case "$goos/$goarch" in
        windows/386) expected="COFF"; expected_machine=4c01 ;;
        windows/amd64) expected="COFF"; expected_machine=6486 ;;
        windows/arm64) expected="COFF"; expected_machine=64aa ;;
        linux/386) expected="ELF 32-bit LSB relocatable, Intel 80386" ;;
        linux/amd64) expected="ELF 64-bit LSB relocatable, x86-64" ;;
        linux/arm) expected="ELF 32-bit LSB relocatable, ARM" ;;
        linux/arm64) expected="ELF 64-bit LSB relocatable, ARM aarch64" ;;
        linux/ppc64le) expected="ELF 64-bit LSB relocatable, 64-bit PowerPC or cisco 7500, OpenPOWER ELF V2 ABI" ;;
        linux/riscv64) expected="ELF 64-bit LSB relocatable, UCB RISC-V" ;;
        darwin/amd64) expected="Mach-O"; expected_macho_cpu=07000001 ;;
        darwin/arm64) expected="Mach-O"; expected_macho_cpu=0c000001 ;;
        *)
            echo "unsupported manifest target: $goos/$goarch" >&2
            failures=$((failures + 1))
            return
            ;;
    esac
    if [[ "$description" != *"$expected"* ]]; then
        echo "wrong format: $artifact: $description" >&2
        failures=$((failures + 1))
    fi
    if [[ -n "$expected_machine" ]]; then
        actual_machine="$(od -An -tx1 -N2 "$artifact" | tr -d '[:space:]')"
        if [[ "$actual_machine" != "$expected_machine" ]]; then
            echo "wrong COFF machine: $artifact: got $actual_machine, want $expected_machine" >&2
            failures=$((failures + 1))
        fi
    fi
    if [[ -n "$expected_macho_cpu" ]]; then
        local macho_header
        local actual_magic
        local actual_cpu
        local actual_type
        macho_header="$(od -An -tx1 -N16 "$artifact" | tr -d '[:space:]')"
        actual_magic="${macho_header:0:8}"
        actual_cpu="${macho_header:8:8}"
        actual_type="${macho_header:24:8}"
        if [[ "$actual_magic" != cffaedfe ]]; then
            echo "wrong Mach-O magic: $artifact: got $actual_magic, want cffaedfe" >&2
            failures=$((failures + 1))
        fi
        if [[ "$actual_cpu" != "$expected_macho_cpu" ]]; then
            echo "wrong Mach-O CPU: $artifact: got $actual_cpu, want $expected_macho_cpu" >&2
            failures=$((failures + 1))
        fi
        if [[ "$actual_type" != 01000000 ]]; then
            echo "wrong Mach-O file type: $artifact: got $actual_type, want MH_OBJECT (01000000)" >&2
            failures=$((failures + 1))
        fi
    fi
    if ! symbols="$("$nm_bin" -g "$artifact")"; then
        echo "cannot inspect symbols: $artifact with $nm_bin" >&2
        failures=$((failures + 1))
    elif ! awk '
        $2 == "T" && ($NF == "go" || $NF == "_go") { found = 1 }
        END { exit found ? 0 : 1 }
    ' <<<"$symbols"; then
        echo "missing logical go/_go BOF entry: $artifact" >&2
        failures=$((failures + 1))
    fi
    case "$goos/$goarch" in
        linux/arm)
            if ! flags="$(read_le_u32 "$artifact" 36)"; then
                echo "cannot read ELF/arm flags: $artifact" >&2
                failures=$((failures + 1))
            elif (( (flags & 0xff000000) != 0x05000000 || (flags & 0x00000600) != 0x00000400 )); then
                printf 'wrong ELF/arm ABI flags: %s: got 0x%08x, want EABI5 hard-float\n' \
                    "$artifact" "$flags" >&2
                failures=$((failures + 1))
            fi
            if ! symbols="$("$nm_bin" -a "$artifact")"; then
                echo "cannot inspect ARM mapping symbols: $artifact with $nm_bin" >&2
                failures=$((failures + 1))
            else
                if awk '$NF ~ /^\$t(\.[0-9]+)?$/ { found = 1 } END { exit found ? 0 : 1 }' <<<"$symbols"; then
                    echo "ELF/arm artifact contains Thumb-state mapping symbols: $artifact" >&2
                    failures=$((failures + 1))
                fi
                entry_address="$(awk '$2 == "T" && ($NF == "go" || $NF == "_go") { print $1; exit }' <<<"$symbols")"
                if [[ -n "$entry_address" ]]; then
                    last_digit="${entry_address: -1}"
                    if [[ "$last_digit" =~ [13579bBdDfF] ]]; then
                        echo "ELF/arm go entry enters Thumb state: $artifact: $entry_address" >&2
                        failures=$((failures + 1))
                    fi
                fi
            fi
            ;;
        linux/ppc64le)
            if ! flags="$(read_le_u32 "$artifact" 48)"; then
                echo "cannot read ELF/ppc64le flags: $artifact" >&2
                failures=$((failures + 1))
            elif (( flags != 0x00000002 )); then
                printf 'wrong ELF/ppc64le ABI flags: %s: got 0x%08x, want ELFv2 (0x00000002)\n' \
                    "$artifact" "$flags" >&2
                failures=$((failures + 1))
            fi
            ;;
        linux/riscv64)
            if ! flags="$(read_le_u32 "$artifact" 48)"; then
                echo "cannot read ELF/riscv64 flags: $artifact" >&2
                failures=$((failures + 1))
            elif (( flags != 0x00000004 && flags != 0x00000005 )); then
                printf 'wrong ELF/riscv64 ABI flags: %s: got 0x%08x, want LP64D with optional RVC only\n' \
                    "$artifact" "$flags" >&2
                failures=$((failures + 1))
            fi
            ;;
        darwin/arm64)
            if ! disassembly="$("$objdump_bin" -d "$artifact")"; then
                echo "cannot disassemble Darwin/arm64 artifact: $artifact with $objdump_bin" >&2
                failures=$((failures + 1))
            elif grep -Eiq '(^|[^[:alnum:]_])([wx]18)([^[:alnum:]_]|$)' <<<"$disassembly"; then
                echo "Darwin/arm64 artifact uses Apple's reserved x18 register: $artifact" >&2
                failures=$((failures + 1))
            fi
            if ! undefined_symbols="$("$nm_bin" -u "$artifact")"; then
                echo "cannot inspect Darwin/arm64 imports: $artifact with $nm_bin" >&2
                failures=$((failures + 1))
            elif awk '
                $NF == "BeaconPrintf" || $NF == "_BeaconPrintf" ||
                $NF == "BeaconFormatPrintf" || $NF == "_BeaconFormatPrintf" { found = 1 }
                END { exit found ? 0 : 1 }
            ' <<<"$undefined_symbols"; then
                echo "Darwin/arm64 artifact imports a forbidden variadic Beacon callback: $artifact" >&2
                failures=$((failures + 1))
            fi
            ;;
    esac
}

for target_spec in "${target_specs[@]}"; do
    target="${target_spec%%:*}"
    command_set="${target_spec#*:}"
    if [[ "$command_set" == all-upstream ]]; then
        commands=("${windows_commands[@]}")
    elif [[ "$command_set" == portable ]]; then
        commands=("${portable_commands[@]}")
    else
        echo "unknown command set $command_set for $target" >&2
        failures=$((failures + 1))
        continue
    fi
    for command in "${commands[@]}"; do
        verify_artifact "$target" "$command"
    done
done

if (( failures != 0 )); then
    echo "matrix verification failed with $failures error(s)" >&2
    exit 1
fi

if ! diff -u \
    <(
        {
            for target_spec in "${target_specs[@]}"; do
                target="${target_spec%%:*}"
                command_set="${target_spec#*:}"
                if [[ "$command_set" == all-upstream ]]; then
                    commands=("${windows_commands[@]}")
                else
                    commands=("${portable_commands[@]}")
                fi
                for command in "${commands[@]}"; do
                    printf "dist/%s/%s.o\n" "$target" "$command"
                done
            done
        } | LC_ALL=C sort
    ) \
    <(find dist -type f -name '*.o' | LC_ALL=C sort); then
    echo "dist does not contain the exact manifest-declared object matrix" >&2
    exit 1
fi

if ! diff -u \
    <(tr -d '\r' < testdata/e2e-manifest.json) \
    <(node scripts/generate-e2e-manifest.mjs | tr -d '\r'); then
    echo "e2e manifest is stale; regenerate it with scripts/generate-e2e-manifest.mjs --write" >&2
    exit 1
fi
if ! jq -e '
    (.command_sets.portable | type == "array" and length > 0 and length == (unique | length)) and
    (.command_sets["windows-only"] | type == "array" and length == (unique | length)) and
    ((.command_sets.portable + .command_sets["windows-only"]) |
        length == (unique | length))
' portable/manifest.json >/dev/null; then
    echo "portable and Windows-only command sets must be nonempty, unique, and disjoint" >&2
    exit 1
fi
if ! diff -u \
    <(find src/SA -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | LC_ALL=C sort) \
    <(jq -r '.command_sets.portable[], .command_sets["windows-only"][]' portable/manifest.json | tr -d '\r' | LC_ALL=C sort); then
    echo "portable manifest does not classify every retained upstream command exactly once" >&2
    exit 1
fi

expected_count=0
for target_spec in "${target_specs[@]}"; do
    command_set="${target_spec#*:}"
    if [[ "$command_set" == all-upstream ]]; then
        expected_count=$((expected_count + ${#windows_commands[@]}))
    else
        expected_count=$((expected_count + ${#portable_commands[@]}))
    fi
done
echo "verified $expected_count objects across ${#target_specs[@]} targets (${#windows_commands[@]} Windows commands; ${#portable_commands[@]} portable commands)"
