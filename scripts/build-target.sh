#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if [[ "$#" -ne 2 ]]; then
    echo "usage: $0 <goos> <goarch>" >&2
    exit 2
fi
goos="$1"
goarch="$2"
object_machine=
macho_cpu=
target_cflags=()

target_count="$(jq -r --arg os "$goos" --arg arch "$goarch" \
    '[.targets[] | select(.goos == $os and .goarch == $arch)] | length' \
    portable/manifest.json)"
if [[ "$target_count" != 1 ]]; then
    echo "error: portable/manifest.json must declare exactly one $goos/$goarch target" >&2
    exit 2
fi
target_command_set="$(jq -er --arg os "$goos" --arg arch "$goarch" \
    '.targets[] | select(.goos == $os and .goarch == $arch) | .commands' \
    portable/manifest.json | tr -d '\r')"

case "$goos/$goarch" in
    windows/386) zig_target=x86-windows-gnu; object_pattern="COFF"; object_machine=4c01 ;;
    windows/amd64) zig_target=x86_64-windows-gnu; object_pattern="COFF"; object_machine=6486 ;;
    windows/arm64) zig_target=aarch64-windows-gnu; object_pattern="COFF"; object_machine=64aa ;;
    linux/386) zig_target=x86-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 32-bit LSB relocatable, Intel 80386" ;;
    linux/amd64) zig_target=x86_64-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 64-bit LSB relocatable, x86-64" ;;
    linux/arm) zig_target=arm-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 32-bit LSB relocatable, ARM"; target_cflags=(-marm -mfloat-abi=hard) ;;
    linux/arm64) zig_target=aarch64-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 64-bit LSB relocatable, ARM aarch64" ;;
    linux/ppc64le) zig_target=powerpc64le-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 64-bit LSB relocatable, 64-bit PowerPC or cisco 7500, OpenPOWER ELF V2 ABI" ;;
    linux/riscv64) zig_target=riscv64-linux-none; platform_define=BOF_LINUX; object_pattern="ELF 64-bit LSB relocatable, UCB RISC-V" ;;
    darwin/amd64) zig_target=x86_64-macos-none; platform_define=BOF_DARWIN; object_pattern="Mach-O"; macho_cpu=07000001 ;;
    darwin/arm64) zig_target=aarch64-macos-none; platform_define=BOF_DARWIN; object_pattern="Mach-O"; macho_cpu=0c000001 ;;
    *) echo "error: unsupported target $goos/$goarch" >&2; exit 2 ;;
esac

zig_bin="${ZIG:-zig}"
if ! command -v "$zig_bin" >/dev/null 2>&1; then
    echo "error: Zig is required (set ZIG=/path/to/zig)" >&2
    exit 1
fi
zig_version="$("$zig_bin" version)"
if [[ "$zig_version" != "0.14.0" ]]; then
    echo "error: Zig 0.14.0 is required, got $zig_version from $zig_bin" >&2
    exit 1
fi
if [[ -n "${NM:-}" ]]; then
    nm_bin="$NM"
elif command -v llvm-nm >/dev/null 2>&1; then
    nm_bin=llvm-nm
else
    nm_bin=nm
fi
if ! command -v "$nm_bin" >/dev/null 2>&1; then
    echo "error: nm is required to verify the BOF entry symbol (set NM=/path/to/llvm-nm)" >&2
    exit 1
fi

cache_root="${TMPDIR:-/tmp}/situational-awareness-bofs-zig"
export ZIG_GLOBAL_CACHE_DIR="${ZIG_GLOBAL_CACHE_DIR:-$cache_root/global}"
export ZIG_LOCAL_CACHE_DIR="${ZIG_LOCAL_CACHE_DIR:-$cache_root/local}"
mkdir -p "$ZIG_GLOBAL_CACHE_DIR" "$ZIG_LOCAL_CACHE_DIR" "dist/$goos/$goarch"

# Native Windows jq.exe emits CRLF under Git Bash; normalize JSON-derived lines.
portable_commands=()
while IFS= read -r command; do
    portable_commands+=("$command")
done < <(jq -er '.command_sets.portable[]' portable/manifest.json | tr -d '\r')
windows_commands=()
while IFS= read -r command; do
    windows_commands+=("$command")
done < <(find src/SA -mindepth 1 -maxdepth 1 -type d -exec basename {} \; | LC_ALL=C sort)

if ! jq -e '
    (.command_sets.portable | type == "array" and length > 0 and length == (unique | length)) and
    (.command_sets["windows-only"] | type == "array" and length == (unique | length)) and
    ((.command_sets.portable + .command_sets["windows-only"]) |
        length == (unique | length))
' portable/manifest.json >/dev/null; then
    echo "error: portable and Windows-only command sets must be nonempty, unique, and disjoint" >&2
    exit 1
fi
if ! diff -u \
    <(printf '%s\n' "${windows_commands[@]}") \
    <(jq -r '.command_sets.portable[], .command_sets["windows-only"][]' \
        portable/manifest.json | tr -d '\r' | LC_ALL=C sort); then
    echo "error: portable manifest does not classify every retained upstream command exactly once" >&2
    exit 1
fi

command_configuration() {
    case "$1" in
        arp) echo BOF_COMMAND_ARP portable/src/portable.c ;;
        cacls) echo BOF_COMMAND_CACLS portable/src/posix.c ;;
        dir) echo BOF_COMMAND_DIR portable/src/portable.c ;;
        enumLocalSessions) echo BOF_COMMAND_ENUM_LOCAL_SESSIONS portable/src/posix.c ;;
        env) echo BOF_COMMAND_ENV portable/src/portable.c ;;
        findLoadedModule) echo BOF_COMMAND_FIND_LOADED_MODULE portable/src/posix.c ;;
        ipconfig) echo BOF_COMMAND_IPCONFIG portable/src/portable.c ;;
        listmods) echo BOF_COMMAND_LISTMODS portable/src/posix.c ;;
        locale) echo BOF_COMMAND_LOCALE portable/src/portable.c ;;
        md5) echo BOF_COMMAND_MD5 portable/src/portable.c ;;
        netlocalgroup) echo BOF_COMMAND_NETLOCALGROUP portable/src/posix.c ;;
        netloggedon) echo BOF_COMMAND_NETLOGGEDON portable/src/posix.c ;;
        netloggedon2) echo BOF_COMMAND_NETLOGGEDON2 portable/src/posix.c ;;
        netstat) echo BOF_COMMAND_NETSTAT portable/src/portable.c ;;
        netuser) echo BOF_COMMAND_NETUSER portable/src/posix.c ;;
        netuserenum) echo BOF_COMMAND_NETUSERENUM portable/src/posix.c ;;
        nslookup) echo BOF_COMMAND_NSLOOKUP portable/src/portable.c ;;
        probe) echo BOF_COMMAND_PROBE portable/src/portable.c ;;
        resources) echo BOF_COMMAND_RESOURCES portable/src/portable.c ;;
        routeprint) echo BOF_COMMAND_ROUTEPRINT portable/src/portable.c ;;
        sha1) echo BOF_COMMAND_SHA1 portable/src/portable.c ;;
        sha256) echo BOF_COMMAND_SHA256 portable/src/portable.c ;;
        tasklist) echo BOF_COMMAND_TASKLIST portable/src/portable.c ;;
        uptime) echo BOF_COMMAND_UPTIME portable/src/portable.c ;;
        whoami) echo BOF_COMMAND_WHOAMI portable/src/portable.c ;;
        *) echo "error: unknown portable command $1" >&2; return 1 ;;
    esac
}

if [[ "$target_command_set" == all-upstream ]]; then
    if [[ "$goos" != windows ]]; then
        echo "error: all-upstream command set is only valid for Windows targets" >&2
        exit 1
    fi
    commands=("${windows_commands[@]}")
    for command in "${commands[@]}"; do
        echo "CC  $goos/$goarch $command (retained Windows source)"
        "$zig_bin" cc -target "$zig_target" -Os \
            -fno-unwind-tables -fno-asynchronous-unwind-tables \
            -fno-exceptions -fno-ident \
            -Wno-missing-prototype-for-cc -Wno-ignored-attributes \
            -Isrc/common -DBOF -c "src/SA/$command/entry.c" \
            -o "dist/$goos/$goarch/$command.o"
    done
elif [[ "$target_command_set" == portable ]]; then
    if [[ "$goos" == windows ]]; then
        echo "error: portable command set is only valid for Unix targets" >&2
        exit 1
    fi
    commands=("${portable_commands[@]}")
    for command in "${commands[@]}"; do
        read -r define source_file <<<"$(command_configuration "$command")"
        echo "CC  $goos/$goarch $command"
        "$zig_bin" cc -target "$zig_target" ${target_cflags[@]+"${target_cflags[@]}"} -std=c11 -Os \
            -ffreestanding -fno-builtin -fno-stack-protector -fPIC \
            -fno-unwind-tables -fno-asynchronous-unwind-tables \
            -fno-exceptions -fno-ident \
            -Werror=implicit-function-declaration -Wno-unused-function \
            -Iportable/include -DBOF -D"$platform_define" -D"$define" \
            -c "$source_file" -o "dist/$goos/$goarch/$command.o"
    done
else
    echo "error: unknown command set $target_command_set for $goos/$goarch" >&2
    exit 1
fi

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

verify_entry_symbol() {
    local artifact="$1"
    local symbols
    if ! symbols="$("$nm_bin" -g "$artifact")"; then
        echo "error: cannot inspect symbols in $artifact with $nm_bin" >&2
        return 1
    fi
    if ! awk '
        $2 == "T" && ($NF == "go" || $NF == "_go") { found = 1 }
        END { exit found ? 0 : 1 }
    ' <<<"$symbols"; then
        echo "error: $artifact does not define the logical go/_go BOF entry symbol" >&2
        return 1
    fi
}

verify_reflektor_abi() {
    local artifact="$1"
    local flags
    local symbols
    local entry_address
    local last_digit
    verify_entry_symbol "$artifact" || return 1
    case "$goos/$goarch" in
        linux/arm)
            if ! flags="$(read_le_u32 "$artifact" 36)"; then
                echo "error: cannot read ELF/arm flags from $artifact" >&2
                return 1
            fi
            if (( (flags & 0xff000000) != 0x05000000 || (flags & 0x00000600) != 0x00000400 )); then
                printf 'error: wrong ELF/arm ABI flags: %s: got 0x%08x, want EABI5 hard-float\n' \
                    "$artifact" "$flags" >&2
                return 1
            fi
            if ! symbols="$("$nm_bin" -a "$artifact")"; then
                echo "error: cannot inspect ARM mapping symbols in $artifact with $nm_bin" >&2
                return 1
            fi
            if awk '$NF ~ /^\$t(\.[0-9]+)?$/ { found = 1 } END { exit found ? 0 : 1 }' <<<"$symbols"; then
                echo "error: ELF/arm artifact contains Thumb-state mapping symbols: $artifact" >&2
                return 1
            fi
            entry_address="$(awk '$2 == "T" && ($NF == "go" || $NF == "_go") { print $1; exit }' <<<"$symbols")"
            last_digit="${entry_address: -1}"
            if [[ "$last_digit" =~ [13579bBdDfF] ]]; then
                echo "error: ELF/arm go entry enters Thumb state: $artifact: $entry_address" >&2
                return 1
            fi
            ;;
        linux/ppc64le)
            if ! flags="$(read_le_u32 "$artifact" 48)"; then
                echo "error: cannot read ELF/ppc64le flags from $artifact" >&2
                return 1
            fi
            if (( flags != 0x00000002 )); then
                printf 'error: wrong ELF/ppc64le ABI flags: %s: got 0x%08x, want ELFv2 (0x00000002)\n' \
                    "$artifact" "$flags" >&2
                return 1
            fi
            ;;
        linux/riscv64)
            if ! flags="$(read_le_u32 "$artifact" 48)"; then
                echo "error: cannot read ELF/riscv64 flags from $artifact" >&2
                return 1
            fi
            if (( flags != 0x00000004 && flags != 0x00000005 )); then
                printf 'error: wrong ELF/riscv64 ABI flags: %s: got 0x%08x, want LP64D with optional RVC only\n' \
                    "$artifact" "$flags" >&2
                return 1
            fi
            ;;
    esac
}

for command in "${commands[@]}"; do
    artifact="dist/$goos/$goarch/$command.o"
    description="$(file -b "$artifact")"
    if [[ "$description" != *"$object_pattern"* ]]; then
        echo "wrong format: $artifact: $description" >&2
        exit 1
    fi
    if [[ -n "$object_machine" ]]; then
        actual_machine="$(od -An -tx1 -N2 "$artifact" | tr -d '[:space:]')"
        if [[ "$actual_machine" != "$object_machine" ]]; then
            echo "wrong COFF machine: $artifact: got $actual_machine, want $object_machine" >&2
            exit 1
        fi
    fi
    if [[ -n "$macho_cpu" ]]; then
        macho_header="$(od -An -tx1 -N16 "$artifact" | tr -d '[:space:]')"
        actual_magic="${macho_header:0:8}"
        actual_cpu="${macho_header:8:8}"
        actual_type="${macho_header:24:8}"
        if [[ "$actual_magic" != cffaedfe ]]; then
            echo "wrong Mach-O magic: $artifact: got $actual_magic, want cffaedfe" >&2
            exit 1
        fi
        if [[ "$actual_cpu" != "$macho_cpu" ]]; then
            echo "wrong Mach-O CPU: $artifact: got $actual_cpu, want $macho_cpu" >&2
            exit 1
        fi
        if [[ "$actual_type" != 01000000 ]]; then
            echo "wrong Mach-O file type: $artifact: got $actual_type, want MH_OBJECT (01000000)" >&2
            exit 1
        fi
    fi
    verify_reflektor_abi "$artifact"
done

if [[ "$goos/$goarch" == linux/arm ]]; then
    for command in dir tasklist; do
        artifact="dist/$goos/$goarch/$command.o"
        if ! undefined_symbols="$("$nm_bin" -u "$artifact")"; then
            echo "error: cannot inspect Linux/arm directory imports in $artifact with $nm_bin" >&2
            exit 1
        fi
        if ! awk '$NF == "readdir64" { found = 1 } END { exit found ? 0 : 1 }' <<<"$undefined_symbols"; then
            echo "error: Linux/arm directory enumeration must import readdir64: $artifact" >&2
            exit 1
        fi
        if awk '$NF == "readdir" { found = 1 } END { exit found ? 0 : 1 }' <<<"$undefined_symbols"; then
            echo "error: Linux/arm directory enumeration imports legacy readdir: $artifact" >&2
            exit 1
        fi
    done
fi

if [[ "$goos/$goarch" == darwin/arm64 ]]; then
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
    for command in "${commands[@]}"; do
        artifact="dist/$goos/$goarch/$command.o"
        if ! disassembly="$("$objdump_bin" -d "$artifact")"; then
            echo "error: cannot disassemble $artifact with $objdump_bin" >&2
            exit 1
        fi
        if grep -Eiq '(^|[^[:alnum:]_])([wx]18)([^[:alnum:]_]|$)' <<<"$disassembly"; then
            echo "error: Darwin/arm64 artifact uses Apple's reserved x18 register: $artifact" >&2
            exit 1
        fi
        if ! undefined_symbols="$("$nm_bin" -u "$artifact")"; then
            echo "error: cannot inspect undefined symbols in $artifact with $nm_bin" >&2
            exit 1
        fi
        if awk '
            $NF == "BeaconPrintf" || $NF == "_BeaconPrintf" ||
            $NF == "BeaconFormatPrintf" || $NF == "_BeaconFormatPrintf" { found = 1 }
            END { exit found ? 0 : 1 }
        ' <<<"$undefined_symbols"; then
            echo "error: Darwin/arm64 artifact imports a forbidden variadic Beacon callback: $artifact" >&2
            exit 1
        fi
    done
fi

if ! diff -u \
    <(for command in "${commands[@]}"; do printf "dist/%s/%s/%s.o\n" "$goos" "$goarch" "$command"; done | LC_ALL=C sort) \
    <(find "dist/$goos/$goarch" -maxdepth 1 -type f -name '*.o' | LC_ALL=C sort); then
    echo "error: dist/$goos/$goarch does not contain the exact target artifact set" >&2
    exit 1
fi
if ! diff -u \
    <(for command in "${commands[@]}"; do printf "dist/%s/%s/%s.o\n" "$goos" "$goarch" "$command"; done | LC_ALL=C sort) \
    <(jq -r --arg os "$goos" --arg arch "$goarch" '.artifacts[] | select(.os == $os and .arch == $arch) | .path' testdata/e2e-manifest.json | tr -d '\r' | LC_ALL=C sort); then
    echo "error: e2e manifest does not exactly cover $goos/$goarch" >&2
    exit 1
fi

echo "verified $goos/$goarch (${#commands[@]} objects)"
