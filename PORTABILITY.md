# Cross-platform BOF provenance

This branch is based on Sliver Armory commit
`991cb07c4aab9cc83f96facfd27b04b0637a27c0`, which merges the current
TrustedSec Windows corpus. The portable implementation, build scripts, and
runtime-manifest generator were imported and adapted from the Reflektor-proven
`sliverarmory/Situational-Awareness-BOFs` commit
`693174ff525595c5ec61b08fdccb5f057ad52c94`.

The complete Windows source tree under `src/` and its GPL-2.0 license remain
the upstream-sync boundary. Cross-platform work is additive under `portable/`
and selects those sources only for Unix targets, so future upstream merges do
not require maintaining a fork of every Windows command implementation.

## Command coverage

All 71 current `src/SA` command directories build as native Windows COFF
objects for 386, amd64, and arm64. The portable Unix set is exactly `arp`,
`cacls`, `dir`,
`enumLocalSessions`, `env`, `findLoadedModule`, `ipconfig`, `listmods`,
`locale`, `md5`, `netlocalgroup`, `netloggedon`, `netloggedon2`, `netstat`,
`netuser`, `netuserenum`, `nslookup`, `probe`, `resources`, `routeprint`,
`sha1`, `sha256`, `tasklist`, `uptime`, and `whoami`. Every current command is
classified exactly once as portable or Windows-only. A Windows-only
classification can mean either a true platform dependency (Active Directory,
COM, DPAPI, Registry, SCM, scheduled tasks, WMI, and similar APIs) or a portable
implementation that is deliberately deferred.

`cat`, `hostname`, and `sha512` are the best next-wave portable candidates
because their Unix behavior can closely match the existing command contract.
`vol` is also mechanically feasible, but its Windows drive/volume semantics
need an explicit Unix filesystem contract before it should be exposed as the
same command.

Linux objects are native ELF `ET_REL` objects. Darwin objects are native thin
Mach-O `MH_OBJECT` files produced with Zig's `x86_64-macos-none` and
`aarch64-macos-none` targets. They are compiled without SDK headers and import
only Darwin ABI symbols selected by `BOF_DARWIN`. A Mach-O `MH_OBJECT` is a
relocatable loader input, not a dylib that can be passed to `dlopen`.
The native Darwin/arm64 target follows Apple's reserved x18 platform-register
rule, and the build verifies the generated disassembly. Portable Darwin BOFs
also use the non-variadic `BeaconOutput` callback, avoiding the Apple/Linux
variadic ABI difference; native Darwin/arm64 BOFs must not import
`BeaconPrintf` or `BeaconFormatPrintf`.

The Reflektor corpus-only Linux targets use the loader's exact native ABI:
ARM is EABI5 hard-float and contains only ARM-state code, ppc64le is
little-endian ELFv2, and riscv64 is LP64D with optional RVC but without RVE,
RVTSO, or unknown ELF flags. Every object must define the logical `go`/`_go`
entry before it is accepted by the build or verification scripts.

The Unix implementation is freestanding: it does not include host SDK headers
and keeps hashing code inside each object. Its external surface is limited to
the Beacon argument/output callbacks plus small, stable POSIX or Darwin libc
APIs. `dir` reports names only, avoiding target-specific stat layouts.

## Build and verify

Zig 0.14.0, Node.js, `jq`, `file`, `nm` (or
`NM=/path/to/llvm-nm`), `objdump` (or
`OBJDUMP=/path/to/llvm-objdump`), and Bash are the build-time dependencies.
Zig 0.14.0 is the version pinned by the Reflektor corpus workflows; do not
silently substitute the local/latest Zig. An explicit compatible binary can be
selected with `ZIG=/path/to/zig`:

```sh
make matrix
```

This produces and verifies 413 objects: 213 objects for all 71 Windows commands
on three targets, 125 objects for the 25 portable commands on five published
Unix targets, and 75 objects for the same portable set on three Reflektor
corpus-only Linux targets. The eight published tuples are Windows, Linux, and
Darwin on 386/amd64/arm64 where applicable; Linux `arm`, `ppc64le`, and
`riscv64` are marked `publish: false`. The exact policy is in
`portable/manifest.json`. The explicit
artifact-by-artifact execution contract is `testdata/e2e-manifest.json`; its
generator also checks that no upstream Windows command silently disappears or
is classified twice.

The build uses temporary Zig caches so no toolchain cache is written into the
repository. Artifacts are written under `dist/<goos>/<goarch>/` and are ignored
by Git.

CI runtime rows should build only their host artifact set:

```sh
./scripts/build-target.sh "$(go env GOOS)" "$(go env GOARCH)"
```

The command accepts the eleven manifest targets and verifies that the selected
`dist/<goos>/<goarch>` directory and E2E manifest contain the exact expected
set (71 Windows objects or 25 Unix objects). Reflektor then runs its corpus test
with `CGO_ENABLED=0 go test ./integration -run '^TestSituationalAwarenessBOFCorpus$'`.

## Sliver end-to-end coverage

The Sliver end-to-end workflow builds the ignored object matrix once, then
runs the published `sliverarmory/sliver-test-bof` action on the eight published
targets. Each BOF is exercised through both a real Sliver session and a real
Sliver beacon. The generated action-native contract is
`.github/sliver-bof-e2e.json`; `testdata/sliver-bof-e2e-policy.json` pins the
Sliver revision and records the hosted-runner inclusion policy.

All 25 portable commands run on the five supported Unix targets. Windows runs
those 25 commands plus 35 read-only Windows commands that do not require a
domain, for 305 target-specific cases and 610 session/beacon invocations. Ten
AD, ADCS, or LDAP commands are recorded as domain-required and remain for a
future domain-joined test environment. `get_dpapi_system` is deliberately not
executed in hosted CI: it requires elevation, temporarily changes LSA registry
ACLs, and can place machine secrets in captured test output.

Fifty-three of the 60 Windows cases require command-specific output, including
fixture contents, cryptographic digests, service/WMI results, and an open
loopback listener. The remaining seven (`arp`, `driversigs`, `netloggedon2`,
`netview`, `notepad`, `sc_qdescription`, and `windowlist`) are explicit
execution smoke tests because their successful result can be empty on a clean,
headless runner. The generator fails closed if another Windows command would
silently fall back to success-only coverage.

Generated objects remain build artifacts. CI transfers them between its
ephemeral build and test jobs, and neither `dist/` nor any `.o` file is tracked
or published by the test workflow. The existing Reflektor corpus job continues
to cover the three non-published Linux architectures that the Sliver action
does not currently support.

## POSIX mappings for Windows-oriented commands

The following ports preserve the upstream packed argument shape but define a
local Unix meaning. Unsupported remote, domain, cross-process, wildcard, and
Windows account-state modes are rejected explicitly instead of being ignored.

| Command | Unix behavior | Deliberate limitation |
| --- | --- | --- |
| `cacls` | Reports `access(2)` existence and real-UID/GID read, write, and execute/search results for one UTF-16 path. | It does not enumerate ACL entries, ownership, mode bits, or wildcards. |
| `enumLocalSessions` | Lists local login records from the base-system `/usr/bin/who` utility. | Local host only. |
| `findLoadedModule` | Case-insensitively searches the current process's `/proc/self/maps` paths on Linux or dyld images on Darwin; the optional process filter must match the current process. | Cross-process search is not exposed. |
| `listmods` | Lists modules for PID `0` or the current PID using procfs or dyld. | Any other PID is rejected. |
| `netlocalgroup` | Operation `0` enumerates the POSIX group database; operation `1` lists members of one group. | A non-empty server/domain selector is rejected. |
| `netloggedon` | Lists local login records in compact form using `/usr/bin/who`. | A non-empty remote computer is rejected. |
| `netloggedon2` | Lists the same local records with structured per-session delimiters. | A non-empty remote computer is rejected. |
| `netuser` | Looks up one POSIX account; an empty username selects the effective user. | A non-empty domain/server is rejected. |
| `netuserenum` | Enumerates the POSIX account database when `use_domain=0` and `filter=1`. | Domain mode and Windows locked/disabled account filters are rejected. |

## Runtime limitations

- BOFs execute in-process and inherit the privileges and filesystem view of
  the host process.
- Unix `dir` is intentionally non-recursive. Its packed `subdirs` argument is
  retained for compatibility, but any nonzero value is rejected explicitly.
- Unix `tasklist` is local-only. An absent or empty UTF-16 resource selects the
  local host; a nonempty Windows/WMI resource is rejected explicitly.
- Linux 386 and the corpus-only ARMv7 hard-float, ppc64le, and riscv64 targets
  use the `dirent` ABI exercised by the current Reflektor images. ARMv7
  explicitly uses the large-inode `readdir64` record so directory enumeration
  cannot stop with `EOVERFLOW` on filesystems whose inode values exceed 32 bits.
- Darwin `arp` invokes the bounded system command `/usr/sbin/arp -an`; Linux
  reads `/proc/net/arp` directly.
- Unix `nslookup` uses the host resolver and supports A, AAAA, and ANY address
  lookups; selecting a custom DNS server remains Windows-only.
- Unix `probe` bounds TCP connection attempts with one monotonic deadline after
  hostname resolution. Linux uses nonblocking `poll`; Darwin uses the public
  TCP connection-timeout socket option. Resolver latency is outside that
  connection deadline.
- Linux network, route, resource, and process enumeration reads procfs where
  available. Darwin uses the platform `netstat`, `vm_stat`, `df`, and `ps`
  utilities at fixed system paths. The Darwin `netstat` port reports all socket
  families and includes the requested Windows-compatible filter value.
- Darwin Mach-O objects are relocatable `MH_OBJECT` inputs for Reflektor;
  `dlopen` consumes linked images instead.
