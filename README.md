# Situational Awareness BOF
This repo intends to serve two purposes.  First it provides a nice set of basic situational awareness commands implemented in a Beacon Object File (BOF).  This allows you to perform some checks on a host before you begin executing commands that may be more invasive.

Its larger goal is providing a code example and workflow for others to begin making more BOFs. It is a companion document of the blog post made here: https://www.trustedsec.com/blog/a-developers-introduction-to-beacon-object-files/

## Cross-platform BOFs

This fork retains the complete upstream Windows command corpus and adds a
curated subset implemented for Linux and macOS (`darwin`) through Reflektor.
Commands that depend on Windows-only facilities such as Active Directory, COM,
DPAPI, the Registry, SCM, scheduled tasks, or WMI remain Windows-only rather
than advertising partial Unix behavior.

[`portable/manifest.json`](portable/manifest.json) is the authoritative target
and command classification. See [`PORTABILITY.md`](PORTABILITY.md) for the exact
portable command set, target matrix, behavior differences, and runtime limits.

## Cross-platform build

The matrix build requires Bash, Zig, Node.js, `jq`, `file`, and an object-file
disassembler. Build and verify the complete declared matrix with:

```sh
make matrix
make verify
```

To build one target for Reflektor integration, run:

```sh
./scripts/build-target.sh linux amd64
```

Objects are generated below `dist/<goos>/<goarch>/`; they are build artifacts
and are not committed. A successful matrix build does not itself publish an
Armory release. Armory packages are published only by the tag-gated release
workflow after a maintainer deliberately creates and pushes an approved,
GitHub-verified signed annotated tag named exactly `vMAJOR.MINOR.PATCH` on a
commit that is still the exact head of `origin/master`. The workflow rechecks
the remote tag before draft creation and publication and never creates a tag.
Before the first release, maintainers must also protect `v*` tags from updates
and deletion and restrict their creation to organization administrators; a
workflow cannot make those remote reference updates atomic by itself. Create a
protected `armory-release` environment with a required reviewer before using
the release workflow. The workflow uses the repository's established
`MINISIGN_PRIVATE_KEY` so existing Armory installations retain signing-key
continuity. Environment approval, exact-master tag verification, and the tag
ruleset gate use of that key; rotate or move it only together with the public
key in `packaging/release-config.json` and the official Armory index.

See [`UPSTREAM.md`](UPSTREAM.md) before synchronizing TrustedSec changes. It
documents the source ownership boundaries, merge procedure, and validation
gates that keep future upstream pulls reviewable.

## Making a new BOF
If you want to use the same workflow as this repository, your basic steps are as follows:
1. Make a folder that covers the target topic, for example in this repo we are using SA
2. Copy the base_template into topic/commandname
3. Modify the Makefile to have your commandname on the first line. This should be the same as the folder name
4. If doing something other then SA, make sure to modify lines 14 and 15 of the makefile as well so its moved to the correct location
5. Make a .cna file in the base of your topic folder and add the commands that you reference. If you followed this format you can take the helper function readbof from SA.cna

Realistically, this could be compressed into a helper script, but those steps were not taken for this effort.

## Available commands
|Commands|Usage|Notes|
|--------|-----|-----|
|adcs_enum | adcs_enum| Enumerate CAs and templates in the AD using Win32 functions|
|adcs_enum_com | adcs_enum_com| Enumerate CAs and templates in the AD using ICertConfig COM object|
|adcs_enum_com2 | adcs_enum_com2| Enumerate CAs and templates in the AD using IX509PolicyServerListManager COM object|
| adrbperms | adrbperms | Check if current user has read access to Active Directory Recycling Bin |
| adrbstatus | adrbstatus | Check the status (Enabled/Disabled) of Active Directory Recycling Bin in the current domain |
| adrblist | adrblist | Enumerate all deleted objects in the Active Directory Recycling Bin |
|adv_audit_policies | adv_audit_policies| Retrieve advanced security audit policies|
|arp | arp| List ARP table|
|cacls|cacls [filepath]| List user permissions for the specified file, wildcards supported|
|cat| cat [filepath] | Return the content of the selected text file |
|dir| dir [directory] [/s]| List files in a directory. Supports wildcards (e.g. "C:\Windows\S*") unlike the CobaltStrike `ls` command|
|driversigs| driversigs| Enumerate installed services Imagepaths to check the signing cert against known AV/EDR vendors|
|enum_filter_driver| enum_filter_driver [opt:computer]| Enumerate filter drivers|
|enumLocalSessions| enumLocalSessions| Enumerate currently attached user sessions both local and over RDP|
|env| env| List process environment variables|
|findLoadedModule| findLoadedModule [modulepart] [opt:procnamepart]| Find what processes \*modulepart\* are loaded into, optionally searching just \*procnamepart\*|
|get_dpapi_system| get_dpapi_system | Get the DPAPI_SYSTEM key and bootkey |
|get_password_policy| get_password_policy [hostname]| Get target server or domain's configured password policy and lockouts|
|get_session_info| get_session_info | prints out information related to the current users logon session |
|ipconfig| ipconfig| List IPv4 address, hostname, and DNS server|
| hostname | hostname | Show the computer name and fully qualified domain name if the system is domain-joined |
|ldapsearch| ldapsearch <query> [--attributes] [--count] [--scope] [--hostname] [--dn] [--ldaps] | Execute LDAP searches (NOTE: specify *,ntsecuritydescriptor as attribute parameter if you want all attributes + base64 encoded ACL of the objects, this can then be resolved using BOFHound. Could possibly break pagination, although everything seemed fine during testing.)|
|listdns| listdns| List DNS cache entries. Attempt to query and resolve each|
|list_firewall_rules| list_firewall_rules| List Windows firewall rules|
|listmods| listmods [opt: pid]| List process modules (DLL). Target current process if PID is empty. Complement to driversigs to determine if our process was injected by AV/EDR|
|listpipes| listpipes| List named pipes|
|locale| locale| List system locale language, locale ID, date, time, and country|
|netGroupList| netGroupList [opt: domain]| List groups from the default or specified domain|
|netGroupListMembers| netGroupListMembers [groupname] [opt: domain]| List group members from the default or specified domain|
|netLocalGroupList| netLocalGroupList [opt: server]| List local groups from the local or specified computer|
|netLocalGroupListMembers| netLocalGroupListMembers [groupname] [opt: server]| List local groups from the local or specified computer|
|netLocalGroupListMembers2| netLocalGroupListMembers2 [opt: groupname] [opt: server]| Modified version of `netLocalGroupListMembers` that supports BOFHound|
|netloggedon| netloggedon [hostname]| Return users logged on the local or remote computer|
|netloggedon2| netloggedon2 [opt: hostname]| Modified version of `netloggedon` that supports BOFHound|
|netsession| netsession [opt:computer]| Enumerate sessions on the local or specified computer|
|netsession2| netsession2 [opt:computer] [opt:resolution method] [opt:dns server]| Modified version of `netsession` that supports BOFHound|
|netshares| netshares [hostname]| List shares on the local or remote computer|
|netstat| netstat| TCP and UDP IPv4 listing ports|
|nettime| nettime [hostname]| Display time on remote computer|
|netuptime| netuptime [hostname]| Return information about the boot time on the local or remote computer|
|netuser| netuser [username] [opt: domain]| Get info about specific user. Pull from domain if a domainname is specified|
|netuse_add| netuse_add [sharename] [opt:username] [opt:password] [opt:/DEVICE:devicename] [opt:/PERSIST] [opt:/REQUIREPRIVACY]| Bind a new connection to a remote computer|
|netuse_delete| netuse_delete [device\|\|sharename] [opt:/PERSIST] [opt:/FORCE]| Delete the bound device / sharename |
|netuse_list| netuse_list [opt:target]| List all bound share resources or info about target local resource|
|netview| netview| List reachable computers in the current domain|
|nslookup| nslookup [hostname] [opt:dns server] [opt: record type]| Make a DNS query.<br/>  DNS server is the server you want to query (do not specify or 0 for default) <br/>record type is something like A, AAAA, or ANY. Some situations are limited due to observed crashes|
| md5 | md5 [filename] | Hash filename using md5 |
|probe| probe [host] [port]| Check if a specific port is open|
|regsession| regsession [opt: hostname]| Return logged on user SIDs by enumerating HKEY_USERS. BOFHound compatible|
|reg_query| [opt:hostname] [hive] [path] [opt: value to query]| Query a registry value or enumerate a single key|
|reg_query_recursive| [opt:hostname] [hive] [path]| Recursively enumerate a key starting at path|
|resources| resources| List memory usage and available disk space on the primary hard drive|
|routeprint| routeprint| List IPv4 routes|
|sc_enum| sc_enum [opt:server]| Enumerate services for qc, query, qfailure, and qtriggers info|
|sc_qc| sc_qc [service name] [opt:server]| sc qc impelmentation in BOF|
|sc_qdescription| sc_qdescription [service name] [opt: server]| sc qdescription implementation in BOF|
|sc_qfailure| sc_qfailure [service name] [opt:server]| Query a service for failure conditions|
|sc_qtriggerinfo| sc_qtriggerinfo [service name] [opt:server]| Query a service for trigger conditions|
|sc_query| sc_query [opt: service name] [opt: server]| sc query implementation in BOF|
|schtasksenum| schtasksenum [opt: server]| Enumerate scheduled tasks on the local or remote computer|
|schtasksquery| schtasksquery [opt: server] [taskpath]| Query the given task on the local or remote computer|
| sha1 | sha1 [filename] | Hash filename using sha1 |
|sha256 | sha256 [filename] | Hash filename using sha256 |
|sha512 | sha512 [filename] | Hash filename using sha512 |
|tasklist| tasklist [opt: server]| List running processes including PID, PPID, and ComandLine (uses wmi)|
|uptime| uptime| List system boot time and how long it has been running|
|useridletime| useridletime| Shows how long the user as been idle, displayed in seconds, minutes, hours and days|
| vol | vol [opt: driver] | Display the volume label and serial number of a specified drive |
|vssenum| vssenum [hostname] [opt:sharename]| Enumerate Shadow Copies on some Server 2012+ servers|
|whoami| whoami| List whoami /all|
|windowlist| windowlist [opt:all]| List visible windows in the current user session|
|wmi_query| wmi_query query [opt: server] [opt: namespace]| Run a wmi query and display results in CSV format|

Note the reason for including reg_query when CS has a built in reg query(v) command is because this one can target remote computers and has the ability to recursively enumerate a whole key.

#### Credits
The functional code for most of these commands was taken from the reactos project or code examples hosted on MSDN.
The driversigs codebase comes from https://gist.github.com/jthuraisamy/4c4c751df09f83d3620013f5d370d3b9

Thanks all of the contributors listed under contributors. Each of you have contributed something meaningful to this repository and dealt with me and my review processes. I appreciate each and every one of you for teaching me and helping make this BOF repository the best it can be!

##### Compilers used

The legacy per-command Windows Makefiles use the
[TrustedSec BOF builder](https://hub.docker.com/r/freefirex2/ts_bof_builder).
The cross-platform matrix uses Zig to produce native COFF, ELF relocatable, and
Mach-O object files for the targets declared in `portable/manifest.json`.

## System Support

The complete upstream BOF set targets Windows Vista+. A curated subset also
targets Linux and macOS; consult `portable/manifest.json` rather than assuming
that every command is available on every operating system. TrustedSec maintains
a less frequently updated [winxp_2003 branch](https://github.com/trustedsec/CS-Situational-Awareness-BOF/tree/winxp_2003)
for older Windows systems.

## Want to Learn More?
If you've found these beacon object files helpful and want to write some of your own bofs following a similar style we invite you to check out our [Beacon Object File (BOF) Development](https://learn.trustedsec.com/courses/cd84409a-36af-4507-be2c-ca7ad1e9fd2d) course.
The course gives a breif overview of the history of beacon object files and then dives into a variety of challenge problems that aim to teach you how to leverage a variety of windows technologies when developing your own beacon object files.
