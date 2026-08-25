#!/usr/bin/env python3
"""Build and verify deterministic Sliver Armory package archives."""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any, Iterable


REPO_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = REPO_ROOT / "src" / "SA"
PORTABILITY_MANIFEST = REPO_ROOT / "portable" / "manifest.json"
RELEASE_CONFIG = REPO_ROOT / "packaging" / "release-config.json"
LICENSE_FILE = REPO_ROOT / "LICENSE"
CHECKSUM_FILE = "SHA256SUMS"
ARTIFACT_TEMPLATE = "dist/{goos}/{goarch}/{command}.o"
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
SAFE_VERSION = re.compile(
    r"^v?[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$"
)


class PackageError(RuntimeError):
    """A user-facing packaging contract violation."""


def fail(message: str) -> None:
    raise PackageError(message)


def json_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            fail(f"duplicate JSON key {key!r}")
        value[key] = item
    return value


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=json_no_duplicates)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read {path.relative_to(REPO_ROOT)}: {exc}")
    if not isinstance(value, dict):
        fail(f"{path.relative_to(REPO_ROOT)} must contain a JSON object")
    return value


def require_regular_file(path: Path, description: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as exc:
        fail(f"cannot read {description} {path}: {exc}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"{description} must be a regular, non-symlink file: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read {description} {path}: {exc}")
    if not data:
        fail(f"{description} is empty: {path}")
    return data


def source_directories() -> list[str]:
    try:
        entries = list(SOURCE_ROOT.iterdir())
    except OSError as exc:
        fail(f"cannot enumerate {SOURCE_ROOT}: {exc}")
    result: list[str] = []
    for entry in entries:
        if not entry.is_dir() or entry.is_symlink():
            continue
        if not SAFE_NAME.fullmatch(entry.name):
            fail(f"unsafe source directory name: {entry.name!r}")
        require_regular_file(entry / "extension.json", "extension manifest")
        result.append(entry.name)
    if not result:
        fail("src/SA contains no package source directories")
    return sorted(result)


def string_list(value: Any, description: str) -> list[str]:
    if not isinstance(value, list) or not value:
        fail(f"{description} must be a non-empty array")
    if any(not isinstance(item, str) or not SAFE_NAME.fullmatch(item) for item in value):
        fail(f"{description} must contain only safe, non-empty names")
    if len(set(value)) != len(value):
        fail(f"{description} contains duplicate names")
    if value != sorted(value):
        fail(f"{description} must be sorted")
    return value


class Contract:
    def __init__(self) -> None:
        self.document = load_json(PORTABILITY_MANIFEST)
        if self.document.get("schema_version") != 1:
            fail("portable/manifest.json schema_version must be 1")
        if self.document.get("entrypoint") != "go":
            fail("portable/manifest.json entrypoint must be 'go'")
        if self.document.get("artifact_template") != ARTIFACT_TEMPLATE:
            fail(f"portable/manifest.json artifact_template must be {ARTIFACT_TEMPLATE!r}")

        self.sources = source_directories()
        command_sets = self.document.get("command_sets")
        if not isinstance(command_sets, dict):
            fail("portable/manifest.json command_sets must be an object")
        self.portable = string_list(command_sets.get("portable"), "command_sets.portable")
        self.windows_only = string_list(
            command_sets.get("windows-only"), "command_sets.windows-only"
        )
        all_upstream = command_sets.get("all-upstream")
        if all_upstream != {"source_directories": "src/SA/*"}:
            fail("command_sets.all-upstream must derive from src/SA/*")
        classified = sorted(self.portable + self.windows_only)
        if len(set(classified)) != len(classified) or classified != self.sources:
            fail("portable and windows-only command sets must exactly partition src/SA")

        raw_targets = self.document.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets:
            fail("portable/manifest.json targets must be a non-empty array")
        self.targets: list[dict[str, Any]] = []
        seen_targets: set[tuple[str, str]] = set()
        for index, target in enumerate(raw_targets):
            if not isinstance(target, dict):
                fail(f"targets[{index}] must be an object")
            for field in ("goos", "goarch", "format", "machine", "commands"):
                if not isinstance(target.get(field), str) or not target[field]:
                    fail(f"targets[{index}].{field} must be a non-empty string")
            if not isinstance(target.get("publish"), bool):
                fail(f"targets[{index}].publish must be boolean")
            selector = target["commands"]
            if selector not in ("all-upstream", "portable", "windows-only"):
                fail(f"targets[{index}].commands references unknown command set {selector!r}")
            pair = (target["goos"], target["goarch"])
            if pair in seen_targets:
                fail(f"duplicate target {pair[0]}/{pair[1]}")
            seen_targets.add(pair)
            self.targets.append(target)

        portable_counts = {len(self.published_targets(command)) for command in self.portable}
        windows_counts = {len(self.published_targets(command)) for command in self.windows_only}
        if portable_counts != {8}:
            fail(f"every portable command must have exactly 8 published targets, got {portable_counts}")
        if windows_counts != {3}:
            fail(f"every Windows-only command must have exactly 3 published targets, got {windows_counts}")

    def selected_commands(self, selector: str) -> set[str]:
        if selector == "all-upstream":
            return set(self.sources)
        if selector == "portable":
            return set(self.portable)
        if selector == "windows-only":
            return set(self.windows_only)
        fail(f"unknown command selector {selector!r}")

    def published_targets(self, source: str) -> list[dict[str, Any]]:
        return [
            target
            for target in self.targets
            if target["publish"] and source in self.selected_commands(target["commands"])
        ]


class PackageSpec:
    def __init__(self, contract: Contract, source: str, version: str) -> None:
        self.source = source
        source_manifest = load_json(SOURCE_ROOT / source / "extension.json")
        self.is_v2 = "commands" in source_manifest
        rendered = copy.deepcopy(source_manifest)

        if not isinstance(rendered.get("name"), str) or not rendered["name"]:
            fail(f"src/SA/{source}/extension.json is missing name")
        rendered["version"] = version
        files = [
            {
                "os": target["goos"],
                "arch": target["goarch"],
                "path": ARTIFACT_TEMPLATE.format(
                    goos=target["goos"], goarch=target["goarch"], command=source
                ),
            }
            for target in contract.published_targets(source)
        ]

        if self.is_v2:
            stem = rendered.get("package_name")
            commands = rendered.get("commands")
            if not isinstance(commands, list) or not commands:
                fail(f"V2 manifest src/SA/{source}/extension.json has no commands")
            command_names: set[str] = set()
            for index, command in enumerate(commands):
                if not isinstance(command, dict):
                    fail(f"src/SA/{source}/extension.json commands[{index}] must be an object")
                command_name = command.get("command_name")
                if not isinstance(command_name, str) or not command_name:
                    fail(f"src/SA/{source}/extension.json commands[{index}] lacks command_name")
                if command_name in command_names:
                    fail(f"src/SA/{source}/extension.json repeats command {command_name!r}")
                command_names.add(command_name)
                if not isinstance(command.get("help"), str) or not command["help"]:
                    fail(f"src/SA/{source}/extension.json command {command_name!r} lacks help")
                command["entrypoint"] = "go"
                command["bof_executor"] = "reflektor"
                command["depends_on"] = "coff-loader"
                command["files"] = copy.deepcopy(files)
        else:
            stem = rendered.get("command_name")
            if not isinstance(rendered.get("help"), str) or not rendered["help"]:
                fail(f"V1 manifest src/SA/{source}/extension.json lacks help")
            rendered["entrypoint"] = "go"
            rendered["bof_executor"] = "reflektor"
            rendered["depends_on"] = "coff-loader"
            rendered["files"] = files

        if not isinstance(stem, str) or not SAFE_NAME.fullmatch(stem):
            fail(f"src/SA/{source}/extension.json has unsafe or missing package stem")
        if not stem.startswith("sa-"):
            fail(f"src/SA/{source}/extension.json package stem must start with 'sa-': {stem}")
        self.stem = stem
        self.manifest = (json.dumps(rendered, ensure_ascii=False, indent=2) + "\n").encode("utf-8")
        self.objects: dict[str, Path] = {}
        for file_entry in files:
            archive_path = file_entry["path"]
            object_path = REPO_ROOT / PurePosixPath(archive_path)
            require_regular_file(object_path, "BOF object")
            self.objects[f"./{archive_path}"] = object_path

    @property
    def archive_name(self) -> str:
        return f"{self.stem}.tar.gz"

    @property
    def signature_name(self) -> str:
        return f"{self.stem}.minisig"

    @property
    def members(self) -> dict[str, bytes]:
        members = {
            "./LICENSE": require_regular_file(LICENSE_FILE, "license"),
            "./extension.json": self.manifest,
        }
        for name, path in self.objects.items():
            members[name] = require_regular_file(path, "BOF object")
        return members


def package_specs(contract: Contract, version: str, requested: str | None) -> list[PackageSpec]:
    if not SAFE_VERSION.fullmatch(version):
        fail(f"invalid package version {version!r}")
    selected = contract.sources
    if requested is not None:
        if requested not in contract.sources:
            fail(f"unknown source package {requested!r}")
        selected = [requested]
    specs = [PackageSpec(contract, source, version) for source in selected]
    stems = [spec.stem for spec in specs]
    if len(stems) != len(set(stems)):
        duplicates = sorted(stem for stem in set(stems) if stems.count(stem) > 1)
        fail(f"multiple source directories resolve to the same package stem: {duplicates}")
    return sorted(specs, key=lambda spec: spec.stem)


def normalized_epoch(value: str | None) -> int:
    raw = value if value is not None else os.environ.get("SOURCE_DATE_EPOCH", "0")
    try:
        epoch = int(raw, 10)
    except ValueError:
        fail(f"SOURCE_DATE_EPOCH must be an integer, got {raw!r}")
    if epoch < 0 or epoch > 0xFFFFFFFF:
        fail("SOURCE_DATE_EPOCH must fit in an unsigned 32-bit gzip timestamp")
    return epoch


def add_tar_member(archive: tarfile.TarFile, name: str, data: bytes, epoch: int) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mtime = epoch
    info.mode = 0o644
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    archive.addfile(info, fileobj=io.BytesIO(data))


def write_archive(path: Path, spec: PackageSpec, epoch: int) -> None:
    with path.open("xb") as destination:
        with gzip.GzipFile(filename="", mode="wb", fileobj=destination, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
                for name, data in sorted(spec.members.items()):
                    add_tar_member(archive, name, data, epoch)


def minisign_config() -> tuple[str, dict[str, Any]]:
    document = load_json(RELEASE_CONFIG)
    config = document.get("minisign")
    if not isinstance(config, dict):
        fail("packaging/release-config.json minisign must be an object")
    public_key = config.get("public_key")
    if not isinstance(public_key, str) or not public_key.startswith("RW"):
        fail("packaging/release-config.json contains an invalid minisign public key")
    return public_key, config


def run_minisign(arguments: list[str], input_data: bytes | None = None) -> None:
    try:
        completed = subprocess.run(
            arguments,
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
    except OSError as exc:
        fail(f"cannot execute minisign: {exc}")
    if completed.returncode != 0:
        output = completed.stdout.decode("utf-8", errors="replace").strip()
        fail(f"minisign failed ({completed.returncode}): {output}")


def trusted_comment(signature: Path) -> str:
    try:
        lines = signature.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        fail(f"cannot read signature {signature}: {exc}")
    if len(lines) != 4:
        fail(f"signature {signature.name} must contain exactly four lines")
    if not lines[0].startswith("untrusted comment:"):
        fail(f"signature {signature.name} lacks its untrusted comment")
    prefix = "trusted comment: "
    if not lines[2].startswith(prefix):
        fail(f"signature {signature.name} lacks its trusted comment")
    for index in (1, 3):
        try:
            base64.b64decode(lines[index], validate=True)
        except (ValueError, binascii.Error):
            fail(f"signature {signature.name} line {index + 1} is not strict base64")
    return lines[2][len(prefix) :]


def sign_archive(minisign: str, secret_key: Path, archive: Path, signature: Path, manifest: bytes) -> None:
    require_regular_file(secret_key, "minisign secret key")
    comment = base64.b64encode(manifest).decode("ascii")
    run_minisign(
        [
            minisign,
            "-S",
            "-s",
            str(secret_key),
            "-m",
            str(archive),
            "-t",
            comment,
            "-x",
            str(signature),
        ],
        input_data=b"\n",
    )
    if trusted_comment(signature) != comment:
        fail(f"minisign did not preserve the exact manifest trusted comment for {archive.name}")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as source:
            for block in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")
    return digest.hexdigest()


def checksum_bytes(directory: Path, asset_names: Iterable[str]) -> bytes:
    return "".join(f"{sha256(directory / name)}  {name}\n" for name in sorted(asset_names)).encode(
        "ascii"
    )


def expected_names(specs: list[PackageSpec], signed: bool) -> set[str]:
    names = {spec.archive_name for spec in specs}
    if signed:
        names.update(spec.signature_name for spec in specs)
    names.add(CHECKSUM_FILE)
    return names


def verify_tar(path: Path, spec: PackageSpec, epoch: int) -> None:
    header = require_regular_file(path, "package archive")[:10]
    if len(header) < 10 or header[:2] != b"\x1f\x8b":
        fail(f"{path.name} is not a gzip archive")
    if int.from_bytes(header[4:8], "little") != epoch:
        fail(f"{path.name} has the wrong deterministic gzip timestamp")
    if header[3] & 0x08:
        fail(f"{path.name} embeds a non-deterministic gzip filename")

    expected = spec.members
    try:
        with tarfile.open(path, mode="r:gz") as archive:
            members = archive.getmembers()
            actual_names = [member.name for member in members]
            if actual_names != sorted(expected):
                fail(f"{path.name} has a stale, missing, duplicate, or unsorted member inventory")
            for member in members:
                pure_name = PurePosixPath(member.name)
                if pure_name.is_absolute() or ".." in pure_name.parts:
                    fail(f"{path.name} contains unsafe member {member.name!r}")
                if not member.isfile():
                    fail(f"{path.name} member {member.name!r} is not a regular file")
                if (
                    member.mode != 0o644
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mtime != epoch
                ):
                    fail(f"{path.name} member {member.name!r} has non-deterministic metadata")
                extracted = archive.extractfile(member)
                if extracted is None or extracted.read() != expected[member.name]:
                    fail(f"{path.name} member {member.name!r} differs from the expected input")
    except (OSError, tarfile.TarError) as exc:
        fail(f"cannot inspect {path.name}: {exc}")


def verify_output(
    directory: Path,
    specs: list[PackageSpec],
    epoch: int,
    require_signatures: bool,
    forbid_signatures: bool,
    minisign: str | None,
) -> None:
    if require_signatures and forbid_signatures:
        fail("cannot both require and forbid signatures")
    try:
        entries = list(directory.iterdir())
    except OSError as exc:
        fail(f"cannot enumerate package directory {directory}: {exc}")
    actual = {entry.name for entry in entries}
    has_signatures = any(name.endswith(".minisig") for name in actual)
    if require_signatures and not has_signatures:
        fail("signed package inventory is required")
    if forbid_signatures and has_signatures:
        fail("unsigned candidate inventory must not contain signatures")
    expected = expected_names(specs, has_signatures)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        fail(f"package inventory mismatch; missing={missing}, extra={extra}")
    for entry in entries:
        require_regular_file(entry, "package output")

    for spec in specs:
        archive = directory / spec.archive_name
        verify_tar(archive, spec, epoch)
        if has_signatures:
            signature = directory / spec.signature_name
            expected_comment = base64.b64encode(spec.manifest).decode("ascii")
            actual_comment = trusted_comment(signature)
            if actual_comment != expected_comment:
                fail(
                    f"{signature.name} trusted comment is not the exact packaged extension.json"
                )
            if minisign is None:
                fail("minisign is required to cryptographically verify signed packages")
            public_key, _ = minisign_config()
            run_minisign(
                [
                    minisign,
                    "-V",
                    "-P",
                    public_key,
                    "-m",
                    str(archive),
                    "-x",
                    str(signature),
                ]
            )

    checksum_assets = sorted(actual - {CHECKSUM_FILE})
    expected_checksums = checksum_bytes(directory, checksum_assets)
    checksum_path = directory / CHECKSUM_FILE
    if require_regular_file(checksum_path, "checksum inventory") != expected_checksums:
        fail("SHA256SUMS does not exactly match the package asset inventory")


def build(args: argparse.Namespace) -> None:
    contract = Contract()
    specs = package_specs(contract, args.version, args.package)
    epoch = normalized_epoch(args.source_date_epoch)
    output = Path(args.output).resolve()
    if output.exists() or output.is_symlink():
        fail(f"refusing to reuse package output path: {output}")
    parent = output.parent
    if not parent.is_dir() or parent.is_symlink():
        fail(f"package output parent must be an existing, non-symlink directory: {parent}")

    signing = args.signing_key is not None
    if signing and args.minisign is None:
        fail("--minisign is required with --signing-key")
    temp = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=parent))
    try:
        for spec in specs:
            archive = temp / spec.archive_name
            write_archive(archive, spec, epoch)
            if signing:
                sign_archive(
                    args.minisign,
                    Path(args.signing_key).resolve(),
                    archive,
                    temp / spec.signature_name,
                    spec.manifest,
                )
        assets = sorted(path.name for path in temp.iterdir())
        (temp / CHECKSUM_FILE).write_bytes(checksum_bytes(temp, assets))
        verify_output(
            temp,
            specs,
            epoch,
            require_signatures=signing,
            forbid_signatures=not signing,
            minisign=args.minisign,
        )
        if output.exists() or output.is_symlink():
            fail(f"package output path appeared during the build: {output}")
        temp.chmod(0o755)
        os.replace(temp, output)
    finally:
        if temp.exists():
            shutil.rmtree(temp)
    kind = "signed" if signing else "unsigned"
    print(f"built and verified {len(specs)} {kind} Armory package(s) in {output}")


def verify(args: argparse.Namespace) -> None:
    contract = Contract()
    specs = package_specs(contract, args.version, args.package)
    epoch = normalized_epoch(args.source_date_epoch)
    directory = Path(args.input).resolve()
    if not directory.is_dir() or directory.is_symlink():
        fail(f"package input must be a non-symlink directory: {directory}")
    verify_output(
        directory,
        specs,
        epoch,
        require_signatures=args.require_signatures,
        forbid_signatures=args.forbid_signatures,
        minisign=args.minisign,
    )
    print(f"verified exact inventory for {len(specs)} Armory package(s) in {directory}")


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)

    build_parser = commands.add_parser("build", help="build a fresh deterministic package set")
    build_parser.add_argument("--version", required=True)
    build_parser.add_argument("--output", required=True)
    build_parser.add_argument("--package", help="build one src/SA source-directory package")
    build_parser.add_argument("--source-date-epoch")
    build_parser.add_argument("--signing-key")
    build_parser.add_argument("--minisign")
    build_parser.set_defaults(function=build)

    verify_parser = commands.add_parser("verify", help="verify an exact package inventory")
    verify_parser.add_argument("--version", required=True)
    verify_parser.add_argument("--input", required=True)
    verify_parser.add_argument("--package", help="verify one src/SA source-directory package")
    verify_parser.add_argument("--source-date-epoch")
    signature_mode = verify_parser.add_mutually_exclusive_group()
    signature_mode.add_argument("--require-signatures", action="store_true")
    signature_mode.add_argument("--forbid-signatures", action="store_true")
    verify_parser.add_argument("--minisign")
    verify_parser.set_defaults(function=verify)
    return result


def main() -> int:
    try:
        args = parser().parse_args()
        args.function(args)
        return 0
    except PackageError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
