# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Version and capability manifest 1.0 (SPEC 20.6): ``sv0cov version --json``.

The manifest is closed, canonical, self-hashed, at most 65,536 bytes, and
independent of the working directory, project configuration, Git state of
any project, and the network. It advertises only what this build has
passed (``sv0cov.capabilities``).
"""

from __future__ import annotations

import hashlib
import platform
import re
import sys
from dataclasses import dataclass

from sv0cov._generated.validators import sv0cov_version_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model import inventory as inv

MAX_BYTES = 65536
RE_DIGEST = re.compile(r"[0-9a-f]{64}")
RE_RUNTIME = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")


class ManifestError(ValueError):
    """Invalid manifest (COV8001 when produced locally, COV5002 when checked by the root)."""


def current_host() -> dict:
    """The effective process OS and architecture as SPEC 20.6 names them."""
    system = {"Darwin": "macos", "Linux": "linux"}.get(platform.system())
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86_64", "AMD64": "x86_64"}.get(platform.machine())
    if system is None or machine is None or sys.maxsize <= 2**32:
        raise ManifestError(f"unsupported host {platform.system()} {platform.machine()}")
    return {"architecture": machine, "operating_system": system}


def manifest_digest(obj: dict) -> str:
    return hashlib.sha256(encode({k: v for k, v in obj.items() if k != "manifest_sha256"})).hexdigest()


@dataclass(frozen=True)
class Advertised:
    commands: tuple[str, ...]
    backends: tuple[str, ...]
    bytecode_profiles: tuple[str, ...]
    features: tuple[str, ...]


def build(
    *,
    tool_version: str,
    revision: str,
    runtime_version: str,
    host: dict,
    registry_revision: int,
    registry_sha256: str,
    advertised: Advertised,
) -> bytes:
    """Construct, seal, and validate a manifest for the running implementation."""
    body = {
        "artifact_versions": {family: ["1.0"] for family in sorted(inv.ARTIFACT_FAMILIES)},
        "backends": list(advertised.backends),
        "bytecode_profiles": list(advertised.bytecode_profiles),
        "commands": list(advertised.commands),
        "diagnostic_registry": {"revision": registry_revision, "sha256": registry_sha256},
        "features": list(advertised.features),
        "host": host,
        "implementation": {"language": "python", "revision": revision, "runtime": {"name": "cpython", "version": runtime_version}},
        "schema": "sv0cov.version",
        "supported_hosts": list(inv.HOSTS),
        "supported_python_versions": list(inv.PYTHON_VERSIONS),
        "tool": {"name": "sv0cov", "version": tool_version},
        "version": "1.0",
    }
    body["manifest_sha256"] = manifest_digest(body)
    data = encode(body)
    validate_manifest(data)
    return data


def check_manifest_object(obj: dict) -> None:
    version = obj["tool"]["version"]
    try:
        inv.parse_product_version(version)
        inv.check_artifact_versions(obj["artifact_versions"], version)
        for name in ("commands", "backends", "bytecode_profiles", "features"):
            inv.check_set(name, obj[name], version)
    except inv.InventoryError as exc:
        raise ManifestError(str(exc)) from exc
    if obj["supported_hosts"] != list(inv.HOSTS):
        raise ManifestError("supported_hosts must be exactly the four R1 hosts")
    impl = obj["implementation"]
    if not inv.RE_REVISION.fullmatch(impl["revision"]):
        raise ManifestError("implementation.revision must be a lowercase 40-hex commit")
    if impl["language"] == "python":
        if obj["supported_python_versions"] != list(inv.PYTHON_VERSIONS):
            raise ManifestError("the Python implementation supports exactly 3.13 and 3.14")
        runtime = impl["runtime"]
        m = RE_RUNTIME.fullmatch(runtime["version"])
        if runtime["name"] != "cpython" or not m or f"{m.group(1)}.{m.group(2)}" not in inv.PYTHON_VERSIONS:
            raise ManifestError("python runtime must be a canonical CPython 3.13 or 3.14 version")
    else:
        if obj["supported_python_versions"] != [] or impl["runtime"]["name"] != "sv0":
            raise ManifestError("the sv0 implementation has no Python versions and an sv0 runtime")
    host = f"{obj['host']['operating_system']}-{obj['host']['architecture']}"
    if host not in obj["supported_hosts"]:
        raise ManifestError(f"host {host} is not a supported host")
    if not RE_DIGEST.fullmatch(obj["diagnostic_registry"]["sha256"]):
        raise ManifestError("diagnostic registry digest must be lowercase hexadecimal")
    if not RE_DIGEST.fullmatch(obj["manifest_sha256"]) or manifest_digest(obj) != obj["manifest_sha256"]:
        raise ManifestError("manifest_sha256 does not match the manifest")


def validate_manifest(data: bytes) -> dict:
    if len(data) > MAX_BYTES:
        raise ManifestError(f"manifest exceeds {MAX_BYTES} bytes")
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise ManifestError(str(exc)) from exc
    check_manifest_object(obj)
    return obj
