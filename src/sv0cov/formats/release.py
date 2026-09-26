# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Release identity, checksums, and the release manifest (SPEC 25.4.1-25.4.4).

- Product versions: exact ``MAJOR.MINOR.PATCH`` (``inventory.parse_product_version``),
  numeric precedence, and the successor rule for a declared change impact.
- ``SHA256SUMS``: exact grammar, ordering, and self-exclusion.
- ``sv0cov.release-manifest`` 1.0: closed schema, self-digest, identity
  rules, and reconciliation with ``SHA256SUMS``.

Interpretations recorded here:

- The release manifest has no separate product-version property; the
  version is the one carried by ``release_tag`` (``v<version>``), and every
  versioned filename must agree with it.
- Before ``1.0.0`` a MAJOR-impact change may ship as a MINOR increment
  (major zero makes no stability claim); from ``1.0.0`` on it needs a MAJOR
  increment.
"""

from __future__ import annotations

import hashlib
import re

from sv0cov._generated.validators import sv0cov_release_manifest_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model.inventory import InventoryError, parse_product_version

MAX_MANIFEST_BYTES = 1048576
MAX_SUMS_BYTES = 1048576
RE_DIGEST = re.compile(r"[0-9a-f]{64}")
RE_COMMIT = re.compile(r"[0-9a-f]{40}")
RE_ASSET = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}")
RE_SUMS_LINE = re.compile(rb"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9._-]{0,254})")
IMPACTS = ("PATCH", "MINOR", "MAJOR")
ROLES = ("conformance", "documentation", "evidence", "license", "package", "protocol", "sbom", "source", "support")
REPOSITORY = "sv0-toolchain/sv0cov"
ISSUER = "https://token.actions.githubusercontent.com"
SUMS_NAME = "SHA256SUMS"


class ReleaseError(ValueError):
    """A release identity, checksum file, or manifest is invalid."""


# --- product versions -------------------------------------------------------


def version_key(text: str) -> tuple[int, int, int]:
    try:
        return parse_product_version(text)
    except InventoryError as exc:
        raise ReleaseError(str(exc)) from None


def check_successor(previous: str | None, new: str, impact: str) -> None:
    """``new`` may follow the latest public release ``previous`` for a change of ``impact``."""
    if impact not in IMPACTS:
        raise ReleaseError(f"impact must be one of {', '.join(IMPACTS)}")
    n = version_key(new)
    if previous is None:
        return
    p = version_key(previous)
    if n <= p:
        raise ReleaseError(f"{new} does not have greater precedence than {previous}")
    if n[0] > p[0]:
        if n[1:] != (0, 0):
            raise ReleaseError("a MAJOR increment resets MINOR and PATCH to 0")
        return
    if n[1] > p[1]:
        if n[2] != 0:
            raise ReleaseError("a MINOR increment resets PATCH to 0")
        if impact == "MAJOR" and p[0] != 0:
            raise ReleaseError("a MAJOR-impact change needs a MAJOR increment")
        return
    if impact != "PATCH":
        raise ReleaseError(f"a {impact}-impact change needs more than a PATCH increment")


def sdist_name(version: str) -> str:
    return f"sv0cov-{version}.tar.gz"


def wheel_name(version: str) -> str:
    return f"sv0cov-{version}-py3-none-any.whl"


def manifest_name(version: str) -> str:
    return f"sv0cov-{version}.release.json"


def sbom_name(version: str) -> str:
    return f"sv0cov-{version}.spdx.json"


def tag_version(tag: str) -> str:
    if not tag.startswith("v"):
        raise ReleaseError("a release tag is exactly v<version>")
    version = tag[1:]
    version_key(version)
    return version


# --- SHA256SUMS -------------------------------------------------------------


def encode_sums(entries: dict[str, str]) -> bytes:
    """``{filename: digest}`` → canonical ``SHA256SUMS`` bytes."""
    lines = [f"{entries[name]}  {name}\n" for name in sorted(entries, key=str.encode)]
    data = "".join(lines).encode("ascii")
    parse_sums(data)
    return data


def parse_sums(data: bytes) -> dict[str, str]:
    """Strictly parse ``SHA256SUMS``; returns ``{filename: digest}``."""
    if len(data) > MAX_SUMS_BYTES:
        raise ReleaseError("SHA256SUMS is too large")
    if not data or not data.endswith(b"\n"):
        raise ReleaseError("SHA256SUMS must be nonempty LF-terminated lines")
    out: dict[str, str] = {}
    previous = b""
    for i, line in enumerate(data[:-1].split(b"\n"), 1):
        m = RE_SUMS_LINE.fullmatch(line)
        if not m:
            raise ReleaseError(f"SHA256SUMS line {i} is not '<64 lowercase hex>  <basename>'")
        digest, name = m.group(1).decode(), m.group(2)
        if name.startswith(b".") or name == SUMS_NAME.encode():
            raise ReleaseError(f"SHA256SUMS line {i}: invalid or self-referencing name")
        if name <= previous:
            raise ReleaseError(f"SHA256SUMS line {i}: names must be unique and in byte order")
        previous = name
        out[name.decode()] = digest
    return out


# --- release manifest -------------------------------------------------------


def manifest_digest(obj: dict) -> str:
    return hashlib.sha256(encode({k: v for k, v in obj.items() if k != "release_manifest_sha256"})).hexdigest()


def seal_manifest(obj: dict) -> bytes:
    body = {k: v for k, v in obj.items() if k != "release_manifest_sha256"}
    body["release_manifest_sha256"] = manifest_digest(body)
    data = encode(body)
    validate_manifest(data)
    return data


def check_manifest_object(obj: dict) -> None:
    version = tag_version(obj["release_tag"])
    if not RE_COMMIT.fullmatch(obj["release_commit"]):
        raise ReleaseError("release_commit must be a lowercase 40-hex commit")
    for key in ("compatibility_policy_sha256", "evidence_manifest_sha256", "license_inventory_sha256", "sbom_sha256", "release_manifest_sha256"):
        if not RE_DIGEST.fullmatch(obj[key]):
            raise ReleaseError(f"{key} must be lowercase hexadecimal")
    if not RE_DIGEST.fullmatch(obj["diagnostic_registry"]["sha256"]):
        raise ReleaseError("diagnostic_registry.sha256 must be lowercase hexadecimal")
    names = [a["filename"] for a in obj["artifacts"]]
    if names != sorted(set(names), key=str.encode):
        raise ReleaseError("artifacts must be unique and ordered by filename bytes")
    by_name = {a["filename"]: a for a in obj["artifacts"]}
    for a in obj["artifacts"]:
        if not RE_ASSET.fullmatch(a["filename"]) or a["filename"] in (SUMS_NAME, manifest_name(version)):
            raise ReleaseError(f"artifact {a['filename']!r}: invalid or excluded filename")
        if not RE_DIGEST.fullmatch(a["sha256"]):
            raise ReleaseError(f"artifact {a['filename']}: digest must be lowercase hexadecimal")
        if a["filename"].startswith("sv0cov-") and not a["filename"].startswith(f"sv0cov-{version}"):
            raise ReleaseError(f"artifact {a['filename']}: version disagrees with {obj['release_tag']}")
    for name, role in ((sdist_name(version), "package"), (wheel_name(version), "package"), (sbom_name(version), "sbom")):
        if by_name.get(name, {}).get("role") != role:
            raise ReleaseError(f"artifacts must include {name} with role {role}")
    if by_name[sbom_name(version)]["sha256"] != obj["sbom_sha256"]:
        raise ReleaseError("sbom_sha256 does not match the SBOM artifact")
    if obj["release_manifest_sha256"] != manifest_digest(obj):
        raise ReleaseError("release_manifest_sha256 does not match the manifest")


def validate_manifest(data: bytes) -> dict:
    """Bytes → size bound → canonical JSON → closed schema → semantics."""
    if len(data) > MAX_MANIFEST_BYTES:
        raise ReleaseError("release manifest is too large")
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise ReleaseError(str(exc)) from exc
    check_manifest_object(obj)
    return obj


def reconcile(manifest_bytes: bytes, sums_bytes: bytes) -> None:
    """``SHA256SUMS`` lists exactly the manifest's artifacts plus the manifest itself."""
    obj = validate_manifest(manifest_bytes)
    sums = parse_sums(sums_bytes)
    expected = {a["filename"]: a["sha256"] for a in obj["artifacts"]}
    expected[manifest_name(tag_version(obj["release_tag"]))] = hashlib.sha256(manifest_bytes).hexdigest()
    if sums != expected:
        missing = sorted(expected.keys() - sums.keys())
        extra = sorted(sums.keys() - expected.keys())
        changed = sorted(k for k in expected.keys() & sums.keys() if expected[k] != sums[k])
        raise ReleaseError(f"SHA256SUMS disagrees with the release manifest: missing {missing}, extra {extra}, digest {changed}")
