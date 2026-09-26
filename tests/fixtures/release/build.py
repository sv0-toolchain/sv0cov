#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Build or check the release-identity fixtures (CV-034).

A fictional ``1.0.0`` release: deterministic attachment bytes, their
``SHA256SUMS``, and the sealed ``sv0cov.release-manifest`` 1.0 that binds
them. The bytes are placeholders; only names, sizes, and digests matter.

    python3 tests/fixtures/release/build.py            # check
    python3 tests/fixtures/release/build.py --write
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2] / "src"))

from sv0cov.formats import release as R  # noqa: E402

VERSION = "1.0.0"
ATTACHMENTS = {  # filename -> (role, media type)
    "LICENSES.tar.gz": ("license", "application/gzip"),
    "sv0cov-1.0.0-py3-none-any.whl": ("package", "application/zip"),
    "sv0cov-1.0.0-protocol.tar.gz": ("protocol", "application/gzip"),
    "sv0cov-1.0.0-source.tar.gz": ("source", "application/gzip"),
    "sv0cov-1.0.0.evidence.json": ("evidence", "application/json"),
    "sv0cov-1.0.0.spdx.json": ("sbom", "application/spdx+json"),
    "sv0cov-1.0.0.tar.gz": ("package", "application/gzip"),
    "INSTALL.md": ("documentation", "text/markdown"),
}


def payload(name: str) -> bytes:
    return f"placeholder bytes for {name}\n".encode()


def manifest_object() -> dict:
    artifacts = []
    for name in sorted(ATTACHMENTS, key=str.encode):
        role, media = ATTACHMENTS[name]
        data = payload(name)
        artifacts.append({"filename": name, "media_type": media, "role": role, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)})
    digest = lambda label: hashlib.sha256(label.encode()).hexdigest()  # noqa: E731
    return {
        "artifacts": artifacts,
        "attestation_policy": {
            "expected_issuer": R.ISSUER,
            "offline_bundle_retention": True,
            "online_verification": True,
            "repository": R.REPOSITORY,
            "subject_digest_algorithm": "sha256",
            "workflow": ".github/workflows/release.yml",
        },
        "compatibility_policy_sha256": digest("compatibility"),
        "diagnostic_registry": {"revision": 1, "sha256": "440aad98c48e372d526d4aefb7c3e8cba8a0d4fc07b31797115a55044b06e3b1"},
        "evidence_manifest_sha256": hashlib.sha256(payload("sv0cov-1.0.0.evidence.json")).hexdigest(),
        "license_inventory_sha256": digest("licenses"),
        "product": "sv0cov",
        "release_commit": "0123456789abcdef0123456789abcdef01234567",
        "release_tag": f"v{VERSION}",
        "sbom_sha256": hashlib.sha256(payload("sv0cov-1.0.0.spdx.json")).hexdigest(),
        "schema": "sv0cov.release-manifest",
        "source_date_epoch": 1790000000,
        "version": "1.0",
    }


def artifacts() -> dict[Path, bytes]:
    manifest = R.seal_manifest(manifest_object())
    obj = R.validate_manifest(manifest)
    sums = {a["filename"]: a["sha256"] for a in obj["artifacts"]}
    sums[R.manifest_name(VERSION)] = hashlib.sha256(manifest).hexdigest()
    return {HERE / R.manifest_name(VERSION): manifest, HERE / "SHA256SUMS": R.encode_sums(sums)}


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print("stale release fixtures: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("release fixtures: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
