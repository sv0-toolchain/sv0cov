# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Root compatibility policy 1.0 (SPEC 20.6.1).

``compatibility/sv0cov.json`` in sv0-toolchain selects one exact sv0cov
release. This module owns its closed schema, canonical encoding, and
self-digest. The self-digest detects accidental mutation; it does not
authenticate anything.
"""

from __future__ import annotations

import hashlib
import re

from sv0cov._generated.validators import sv0cov_compatibility_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model import inventory as inv

MAX_BYTES = 65536
RE_DIGEST = re.compile(r"[0-9a-f]{64}")


class PolicyError(ValueError):
    """Invalid policy; callers report COV5002 (compatibility failed)."""


def policy_digest(obj: dict) -> str:
    return hashlib.sha256(encode({k: v for k, v in obj.items() if k != "compatibility_sha256"})).hexdigest()


def seal(obj: dict) -> bytes:
    """Insert the self-digest and return canonical bytes (for authoring policies)."""
    body = {k: v for k, v in obj.items() if k != "compatibility_sha256"}
    body["compatibility_sha256"] = policy_digest(body)
    data = encode(body)
    validate_policy(data)
    return data


def check_policy_object(obj: dict) -> None:
    """Semantic checks on a structurally valid policy object."""
    version = obj["expected_tool"]["version"]
    try:
        inv.parse_product_version(version)
    except inv.InventoryError as exc:
        raise PolicyError(str(exc)) from exc
    if not inv.RE_REVISION.fullmatch(obj["expected_revision"]):
        raise PolicyError("expected_revision must be a lowercase 40-hex commit")
    registries = obj["allowed_diagnostic_registries"]
    keys = [(r["revision"], r["sha256"]) for r in registries]
    if keys != sorted(set(keys)):
        raise PolicyError("allowed_diagnostic_registries must be unique and ordered by revision, then digest")
    if any(not RE_DIGEST.fullmatch(r["sha256"]) for r in registries):
        raise PolicyError("registry digests must be lowercase hexadecimal")
    if len(registries) != 1:
        raise PolicyError("through R1 exactly one diagnostic registry is allowed")
    if obj["allowed_implementation_languages"] != ["python"] or obj["default_implementation_language"] != "python":
        raise PolicyError("through R1 the only implementation language is python")
    try:
        inv.check_artifact_versions(obj["expected_artifact_versions"], version)
        for name in ("commands", "backends", "bytecode_profiles", "features", "hosts"):
            inv.check_set(name, obj[f"required_{name}"], version)
    except inv.InventoryError as exc:
        raise PolicyError(str(exc)) from exc
    if not RE_DIGEST.fullmatch(obj["compatibility_sha256"]) or policy_digest(obj) != obj["compatibility_sha256"]:
        raise PolicyError("compatibility_sha256 does not match the policy")


def validate_policy(data: bytes) -> dict:
    """Bytes → size bound → canonical JSON → structural schema → semantics."""
    if len(data) > MAX_BYTES:
        raise PolicyError(f"policy exceeds {MAX_BYTES} bytes")
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise PolicyError(str(exc)) from exc
    check_policy_object(obj)
    return obj
