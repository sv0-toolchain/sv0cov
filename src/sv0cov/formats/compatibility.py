# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Root compatibility policy 1.0 (SPEC 20.6.1, 20.6.2).

``compatibility/sv0cov.json`` in sv0-toolchain selects one exact sv0cov
release. This module owns its closed schema, canonical encoding,
self-digest, and the comparison with a capability manifest
(:func:`evaluate`), which the root preflight and doctor D012 share. The
self-digest detects accidental mutation; it does not authenticate anything.
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


class Incompatible(ValueError):
    """A valid policy and a valid capability manifest that do not agree (SPEC 20.6.2; COV5002)."""


def evaluate(policy: dict, manifest: dict, host: dict, registry: dict) -> None:
    """Rules 3 to 9 of SPEC 20.6.2, in order, for a validated policy and a
    validated capability manifest. ``host`` is the effective host the caller
    observed itself (``{"architecture", "operating_system"}``) and
    ``registry`` the ``{"revision", "sha256"}`` of the registry the pinned
    components carry. Rules 1 and 2 (the policy itself, the gitlink) are the
    caller's. Raises :class:`Incompatible` with the first disagreement."""
    # 3. the manifest version
    if manifest["version"] != policy["version_manifest_version"]:
        raise Incompatible(f"manifest version {manifest['version']} != {policy['version_manifest_version']}")
    # 4. identity
    tool, impl = manifest["tool"], manifest["implementation"]
    if tool != policy["expected_tool"]:
        raise Incompatible(f"sv0cov reports {tool['name']} {tool['version']}, the policy expects "
                           f"{policy['expected_tool']['name']} {policy['expected_tool']['version']}")
    if impl["revision"] != policy["expected_revision"]:
        raise Incompatible(f"sv0cov reports revision {impl['revision']}, the policy expects {policy['expected_revision']}")
    # 5. implementation language
    if impl["language"] not in policy["allowed_implementation_languages"] or impl["language"] != policy["default_implementation_language"]:
        raise Incompatible(f"sv0cov reports implementation {impl['language']}, the policy selects {policy['default_implementation_language']}")
    # 6. host
    if manifest["host"] != host:
        raise Incompatible(f"sv0cov reports host {manifest['host']['operating_system']}-{manifest['host']['architecture']}, "
                           f"this is {host['operating_system']}-{host['architecture']}")
    composite = f"{host['operating_system']}-{host['architecture']}"
    if composite not in policy["required_hosts"] or composite not in manifest["supported_hosts"]:
        raise Incompatible(f"host {composite} is not both required by the policy and supported by sv0cov")
    # 7. required capability sets
    for name in ("commands", "backends", "bytecode_profiles", "features"):
        missing = [v for v in policy[f"required_{name}"] if v not in manifest[name]]
        if missing:
            raise Incompatible(f"sv0cov does not advertise required {name.replace('_', ' ')}: {', '.join(missing)}")
    # 8. artifact versions
    for family, versions in policy["expected_artifact_versions"].items():
        missing = [v for v in versions if v not in manifest["artifact_versions"].get(family, [])]
        if missing:
            raise Incompatible(f"sv0cov does not read or write {family} {', '.join(missing)}")
    # 9. the diagnostic registry: revision and digest, allowed and the components' own
    advertised = manifest["diagnostic_registry"]
    if advertised not in policy["allowed_diagnostic_registries"] or advertised != registry:
        raise Incompatible(f"sv0cov reports diagnostic registry revision {advertised['revision']} ({advertised['sha256'][:12]}), "
                           "which is not the allowed registry the components carry")
