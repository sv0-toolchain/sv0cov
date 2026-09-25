# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Fixed capability vocabulary and product versions (SPEC 20.6, 20.6.1, 25.4.1).

R1 inventories are exact. Interpretation for pre-R1 products (major version
``0``): each advertised or required set is a sorted, duplicate-free subset of
the R1 inventory, and never includes the VM-v2 capability (SPEC 15.6). A
producer must not advertise anything that has not passed its gate, so a
pre-R1 product cannot advertise the full R1 sets. This rule is recorded in
the sv0cov planning hub as a proposed SPEC clarification.
"""

from __future__ import annotations

import re

COMMANDS = ("check", "clean", "doctor", "merge", "report", "run", "version")
BACKENDS = ("native", "vm-v1", "vm-v2")
BYTECODE_PROFILES = ("sv0vm-v1-coverage", "sv0vm-v2-typed")
FEATURES = (
    "branch-outcomes",
    "changed-region",
    "cobertura-r1-core",
    "contexts",
    "contract-coverage",
    "cumulative-scopes",
    "exclusion-audit",
    "gitignore-scopes",
    "html-report",
    "lcov-r1-core",
    "native-json-report",
    "process-tree-spawn",
    "ratchets",
    "run-sets",
    "saturation-lower-bounds",
    "self-contained-indexed",
    "source-integrity",
)
HOSTS = ("linux-arm64", "linux-x86_64", "macos-arm64", "macos-x86_64")
PYTHON_VERSIONS = ("3.13", "3.14")
LANGUAGES = ("python", "sv0")
ARTIFACT_FAMILIES = (
    "coverage_map",
    "diagnostic",
    "diagnostic_registry",
    "export_manifest",
    "indexed",
    "indexed_semantic",
    "native_report",
    "raw_profile",
    "resolved_configuration",
    "run_set",
    "vm_binding",
    "vm_covr",
)
PRE_R1_EXCLUDED = {"backends": {"vm-v2"}, "bytecode_profiles": {"sv0vm-v2-typed"}}
INVENTORIES = {
    "commands": COMMANDS,
    "backends": BACKENDS,
    "bytecode_profiles": BYTECODE_PROFILES,
    "features": FEATURES,
    "hosts": HOSTS,
}

RE_PRODUCT_VERSION = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)")
RE_REVISION = re.compile(r"[0-9a-f]{40}")
RE_FORMAT_VERSION = re.compile(r"[\x21-\x7e]{1,32}")


class InventoryError(ValueError):
    pass


def parse_product_version(text: str) -> tuple[int, int, int]:
    """Exact ``MAJOR.MINOR.PATCH`` (SPEC 25.4.1): 5..128 ASCII bytes, no leading zeros."""
    if not isinstance(text, str) or not 5 <= len(text.encode("utf-8")) <= 128 or not RE_PRODUCT_VERSION.fullmatch(text):
        raise InventoryError(f"invalid product version {text!r}")
    major, minor, patch = (int(p) for p in text.split("."))
    return major, minor, patch


def is_pre_r1(product_version: str) -> bool:
    return parse_product_version(product_version)[0] == 0


def check_set(name: str, values: list, product_version: str) -> None:
    """Validate one capability set for the given product version."""
    universe = INVENTORIES[name]
    if values != sorted(set(values), key=str.encode) or len(set(values)) != len(values):
        raise InventoryError(f"{name} must be bytewise sorted and duplicate-free")
    if any(v not in universe for v in values):
        raise InventoryError(f"{name} contains an unknown value")
    if is_pre_r1(product_version):
        if set(values) & PRE_R1_EXCLUDED.get(name, set()):
            raise InventoryError(f"{name}: a pre-R1 product cannot include VM-v2 (SPEC 15.6)")
    elif tuple(values) != universe:
        raise InventoryError(f"{name} must be exactly {list(universe)} at R1")


def check_artifact_versions(obj: dict, product_version: str, *, exact_r1: bool = True) -> None:
    if list(obj) != sorted(ARTIFACT_FAMILIES) or set(obj) != set(ARTIFACT_FAMILIES):
        raise InventoryError("artifact versions must have exactly the twelve family keys")
    for family, versions in obj.items():
        if not 1 <= len(versions) <= 16 or versions != sorted(set(versions), key=str.encode):
            raise InventoryError(f"{family}: 1..16 sorted unique versions")
        if any(not RE_FORMAT_VERSION.fullmatch(v) for v in versions):
            raise InventoryError(f"{family}: versions are 1..32 printable ASCII bytes")
        if exact_r1 and versions != ["1.0"]:
            raise InventoryError(f"{family}: exactly ['1.0'] through R1")
