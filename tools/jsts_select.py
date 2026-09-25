#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Outcome-independent selection of upstream Draft 2020-12 cases (CV-012, SPEC 25.2.4).

Selection is mechanical and runs before any validator:

1. enumerate every JSON file directly under ``tests/draft2020-12/`` of the
   vendored suite in UTF-8 path order (``optional/`` and other directories
   are excluded; symlinks are never followed);
2. parse each case without changing its schema, instances, descriptions, or
   expected results, and bind it to the SHA-256 of the complete file;
3. a case is **applicable** exactly when its schema is an object that already
   declares the exact Draft 2020-12 ``$schema`` URI, passes the R1 authoring
   profile (``tools/schemagen/preflight.py`` rules) without modification, and
   makes no reference outside the schema itself;
4. every other case is excluded with one or more structural reason codes.

This module never imports the generated validators or the oracle, and never
looks at expected-result polarity when deciding applicability.

Case identity: SHA-256 over ``sv0cov.jsts-case.v1\\0`` followed by, in order,
the upstream commit, the relative file path, the file SHA-256 (each as a
``u32le``-length-prefixed UTF-8 string), the case index (``u32le``), the case
description (length-prefixed), the test index (``u32le``), the test
description (length-prefixed), and the expected result (one byte, 0 or 1).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools" / "schemagen"))
sys.path.insert(0, str(ROOT / "tools"))

import jsts_vendor  # noqa: E402
import preflight  # noqa: E402

from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402

SELECTION = ROOT / "tests" / "conformance" / "jsts-selection.json"
DIR = "tests/draft2020-12/"
DOMAIN = b"sv0cov.jsts-case.v1\x00"


def _s(text: str) -> bytes:
    data = text.encode("utf-8")
    return struct.pack("<I", len(data)) + data


def case_identity(commit: str, path: str, file_sha: str, ci: int, cdesc: str, ti: int, tdesc: str, valid: bool) -> str:
    preimage = (
        DOMAIN
        + _s(commit)
        + _s(path)
        + _s(file_sha)
        + struct.pack("<I", ci)
        + _s(cdesc)
        + struct.pack("<I", ti)
        + _s(tdesc)
        + (b"\x01" if valid else b"\x00")
    )
    return hashlib.sha256(preimage).hexdigest()


def _refs(node: object) -> list[str]:
    out: list[str] = []
    stack = [node]
    while stack:
        n = stack.pop()
        if isinstance(n, dict):
            for k, v in n.items():
                if k in ("$ref", "$dynamicRef") and isinstance(v, str):
                    out.append(v)
                stack.append(v)
        elif isinstance(n, list):
            stack.extend(n)
    return out


def exclusion_reasons(schema: object) -> list[str]:
    """Structural reasons a schema is outside the R1 profile (empty = applicable)."""
    if not isinstance(schema, dict):
        return ["boolean_schema"]
    reasons = []
    if schema.get("$schema") != preflight.DIALECT:
        reasons.append("no_exact_dialect")
    if any(not r.startswith("#") for r in _refs(schema)):
        reasons.append("external_reference")
    try:
        encode(schema)
    except ValueError:
        reasons.append("non_integer_or_out_of_range_number")
    checker = preflight._Checker("case-1.0.schema.json")
    checker.check_root(schema)
    local_defs = schema.get("$defs", {}) if isinstance(schema.get("$defs"), dict) else {}
    for _ptr, target, name in checker.refs:
        if target != "case-1.0.schema.json" or name not in local_defs:
            reasons.append("unresolved_local_reference")
            break
    if checker.findings:
        reasons.append("outside_r1_profile")
    return sorted(set(reasons))


def build_selection() -> dict:
    manifest = jsts_vendor.load_manifest()
    commit = manifest["commit"]
    files = [
        e
        for e in manifest["entries"]
        if e["path"].startswith(DIR) and "/" not in e["path"][len(DIR):] and e["path"].endswith(".json")
        and e["type"] == "blob"
    ]
    cases = []
    counts = {"applicable_cases": 0, "applicable_tests": 0, "excluded_cases": 0, "excluded_tests": 0, "files": len(files)}
    for entry in files:  # already in UTF-8 path order
        path = entry["path"]
        raw = (jsts_vendor.VENDOR / path).read_bytes()
        if hashlib.sha256(raw).hexdigest() != entry["sha256"]:
            raise SystemExit(f"{path}: vendored bytes differ from the manifest")
        doc = json.loads(raw)
        for ci, case in enumerate(doc):
            reasons = exclusion_reasons(case["schema"])
            tests = []
            seen = set()
            for ti, test in enumerate(case["tests"]):
                if not isinstance(test.get("valid"), bool):
                    raise SystemExit(f"{path} case {ci} test {ti}: missing or non-Boolean expected result")
                if test["description"] in seen:
                    raise SystemExit(f"{path} case {ci}: duplicate test description {test['description']!r}")
                seen.add(test["description"])
                ident = case_identity(commit, path, entry["sha256"], ci, case["description"], ti, test["description"], test["valid"])
                tests.append({"description": test["description"], "expected": test["valid"], "identity": ident, "index": ti})
            key = "applicable" if not reasons else "excluded"
            counts[f"{key}_cases"] += 1
            counts[f"{key}_tests"] += len(tests)
            cases.append(
                {
                    "applicable": not reasons,
                    "description": case["description"],
                    "exclusion_reasons": reasons,
                    "file": path,
                    "file_sha256": entry["sha256"],
                    "index": ci,
                    "tests": tests,
                }
            )
    identities = [t["identity"] for c in cases for t in c["tests"]]
    if len(set(identities)) != len(identities):
        raise SystemExit("duplicate case identities")
    return {
        "cases": cases,
        "commit": commit,
        "counts": counts,
        "schema": "sv0cov.jsts-selection",
        "version": "1.0",
    }


def load_selection() -> dict:
    return decode_canonical(SELECTION.read_bytes())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true", help="rewrite the checked-in selection manifest")
    args = ap.parse_args(argv)
    selection = build_selection()
    data = encode(selection)
    if args.write:
        SELECTION.parent.mkdir(parents=True, exist_ok=True)
        SELECTION.write_bytes(data)
    elif not SELECTION.is_file() or SELECTION.read_bytes() != data:
        print("jsts_select: checked-in selection manifest is stale (run with --write after review)", file=sys.stderr)
        return 1
    c = selection["counts"]
    print(
        f"jsts_select: {c['files']} files; {c['applicable_cases']} applicable cases "
        f"({c['applicable_tests']} tests); {c['excluded_cases']} excluded ({c['excluded_tests']} tests)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
