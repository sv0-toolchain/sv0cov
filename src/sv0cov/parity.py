# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""F0 backend parity comparator (CV-171, BL-013; SPEC 27.11, F0-G4,
AC-001, AC-002).

The same deterministic fixture is compiled once to generated C and once to
``sv0vm-v1-coverage`` bytecode, and each runs the same input. The comparator
takes both maps and both sets of raw profiles and checks:

- AC-001 identity: the two maps contain the same global point IDs, and every
  shared point has identical semantic metadata -- kind, semantic
  discriminator, outcome ordinal, classification, span, whether it is
  counted, its source (logical path and digest), and its owning entity
  (kind, qualified name, span). Indexes into the maps' own arrays (entity,
  source, counter, fragment) are compared through what they name, not as
  numbers;
- AC-002 counts: each side resolves through its own map
  (:func:`sv0cov.resolve.resolve`) to the same count, saturation included,
  for every counted point.

Backend provenance (map ID, target name, run and profile IDs, timing) may
differ without changing coverage meaning. The report is canonical JSON with
``status`` ``pass`` or ``fail`` and every mismatch listed. ``sv0vm-v2-typed``
joins as a third path at R1 (SPEC 15.6).

    python -m sv0cov.parity --fixture NAME --c-map MAP --c-profile P [...]
                            --vm-map MAP --vm-profile P [...]

prints the report and exits 0 on pass, 1 on fail or invalid input (an
internal F0 tool, not a public ``sv0cov`` command).
"""

from __future__ import annotations

import argparse
import sys
from typing import Iterable

from sv0cov.formats.canonical_json import encode
from sv0cov.formats.map import MapError, validate_map
from sv0cov.resolve import ResolveError, resolve

SEMANTIC_POINT_FIELDS = ("kind", "semantic_discriminator", "outcome_ordinal", "classification", "span")


def point_semantics(m: dict, point: dict) -> dict:
    """The backend-independent semantic metadata of one point of map ``m``."""
    src = m["sources"][point["source_index"]]
    ent = None if point.get("entity_index") is None else m["entities"][point["entity_index"]]
    return {
        **{k: point.get(k) for k in SEMANTIC_POINT_FIELDS},
        "counted": point.get("counter_index") is not None,
        "source": {"digest": src["digest"], "path": src["path"]},
        "entity": None if ent is None else {"kind": ent["kind"], "qualified_name": ent["qualified_name"],
                                            "span": ent["span"]},
    }


def compare(fixture: str, c_map: bytes, c_profiles: Iterable[bytes], vm_map: bytes,
            vm_profiles: Iterable[bytes]) -> dict:
    """The parity report for one fixture. Raises ResolveError for invalid input."""
    try:
        cm, vm = validate_map(c_map), validate_map(vm_map)
    except MapError as exc:
        raise ResolveError(exc.code, f"map: {exc.detail}") from exc
    c_points = {p["point_id"]: point_semantics(cm, p) for p in cm["points"]}
    v_points = {p["point_id"]: point_semantics(vm, p) for p in vm["points"]}

    only_c = sorted(set(c_points) - set(v_points))
    only_vm = sorted(set(v_points) - set(c_points))
    shared = sorted(set(c_points) & set(v_points))
    metadata = [
        {"point_id": pid, "generated_c": c_points[pid], "vm_v1": v_points[pid]}
        for pid in shared if c_points[pid] != v_points[pid]
    ]

    c_res = resolve(c_map, list(c_profiles))
    v_res = resolve(vm_map, list(vm_profiles))
    if c_res.backends != ("native",):
        raise ResolveError("COV2110", f"generated-C side has profiles from {list(c_res.backends)}, want native only")
    if v_res.backends != ("vm-v1",):
        raise ResolveError("COV2110", f"VM side has profiles from {list(v_res.backends)}, want vm-v1 only")
    c_counts = {p.point_id: (p.value, p.saturated) for p in c_res.points}
    v_counts = {p.point_id: (p.value, p.saturated) for p in v_res.points}
    counts = [
        {"point_id": pid,
         "generated_c": {"saturated": c_counts[pid][1], "value": c_counts[pid][0]},
         "vm_v1": {"saturated": v_counts[pid][1], "value": v_counts[pid][0]}}
        for pid in sorted(set(c_counts) & set(v_counts)) if c_counts[pid] != v_counts[pid]
    ]
    ok = not (only_c or only_vm or metadata or counts)
    return {
        "backends": ["generated-c", "sv0vm-v1-coverage"],
        "count_mismatches": counts,
        "counted_points": len(set(c_counts) & set(v_counts)),
        "fixture": fixture,
        "identity": {"only_generated_c": only_c, "only_vm_v1": only_vm},
        "maps": {"generated_c": cm["map_id"], "vm_v1": vm["map_id"]},
        "metadata_mismatches": metadata,
        "points": len(shared),
        "profiles": {"generated_c": list(c_res.profile_ids), "vm_v1": list(v_res.profile_ids)},
        "schema": "sv0cov.f0-parity",
        "status": "pass" if ok else "fail",
        "version": "1.0",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m sv0cov.parity")
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--c-map", required=True)
    ap.add_argument("--c-profile", action="append", required=True)
    ap.add_argument("--vm-map", required=True)
    ap.add_argument("--vm-profile", action="append", required=True)
    args = ap.parse_args(argv)

    def read(path: str) -> bytes:
        with open(path, "rb") as f:
            return f.read()

    try:
        report = compare(args.fixture, read(args.c_map), [read(p) for p in args.c_profile],
                         read(args.vm_map), [read(p) for p in args.vm_profile])
    except OSError as exc:
        print(f"error[COV2010]: {exc.strerror}: {exc.filename}", file=sys.stderr)
        return 1
    except ResolveError as exc:
        print(f"error[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encode(report))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
