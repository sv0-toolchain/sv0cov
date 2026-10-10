# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Line coverage derived from executable regions (CV-202, BL-021; SPEC 11.4,
COV-MET-003).

There is no line counter. A physical line (lines split at LF, as in a map's
``line_numbers``) is executable when a line-contributing ``user`` region
lists it; its status then follows from those regions' counts:

- ``covered``: every contributing region executed;
- ``partial``: at least one, but not all, executed;
- ``uncovered``: none executed;
- ``non_executable``: no contributing region lists the line.

Containers (branch and loop bodies, block match arms) and statically
unreachable regions are written with ``line_contributing`` false by sv0c, so
a brace-only line or a line of dead code is ``non_executable``. Only ``user``
regions enter line status (SPEC 11.7); a contributing region of any other
classification is ignored here. ``excluded`` lines arrive with exclusions
(R1). Partial lines are not covered: line coverage is
``covered_lines / executable_lines``.

Region counts come from :mod:`sv0cov.expr` (SPEC 11.1): evaluated per
context and aggregated; a region is executed when its count proves at least
one execution, so a saturation lower-bound zero counts as not executed
(conservatively uncovered, COV-MET-017).

    python -m sv0cov.lines MAP SOURCE_ROOT PROFILE [PROFILE ...]

resolves the profiles through the map and prints one ``path:line status``
line per physical line (an internal tool, not a public ``sv0cov`` command).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping

from sv0cov.expr import Count, CountRecord, check_expression, evaluate, evaluate_contexts

STATUSES = ("covered", "partial", "uncovered", "non_executable")


def physical_lines(data: bytes) -> int:
    """Number of physical lines: a final line without LF still counts."""
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def region_count(region: dict, counts: Mapping[str, int]) -> int:
    """A region's count over one context of point counts (SPEC 11.1; a
    count of exactly ``UINT64_MAX`` is saturated)."""
    terms = check_expression(region["counter_expression"])
    return evaluate(terms, {p: Count.physical(counts[p]) for _, p in terms}).value


def region_counts(m: dict, contexts: Mapping[int, Mapping[str, Count]]) -> dict[int, CountRecord]:
    """region index -> count record, for every ``user`` region of a validated
    map, from per-context point counts (``Resolution.context_counts()``)."""
    counted = {p["point_id"] for p in m["points"] if p["counter_index"] is not None}
    return {r["region_index"]: evaluate_contexts(check_expression(r["counter_expression"], counted), contexts)
            for r in m["regions"] if r["classification"] == "user"}


def line_records(m: dict, counts: Mapping[str, int] | None, sources: Mapping[str, bytes], *,
                 contexts: Mapping[int, Mapping[str, Count]] | None = None) -> list[dict]:
    """One record per physical line of every mapped source, ordered by source
    then line: ``line``, ``line_index``, ``region_indices`` (the contributing
    user regions on the line), ``source_index``, ``status``.

    ``m`` is a validated map and ``sources`` maps each logical path to its
    exact bytes. Point counts are either ``contexts`` (per-context counts,
    as from ``Resolution.context_counts()``) or ``counts`` (one context:
    point ID -> count).
    """
    if contexts is None:
        contexts = {0: {p: Count.physical(v) for p, v in (counts or {}).items()}}
    by_line: dict[tuple[int, int], list[int]] = {}
    for r in m["regions"]:
        if r["line_contributing"] and r["classification"] == "user":
            for line in r["line_numbers"]:
                by_line.setdefault((r["source_index"], line), []).append(r["region_index"])
    executed = {i: rec.value > 0 for i, rec in region_counts(m, contexts).items()}
    out: list[dict] = []
    for s in sorted(m["sources"], key=lambda s: s["source_index"]):
        for line in range(1, physical_lines(sources[s["path"]]) + 1):
            regions = sorted(by_line.get((s["source_index"], line), []))
            ran = [executed[i] for i in regions]
            if not regions:
                status = "non_executable"
            elif all(ran):
                status = "covered"
            elif any(ran):
                status = "partial"
            else:
                status = "uncovered"
            out.append({"line": line, "line_index": len(out), "region_indices": regions,
                        "source_index": s["source_index"], "status": status})
    return out


def line_statuses(m: dict, counts: Mapping[str, int], sources: Mapping[str, bytes]) -> dict[str, list[str]]:
    """logical path -> status of each physical line, in order."""
    paths = {s["source_index"]: s["path"] for s in m["sources"]}
    out: dict[str, list[str]] = {p: [] for p in paths.values()}
    for rec in line_records(m, counts, sources):
        out[paths[rec["source_index"]]].append(rec["status"])
    return out


def user_source_indices(m: dict) -> set[int]:
    """The root project's sources: the default coverage scope (SPEC 18.1).

    Every compiled ``user`` source is in scope whatever directory it sits
    in (tests/, examples/, vendor/, ... mean nothing); ``dependency``
    sources are reported separately and stay out of root metrics. Ownership
    is the map's build-graph fact, never inferred from a path (CV-209).
    """
    return {s["source_index"] for s in m["sources"] if s["ownership"] == "user"}


def line_metric(records: list[dict], sources: set[int] | None = None) -> dict[str, int]:
    """``covered``, ``partial``, ``total`` (executable lines) of some records,
    limited to the source indexes in ``sources`` when given (the root
    project's metric: ``line_metric(records, user_source_indices(m))``)."""
    executable = [r for r in records if r["status"] != "non_executable"
                  and (sources is None or r["source_index"] in sources)]
    return {"covered": sum(r["status"] == "covered" for r in executable),
            "partial": sum(r["status"] == "partial" for r in executable),
            "total": len(executable)}


def main(argv: list[str] | None = None) -> int:
    import json

    from sv0cov.expr import ExprError
    from sv0cov.resolve import ResolveError, resolve

    ap = argparse.ArgumentParser(prog="python -m sv0cov.lines")
    ap.add_argument("map")
    ap.add_argument("source_root")
    ap.add_argument("profiles", nargs="+")
    a = ap.parse_args(argv)
    map_bytes = Path(a.map).read_bytes()
    m = json.loads(map_bytes)
    sources = {s["path"]: (Path(a.source_root) / s["path"]).read_bytes() for s in m["sources"]}
    try:
        res = resolve(map_bytes, [Path(p).read_bytes() for p in a.profiles], sources=sources)
    except ResolveError as exc:
        print(f"error[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 1
    paths = {s["source_index"]: s["path"] for s in m["sources"]}
    try:
        recs = line_records(m, None, sources, contexts=res.context_counts())
    except ExprError as exc:
        print(f"error[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 1
    for rec in recs:
        print(f"{paths[rec['source_index']]}:{rec['line']} {rec['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
