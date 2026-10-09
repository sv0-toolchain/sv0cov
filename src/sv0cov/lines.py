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

    python -m sv0cov.lines MAP SOURCE_ROOT PROFILE [PROFILE ...]

resolves the profiles through the map and prints one ``path:line status``
line per physical line (an internal tool, not a public ``sv0cov`` command).
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Mapping

STATUSES = ("covered", "partial", "uncovered", "non_executable")


def physical_lines(data: bytes) -> int:
    """Number of physical lines: a final line without LF still counts."""
    return data.count(b"\n") + (1 if data and not data.endswith(b"\n") else 0)


def region_count(region: dict, counts: Mapping[str, int]) -> int:
    """A region's count from its counter expression (SPEC 11.1)."""
    return sum(t["coefficient"] * counts[t["point_id"]] for t in region["counter_expression"]["terms"])


def line_records(m: dict, counts: Mapping[str, int], sources: Mapping[str, bytes]) -> list[dict]:
    """One record per physical line of every mapped source, ordered by source
    then line: ``line``, ``line_index``, ``region_indices`` (the contributing
    user regions on the line), ``source_index``, ``status``.

    ``m`` is a validated map, ``counts`` maps each counted point ID to its
    resolved count, and ``sources`` maps each logical path to its exact bytes.
    """
    by_line: dict[tuple[int, int], list[int]] = {}
    for r in m["regions"]:
        if r["line_contributing"] and r["classification"] == "user":
            for line in r["line_numbers"]:
                by_line.setdefault((r["source_index"], line), []).append(r["region_index"])
    executed = {r["region_index"]: region_count(r, counts) > 0 for r in m["regions"] if r["classification"] == "user"}
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


def line_metric(records: list[dict]) -> dict[str, int]:
    """``covered``, ``partial``, ``total`` (executable lines) of some records."""
    executable = [r for r in records if r["status"] != "non_executable"]
    return {"covered": sum(r["status"] == "covered" for r in executable),
            "partial": sum(r["status"] == "partial" for r in executable),
            "total": len(executable)}


def main(argv: list[str] | None = None) -> int:
    import json

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
    for rec in line_records(m, res.counts(), sources):
        print(f"{paths[rec['source_index']]}:{rec['line']} {rec['status']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
