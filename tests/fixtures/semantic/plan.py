# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Declarative builder for hand-reviewed expected coverage maps.

A fixture states its planning decisions by hand (which functions, branches,
and regions exist, which kind each is, and which counter expression each
region uses), anchored to exact source text. The builder only does the
mechanical work: locating byte offsets, line/column coordinates, point IDs,
counter numbering in source order, fragment and map IDs. The conventions are
in docs/planning-conventions.md.
"""

from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.map import CAPABILITIES, _Text, fragment_id, map_id, validate_map  # noqa: E402
from sv0cov.model.identity import NO_ORDINAL, EntityKind, PointIdentity, PointKind, point_id  # noqa: E402

KIND_ORDER = {"function_entry": 0, "branch_outcome": 1}
OUTCOMES = {"if": ("true", "false"), "loop": ("body", "exit")}


@dataclass(eq=False)
class Point:
    path: str
    entity: "Function"
    kind: str
    span: tuple[int, int]
    discriminator: str
    ordinal: int | None = None
    label: str = ""


@dataclass(eq=False)
class Function:
    path: str
    name: str
    span: tuple[int, int]
    entry: Point | None = None


@dataclass(eq=False)
class Branch:
    fn: Function
    kind: str
    span: tuple[int, int]
    outcomes: list[Point] = field(default_factory=list)

    def __getitem__(self, name: str) -> Point:
        return next(p for p in self.outcomes if p.label.endswith("." + name))


@dataclass(eq=False)
class Region:
    fn: Function
    kind: str
    span: tuple[int, int]
    terms: list[tuple[Point, int]]
    line_contributing: bool


class Plan:
    def __init__(self, name: str, sources: dict[str, bytes], target: str | None = None) -> None:
        self.name = name
        self.sources = sources
        self.target = target or name
        self.functions: list[Function] = []
        self.branches: list[Branch] = []
        self.regions: list[Region] = []

    # ── locating source text ─────────────────────────────────────────────

    def find(self, path: str, text: str, occurrence: int = 0, after: int = 0) -> tuple[int, int]:
        data = self.sources[path]
        needle = text.encode("utf-8")
        at = after - 1
        for _ in range(occurrence + 1):
            at = data.find(needle, at + 1)
            if at < 0:
                raise ValueError(f"{self.name}: {text!r} (occurrence {occurrence}) not found in {path}")
        return at, at + len(needle)

    def block_end(self, path: str, start: int) -> int:
        """Offset just past the `}` matching the first `{` at or after ``start``."""
        data = self.sources[path]
        depth, i = 0, data.index(b"{", start)
        while True:
            if data[i] == 0x7B:
                depth += 1
            elif data[i] == 0x7D:
                depth -= 1
                if depth == 0:
                    return i + 1
            i += 1

    def through_block(self, path: str, text: str, occurrence: int = 0, after: int = 0) -> tuple[int, int]:
        start, _ = self.find(path, text, occurrence, after)
        return start, self.block_end(path, start)

    # ── declarations ─────────────────────────────────────────────────────

    def function(self, path: str, name: str, qualified: str | None = None) -> Function:
        span = self.through_block(path, f"fn {name}(")
        fn = Function(path, qualified or name, span)
        fn.entry = Point(path, fn, "function_entry", span, "entry", label=f"{fn.name}.entry")
        self.functions.append(fn)
        return fn

    def branch(self, fn: Function, kind: str, span: tuple[int, int], arms: int = 0) -> Branch:
        names = OUTCOMES.get(kind) or tuple(f"arm:{i}" for i in range(arms))
        b = Branch(fn, kind, span)
        for i, n in enumerate(names):
            b.outcomes.append(Point(fn.path, fn, "branch_outcome", span, kind, i, label=f"{fn.name}.{kind}@{span[0]}.{n}"))
        self.branches.append(b)
        return b

    def region(self, fn: Function, kind: str, span: tuple[int, int], *terms, lc: bool = True) -> Region:
        norm = [(t, 1) if isinstance(t, Point) else t for t in terms]
        r = Region(fn, kind, span, norm, lc)
        self.regions.append(r)
        return r

    # ── assembly ─────────────────────────────────────────────────────────

    def points(self) -> list[Point]:
        pts = [f.entry for f in self.functions] + [o for b in self.branches for o in b.outcomes]
        return sorted(pts, key=lambda p: (p.path, p.span[0], KIND_ORDER[p.kind], p.ordinal or 0))

    def _span(self, path: str, span: tuple[int, int]) -> dict:
        t = _Text(self.sources[path])
        sl, sc = t.position(span[0])
        el, ec = t.position(span[1])
        return {"end_byte": span[1], "end_column": ec, "end_line": el, "start_byte": span[0], "start_column": sc, "start_line": sl}

    def build(self) -> dict:
        paths = sorted(self.sources, key=str.encode)
        src_index = {p: i for i, p in enumerate(paths)}
        digests = {p: hashlib.sha256(self.sources[p]).hexdigest() for p in paths}
        sources = [{"digest": digests[p], "ownership": "user", "package": None, "path": p, "source_index": i} for i, p in enumerate(paths)]

        fns = sorted(self.functions, key=lambda f: (src_index[f.path], f.span, f.name.encode()))
        ent_index = {id(f): i for i, f in enumerate(fns)}
        entities = [
            {"entity_index": i, "kind": "function", "qualified_name": f.name, "source_index": src_index[f.path], "span": self._span(f.path, f.span)}
            for i, f in enumerate(fns)
        ]

        ordered = sorted(self.points(), key=lambda p: (src_index[p.path], p.span[0], KIND_ORDER[p.kind], p.ordinal or 0))
        counter = {id(p): n for n, p in enumerate(ordered)}
        ids: dict[int, str] = {}
        records = []
        for p in ordered:
            pid = point_id(
                PointIdentity(
                    p.path, digests[p.path], EntityKind.FUNCTION, p.entity.name,
                    PointKind.FUNCTION_ENTRY if p.kind == "function_entry" else PointKind.BRANCH_OUTCOME,
                    p.span[0], p.span[1], NO_ORDINAL if p.ordinal is None else p.ordinal, p.discriminator,
                )
            )
            ids[id(p)] = pid
            records.append(
                {
                    "classification": "user",
                    "counter_index": counter[id(p)],
                    "entity_index": ent_index[id(p.entity)],
                    "fragment_index": None,  # set below
                    "kind": p.kind,
                    "outcome_ordinal": p.ordinal,
                    "point_id": pid,
                    "semantic_discriminator": p.discriminator,
                    "source_index": src_index[p.path],
                    "span": self._span(p.path, p.span),
                    "_source": p.path,
                }
            )

        # One fragment per source, in path order; counters are already in source order.
        fragments = []
        base = 0
        for path in paths:
            members = [r for r in records if r["_source"] == path]
            fragments.append({"fragment_index": len(fragments), "slice_base": base, "slice_length": len(members), "source_indices": [src_index[path]]})
            for r in members:
                r["fragment_index"] = fragments[-1]["fragment_index"]
            base += len(members)
        for f in fragments:
            f["fragment_id"] = fragment_id([sources[i] for i in f["source_indices"]], [r["point_id"] for r in records if r["fragment_index"] == f["fragment_index"]])
        for r in records:
            del r["_source"]

        regions = []
        for r in self.regions:
            terms = sorted(({"coefficient": c, "point_id": ids[id(p)]} for p, c in r.terms), key=lambda t: t["point_id"])
            regions.append(
                {
                    "classification": "user",
                    "counter_expression": {"terms": terms},
                    "entity_index": ent_index[id(r.fn)],
                    "kind": r.kind,
                    "line_contributing": r.line_contributing,
                    "line_numbers": _Text(self.sources[r.fn.path]).line_numbers(*r.span),
                    "region_index": 0,
                    "source_index": src_index[r.fn.path],
                    "span": self._span(r.fn.path, r.span),
                }
            )
        regions.sort(key=lambda r: (r["source_index"], r["span"]["start_byte"], r["span"]["end_byte"], r["kind"].encode(), encode(r["counter_expression"])))
        for i, r in enumerate(regions):
            r["region_index"] = i

        branches = []
        for b in self.branches:
            branches.append(
                {
                    "branch_index": 0,
                    "entity_index": ent_index[id(b.fn)],
                    "kind": b.kind,
                    "outcomes": [
                        {"classification": "eligible", "evidence_identity": None, "name": o.label.rsplit(".", 1)[1], "ordinal": o.ordinal, "point_id": ids[id(o)]}
                        for o in b.outcomes
                    ],
                    "source_index": src_index[b.fn.path],
                    "span": self._span(b.fn.path, b.span),
                }
            )
        branches.sort(key=lambda b: (b["source_index"], b["span"]["start_byte"], b["span"]["end_byte"], b["kind"].encode(), b["outcomes"][0]["point_id"]))
        for i, b in enumerate(branches):
            b["branch_index"] = i

        obj = {
            "branches": branches,
            "capabilities": list(CAPABILITIES),
            "compiler": {"identity": "sv0cov-fixture", "name": "sv0c"},
            "contracts": [],
            "entities": entities,
            "exclusions": [],
            "fragments": fragments,
            "point_identity_version": "1.0",
            "points": sorted(records, key=lambda r: r["point_id"]),
            "program_counter_count": len(records),
            "regions": regions,
            "schema": "sv0cov.map",
            "sources": sources,
            "target": {"kind": "executable", "name": self.target},
            "version": "1.0",
        }
        obj["map_id"] = map_id(obj)
        validate_map(encode(obj), sources=self.sources)
        self._ids = ids
        return obj

    def counts(self, observed: dict[Point, int]) -> list[dict]:
        """Expected per-point counts for the fixture's fixed input (unlisted = 0)."""
        out = []
        for p in self.points():
            out.append({"count": observed.get(p, 0), "label": p.label, "point_id": self._ids[id(p)]})
        return sorted(out, key=lambda r: r["point_id"])


def dump(obj: object) -> bytes:
    return encode(obj)


def pretty(obj: object) -> str:
    return json.dumps(obj, indent=1, ensure_ascii=False, sort_keys=True)
