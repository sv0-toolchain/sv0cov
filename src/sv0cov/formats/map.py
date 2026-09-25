# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Closed coverage map 1.0 reader (SPEC 16.3).

Validation order (SPEC 25.2.2):

1. canonical JSON bytes within resource limits;
2. schema name, version, point-identity version, and capabilities, so a
   version or capability mismatch gets its own code;
3. the generated structural validator;
4. semantic checks, section by section: compiler and target; sources;
   entities; fragments, points, and the counter space; regions and counter
   expressions; branches and outcomes; contracts; exclusions; ``map_id``.

When the exact source bytes are supplied (``sources={path: bytes}``), spans,
line and column coordinates, and region ``line_numbers`` are also checked
against them, and each source digest must match. Whitespace for line
membership is the sv0 grammar's: space, tab, LF, CR (sv0doc grammar).

Every failure raises :class:`MapError` with a stable registry code:
``COV1010`` invalid map, ``COV1011`` unsupported version, ``COV1012``
unsupported capability, ``COV1013`` map identity mismatch, ``COV1014`` point
identity mismatch, ``COV1015`` invalid counter or fragment binding,
``COV1004`` source digest mismatch.
"""

from __future__ import annotations

import bisect
import hashlib
from dataclasses import dataclass
from typing import Mapping

from sv0cov._generated.validators import sv0cov_map_1_0 as _schema
from sv0cov.formats.canonical_json import DEFAULT_LIMITS, CanonicalJsonError, Limits, decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model.identity import (
    ALLOWED_ENTITY_KINDS,
    NO_ORDINAL,
    EntityKind,
    PointIdentity,
    PointKind,
    point_id,
)
from sv0cov.model.logical import LogicalValueError, check_digest, check_logical_path, check_logical_string

CAPABILITIES = [
    "branch-outcomes",
    "contract-coverage",
    "exclusion-audit",
    "module-fragments",
    "normalized-linear-expressions",
    "nullable-counter-bindings",
    "semantic-function-ownership",
    "source-digests",
]
MAX_ARRAY = 4294967295
WHITESPACE = b" \t\n\r"
POINT_KINDS = {
    "function_entry": PointKind.FUNCTION_ENTRY,
    "region": PointKind.REGION,
    "branch_outcome": PointKind.BRANCH_OUTCOME,
    "contract_true": PointKind.CONTRACT_TRUE,
    "contract_false": PointKind.CONTRACT_FALSE,
}
ENTITY_KINDS = {"function": EntityKind.FUNCTION, "contract": EntityKind.CONTRACT}
OUTCOME_NAMES = {
    "if": ("true", "false"),
    "conditional_expression": ("true", "false"),
    "loop": ("body", "exit"),
    "short_circuit": ("evaluated", "skipped"),
}
OUTCOME_POINT_CLASS = {"eligible": "user", "excluded": "excluded", "statically_unreachable": "statically_unreachable"}
UNCOUNTED_CLASSES = ("excluded", "statically_unreachable")
PRINTABLE = frozenset(range(0x21, 0x7F))


class MapError(ValueError):
    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(code: str, detail: str) -> None:
    raise MapError(code, detail)


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _span_key(r: dict) -> tuple[int, int]:
    return (r["span"]["start_byte"], r["span"]["end_byte"])


def _strictly_ordered(items: list, key, what: str) -> None:
    keys = [key(x) for x in items]
    for a, b in zip(keys, keys[1:]):
        if not a < b:
            _fail("COV1010", f"{what} are not strictly ordered or contain a duplicate")


def _positions(items: list[dict], field: str, what: str) -> None:
    if len(items) > MAX_ARRAY:
        _fail("COV1010", f"too many {what}")
    for n, r in enumerate(items):
        if r[field] != n:
            _fail("COV1010", f"{what}[{n}].{field} must equal its position")


def fragment_id(sources: list[dict], point_ids_by_counter: list[str]) -> str:
    """SHA-256 of the canonical fragment-identity projection (SPEC 16.3.3)."""
    projection = {
        "point_ids": point_ids_by_counter,
        "schema": "sv0cov.fragment-identity",
        "sources": [{"digest": s["digest"], "path": s["path"]} for s in sources],
        "version": "1.0",
    }
    return hashlib.sha256(encode(projection)).hexdigest()


def map_id(obj: dict) -> str:
    """SHA-256 of the canonical map with only ``map_id`` removed (SPEC 16.3.8)."""
    return hashlib.sha256(encode({k: v for k, v in obj.items() if k != "map_id"})).hexdigest()


# ── source text helpers ─────────────────────────────────────────────────────


class _Text:
    """Line/column arithmetic over exact source bytes (lines split at LF)."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.starts = [0] + [i + 1 for i, b in enumerate(data) if b == 0x0A]

    def position(self, offset: int) -> tuple[int, int]:
        if offset > len(self.data):
            raise ValueError("offset beyond the end of the source")
        if offset < len(self.data) and (self.data[offset] & 0xC0) == 0x80:
            raise ValueError("offset is inside a UTF-8 sequence")
        line = bisect.bisect_right(self.starts, offset) - 1
        column = 1 + len(self.data[self.starts[line] : offset].decode("utf-8"))
        return line + 1, column

    def line_numbers(self, start: int, end: int) -> list[int]:
        lines = []
        first = bisect.bisect_right(self.starts, start) - 1
        for line in range(first, len(self.starts)):
            lo = max(start, self.starts[line])
            if lo >= end:
                break
            hi = min(end, self.starts[line + 1] if line + 1 < len(self.starts) else len(self.data))
            if any(b not in WHITESPACE for b in self.data[lo:hi]):
                lines.append(line + 1)
        return lines


# ── validation ──────────────────────────────────────────────────────────────


@dataclass
class _Ctx:
    obj: dict
    texts: dict[int, _Text]


def _check_span(ctx: _Ctx, span: dict, source_index: int, where: str) -> None:
    if span["end_byte"] < span["start_byte"]:
        _fail("COV1010", f"{where}: span ends before it starts")
    if (span["end_line"], span["end_column"]) < (span["start_line"], span["start_column"]):
        _fail("COV1010", f"{where}: span end line/column precedes its start")
    text = ctx.texts.get(source_index)
    if text is None:
        return
    try:
        start = text.position(span["start_byte"])
        end = text.position(span["end_byte"])
    except ValueError as exc:
        _fail("COV1010", f"{where}: {exc}")
    if start != (span["start_line"], span["start_column"]) or end != (span["end_line"], span["end_column"]):
        _fail("COV1010", f"{where}: line/column coordinates do not match the source bytes")


def _within(inner: dict, outer: dict) -> bool:
    return outer["start_byte"] <= inner["start_byte"] and inner["end_byte"] <= outer["end_byte"]


def _check_sources(ctx: _Ctx, supplied: Mapping[str, bytes] | None) -> None:
    sources = ctx.obj["sources"]
    _positions(sources, "source_index", "sources")
    _strictly_ordered(sources, lambda s: _b(s["path"]), "sources (by path)")
    for s in sources:
        try:
            check_digest(s["digest"], "digest")
            check_logical_path(s["path"], "path")
            if s["package"] is not None:
                check_logical_string(s["package"], "package", min_bytes=1, max_bytes=1024)
        except LogicalValueError as exc:
            _fail("COV1010", f"source {s['path']!r}: {exc}")
        if supplied is not None and s["path"] in supplied:
            data = supplied[s["path"]]
            if hashlib.sha256(data).hexdigest() != s["digest"]:
                _fail("COV1004", f"{s['path']}: source bytes do not match the recorded digest")
            ctx.texts[s["source_index"]] = _Text(data)


def _check_entities(ctx: _Ctx) -> None:
    entities, n_sources = ctx.obj["entities"], len(ctx.obj["sources"])
    _positions(entities, "entity_index", "entities")
    for e in entities:
        if e["source_index"] >= n_sources:
            _fail("COV1010", f"entity {e['entity_index']}: dangling source_index")
        try:
            check_logical_string(e["qualified_name"], "qualified_name", min_bytes=1)
        except LogicalValueError as exc:
            _fail("COV1010", f"entity {e['entity_index']}: {exc}")
        _check_span(ctx, e["span"], e["source_index"], f"entity {e['entity_index']}")
    _strictly_ordered(
        entities,
        lambda e: (e["source_index"], *_span_key(e), _b(e["kind"]), _b(e["qualified_name"])),
        "entities",
    )


def _check_points(ctx: _Ctx) -> dict[str, dict]:
    obj = ctx.obj
    sources, entities, points = obj["sources"], obj["entities"], obj["points"]
    by_id: dict[str, dict] = {}
    counted: dict[int, dict] = {}
    for p in points:
        where = f"point {p['point_id']}"
        if p["source_index"] >= len(sources):
            _fail("COV1010", f"{where}: dangling source_index")
        _check_span(ctx, p["span"], p["source_index"], where)
        kind = POINT_KINDS[p["kind"]]
        ent = p["entity_index"]
        if ent is None:
            entity_kind, entity_name = EntityKind.NONE, ""
        else:
            if ent >= len(entities):
                _fail("COV1010", f"{where}: dangling entity_index")
            e = entities[ent]
            if e["source_index"] != p["source_index"] or not _within(p["span"], e["span"]):
                _fail("COV1010", f"{where}: point lies outside its owning entity")
            entity_kind, entity_name = ENTITY_KINDS[e["kind"]], e["qualified_name"]
        if entity_kind not in ALLOWED_ENTITY_KINDS[kind]:
            _fail("COV1010", f"{where}: a {p['kind']} point cannot be owned by {entity_kind.name.lower()}")
        if (kind is PointKind.BRANCH_OUTCOME) != (p["outcome_ordinal"] is not None):
            _fail("COV1010", f"{where}: outcome_ordinal must be set exactly for a branch outcome")
        if kind in (PointKind.CONTRACT_TRUE, PointKind.CONTRACT_FALSE) and p["classification"] != "contract":
            _fail("COV1010", f"{where}: contract outcome points must be classified 'contract'")
        if kind not in (PointKind.CONTRACT_TRUE, PointKind.CONTRACT_FALSE) and p["classification"] == "contract":
            _fail("COV1010", f"{where}: only contract outcome points may be classified 'contract'")
        source = sources[p["source_index"]]
        identity = PointIdentity(
            source_path=source["path"],
            source_digest=source["digest"],
            entity_kind=entity_kind,
            entity_name=entity_name,
            point_kind=kind,
            start_byte=p["span"]["start_byte"],
            end_byte=p["span"]["end_byte"],
            outcome_ordinal=NO_ORDINAL if p["outcome_ordinal"] is None else p["outcome_ordinal"],
            discriminator=p["semantic_discriminator"],
        )
        try:
            computed = point_id(identity)
        except LogicalValueError as exc:
            _fail("COV1010", f"{where}: {exc}")
        if computed != p["point_id"]:
            _fail("COV1014", f"{where}: recomputed point ID is {computed}")
        if (p["counter_index"] is None) != (p["fragment_index"] is None):
            _fail("COV1015", f"{where}: counter_index and fragment_index must both be null or both be set")
        if p["counter_index"] is not None:
            if p["classification"] in UNCOUNTED_CLASSES:
                _fail("COV1015", f"{where}: {p['classification']} points must be uncounted")
            if p["counter_index"] in counted:
                _fail("COV1015", f"{where}: counter index {p['counter_index']} is bound twice")
            counted[p["counter_index"]] = p
        by_id[p["point_id"]] = p
    _strictly_ordered(points, lambda p: p["point_id"], "points (by point_id)")
    count = obj["program_counter_count"]
    if sorted(counted) != list(range(count)):
        _fail("COV1015", "counter indexes must be exactly 0..program_counter_count-1")
    _check_fragments(ctx, counted)
    return by_id


def _check_fragments(ctx: _Ctx, counted: dict[int, dict]) -> None:
    obj = ctx.obj
    sources, fragments, count = obj["sources"], obj["fragments"], obj["program_counter_count"]
    _positions(fragments, "fragment_index", "fragments")
    for f in fragments:
        idx = f["source_indices"]
        if any(i >= len(sources) for i in idx) or idx != sorted(set(idx)):
            _fail("COV1010", f"fragment {f['fragment_index']}: source_indices must be valid and strictly increasing")
    _strictly_ordered(
        fragments,
        lambda f: (_b(sources[f["source_indices"][0]]["path"]), sources[f["source_indices"][0]]["digest"], f["fragment_id"]),
        "fragments",
    )
    projections = set()
    for f in fragments:
        idx = f["source_indices"]
        if f["slice_base"] + f["slice_length"] > count:
            _fail("COV1015", f"fragment {f['fragment_index']}: slice exceeds program_counter_count")
        members = [counted[c] for c in range(f["slice_base"], f["slice_base"] + f["slice_length"])]
        for p in members:
            if p["fragment_index"] != f["fragment_index"]:
                _fail("COV1015", f"counter {p['counter_index']}: bound to a different fragment than its slice")
            if p["source_index"] not in idx:
                _fail("COV1015", f"counter {p['counter_index']}: point source is outside its fragment")
        fid = fragment_id([sources[i] for i in idx], [p["point_id"] for p in members])
        if fid != f["fragment_id"]:
            _fail("COV1015", f"fragment {f['fragment_index']}: recomputed fragment_id is {fid}")
        if fid in projections:
            _fail("COV1015", f"fragment {f['fragment_index']}: duplicate fragment projection")
        projections.add(fid)
    for p in counted.values():
        if p["fragment_index"] >= len(fragments):
            _fail("COV1015", f"point {p['point_id']}: dangling fragment_index")
    # Positive slices tile 0..count-1 in fragment order; zero-length slices
    # sit at the next positive base (or at count when none follows).
    expected_base = 0
    for n, f in enumerate(fragments):
        if f["slice_length"] > 0:
            if f["slice_base"] != expected_base:
                _fail("COV1015", f"fragment {n}: positive slices must be contiguous in fragment order")
            expected_base += f["slice_length"]
        else:
            nxt = next((g["slice_base"] for g in fragments[n + 1 :] if g["slice_length"] > 0), count)
            if f["slice_base"] != nxt:
                _fail("COV1015", f"fragment {n}: a zero-length slice must sit at the next positive base")
    if expected_base != count:
        _fail("COV1015", "fragment slices do not cover the counter space")


def _owner_ok(ctx: _Ctx, entity_index: int | None, source_index: int, span: dict, where: str) -> None:
    entities = ctx.obj["entities"]
    if entity_index is None:
        return
    if entity_index >= len(entities):
        _fail("COV1010", f"{where}: dangling entity_index")
    e = entities[entity_index]
    if e["kind"] != "function" or e["source_index"] != source_index:
        _fail("COV1010", f"{where}: owner must be a function entity in the same source")
    if not _within(span, e["span"]):
        _fail("COV1010", f"{where}: span lies outside its owning function")


def _check_regions(ctx: _Ctx, points: dict[str, dict]) -> None:
    regions = ctx.obj["regions"]
    _positions(regions, "region_index", "regions")
    for r in regions:
        where = f"region {r['region_index']}"
        if r["source_index"] >= len(ctx.obj["sources"]):
            _fail("COV1010", f"{where}: dangling source_index")
        _check_span(ctx, r["span"], r["source_index"], where)
        _owner_ok(ctx, r["entity_index"], r["source_index"], r["span"], where)
        terms = r["counter_expression"]["terms"]
        ids = [t["point_id"] for t in terms]
        if ids != sorted(set(ids)):
            _fail("COV1010", f"{where}: terms must be strictly ordered by point_id without duplicates")
        for t in terms:
            if t["coefficient"] == 0:
                _fail("COV1010", f"{where}: zero coefficient")
            p = points.get(t["point_id"])
            if p is None or p["counter_index"] is None:
                _fail("COV1010", f"{where}: terms must reference runtime-counted points")
            if p["source_index"] != r["source_index"] or p["entity_index"] != r["entity_index"]:
                _fail("COV1010", f"{where}: expression points must share the region's source and entity")
        if r["classification"] == "user" and not terms:
            _fail("COV1010", f"{where}: a user region needs a nonempty counter expression")
        if r["classification"] in UNCOUNTED_CLASSES and terms:
            _fail("COV1010", f"{where}: {r['classification']} regions use the empty expression")
        lines = r["line_numbers"]
        if lines != sorted(set(lines)):
            _fail("COV1010", f"{where}: line_numbers must be strictly increasing")
        span = r["span"]
        if any(not span["start_line"] <= n <= span["end_line"] for n in lines):
            _fail("COV1010", f"{where}: line_numbers outside the span's lines")
        if span["start_byte"] == span["end_byte"] and lines:
            _fail("COV1010", f"{where}: an empty span has no lines")
        text = ctx.texts.get(r["source_index"])
        if text is not None and lines != text.line_numbers(span["start_byte"], span["end_byte"]):
            _fail("COV1010", f"{where}: line_numbers do not match the non-whitespace lines of the span")
    _strictly_ordered(
        regions,
        lambda r: (r["source_index"], *_span_key(r), _b(r["kind"]), encode(r["counter_expression"])),
        "regions",
    )


def _check_branches(ctx: _Ctx, points: dict[str, dict]) -> None:
    branches = ctx.obj["branches"]
    _positions(branches, "branch_index", "branches")
    used: set[str] = set()
    for b in branches:
        where = f"branch {b['branch_index']}"
        if b["source_index"] >= len(ctx.obj["sources"]):
            _fail("COV1010", f"{where}: dangling source_index")
        _check_span(ctx, b["span"], b["source_index"], where)
        _owner_ok(ctx, b["entity_index"], b["source_index"], b["span"], where)
        outcomes = b["outcomes"]
        names = [o["name"] for o in outcomes]
        expected = OUTCOME_NAMES.get(b["kind"]) or tuple(f"arm:{i}" for i in range(len(outcomes)))
        if tuple(names) != expected:
            _fail("COV1010", f"{where}: a {b['kind']} branch must have outcomes {list(expected)}")
        for n, o in enumerate(outcomes):
            if o["ordinal"] != n:
                _fail("COV1010", f"{where}: outcome ordinals must equal their positions")
            if (o["classification"] == "statically_unreachable") != (o["evidence_identity"] is not None):
                _fail("COV1010", f"{where}: evidence_identity is required exactly for statically unreachable outcomes")
            if o["evidence_identity"] is not None:
                try:
                    check_logical_string(o["evidence_identity"], "evidence_identity", min_bytes=1)
                except LogicalValueError as exc:
                    _fail("COV1010", f"{where}: {exc}")
            p = points.get(o["point_id"])
            if p is None or p["kind"] != "branch_outcome":
                _fail("COV1010", f"{where}: outcome must reference a branch_outcome point")
            if o["point_id"] in used:
                _fail("COV1010", f"{where}: a branch_outcome point is referenced twice")
            used.add(o["point_id"])
            if (p["source_index"], p["entity_index"], p["outcome_ordinal"]) != (b["source_index"], b["entity_index"], n) or p["span"] != b["span"]:
                _fail("COV1010", f"{where}: outcome point does not match the branch source, owner, span, or ordinal")
            if p["classification"] != OUTCOME_POINT_CLASS[o["classification"]]:
                _fail("COV1010", f"{where}: outcome and point classifications disagree")
    unused = [p for p in points.values() if p["kind"] == "branch_outcome" and p["point_id"] not in used]
    if unused:
        _fail("COV1010", f"branch_outcome point {unused[0]['point_id']} belongs to no branch")
    _strictly_ordered(
        branches,
        lambda b: (b["source_index"], *_span_key(b), _b(b["kind"]), b["outcomes"][0]["point_id"]),
        "branches",
    )


def _check_contracts(ctx: _Ctx, points: dict[str, dict]) -> None:
    obj = ctx.obj
    contracts, entities = obj["contracts"], obj["entities"]
    _positions(contracts, "clause_index", "contracts")
    seen_entities: set[int] = set()
    used_points: set[str] = set()
    for c in contracts:
        where = f"contract {c['clause_index']}"
        if c["entity_index"] >= len(entities):
            _fail("COV1010", f"{where}: dangling entity_index")
        e = entities[c["entity_index"]]
        if e["kind"] != "contract" or e["source_index"] != c["source_index"] or e["span"] != c["span"]:
            _fail("COV1010", f"{where}: entity must be the clause's own contract entity")
        if c["entity_index"] in seen_entities:
            _fail("COV1010", f"{where}: contract entity used by two clauses")
        seen_entities.add(c["entity_index"])
        _check_span(ctx, c["span"], c["source_index"], where)
        _owner_ok(ctx, c["function_entity_index"], c["source_index"], c["span"], where)
        tp, fp, ev = c["true_point_id"], c["false_point_id"], c["evidence_identity"]
        if c["enforcement"] == "runtime_checked":
            if tp is None or fp is None or tp == fp or ev is not None:
                _fail("COV1010", f"{where}: runtime_checked needs two distinct points and no evidence")
            for pid, kind in ((tp, "contract_true"), (fp, "contract_false")):
                p = points.get(pid)
                if p is None or p["kind"] != kind or p["entity_index"] != c["entity_index"] or p["counter_index"] is None:
                    _fail("COV1010", f"{where}: {kind} point must be a runtime-counted point of this clause")
                used_points.add(pid)
        elif c["enforcement"] == "statically_verified":
            if tp is not None or fp is not None or ev is None:
                _fail("COV1010", f"{where}: statically_verified needs evidence and no points")
            try:
                check_logical_string(ev, "evidence_identity", min_bytes=1)
            except LogicalValueError as exc:
                _fail("COV1010", f"{where}: {exc}")
        elif tp is not None or fp is not None or ev is not None:
            _fail("COV1010", f"{where}: {c['enforcement']} clauses have no points or evidence")
    contract_entities = {e["entity_index"] for e in entities if e["kind"] == "contract"}
    if seen_entities != contract_entities:
        _fail("COV1010", "every contract entity must appear in exactly one contract record")
    stray = [p for p in points.values() if p["kind"] in ("contract_true", "contract_false") and p["point_id"] not in used_points]
    if stray:
        _fail("COV1010", f"contract point {stray[0]['point_id']} belongs to no runtime-checked clause")
    _strictly_ordered(
        contracts,
        lambda c: (c["source_index"], *_span_key(c), _b(c["kind"]), c["entity_index"]),
        "contracts",
    )


def _check_exclusions(ctx: _Ctx, points: dict[str, dict]) -> None:
    obj = ctx.obj
    exclusions = obj["exclusions"]
    _positions(exclusions, "exclusion_index", "exclusions")
    claimed: dict[str, set] = {k: set() for k in ("branch_indices", "clause_indices", "entity_indices", "point_ids", "region_indices")}
    sizes = {
        "branch_indices": len(obj["branches"]),
        "clause_indices": len(obj["contracts"]),
        "entity_indices": len(obj["entities"]),
        "region_indices": len(obj["regions"]),
    }
    for x in exclusions:
        where = f"exclusion {x['exclusion_index']}"
        if x["source_index"] >= len(obj["sources"]):
            _fail("COV1010", f"{where}: dangling source_index")
        _check_span(ctx, x["span"], x["source_index"], where)
        try:
            check_logical_string(x["reason"], "reason", min_bytes=1, max_bytes=1024)
        except LogicalValueError as exc:
            _fail("COV1010", f"{where}: {exc}")
        a = x["affected"]
        for key, values in a.items():
            if values != sorted(set(values)):
                _fail("COV1010", f"{where}: affected.{key} must be sorted and unique")
            if key in sizes and any(v >= sizes[key] for v in values):
                _fail("COV1010", f"{where}: affected.{key} has a dangling index")
            if key == "point_ids" and any(v not in points for v in values):
                _fail("COV1010", f"{where}: affected.point_ids names an unknown point")
            if claimed[key] & set(values):
                _fail("COV1010", f"{where}: a construct is excluded twice (redundant or conflicting exclusion)")
            claimed[key].update(values)
        if not any(a.values()):
            _fail("COV1010", f"{where}: exclusion affects nothing")
        affected_points = [points[p] for p in a["point_ids"]]
        mode = x["mode"]
        if mode == "contract_off":
            if a["branch_indices"] or a["region_indices"] or not a["clause_indices"]:
                _fail("COV1010", f"{where}: contract_off affects only contract clauses")
            clause_entities = {obj["contracts"][i]["entity_index"] for i in a["clause_indices"]}
            if not set(a["entity_indices"]) <= clause_entities:
                _fail("COV1010", f"{where}: contract_off entities must be its clauses' entities")
            if any(p["entity_index"] not in clause_entities for p in affected_points):
                _fail("COV1010", f"{where}: contract_off points must belong to its clauses")
            continue
        if a["clause_indices"]:
            _fail("COV1010", f"{where}: {mode} cannot exclude contract clauses")
        if any(p["classification"] != "excluded" for p in affected_points):
            _fail("COV1010", f"{where}: affected points must be classified 'excluded'")
        if any(obj["regions"][i]["classification"] != "excluded" for i in a["region_indices"]):
            _fail("COV1010", f"{where}: affected regions must be classified 'excluded'")
        for i in a["branch_indices"]:
            outcome_ids = {o["point_id"] for o in obj["branches"][i]["outcomes"]}
            if not outcome_ids <= set(a["point_ids"]):
                _fail("COV1010", f"{where}: an excluded branch must list all its outcome points")
        if mode == "branch_off":
            if a["region_indices"] or a["entity_indices"] or not a["branch_indices"]:
                _fail("COV1010", f"{where}: branch_off affects only decision outcomes")
            outcome_ids = {o["point_id"] for i in a["branch_indices"] for o in obj["branches"][i]["outcomes"]}
            if set(a["point_ids"]) != outcome_ids:
                _fail("COV1010", f"{where}: branch_off points must be exactly its branches' outcomes")
        if any(obj["entities"][i]["kind"] != "function" for i in a["entity_indices"]):
            _fail("COV1010", f"{where}: off excludes only function entities")
    # Every excluded construct is claimed by an off/branch_off exclusion.
    for p in points.values():
        if p["classification"] == "excluded" and p["point_id"] not in claimed["point_ids"]:
            _fail("COV1010", f"point {p['point_id']}: classified excluded without an exclusion record")
    for r in obj["regions"]:
        if r["classification"] == "excluded" and r["region_index"] not in claimed["region_indices"]:
            _fail("COV1010", f"region {r['region_index']}: classified excluded without an exclusion record")
    _strictly_ordered(
        exclusions,
        lambda x: (x["source_index"], *_span_key(x), _b(x["mode"]), _b(x["reason"])),
        "exclusions",
    )


def validate_map(
    data: bytes,
    *,
    sources: Mapping[str, bytes] | None = None,
    limits: Limits = DEFAULT_LIMITS,
) -> dict:
    """Validate canonical map bytes; return the decoded map. Raises :class:`MapError`."""
    try:
        obj = decode_canonical(data, limits)
    except CanonicalJsonError as exc:
        raise MapError("COV1010", f"not canonical JSON ({exc.reason})") from exc
    if not isinstance(obj, dict) or obj.get("schema") != "sv0cov.map":
        _fail("COV1010", "not an sv0cov.map object")
    if obj.get("version") != "1.0" or obj.get("point_identity_version") != "1.0":
        _fail("COV1011", f"unsupported map version {obj.get('version')!r} / point identity {obj.get('point_identity_version')!r}")
    if obj.get("capabilities") != CAPABILITIES:
        _fail("COV1012", f"capabilities must be exactly {CAPABILITIES}")
    try:
        _schema.validate(obj)
    except StructuralError as exc:
        raise MapError("COV1010", str(exc)) from exc

    compiler = obj["compiler"]["identity"]
    if not all(b in PRINTABLE for b in compiler.encode("utf-8")):
        _fail("COV1010", "compiler identity must be printable ASCII without whitespace")
    try:
        check_logical_string(obj["target"]["name"], "target.name", min_bytes=1, max_bytes=1024)
    except LogicalValueError as exc:
        _fail("COV1010", str(exc))

    ctx = _Ctx(obj, {})
    _check_sources(ctx, sources)
    _check_entities(ctx)
    points = _check_points(ctx)
    _check_regions(ctx, points)
    _check_branches(ctx, points)
    _check_contracts(ctx, points)
    _check_exclusions(ctx, points)
    if map_id(obj) != obj["map_id"]:
        _fail("COV1013", f"map_id does not match; recomputed {map_id(obj)}")
    return obj
