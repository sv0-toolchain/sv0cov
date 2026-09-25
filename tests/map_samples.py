# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""A small valid coverage map used by the map validator tests (CV-014..CV-018).

Two sources, two fragments, a function with an ``if`` (true and implicit
false outcome), a subtraction counter expression, a runtime-checked
``requires`` clause, and a function excluded by a ``coverage(off)``
attribute. Offsets and line/column coordinates are located by searching the
source text; ``finalize`` recomputes fragment IDs and the map ID so a test can
mutate one fact without tripping an unrelated digest.

This is validator test data, not the F0 semantic oracle (that is CV-027's
hand-reviewed map).
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sv0cov.formats.map import CAPABILITIES, _Text, fragment_id, map_id  # noqa: E402
from sv0cov.model.identity import NO_ORDINAL, EntityKind, PointIdentity, PointKind, point_id  # noqa: E402

MATH = (
    "fn div(a: i32, b: i32) -> i32\n"
    "    requires(b != 0)\n"
    "{\n"
    "    return a / b;\n"
    "}\n"
    "\n"
    '#[coverage(off, reason = "fallback path")]\n'
    "fn unused() -> i32 {\n"
    "    return 0;\n"
    "}\n"
    "// é\n"
).encode()
SIGN = (
    "fn positive(x: i32) -> bool {\n"
    "    if x > 0 {\n"
    "        return true;\n"
    "    }\n"
    "    return false;\n"
    "}\n"
).encode()
SOURCES = {"src/math.sv0": MATH, "src/sign.sv0": SIGN}

import hashlib  # noqa: E402

DIGESTS = {p: hashlib.sha256(b).hexdigest() for p, b in SOURCES.items()}


def span(path: str, text: str, occurrence: int = 0) -> dict:
    data = SOURCES[path]
    start = -1
    for _ in range(occurrence + 1):
        start = data.index(text.encode(), start + 1)
    end = start + len(text.encode())
    t = _Text(data)
    sl, sc = t.position(start)
    el, ec = t.position(end)
    return {"end_byte": end, "end_column": ec, "end_line": el, "start_byte": start, "start_column": sc, "start_line": sl}


def lines(path: str, sp: dict) -> list[int]:
    return _Text(SOURCES[path]).line_numbers(sp["start_byte"], sp["end_byte"])


def build() -> dict:
    sources = [
        {"digest": DIGESTS[p], "ownership": "user", "package": None, "path": p, "source_index": i}
        for i, p in enumerate(sorted(SOURCES))
    ]
    src_index = {s["path"]: s["source_index"] for s in sources}
    m, g = "src/math.sv0", "src/sign.sv0"
    div_sp = span(m, "fn div(a: i32, b: i32) -> i32\n    requires(b != 0)\n{\n    return a / b;\n}")
    req_sp = span(m, "requires(b != 0)")
    unused_sp = span(m, 'fn unused() -> i32 {\n    return 0;\n}')
    pos_sp = span(g, "fn positive(x: i32) -> bool {\n    if x > 0 {\n        return true;\n    }\n    return false;\n}")
    entities = [
        {"entity_index": 0, "kind": "function", "qualified_name": "div", "source_index": 0, "span": div_sp},
        {"entity_index": 1, "kind": "contract", "qualified_name": "div#requires0", "source_index": 0, "span": req_sp},
        {"entity_index": 2, "kind": "function", "qualified_name": "unused", "source_index": 0, "span": unused_sp},
        {"entity_index": 3, "kind": "function", "qualified_name": "positive", "source_index": 1, "span": pos_sp},
    ]

    def point(path, entity, kind, sp, disc, classification, counter=None, fragment=None, ordinal=None) -> dict:
        e = entities[entity] if entity is not None else None
        pid = point_id(
            PointIdentity(
                source_path=path,
                source_digest=DIGESTS[path],
                entity_kind=EntityKind.NONE if e is None else (EntityKind.FUNCTION if e["kind"] == "function" else EntityKind.CONTRACT),
                entity_name="" if e is None else e["qualified_name"],
                point_kind={"function_entry": PointKind.FUNCTION_ENTRY, "region": PointKind.REGION, "branch_outcome": PointKind.BRANCH_OUTCOME, "contract_true": PointKind.CONTRACT_TRUE, "contract_false": PointKind.CONTRACT_FALSE}[kind],
                start_byte=sp["start_byte"],
                end_byte=sp["end_byte"],
                outcome_ordinal=NO_ORDINAL if ordinal is None else ordinal,
                discriminator=disc,
            )
        )
        return {
            "classification": classification,
            "counter_index": counter,
            "entity_index": entity,
            "fragment_index": fragment,
            "kind": kind,
            "outcome_ordinal": ordinal,
            "point_id": pid,
            "semantic_discriminator": disc,
            "source_index": src_index[path],
            "span": dict(sp),
        }

    if_sp = span(g, "if x > 0 {\n        return true;\n    }")
    p_div = point(m, 0, "function_entry", div_sp, "entry", "user", 0, 0)
    p_true_c = point(m, 1, "contract_true", req_sp, "requires", "contract", 1, 0)
    p_false_c = point(m, 1, "contract_false", req_sp, "requires", "contract", 2, 0)
    p_unused = point(m, 2, "function_entry", unused_sp, "entry", "excluded")
    p_pos = point(g, 3, "function_entry", pos_sp, "entry", "user", 3, 1)
    p_t = point(g, 3, "branch_outcome", if_sp, "if", "user", 4, 1, 0)
    p_f = point(g, 3, "branch_outcome", if_sp, "if", "user", 5, 1, 1)
    points = sorted([p_div, p_true_c, p_false_c, p_unused, p_pos, p_t, p_f], key=lambda p: p["point_id"])

    def term(p, c=1):
        return {"coefficient": c, "point_id": p["point_id"]}

    def expr(*terms):
        return {"terms": sorted(terms, key=lambda t: t["point_id"])}

    ret_div = span(m, "return a / b;")
    ret_unused = span(m, "return 0;")
    ret_true = span(g, "return true;")
    ret_false = span(g, "return false;")
    regions = [
        {"classification": "user", "counter_expression": expr(term(p_div)), "entity_index": 0, "kind": "return", "line_contributing": True, "line_numbers": lines(m, ret_div), "region_index": 0, "source_index": 0, "span": ret_div},
        {"classification": "excluded", "counter_expression": expr(), "entity_index": 2, "kind": "return", "line_contributing": True, "line_numbers": lines(m, ret_unused), "region_index": 1, "source_index": 0, "span": ret_unused},
        {"classification": "user", "counter_expression": expr(term(p_t)), "entity_index": 3, "kind": "return", "line_contributing": True, "line_numbers": lines(g, ret_true), "region_index": 2, "source_index": 1, "span": ret_true},
        {"classification": "user", "counter_expression": expr(term(p_pos), term(p_t, -1)), "entity_index": 3, "kind": "return", "line_contributing": True, "line_numbers": lines(g, ret_false), "region_index": 3, "source_index": 1, "span": ret_false},
    ]
    branches = [
        {
            "branch_index": 0,
            "entity_index": 3,
            "kind": "if",
            "outcomes": [
                {"classification": "eligible", "evidence_identity": None, "name": "true", "ordinal": 0, "point_id": p_t["point_id"]},
                {"classification": "eligible", "evidence_identity": None, "name": "false", "ordinal": 1, "point_id": p_f["point_id"]},
            ],
            "source_index": 1,
            "span": if_sp,
        }
    ]
    contracts = [
        {"clause_index": 0, "enforcement": "runtime_checked", "entity_index": 1, "evidence_identity": None, "false_point_id": p_false_c["point_id"], "function_entity_index": 0, "kind": "requires", "source_index": 0, "span": req_sp, "true_point_id": p_true_c["point_id"]}
    ]
    exclusions = [
        {
            "affected": {"branch_indices": [], "clause_indices": [], "entity_indices": [2], "point_ids": [p_unused["point_id"]], "region_indices": [1]},
            "exclusion_index": 0,
            "mode": "off",
            "origin": "attribute",
            "reason": "fallback path",
            "source_index": 0,
            "span": span(m, '#[coverage(off, reason = "fallback path")]'),
        }
    ]
    fragments = [
        {"fragment_id": "", "fragment_index": 0, "slice_base": 0, "slice_length": 3, "source_indices": [0]},
        {"fragment_id": "", "fragment_index": 1, "slice_base": 3, "slice_length": 3, "source_indices": [1]},
    ]
    obj = {
        "branches": branches,
        "capabilities": list(CAPABILITIES),
        "compiler": {"identity": "sv0c@d1a51004", "name": "sv0c"},
        "contracts": contracts,
        "entities": entities,
        "exclusions": exclusions,
        "fragments": fragments,
        "map_id": "",
        "point_identity_version": "1.0",
        "points": points,
        "program_counter_count": 6,
        "regions": regions,
        "schema": "sv0cov.map",
        "sources": sources,
        "target": {"kind": "executable", "name": "sample"},
        "version": "1.0",
    }
    # A JSON round trip breaks shared span dicts (deepcopy would keep sharing).
    return finalize(json.loads(json.dumps(obj)))


def finalize(obj: dict, *, fragments: bool = True) -> dict:
    """Recompute fragment IDs (optionally) and the map ID, in place and returned."""
    if fragments:
        by_counter = {p["counter_index"]: p for p in obj["points"] if p["counter_index"] is not None}
        for f in obj["fragments"]:
            members = [by_counter[c]["point_id"] for c in range(f["slice_base"], f["slice_base"] + f["slice_length"]) if c in by_counter]
            f["fragment_id"] = fragment_id([obj["sources"][i] for i in f["source_indices"]], members)
    obj["map_id"] = map_id(obj)
    return obj


def mutated(fn, *, refragment: bool = True) -> dict:
    obj = copy.deepcopy(build())
    fn(obj)
    return finalize(obj, fragments=refragment)
