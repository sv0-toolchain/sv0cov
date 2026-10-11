#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Build or check the indexed-evidence structure fixtures (CV-220).

Hand-written ``sv0cov.indexed`` 1.0 documents for the schema and
record-level layer (``sv0cov.formats.indexed``), and one mutation corpus:

- ``empty.json``: diagnostic evidence with no input at all;
- ``all-kinds.json``: every record kind and every enumeration value;
- ``bounds.json``: every integer and length at its largest value;
- ``mutations.json``: single changes to those documents, each with its
  outcome: ``valid``, ``COV3010``, or ``COV3011``.

These are structure fixtures. Their digests are made up
(``sha256("<label>")``) and their counts are not derived from a real map, so
they say nothing about cross-record validity; real merged evidence arrives
with the semantic model (CV-221) and the indexed reader (CV-222).

    python3 tests/fixtures/indexed/build.py            # check (exit 1 if stale)
    python3 tests/fixtures/indexed/build.py --write    # rewrite after review
"""

from __future__ import annotations

import copy
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.indexed import projection_sha256  # noqa: E402

U64 = 2**64 - 1
I63 = 2**63 - 1
INDEX_MAX = 4294967294
U32 = 4294967295
CAPABILITIES = ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "line-membership",
                "normalized-linear-expressions", "saturation-lower-bounds", "semantic-function-ownership", "source-digests"]
REGISTRY_SHA = "440aad98c48e372d526d4aefb7c3e8cba8a0d4fc07b31797115a55044b06e3b1"


def d(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()


def ident(label: str) -> str:
    return hashlib.sha256(label.encode()).hexdigest()[:32]


def span(start: int, end: int, line: int = 1, end_line: int | None = None) -> dict:
    return {"end_byte": end, "end_column": end - start + 1, "end_line": end_line or line, "start_byte": start, "start_column": 1,
            "start_line": line}


def count(*by_context: tuple[int, int], inexact: bool = False, value: int | None = None) -> dict:
    """Exact count from (context, value) pairs; ``inexact`` marks the aggregate a lower bound."""
    ctx = [{"context_index": c, "lower_bound": False, "saturated": False, "value": v} for c, v in by_context]
    total = sum(v for _, v in by_context) if value is None else value
    return {"by_context": ctx, "lower_bound": inexact, "saturated": inexact, "value": total}


ZERO = count()


def saturated(context: int) -> dict:
    return {"by_context": [{"context_index": context, "lower_bound": True, "saturated": True, "value": U64}], "lower_bound": True,
            "saturated": True, "value": U64}


def semantic(**over) -> dict:
    s = {
        "branches": [], "capabilities": list(CAPABILITIES), "complete": False, "contexts": [], "contracts": [], "diagnostics": [],
        "entities": [], "exclusions": [], "lines": [], "map_ids": [], "map_version": "1.0", "point_identity_version": "1.0",
        "points": [], "regions": [],
        "saturation": {"affected_point_ids": [], "affected_region_indices": [], "any": False, "eligible_metrics": [],
                       "ineligible_uses": [], "policy": "fail"},
        "schema": "sv0cov.indexed-semantic", "sources": [], "version": "1.0",
    }
    s.update(over)
    return s


def indexed(sem: dict, **over) -> dict:
    o = {
        "diagnostics": [],
        "execution": {"exit_code": None, "signal": None, "status": "not_applicable"},
        "map_inputs": [], "maps": [],
        "merge": {"allow_rejected_inputs": False,
                  "limits": {"max_bytes": 67108864, "max_counters": 4194304, "tier": "standard"},
                  "tool": {"diagnostic_registry_revision": 1, "diagnostic_registry_sha256": REGISTRY_SHA, "name": "sv0cov",
                           "version": "0.0.0"}},
        "profile_inputs": [],
        "run_selection": {"manifest_sha256": None, "mode": "none", "requested_run_ids": [], "selected_run_ids": []},
        "schema": "sv0cov.indexed", "semantic": sem, "semantic_projection_sha256": "", "version": "1.0",
    }
    o.update(over)
    o["semantic_projection_sha256"] = projection_sha256(o["semantic"])
    return o


# ── empty.json ───────────────────────────────────────────────────────────────


def empty() -> dict:
    """Selection failed before any input was found: nothing accepted, nothing rejected."""
    return indexed(semantic(diagnostics=["COV3001"]), diagnostics=["COV3003"])


# ── all-kinds.json ───────────────────────────────────────────────────────────


def all_kinds() -> dict:
    map_a = d("map a")
    point = {name: d(f"point {name}") for name in (
        "entry", "question", "if-true", "if-false", "loop-body", "loop-exit", "arm", "ce-true", "ce-false", "sc-evaluated",
        "sc-skipped", "req-true", "req-false", "ens-true", "ens-false", "asr-true", "asr-false", "chk-true", "chk-false", "hot")}

    def pt(name: str, kind: str, classification: str, cnt: dict, entity: int | None, sp: dict, disc: str, ordinal: int | None = None,
           source: int = 0) -> dict:
        return {"classification": classification, "count": cnt, "entity_index": entity, "kind": kind, "outcome_ordinal": ordinal,
                "point_id": point[name], "semantic_discriminator": disc, "source_index": source, "span": sp}

    f_span, if_span, loop_span, match_span, ce_span, sc_span = span(10, 400, 2, 30), span(40, 90, 4, 6), span(100, 160, 8, 10), \
        span(170, 200, 12, 14), span(210, 240, 16), span(250, 270, 18)
    points = [
        pt("entry", "function_entry", "user", count((0, 2), (2, 3)), 0, f_span, "entry"),
        pt("question", "region", "synthetic_support", count((0, 1)), 0, span(30, 31, 3), "question:propagate"),
        pt("if-true", "branch_outcome", "user", count((0, 1), (2, 3)), 0, if_span, "if", 0),
        pt("if-false", "branch_outcome", "user", ZERO, 0, if_span, "if", 1),
        pt("loop-body", "branch_outcome", "user", count((2, 9)), 0, loop_span, "loop", 0),
        pt("loop-exit", "branch_outcome", "statically_unreachable", ZERO, 0, loop_span, "loop", 1),
        pt("arm", "branch_outcome", "excluded", ZERO, 0, match_span, "match", 0),
        pt("ce-true", "branch_outcome", "user", count((1, 1)), 0, ce_span, "conditional_expression", 0),
        pt("ce-false", "branch_outcome", "user", count((1, 2)), 0, ce_span, "conditional_expression", 1),
        pt("sc-evaluated", "branch_outcome", "user", count((0, 4)), 0, sc_span, "short_circuit", 0),
        pt("sc-skipped", "branch_outcome", "user", ZERO, 0, sc_span, "short_circuit", 1),
        pt("req-true", "contract_true", "contract", count((0, 2), (2, 2)), 1, span(12, 28, 2), "requires"),
        pt("req-false", "contract_false", "contract", count((2, 1)), 1, span(12, 28, 2), "requires"),
        pt("ens-true", "contract_true", "contract", count((0, 5)), 2, span(280, 300, 20), "ensures"),
        pt("ens-false", "contract_false", "contract", ZERO, 2, span(280, 300, 20), "ensures"),
        pt("asr-true", "contract_true", "contract", ZERO, 3, span(310, 330, 22), "assert"),
        pt("asr-false", "contract_false", "contract", ZERO, 3, span(310, 330, 22), "assert"),
        pt("chk-true", "contract_true", "contract", ZERO, 4, span(340, 360, 24), "assert"),
        pt("chk-false", "contract_false", "contract", count((0, 1)), 4, span(340, 360, 24), "assert"),
        pt("hot", "function_entry", "user", saturated(0), 8, span(0, 50, 1, 4), "entry", source=1),
    ]
    points.sort(key=lambda p: p["point_id"])

    def term(name: str, coefficient: int = 1) -> dict:
        return {"coefficient": coefficient, "point_id": point[name]}

    def rg(index: int, kind: str, classification: str, cnt: dict, terms: list[dict], sp: dict, lines: list[int], lc: bool = True,
           entity: int | None = 0, source: int = 0) -> dict:
        return {"classification": classification, "count": cnt, "counter_expression": {"terms": sorted(terms, key=lambda t: t["point_id"])},
                "entity_index": entity, "kind": kind, "line_contributing": lc, "line_numbers": lines, "region_index": index,
                "source_index": source, "span": sp}

    regions = [
        rg(0, "initializer", "user", count((0, 2), (2, 3)), [term("entry")], span(30, 39, 3), [3]),
        rg(1, "return", "synthetic_support", count((0, 1)), [term("question")], span(30, 31, 3), [3], lc=False),
        rg(2, "expression", "user", count((0, 1), (2, 3)), [term("entry"), term("question", -1)], span(43, 50, 4), [4]),
        rg(3, "branch_body", "user", count((0, 1), (2, 3)), [term("if-true")], span(51, 90, 4, 6), [4, 5, 6], lc=False),
        rg(4, "assignment", "user", count((0, 1), (2, 3)), [term("if-true")], span(60, 70, 5), [5]),
        rg(5, "loop_body", "user", count((2, 9)), [term("loop-body")], span(110, 160, 8, 10), [8, 9, 10], lc=False),
        rg(6, "mutation", "user", count((2, 9)), [term("loop-body")], span(120, 130, 9), [9]),
        rg(7, "continue", "user", count((2, 9)), [term("loop-body")], span(131, 140, 9), [9]),
        rg(8, "break", "statically_unreachable", ZERO, [], span(141, 147, 9), [9], lc=False),
        rg(9, "match_arm", "excluded", ZERO, [], span(180, 190, 13), [13], lc=False),
        rg(10, "expression_statement", "user", count((0, 4)), [term("sc-evaluated")], span(250, 271, 18), [18]),
        rg(11, "call", "contract", count((0, 5)), [term("ens-true")], span(285, 295, 20), [20], lc=False, entity=None),
        rg(12, "return", "user", count((0, 1), (2, 3)), [term("entry"), term("question", -1)], span(380, 398, 28), [28]),
        rg(13, "return", "user", count(inexact=True, value=U64), [term("hot", 2)], span(10, 20, 2), [2], entity=8, source=1),
    ]

    def ln(index: int, line: int, status: str, region_indices: list[int], source: int = 0) -> dict:
        return {"line": line, "line_index": index, "region_indices": region_indices, "source_index": source, "status": status}

    lines = [ln(0, 3, "covered", [0, 2]), ln(1, 4, "covered", [2]), ln(2, 5, "covered", [4]), ln(3, 7, "non_executable", []),
             ln(4, 9, "partial", [6, 7]), ln(5, 13, "excluded", []), ln(6, 18, "covered", [10]), ln(7, 26, "uncovered", []),
             ln(8, 28, "covered", [12]), ln(9, 2, "covered", [13], source=1)]

    by_id = {p["point_id"]: p for p in points}

    def outcome(name: str, ordinal: int, label: str, status: str, evidence: str | None = None) -> dict:
        return {"count": by_id[point[name]]["count"], "evidence_identity": evidence, "name": label, "ordinal": ordinal,
                "point_id": point[name], "status": status}

    def br(index: int, kind: str, sp: dict, outcomes: list[dict]) -> dict:
        return {"branch_index": index, "entity_index": 0, "kind": kind, "outcomes": outcomes, "source_index": 0, "span": sp}

    branches = [
        br(0, "if", if_span, [outcome("if-true", 0, "true", "covered"), outcome("if-false", 1, "false", "uncovered")]),
        br(1, "loop", loop_span, [outcome("loop-body", 0, "body", "covered"),
                                  outcome("loop-exit", 1, "exit", "statically_unreachable", "sv0c:loop:no-condition")]),
        br(2, "match", match_span, [outcome("arm", 0, "arm:0", "excluded")]),
        br(3, "conditional_expression", ce_span, [outcome("ce-true", 0, "true", "covered"), outcome("ce-false", 1, "false", "covered")]),
        br(4, "short_circuit", sc_span, [outcome("sc-evaluated", 0, "evaluated", "covered"), outcome("sc-skipped", 1, "skipped", "uncovered")]),
    ]

    def contract(index: int, kind: str, enforcement: str, entity: int, sp: dict, result: str, true: str | None = None,
                 false: str | None = None, evidence: str | None = None, function: int | None = 0) -> dict:
        return {"clause_index": index, "count_false": by_id[point[false]]["count"] if false else None,
                "count_true": by_id[point[true]]["count"] if true else None, "enforcement": enforcement, "entity_index": entity,
                "evidence_identity": evidence, "function_entity_index": function, "kind": kind, "runtime_result": result,
                "source_index": 0, "span": sp}

    contracts = [
        contract(0, "requires", "runtime_checked", 1, span(12, 28, 2), "mixed", "req-true", "req-false"),
        contract(1, "ensures", "runtime_checked", 2, span(280, 300, 20), "evaluated_true", "ens-true", "ens-false"),
        contract(2, "assert", "runtime_checked", 3, span(310, 330, 22), "not_evaluated", "asr-true", "asr-false"),
        contract(3, "assert", "runtime_checked", 4, span(340, 360, 24), "evaluated_false", "chk-true", "chk-false"),
        contract(4, "loop_invariant", "statically_verified", 5, span(102, 108, 8), "not_applicable", evidence="sv0c:smt:proof-1"),
        contract(5, "assert", "disabled", 6, span(365, 372, 25), "not_applicable"),
        contract(6, "ensures", "unsupported", 7, span(410, 420, 32), "not_applicable", function=None),
    ]

    def entity(index: int, kind: str, name: str, sp: dict, source: int = 0) -> dict:
        return {"entity_index": index, "kind": kind, "qualified_name": name, "source_index": source, "span": sp}

    entities = [entity(0, "function", "app::run", f_span), entity(1, "contract", "app::run#requires:0", span(12, 28, 2)),
                entity(2, "contract", "app::run#ensures:0", span(280, 300, 20)), entity(3, "contract", "app::run#assert:0", span(310, 330, 22)),
                entity(4, "contract", "app::run#assert:1", span(340, 360, 24)),
                entity(5, "contract", "app::run#loop_invariant:0", span(102, 108, 8)),
                entity(6, "contract", "app::run#assert:2", span(365, 372, 25)), entity(7, "contract", "app#ensures:0", span(410, 420, 32)),
                entity(8, "function", "dep::hot", span(0, 50, 1, 4), source=1)]

    def exclusion(index: int, mode: str, origin: str, reason: str, sp: dict, **affected) -> dict:
        full = {"branch_indices": [], "clause_indices": [], "entity_indices": [], "point_ids": [], "region_indices": []}
        full.update(affected)
        return {"affected": full, "exclusion_index": index, "mode": mode, "origin": origin, "reason": reason, "source_index": 0, "span": sp}

    exclusions = [
        exclusion(0, "branch_off", "comment", "generated dispatch table", span(165, 169, 11), branch_indices=[2], point_ids=[point["arm"]]),
        exclusion(1, "off", "attribute", "platform-specific arm, tested elsewhere", span(175, 179, 13), region_indices=[9]),
        exclusion(2, "contract_off", "comment", "checked by the caller: see app::main", span(362, 364, 25), clause_indices=[5],
                  entity_indices=[6]),
    ]

    sem = semantic(
        branches=branches, contexts=[{"context_index": 0, "value": None}, {"context_index": 1, "value": ""},
                                     {"context_index": 2, "value": "shard é"}],
        contracts=contracts, diagnostics=["COV3002", "COV3004"], entities=entities, exclusions=exclusions, lines=lines, map_ids=[map_a],
        points=points, regions=regions,
        saturation={"affected_point_ids": [point["hot"]], "affected_region_indices": [13], "any": True,
                    "eligible_metrics": ["branch", "function", "line", "region"],
                    "ineligible_uses": ["context_exact_counts", "contract_counts", "exact_count_assertions", "ratchets", "standard_exports"],
                    "policy": "allow-ordinary"},
        sources=[{"digest": d("src app"), "ownership": "user", "package": None, "path": "src/app.sv0", "source_index": 0},
                 {"digest": d("src dep"), "ownership": "dependency", "package": "dep-lib", "path": "vendor/dep/hot.sv0", "source_index": 1}],
    )
    counted = [p for p in points if p["classification"] in ("user", "contract", "synthetic_support")]
    run_a, run_b = sorted((ident("run a"), ident("run b")))

    def profile(status: str, name: str, backend: str | None, context: int | None, diagnostics: list[str], run: str | None,
                sha: bool = True) -> dict:
        return {"artifact_sha256": d(f"profile {name}") if sha else None, "backend": backend, "byte_length": 132 if sha else 0,
                "context_index": context, "diagnostics": diagnostics, "map_id": map_a if status == "accepted" else None, "name": name,
                "profile_id": ident(f"profile id {name}") if run else None, "run_id": run, "status": status}

    profiles = [profile("accepted", f"{run_a}-0001.sv0profraw", "native", 0, [], run_a),
                profile("accepted", f"{run_a}-0002.sv0profraw", "vm-v1", 2, [], run_a),
                profile("accepted", f"{run_b}-0003.sv0profraw", "vm-v2", 1, [], run_b),
                profile("incomplete", "truncated.sv0profraw", None, None, ["COV2011"], None, sha=False),
                profile("rejected", "collision.sv0profraw", "native", 0, ["COV2112"], run_a)]
    profiles.sort(key=lambda r: (r["status"].encode(), r["artifact_sha256"] or "", r["name"].encode()))
    return indexed(
        sem, diagnostics=["COV3002"],
        execution={"exit_code": 3, "signal": None, "status": "failed"},
        map_inputs=[{"artifact_sha256": d("map a bytes"), "byte_length": 20480, "diagnostics": [], "map_id": map_a,
                     "name": "app.sv0covmap.json", "status": "accepted"},
                    {"artifact_sha256": None, "byte_length": 0, "diagnostics": ["COV1010", "COV6002"], "map_id": None,
                     "name": "unreadable.sv0covmap.json", "status": "rejected"}],
        maps=[{"bindings": [{"counter_index": n, "point_id": p["point_id"]} for n, p in enumerate(counted)],
               "compiler_identity": "sv0c+0.1.0+be4e4b8", "map_id": map_a, "program_counter_count": len(counted), "source_indices": [0, 1],
               "target": {"kind": "executable", "name": "app"}}],
        merge={"allow_rejected_inputs": True, "limits": {"max_bytes": 268435456, "max_counters": 16777216, "tier": "large"},
               "tool": {"diagnostic_registry_revision": 1, "diagnostic_registry_sha256": REGISTRY_SHA, "name": "sv0cov", "version": "0.1.0"}},
        profile_inputs=profiles,
        run_selection={"manifest_sha256": None, "mode": "explicit-list", "requested_run_ids": [run_a, run_b],
                       "selected_run_ids": [run_a, run_b]},
    )


# ── bounds.json ──────────────────────────────────────────────────────────────


def bounds() -> dict:
    """Every integer at its maximum and every bounded string at its longest."""
    far = {"end_byte": I63, "end_column": U32, "end_line": U32, "start_byte": I63, "start_column": U32, "start_line": U32}
    big = {"by_context": [{"context_index": INDEX_MAX, "lower_bound": False, "saturated": False, "value": U64}], "lower_bound": False,
           "saturated": False, "value": U64}
    pid = d("far point")
    sem = semantic(
        branches=[{"branch_index": INDEX_MAX, "entity_index": INDEX_MAX, "kind": "match", "source_index": INDEX_MAX, "span": far,
                   "outcomes": [{"count": big, "evidence_identity": None, "name": "n" * 256, "ordinal": 0, "point_id": pid,
                                 "status": "covered"}]}],
        contexts=[{"context_index": INDEX_MAX, "value": "c" * 256}],
        contracts=[{"clause_index": INDEX_MAX, "count_false": None, "count_true": None, "enforcement": "statically_verified",
                    "entity_index": INDEX_MAX, "evidence_identity": "e" * 4096, "function_entity_index": INDEX_MAX, "kind": "requires",
                    "runtime_result": "not_applicable", "source_index": INDEX_MAX, "span": far}],
        entities=[{"entity_index": INDEX_MAX, "kind": "function", "qualified_name": "q" * 4096, "source_index": INDEX_MAX, "span": far}],
        exclusions=[{"affected": {"branch_indices": [INDEX_MAX], "clause_indices": [INDEX_MAX], "entity_indices": [INDEX_MAX],
                                  "point_ids": [pid], "region_indices": [INDEX_MAX]},
                     "exclusion_index": INDEX_MAX, "mode": "off", "origin": "attribute", "reason": "r" * 1024, "source_index": INDEX_MAX,
                     "span": far}],
        lines=[{"line": U32, "line_index": INDEX_MAX, "region_indices": [INDEX_MAX], "source_index": INDEX_MAX, "status": "covered"}],
        map_ids=[d("far map")],
        points=[{"classification": "user", "count": big, "entity_index": INDEX_MAX, "kind": "branch_outcome",
                 "outcome_ordinal": INDEX_MAX, "point_id": pid, "semantic_discriminator": "s" * 256, "source_index": INDEX_MAX,
                 "span": far}],
        regions=[{"classification": "user", "count": big,
                  "counter_expression": {"terms": [{"coefficient": 2147483647, "point_id": pid},
                                                   {"coefficient": -2147483648, "point_id": "f" * 64}]},
                  "entity_index": INDEX_MAX, "kind": "return", "line_contributing": True, "line_numbers": [U32], "region_index": INDEX_MAX,
                  "source_index": INDEX_MAX, "span": far}],
        sources=[{"digest": d("far source"), "ownership": "dependency", "package": "p" * 1024, "path": "d/" + "f" * 4094,
                  "source_index": INDEX_MAX}],
    )
    run = "f" * 32
    return indexed(
        sem,
        execution={"exit_code": 255, "signal": None, "status": "failed"},
        map_inputs=[{"artifact_sha256": d("far map bytes"), "byte_length": I63, "diagnostics": [], "map_id": d("far map"),
                     "name": "m" * 255, "status": "accepted"}],
        maps=[{"bindings": [{"counter_index": 0, "point_id": pid}], "compiler_identity": "~" * 255, "map_id": d("far map"),
               "program_counter_count": 1, "source_indices": [INDEX_MAX], "target": {"kind": "executable", "name": "t" * 1024}}],
        merge={"allow_rejected_inputs": False, "limits": {"max_bytes": 68719476736, "max_counters": U32, "tier": "custom"},
               "tool": {"diagnostic_registry_revision": U32, "diagnostic_registry_sha256": "f" * 64, "name": "sv0cov",
                        "version": "v" * 128}},
        profile_inputs=[{"artifact_sha256": "f" * 64, "backend": "vm-v2", "byte_length": I63, "context_index": INDEX_MAX,
                         "diagnostics": [], "map_id": d("far map"), "name": "é" * 127 + "p", "profile_id": run, "run_id": run,
                         "status": "accepted"}],
        run_selection={"manifest_sha256": "f" * 64, "mode": "manifest", "requested_run_ids": [run], "selected_run_ids": [run]},
    )


# ── mutations.json ───────────────────────────────────────────────────────────
# (name, base fixture, [(JSON pointer, value) or (JSON pointer,) to delete], outcome).
# A pointer ending in "/-" appends to an array. After the changes the
# projection digest is recomputed unless the entry sets "rehash": false.

A, B, E = "all-kinds", "bounds", "empty"
SEM = "/semantic"


def mutations() -> list[dict]:
    out: list[dict] = []

    def add(name: str, base: str, ops: list[tuple], expect: str, rehash: bool = True) -> None:
        out.append({"base": base, "expect": expect, "name": name, "rehash": rehash,
                    "ops": [{"pointer": op[0], "remove": len(op) == 1, "value": op[1] if len(op) > 1 else None} for op in ops]})

    # Valid variants: each status, mode and tier the fixtures do not already use.
    add("execution passed", E, [("/execution", {"exit_code": 0, "signal": None, "status": "passed"})], "valid")
    add("execution signaled", E, [("/execution", {"exit_code": None, "signal": 127, "status": "signaled"})], "valid")
    add("execution failed at 1", E, [("/execution", {"exit_code": 1, "signal": None, "status": "failed"})], "valid")
    add("implicit single run", A, [("/run_selection", {"manifest_sha256": None, "mode": "implicit-single", "requested_run_ids": [],
                                                       "selected_run_ids": [ident("run a")]})], "valid")
    add("standard tier", A, [("/merge/limits", {"max_bytes": 67108864, "max_counters": 4194304, "tier": "standard"})], "valid")
    add("custom tier at 1", A, [("/merge/limits", {"max_bytes": 1, "max_counters": 1, "tier": "custom"})], "valid")
    add("saturation under fail", A, [(f"{SEM}/saturation/policy", "fail"), (f"{SEM}/saturation/eligible_metrics", []),
                                     (f"{SEM}/saturation/ineligible_uses", [])], "valid")
    add("lower-bound zero context kept", A, [(f"{SEM}/regions/13/count",
                                             {"by_context": [{"context_index": 0, "lower_bound": True, "saturated": True, "value": 0}],
                                              "lower_bound": True, "saturated": True, "value": 0})], "valid")
    add("complete flag true", E, [(f"{SEM}/complete", True)], "valid")

    # Projection digest.
    add("semantic changed without rehash", A, [(f"{SEM}/complete", True)], "COV3011", rehash=False)
    add("digest of other bytes", E, [("/semantic_projection_sha256", d("something else"))], "COV3011", rehash=False)
    add("digest in uppercase", E, [("/semantic_projection_sha256", "A" * 64)], "COV3010", rehash=False)

    # Closed shapes: unknown, missing, mistyped, wrong constants.
    for where in ("", "/execution", "/merge", "/merge/limits", "/merge/tool", "/run_selection", "/map_inputs/0", "/profile_inputs/0",
                  "/maps/0", "/maps/0/bindings/0", "/maps/0/target", SEM, f"{SEM}/contexts/0", f"{SEM}/sources/0", f"{SEM}/entities/0",
                  f"{SEM}/points/0", f"{SEM}/points/0/count", f"{SEM}/points/0/span", f"{SEM}/regions/0",
                  f"{SEM}/regions/0/counter_expression", f"{SEM}/regions/0/counter_expression/terms/0", f"{SEM}/lines/0",
                  f"{SEM}/branches/0", f"{SEM}/branches/0/outcomes/0", f"{SEM}/contracts/0", f"{SEM}/exclusions/0",
                  f"{SEM}/exclusions/0/affected", f"{SEM}/saturation"):
        add(f"unknown property at {where or '/'}", A, [(f"{where}/extension", 1)], "COV3010")
    add("unknown property in a context count", A, [(f"{SEM}/regions/0/count/by_context/0/extension", 1)], "COV3010")
    for key in ("diagnostics", "execution", "map_inputs", "maps", "merge", "profile_inputs", "run_selection", "schema", "semantic",
                "semantic_projection_sha256", "version"):
        add(f"missing /{key}", A, [(f"/{key}",)], "COV3010", rehash=key not in ("semantic", "semantic_projection_sha256"))
    for key in ("branches", "capabilities", "complete", "contexts", "contracts", "diagnostics", "entities", "exclusions", "lines",
                "map_ids", "map_version", "point_identity_version", "points", "regions", "saturation", "schema", "sources", "version"):
        add(f"missing semantic {key}", A, [(f"{SEM}/{key}",)], "COV3010")
    for name, pointer, value in (
        ("schema name", "/schema", "sv0cov.indexed-semantic"), ("version 1.1", "/version", "1.1"),
        ("semantic schema name", f"{SEM}/schema", "sv0cov.indexed"), ("semantic version", f"{SEM}/version", "2.0"),
        ("map version", f"{SEM}/map_version", "1.1"), ("point identity version", f"{SEM}/point_identity_version", "1"),
        ("capability removed", f"{SEM}/capabilities", [c for c in CAPABILITIES if c != "contexts"]),
        ("capability added", f"{SEM}/capabilities", CAPABILITIES + ["vendor-extension"]),
        ("capabilities reordered", f"{SEM}/capabilities", list(reversed(CAPABILITIES))),
        ("tool name", "/merge/tool/name", "sv0cov-fork"), ("target kind", "/maps/0/target/kind", "library"),
        ("complete as a string", f"{SEM}/complete", "true"), ("allow flag as an integer", "/merge/allow_rejected_inputs", 1),
        ("diagnostics as an object", "/diagnostics", {}), ("count value as a string", f"{SEM}/points/0/count/value", "1"),
        ("line as a float-like string", f"{SEM}/lines/0/line", "3"), ("semantic as an array", "/semantic", []),
    ):
        add(f"wrong {name}", A, [(pointer, value)], "COV3010")

    # Enumerations.
    for name, pointer in (
        ("execution status", "/execution/status"), ("tier", "/merge/limits/tier"), ("run mode", "/run_selection/mode"),
        ("map input status", "/map_inputs/0/status"), ("profile input status", "/profile_inputs/0/status"),
        ("backend", "/profile_inputs/0/backend"), ("point classification", f"{SEM}/points/0/classification"),
        ("point kind", f"{SEM}/points/0/kind"), ("region kind", f"{SEM}/regions/0/kind"), ("line status", f"{SEM}/lines/0/status"),
        ("branch kind", f"{SEM}/branches/0/kind"), ("outcome status", f"{SEM}/branches/0/outcomes/0/status"),
        ("contract kind", f"{SEM}/contracts/0/kind"), ("enforcement", f"{SEM}/contracts/0/enforcement"),
        ("runtime result", f"{SEM}/contracts/0/runtime_result"), ("exclusion mode", f"{SEM}/exclusions/0/mode"),
        ("exclusion origin", f"{SEM}/exclusions/0/origin"), ("saturation policy", f"{SEM}/saturation/policy"),
        ("source ownership", f"{SEM}/sources/0/ownership"), ("entity kind", f"{SEM}/entities/0/kind"),
    ):
        add(f"unknown {name}", A, [(pointer, "other")], "COV3010")
    add("map input status incomplete", A, [("/map_inputs/1/status", "incomplete")], "COV3010")
    add("contract kind alias", A, [(f"{SEM}/contracts/0/kind", "precondition")], "COV3010")
    add("eligible metric contract", A, [(f"{SEM}/saturation/eligible_metrics/0", "contract")], "COV3010")
    add("unknown ineligible use", A, [(f"{SEM}/saturation/ineligible_uses/0", "html_reports")], "COV3010")

    # Integer and length bounds, one past each maximum (bounds.json holds the
    # maxima) or below each minimum. A count above 2^64 - 1 is not canonical
    # JSON at all, so the decoder refuses it before any schema runs.
    for name, pointer, value in (
        ("index", f"{SEM}/points/0/entity_index", U32), ("negative count", f"{SEM}/points/0/count/value", -1),
        ("byte offset", f"{SEM}/points/0/span/end_byte", I63 + 1), ("line zero", f"{SEM}/lines/0/line", 0),
        ("line number zero", f"{SEM}/regions/0/line_numbers", [0]), ("column zero", f"{SEM}/points/0/span/start_column", 0),
        ("coefficient", f"{SEM}/regions/0/counter_expression/terms/0/coefficient", 2147483648),
        ("exit code", "/execution/exit_code", 256), ("signal", "/execution", {"exit_code": None, "signal": 128, "status": "signaled"}),
        ("signal zero", "/execution", {"exit_code": None, "signal": 0, "status": "signaled"}),
        ("byte length", "/map_inputs/0/byte_length", I63 + 1), ("negative byte length", "/profile_inputs/0/byte_length", -1),
        ("counter count", "/maps/0/program_counter_count", U32 + 1), ("counter ceiling", "/merge/limits/max_counters", U32 + 1),
        ("byte ceiling", "/merge/limits/max_bytes", 68719476737), ("zero counter ceiling", "/merge/limits/max_counters", 0),
        ("registry revision zero", "/merge/tool/diagnostic_registry_revision", 0),
        ("context longer than 256 characters", f"{SEM}/contexts/0/value", "c" * 257),
        ("discriminator", f"{SEM}/points/0/semantic_discriminator", "s" * 257), ("empty discriminator", f"{SEM}/points/0/semantic_discriminator", ""),
        ("outcome name", f"{SEM}/branches/0/outcomes/0/name", "n" * 257), ("reason", f"{SEM}/exclusions/0/reason", "r" * 1025),
        ("empty reason", f"{SEM}/exclusions/0/reason", ""), ("qualified name", f"{SEM}/entities/0/qualified_name", "q" * 4097),
        ("input name", "/map_inputs/0/name", "m" * 256), ("empty input name", "/map_inputs/0/name", ""),
        ("tool version", "/merge/tool/version", "v" * 129), ("empty tool version", "/merge/tool/version", ""),
        ("compiler identity", "/maps/0/compiler_identity", "~" * 256), ("target name", "/maps/0/target/name", "t" * 1025),
        ("short digest", "/maps/0/map_id", "f" * 63), ("long run ID", "/run_selection/selected_run_ids/0", "f" * 33),
        ("short stable code", "/diagnostics", ["COV300"]), ("no outcomes", f"{SEM}/branches/0/outcomes", []),
        ("five eligible metrics", f"{SEM}/saturation/eligible_metrics", ["branch", "function", "line", "region", "branch"]),
    ):
        add(f"out of range: {name}", A, [(pointer, value)], "COV3010")

    # Lexical forms.
    for name, pointer, value in (
        ("uppercase digest", "/maps/0/map_id", "A" * 64), ("non-hex digest", f"{SEM}/points/0/point_id", "g" * 64),
        ("stable code in lowercase", "/diagnostics", ["cov3002"]), ("stable code with a letter", f"{SEM}/diagnostics", ["COV30A2"]),
        ("zero run ID", "/run_selection/selected_run_ids/0", "0" * 32), ("uppercase run ID", "/run_selection/requested_run_ids/0", "A" * 32),
        ("zero profile ID", "/profile_inputs/0/profile_id", "0" * 32), ("input name with a slash", "/map_inputs/0/name", "dir/app.json"),
        ("input name with a backslash", "/profile_inputs/0/name", "dir\\p.sv0profraw"), ("input name with NUL", "/map_inputs/0/name", "a\u0000b"),
        ("input name over 255 bytes", "/map_inputs/0/name", "é" * 128), ("context over 256 bytes", f"{SEM}/contexts/2/value", "é" * 129),
        ("compiler identity with a space", "/maps/0/compiler_identity", "sv0c 0.1"), ("compiler identity not ASCII", "/maps/0/compiler_identity", "sv0c+é"),
        ("target name with a newline", "/maps/0/target/name", "app\nx"), ("qualified name with CR", f"{SEM}/entities/0/qualified_name", "a\rb"),
        ("absolute source path", f"{SEM}/sources/0/path", "/src/app.sv0"), ("source path with ..", f"{SEM}/sources/0/path", "src/../app.sv0"),
        ("package over 1024 bytes", f"{SEM}/sources/1/package", "é" * 513), ("discriminator over 256 bytes", f"{SEM}/points/0/semantic_discriminator", "é" * 129),
        ("tool version over 128 bytes", "/merge/tool/version", "é" * 65),
        ("reason over 1024 bytes", f"{SEM}/exclusions/0/reason", "é" * 513), ("outcome name over 256 bytes", f"{SEM}/branches/0/outcomes/0/name", "é" * 129),
        ("evidence with a newline", f"{SEM}/branches/1/outcomes/1/evidence_identity", "proof\nline"),
        ("contract evidence with NUL", f"{SEM}/contracts/4/evidence_identity", "proof\u0000"),
    ):
        add(f"lexical: {name}", A, [(pointer, value)], "COV3010")

    # Scalar arrays are strictly ordered and unique.
    run_a, run_b = sorted((ident("run a"), ident("run b")))
    for name, pointer, value in (
        ("diagnostics unsorted", f"{SEM}/diagnostics", ["COV3004", "COV3002"]), ("diagnostics duplicated", "/diagnostics", ["COV3002", "COV3002"]),
        ("map IDs duplicated", f"{SEM}/map_ids", [d("map a"), d("map a")]), ("run IDs unsorted", "/run_selection/requested_run_ids", [run_b, run_a]),
        ("source indices unsorted", "/maps/0/source_indices", [1, 0]), ("line numbers duplicated", f"{SEM}/regions/3/line_numbers", [4, 4, 5]),
        ("region indices unsorted", f"{SEM}/lines/0/region_indices", [2, 0]), ("affected branches duplicated", f"{SEM}/exclusions/0/affected/branch_indices", [2, 2]),
        ("ineligible uses unsorted", f"{SEM}/saturation/ineligible_uses", ["ratchets", "contract_counts"]),
        ("context counts unsorted", f"{SEM}/regions/0/count/by_context",
         [{"context_index": 2, "lower_bound": False, "saturated": False, "value": 3}, {"context_index": 0, "lower_bound": False, "saturated": False, "value": 2}]),
    ):
        add(f"order: {name}", A, [(pointer, value)], "COV3010")

    # What one record fixes by itself.
    ex = "/execution"
    for name, value in (
        ("not_applicable with an exit code", {"exit_code": 0, "signal": None, "status": "not_applicable"}),
        ("passed with exit code 1", {"exit_code": 1, "signal": None, "status": "passed"}),
        ("passed without an exit code", {"exit_code": None, "signal": None, "status": "passed"}),
        ("failed with exit code 0", {"exit_code": 0, "signal": None, "status": "failed"}),
        ("failed with a signal", {"exit_code": 2, "signal": 9, "status": "failed"}),
        ("signaled with an exit code", {"exit_code": 1, "signal": 9, "status": "signaled"}),
        ("signaled without a signal", {"exit_code": None, "signal": None, "status": "signaled"}),
    ):
        add(f"execution: {name}", E, [(ex, value)], "COV3010")
    add("limits: standard tier with other ceilings", A, [("/merge/limits", {"max_bytes": 67108865, "max_counters": 4194304, "tier": "standard"})], "COV3010")
    add("limits: large tier with standard ceilings", A, [("/merge/limits", {"max_bytes": 67108864, "max_counters": 4194304, "tier": "large"})], "COV3010")
    add("map input: accepted with a diagnostic", A, [("/map_inputs/0/diagnostics", ["COV1010"])], "COV3010")
    add("map input: accepted without a digest", A, [("/map_inputs/0/artifact_sha256", None)], "COV3010")
    add("map input: accepted without a map ID", A, [("/map_inputs/0/map_id", None)], "COV3010")
    add("map input: rejected without a diagnostic", A, [("/map_inputs/1/diagnostics", [])], "COV3010")
    for key in ("artifact_sha256", "backend", "context_index", "map_id", "profile_id", "run_id"):
        add(f"profile input: accepted without {key}", A, [(f"/profile_inputs/0/{key}", None)], "COV3010")
    add("profile input: accepted with a diagnostic", A, [("/profile_inputs/0/diagnostics", ["COV2011"])], "COV3010")
    add("profile input: incomplete without a diagnostic", A, [("/profile_inputs/3/diagnostics", [])], "COV3010")
    add("profile input: rejected without a diagnostic", A, [("/profile_inputs/4/diagnostics", [])], "COV3010")
    add("binding: fewer bindings than counters", A, [("/maps/0/program_counter_count", 99)], "COV3010")
    add("binding: counter index out of position", A, [("/maps/0/bindings/1/counter_index", 2)], "COV3010")
    for name, value in (
        ("explicit list without requested runs", {"manifest_sha256": None, "mode": "explicit-list", "requested_run_ids": [], "selected_run_ids": []}),
        ("explicit list with a manifest digest", {"manifest_sha256": d("m"), "mode": "explicit-list", "requested_run_ids": [run_a], "selected_run_ids": []}),
        ("implicit single with requested runs", {"manifest_sha256": None, "mode": "implicit-single", "requested_run_ids": [run_a], "selected_run_ids": [run_a]}),
        ("manifest without a digest", {"manifest_sha256": None, "mode": "manifest", "requested_run_ids": [run_a], "selected_run_ids": [run_a]}),
        ("manifest without requested runs", {"manifest_sha256": d("m"), "mode": "manifest", "requested_run_ids": [], "selected_run_ids": []}),
        ("none with a selected run", {"manifest_sha256": None, "mode": "none", "requested_run_ids": [], "selected_run_ids": [run_a]}),
        ("none with a manifest digest", {"manifest_sha256": d("m"), "mode": "none", "requested_run_ids": [], "selected_run_ids": []}),
    ):
        add(f"run selection: {name}", A, [("/run_selection", value)], "COV3010")
    exact = {"context_index": 0, "lower_bound": False, "saturated": False, "value": 5}
    for name, value in (
        ("saturated without lower_bound", {"by_context": [], "lower_bound": False, "saturated": True, "value": 0}),
        ("context saturated without lower_bound", {"by_context": [dict(exact, saturated=True)], "lower_bound": True, "saturated": True, "value": 5}),
        ("exact zero context kept", {"by_context": [dict(exact, value=0)], "lower_bound": False, "saturated": False, "value": 0}),
        ("exact aggregate is not the sum", {"by_context": [exact], "lower_bound": False, "saturated": False, "value": 6}),
        ("inexact context under an exact aggregate", {"by_context": [dict(exact, lower_bound=True, saturated=True)], "lower_bound": False, "saturated": False, "value": 5}),
        ("context listed twice", {"by_context": [exact, exact], "lower_bound": False, "saturated": False, "value": 10}),
    ):
        add(f"count: {name}", A, [(f"{SEM}/regions/0/count", value)], "COV3010")
    add("span: ends before it starts", A, [(f"{SEM}/regions/0/span/end_byte", 29)], "COV3010")
    add("point: ordinal on a function entry", B, [(f"{SEM}/points/0/kind", "function_entry")], "COV3010")
    add("point: branch outcome without an ordinal", B, [(f"{SEM}/points/0/outcome_ordinal", None)], "COV3010")
    add("point: function entry without an entity", B, [(f"{SEM}/points/0/kind", "function_entry"), (f"{SEM}/points/0/outcome_ordinal", None),
                                                       (f"{SEM}/points/0/entity_index", None)], "COV3010")
    add("point: contract point without an entity", B, [(f"{SEM}/points/0/kind", "contract_true"), (f"{SEM}/points/0/outcome_ordinal", None),
                                                       (f"{SEM}/points/0/entity_index", None)], "COV3010")
    add("region: zero coefficient", A, [(f"{SEM}/regions/0/counter_expression/terms/0/coefficient", 0)], "COV3010")
    add("region: term listed twice", B, [(f"{SEM}/regions/0/counter_expression/terms/1/point_id", d("far point"))], "COV3010")
    add("outcome: ordinal out of position", A, [(f"{SEM}/branches/0/outcomes/1/ordinal", 2)], "COV3010")
    add("outcome: unreachable without evidence", A, [(f"{SEM}/branches/1/outcomes/1/evidence_identity", None)], "COV3010")
    add("outcome: evidence on a covered outcome", A, [(f"{SEM}/branches/0/outcomes/0/evidence_identity", "proof")], "COV3010")
    add("outcome: covered with a zero count", A, [(f"{SEM}/branches/0/outcomes/1/status", "covered")], "COV3010")
    add("outcome: uncovered with a nonzero count", A, [(f"{SEM}/branches/0/outcomes/0/status", "uncovered")], "COV3010")
    add("outcome: excluded with a count", A, [(f"{SEM}/branches/2/outcomes/0/count", count((0, 1)))], "COV3010")
    add("branch: a single outcome on an if", B, [(f"{SEM}/branches/0/kind", "if")], "COV3010")
    add("contract: runtime_checked without counts", A, [(f"{SEM}/contracts/0/count_true", None)], "COV3010")
    add("contract: counts on a disabled clause", A, [(f"{SEM}/contracts/5/count_false", count())], "COV3010")
    add("contract: statically_verified without evidence", A, [(f"{SEM}/contracts/4/evidence_identity", None)], "COV3010")
    add("contract: evidence on a runtime clause", A, [(f"{SEM}/contracts/0/evidence_identity", "proof")], "COV3010")
    for index, result in ((0, "evaluated_true"), (1, "mixed"), (2, "evaluated_false"), (3, "not_evaluated"), (4, "not_evaluated"), (0, "not_applicable")):
        add(f"contract: clause {index} reported {result}", A, [(f"{SEM}/contracts/{index}/runtime_result", result)], "COV3010")
    sat = f"{SEM}/saturation"
    add("saturation: any false with an affected point", A, [(f"{sat}/any", False)], "COV3010")
    add("saturation: any true with nothing affected", E, [(f"{sat}/any", True)], "COV3010")
    add("saturation: eligible metrics under fail", A, [(f"{sat}/policy", "fail")], "COV3010")
    add("saturation: no eligible metrics under allow-ordinary", A, [(f"{sat}/eligible_metrics", [])], "COV3010")
    add("saturation: three eligible metrics", A, [(f"{sat}/eligible_metrics", ["branch", "function", "line"])], "COV3010")
    add("saturation: ineligible uses with nothing saturated", E, [(f"{sat}/ineligible_uses", ["ratchets"])], "COV3010")
    return out


def documents() -> dict[str, dict]:
    return {"empty": empty(), "all-kinds": all_kinds(), "bounds": bounds()}


def artifacts() -> dict[Path, bytes]:
    out = {HERE / f"{name}.json": encode(doc) for name, doc in documents().items()}
    out[HERE / "mutations.json"] = encode({"mutations": mutations(), "schema": "sv0cov.indexed-structure-mutations", "version": "1.0"})
    return out


def apply(doc: dict, entry: dict) -> dict:
    """One mutation applied to a copy of its base document."""
    o = copy.deepcopy(doc)
    for op in entry["ops"]:
        parts = [p.replace("~1", "/").replace("~0", "~") for p in op["pointer"].split("/")[1:]]
        node = o
        for p in parts[:-1]:
            node = node[int(p)] if isinstance(node, list) else node[p]
        last = parts[-1]
        if isinstance(node, list):
            if op["remove"]:
                del node[int(last)]
            elif last == "-":
                node.append(op["value"])
            else:
                node[int(last)] = op["value"]
        elif op["remove"]:
            del node[last]
        else:
            node[last] = op["value"]
    if entry["rehash"] and isinstance(o.get("semantic"), dict):
        o["semantic_projection_sha256"] = projection_sha256(o["semantic"])
    return o


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print("stale indexed fixture artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("indexed fixtures: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
