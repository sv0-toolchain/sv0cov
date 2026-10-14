#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Build or check the native-report structure fixtures (CV-228).

Hand-written ``sv0cov.report`` 1.0 documents for the schema and record-level
layer (``sv0cov.formats.report``), and one mutation corpus:

- ``empty.json``: a report of diagnostic evidence with no input at all;
- ``passing.json``: a small, clean, passing report;
- ``all-kinds.json``: every record kind and (with the valid mutations)
  every enumeration value;
- ``bounds.json``: every integer and length at its largest value;
- ``mutations.json``: single changes to those documents, each with its
  outcome: ``valid`` or ``COV4001``.

The shared records (points, regions, lines, branches, contracts, contexts,
inputs, saturation) are taken from the indexed structure fixtures of
CV-220, so the two contracts are exercised on the same data. These are
structure fixtures: digests are made up, and summaries and policy fractions
are not derived from the detail. A report that cross-validates arrives with
the producer and reader (CV-229).

    python3 tests/fixtures/report/build.py            # check (exit 1 if stale)
    python3 tests/fixtures/report/build.py --write    # rewrite after review
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import sys
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402

_spec = importlib.util.spec_from_file_location("indexed_fixture_build", HERE.parent / "indexed" / "build.py")
ix = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ix)

U64, I63, INDEX_MAX, U32 = ix.U64, ix.I63, ix.INDEX_MAX, ix.U32
CAPABILITIES = ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "policy-assertions", "saturation-lower-bounds",
                "source-integrity"]
METRICS = ("branch", "contract", "function", "line", "region")
NO_MEMBERS = {"branch_indices": [], "clause_indices": [], "entity_indices": [], "line_indices": [], "region_indices": [],
              "source_indices": []}
d = ix.d


def metric(covered: int, total: int, partial: int | None = None) -> dict:
    """A metric record. The ratio is worked out here with decimal arithmetic,
    independently of the integer code under test."""
    r = None
    if total:
        q = (Decimal(covered) / Decimal(total)).quantize(Decimal("0.000001"), rounding=ROUND_HALF_EVEN)
        r = f"{q:.6f}"
    return {"covered": covered, "partial": partial, "ratio": r, "total": total}


def metric_set(branch=(0, 0), contract=(0, 0), function=(0, 0), line=(0, 0, 0), region=(0, 0)) -> dict:
    return {"branch": metric(*branch), "contract": metric(*contract), "function": metric(*function), "line": metric(*line),
            "region": metric(*region)}


def contract_only(covered: int, total: int) -> dict:
    return {"branch": None, "contract": metric(covered, total), "function": None, "line": None, "region": None}


def fraction(numerator: int, denominator: int) -> dict:
    return {"denominator": denominator, "numerator": numerator}


def members(**over) -> dict:
    return {**NO_MEMBERS, **over}


def evaluation(kind: str, name: str, metric_name: str, comparison: str, result: str, *, actual=None, limit=None, source=None,
               diagnostics=(), **member) -> dict:
    return {"actual": actual, "assertion_kind": kind, "assertion_name": name, "comparison": comparison, "diagnostics": list(diagnostics),
            "limit": limit, "members": members(**member), "metric": metric_name, "result": result, "threshold_source": source}


def integrity(result: str = "pass", diagnostics=()) -> dict:
    return evaluation("integrity", "integrity", "evidence", "none", result, diagnostics=diagnostics)


def configuration(options=(), toml: str = "") -> dict:
    return resolve("run", options, toml.encode() if toml else None).document()


def from_indexed(doc: dict, *, eligibility: str, evaluations: list[dict], passed: bool, config: dict, summary: dict,
                 source_extra: list[dict], entity_summaries: list[dict], accuracy: str = "current", line_indices=None,
                 tool_version: str = "0.1.0") -> dict:
    """A report over an indexed structure fixture: the shared records as they
    are, plus what only a report has."""
    sem = doc["semantic"]
    accepted = [r for r in doc["profile_inputs"] if r["status"] == "accepted"]
    sources = [{**s, **extra} for s, extra in zip(sem["sources"], source_extra, strict=True)]
    return {
        "branches": sem["branches"],
        "capabilities": list(CAPABILITIES),
        "complete": sem["complete"],
        "contexts": sem["contexts"],
        "contracts": sem["contracts"],
        "entities": [{**e, "summary": s} for e, s in zip(sem["entities"], entity_summaries, strict=True)],
        "evidence_eligibility": eligibility,
        "exclusions": [{**x, "affected": {**x["affected"], "line_indices": (line_indices or {}).get(x["exclusion_index"], [])}}
                       for x in sem["exclusions"]],
        "inputs": doc["profile_inputs"],
        "lines": sem["lines"],
        "maps": [{k: v for k, v in m.items() if k != "bindings"} for m in doc["maps"]],
        "points": sem["points"],
        "policy": {"evaluations": evaluations, "passed": passed},
        "provenance": {
            "backends": sorted({r["backend"] for r in accepted}),
            "execution_exit_code": doc["execution"]["exit_code"],
            "execution_signal": doc["execution"]["signal"],
            "execution_status": doc["execution"]["status"],
            "indexed_diagnostic_registry_revision": doc["merge"]["tool"]["diagnostic_registry_revision"],
            "indexed_diagnostic_registry_sha256": doc["merge"]["tool"]["diagnostic_registry_sha256"],
            "indexed_input_sha256": hashlib.sha256(encode(doc)).hexdigest(),
            "map_ids": sem["map_ids"],
            "run_ids": doc["run_selection"]["selected_run_ids"],
            "run_manifest_sha256": doc["run_selection"]["manifest_sha256"],
            "run_selection": doc["run_selection"]["mode"],
            "semantic_projection_sha256": doc["semantic_projection_sha256"],
            "source_accuracy": accuracy,
        },
        "regions": [{**r, "point_ids": sorted({t["point_id"] for t in r["counter_expression"]["terms"]})} for r in sem["regions"]],
        "resolved_configuration": config,
        "saturation": sem["saturation"],
        "schema": "sv0cov.report",
        "sources": sources,
        "summary": summary,
        "tool": {"diagnostic_registry_revision": 2, "diagnostic_registry_sha256": ix.REGISTRY_SHA, "name": "sv0cov", "version": tool_version},
        "version": "1.0",
    }


# ── the four documents ───────────────────────────────────────────────────────


def empty() -> dict:
    """Nothing was accepted: the only evaluation is the failing integrity one."""
    return from_indexed(ix.empty(), eligibility="incomplete", passed=False, config=configuration(), summary=metric_set(),
                        evaluations=[integrity("fail", ["COV3001", "COV3003"])], source_extra=[], entity_summaries=[])


def passing() -> dict:
    """One function with an `if`, fully covered, thresholds met."""
    src, mid, run = d("src ok"), d("map ok"), ix.ident("run ok")
    pts = {name: d(f"ok {name}") for name in ("entry", "true", "false")}
    span = ix.span

    def pt(name, kind, cnt, sp, disc, ordinal=None):
        return {"classification": "user", "count": cnt, "entity_index": 0, "kind": kind, "outcome_ordinal": ordinal, "point_id": pts[name],
                "semantic_discriminator": disc, "source_index": 0, "span": sp}

    def rg(index, kind, cnt, terms, sp, line, lc=True):
        return {"classification": "user", "count": cnt, "counter_expression": {"terms": sorted(terms, key=lambda t: t["point_id"])},
                "entity_index": 0, "kind": kind, "line_contributing": lc, "line_numbers": [line], "region_index": index, "source_index": 0,
                "span": sp}

    t = lambda name, c=1: {"coefficient": c, "point_id": pts[name]}  # noqa: E731
    one, two = ix.count((0, 1)), ix.count((0, 2))
    sem = ix.semantic(
        complete=True, contexts=[{"context_index": 0, "value": None}], map_ids=[mid],
        entities=[{"entity_index": 0, "kind": "function", "qualified_name": "main", "source_index": 0, "span": span(0, 60, 1, 5)}],
        points=sorted([pt("entry", "function_entry", two, span(0, 60, 1, 5), "entry"),
                       pt("true", "branch_outcome", one, span(20, 40, 2, 4), "if", 0),
                       pt("false", "branch_outcome", one, span(20, 40, 2, 4), "if", 1)], key=lambda p: p["point_id"]),
        regions=[rg(0, "expression", two, [t("entry")], span(23, 28, 2), 2),
                 rg(1, "return", one, [t("true")], span(31, 40, 3), 3),
                 rg(2, "return", one, [t("entry"), t("true", -1)], span(44, 53, 5), 5)],
        lines=[{"line": n, "line_index": i, "region_indices": [i], "source_index": 0, "status": "covered"} for i, n in enumerate((2, 3, 5))],
        branches=[{"branch_index": 0, "entity_index": 0, "kind": "if", "source_index": 0, "span": span(20, 40, 2, 4),
                   "outcomes": [{"count": one, "evidence_identity": None, "name": name, "ordinal": n, "point_id": pts[name], "status": "covered"}
                                for n, name in enumerate(("true", "false"))]}],
        sources=[{"digest": src, "ownership": "user", "package": None, "path": "main.sv0", "source_index": 0}],
    )
    doc = ix.indexed(
        sem, execution={"exit_code": 0, "signal": None, "status": "passed"},
        map_inputs=[{"artifact_sha256": d("map ok bytes"), "byte_length": 2048, "diagnostics": [], "map_id": mid, "name": "main.sv0covmap.json",
                     "status": "accepted"}],
        maps=[{"bindings": [{"counter_index": n, "point_id": p} for n, p in enumerate(sorted(pts.values()))], "compiler_identity": "sv0c+0.1.0",
               "map_id": mid, "program_counter_count": 3, "source_indices": [0], "target": {"kind": "executable", "name": "main"}}],
        profile_inputs=[{"artifact_sha256": d("profile ok"), "backend": "native", "byte_length": 132, "context_index": 0, "diagnostics": [],
                         "map_id": mid, "name": f"{run}-0001.sv0profraw", "profile_id": ix.ident("profile ok"), "run_id": run,
                         "status": "accepted"}],
        run_selection={"manifest_sha256": None, "mode": "implicit-single", "requested_run_ids": [], "selected_run_ids": [run]},
    )
    summary = metric_set(branch=(2, 2), function=(1, 1), line=(3, 3, 0), region=(3, 3))
    return from_indexed(
        doc, eligibility="passing", passed=True, summary=summary, entity_summaries=[summary],
        config=configuration([("--threshold-line", "85"), ("--threshold-branch", "7500bp")]),
        source_extra=[{"observed_digest": src, "source_state": "current", "summary": summary}],
        evaluations=[
            integrity(),
            evaluation("project", "project", "branch", "at_least", "pass", actual=fraction(2, 2), limit=fraction(7500, 10000), source="project",
                       branch_indices=[0]),
            evaluation("project", "project", "line", "at_least", "pass", actual=fraction(3, 3), limit=fraction(8500, 10000), source="project",
                       line_indices=[0, 1, 2]),
        ])


ALL_KINDS_TOML = '''[tool.sv0cov]
schema = "1.0"
output_dir = "build/cov"
reports = ["term", "html", "json", "lcov", "cobertura"]
empty = "pass"
context = "shard é"
reproducible_epoch = 1700000000

[tool.sv0cov.integrity]
saturation = "allow-ordinary"

[tool.sv0cov.limits.raw_profile]
tier = "custom"
max_counters = 1000
max_bytes = 100000

[tool.sv0cov.thresholds]
function = 90
region = "8250bp"
line = 85
branch = 75
contract = 100

[[tool.sv0cov.scopes]]
name = "core"
include = ["src/**", "!src/gen/**"]
packages = ["dep-lib"]
sources = ["src/app.sv0"]
line = 95

[[tool.sv0cov.entities]]
name = "check-contract"
source = "src/app.sv0"
qualified_name = "app::check#requires0"
kind = "contract"
contract = 100

[[tool.sv0cov.entities]]
name = "main-fn"
source = "src/app.sv0"
qualified_name = "app::main"
kind = "function"
branch = 50

[tool.sv0cov.diff]
base = "merge-base:origin/main"
line = 100
region = 100
branch = 90

[tool.sv0cov.ratchet]
baseline = ".sv0cov-baseline.json"
metrics = ["function", "region", "line", "branch", "contract"]
tolerance_basis_points = 25

[tool.sv0cov.exclusions]
max_records = 3
function_basis_points = 0
region_basis_points = 500
line_basis_points = 500
branch_basis_points = 2500
contract_basis_points = 2000
forbidden_reasons = ["todo", "later"]
forbidden_sources = ["src/core/**"]
'''


def all_kinds() -> dict:
    doc = ix.all_kinds()
    sem = doc["semantic"]
    big = metric_set(branch=(5, 9), contract=(3, 4), function=(1, 2), line=(7, 12, 2), region=(9, 14))
    dep = metric_set(branch=(0, 0), contract=(0, 0), function=(1, 1), line=(1, 1, 0), region=(1, 1))
    entity_summaries = [big if e["kind"] == "function" else contract_only(1, 1) for e in sem["entities"]]
    f = fraction
    evaluations = [
        evaluation("diff", "diff", "branch", "at_least", "not_applicable", limit=f(9000, 10000), source="diff"),
        evaluation("diff", "diff", "line", "at_least", "fail", actual=f(3, 4), limit=f(10000, 10000), source="diff",
                   diagnostics=["COV4101"], line_indices=[0, 1, 2, 3], source_indices=[0]),
        evaluation("diff", "diff", "region", "at_least", "pass", actual=f(2, 2), limit=f(10000, 10000), source="diff", region_indices=[0, 1]),
        evaluation("entity", "check-contract", "contract", "at_least", "pass", actual=f(1, 1), limit=f(10000, 10000), source="assertion",
                   clause_indices=[0], entity_indices=[1]),
        evaluation("entity", "main-fn", "branch", "at_least", "pass", actual=f(5, 9), limit=f(5000, 10000), source="assertion",
                   branch_indices=[0, 1], entity_indices=[0]),
        evaluation("entity", "main-fn", "line", "at_least", "fail", actual=f(7, 12), limit=f(8500, 10000), source="project",
                   diagnostics=["COV4101"], entity_indices=[0], line_indices=[0, 1]),
        evaluation("exclusion", "exclusions", "branch", "at_most", "pass", actual=f(1, 10), limit=f(2500, 10000), source="exclusion",
                   branch_indices=[2]),
        evaluation("exclusion", "exclusions", "exclusion_records", "at_most", "pass", actual=f(3, 1), limit=f(3, 1), source="exclusion"),
        integrity("ineligible", ["COV1004", "COV3002", "COV3004", "COV4020"]),
        evaluation("project", "project", "contract", "at_least", "ineligible", limit=f(10000, 10000), source="project",
                   diagnostics=["COV4020"], clause_indices=[0, 1, 2]),
        evaluation("project", "project", "function", "at_least", "fail", actual=f(1, 2), limit=f(9000, 10000), source="project",
                   diagnostics=["COV4101"], entity_indices=[0, 2]),
        evaluation("project", "project", "region", "at_least", "fail", actual=f(9, 14), limit=f(8250, 10000), source="project",
                   diagnostics=["COV4101"], region_indices=[0, 1, 2]),
        evaluation("ratchet", "ratchet", "line", "at_least", "ineligible", limit=f(7, 12), source="ratchet", diagnostics=["COV4020"]),
        evaluation("ratchet", "ratchet", "region", "equal", "pass", actual=f(9, 14), limit=f(9, 14), source="ratchet"),
        evaluation("scope", "core", "line", "at_least", "fail", actual=f(7, 12), limit=f(9500, 10000), source="assertion",
                   diagnostics=["COV4101", "COV4102"], line_indices=[0, 1], source_indices=[0]),
        evaluation("scope", "core", "region", "none", "not_applicable"),
    ]
    app, lib = sem["sources"]
    return from_indexed(
        doc, eligibility="incomplete", passed=False, summary=big, entity_summaries=entity_summaries, accuracy="mismatch_allowed",
        config=configuration([("--allow-lossy-saturated-export", None), ("--no-context", None), ("--threshold-branch", "75")], ALL_KINDS_TOML),
        source_extra=[{"observed_digest": d("src app, edited"), "source_state": "mismatch", "summary": big},
                      {"observed_digest": None, "source_state": "unavailable", "summary": dep}],
        evaluations=evaluations, line_indices={0: [0], 1: [1, 2]})


def bounds() -> dict:
    """Every integer at its maximum and every bounded string at its longest."""
    doc = ix.bounds()
    top = {"covered": U64, "partial": None, "ratio": "1.000000", "total": U64}
    summary = {"branch": top, "contract": top, "function": top, "line": {**top, "covered": U64 - 1, "partial": 1, "ratio": "1.000000"},
               "region": top}
    far = [INDEX_MAX]
    cfg = configuration([], '[tool.sv0cov]\nschema = "1.0"\nreproducible_epoch = 9223372036854775807\ncontext = "' + "c" * 256 + '"\n'
                        '[tool.sv0cov.limits.raw_profile]\ntier = "custom"\nmax_counters = 4294967295\nmax_bytes = 68719476736\n'
                        '[tool.sv0cov.thresholds]\nline = 100\nbranch = "10000bp"\n'
                        '[[tool.sv0cov.scopes]]\nname = "' + "n" * 128 + '"\ninclude = ["' + "p" * 4096 + '"]\n'
                        '[tool.sv0cov.ratchet]\nbaseline = "b.json"\nmetrics = ["line"]\ntolerance_basis_points = 10000\n'
                        '[tool.sv0cov.exclusions]\nmax_records = 4294967295\nline_basis_points = 10000\nforbidden_reasons = ["' + "r" * 256 + '"]\n')
    return from_indexed(
        doc, eligibility="incomplete", passed=False, summary=summary, entity_summaries=[summary], tool_version="~" * 128, config=cfg,
        source_extra=[{"observed_digest": "f" * 64, "source_state": "mismatch", "summary": summary}], accuracy="mismatch_allowed",
        line_indices={INDEX_MAX: far},
        evaluations=[integrity("fail", ["COV9999"]),
                     evaluation("scope", "n" * 128, "line", "at_least", "pass", actual=fraction(U64, U64), limit=fraction(U64, U64),
                                source="assertion", branch_indices=far, clause_indices=far, entity_indices=far, line_indices=far,
                                region_indices=far, source_indices=far)])


# ── mutations.json ───────────────────────────────────────────────────────────
# (name, base fixture, [(JSON pointer, value) or (JSON pointer,) to delete], outcome).

A, B, E, P = "all-kinds", "bounds", "empty", "passing"
BAD = "COV4001"


def mutations() -> list[dict]:
    out: list[dict] = []

    def add(name: str, base: str, ops: list[tuple], expect: str = BAD) -> None:
        out.append({"base": base, "expect": expect, "name": name,
                    "ops": [{"pointer": op[0], "remove": len(op) == 1, "value": op[1] if len(op) > 1 else None} for op in ops]})

    ev, src, prov, cfg = "/policy/evaluations", "/sources/0", "/provenance", "/resolved_configuration"
    f = fraction

    # Valid variants: the enumeration values and states the four documents do not already use.
    add("eligibility policy_failed", P, [("/evidence_eligibility", "policy_failed"), ("/policy/passed", False),
                                         (f"{ev}/1/result", "fail"), (f"{ev}/1/diagnostics", ["COV4101"])], "valid")
    add("eligibility diagnostic_only by lossy export", P, [("/evidence_eligibility", "diagnostic_only")], "valid")
    add("eligibility diagnostic_only by source mismatch", P, [("/evidence_eligibility", "diagnostic_only"),
                                                             (f"{prov}/source_accuracy", "mismatch_allowed"),
                                                             (f"{src}/source_state", "unavailable"), (f"{src}/observed_digest", None)], "valid")
    add("policy passed with a not_applicable evaluation", P, [(f"{ev}/1/result", "not_applicable"), (f"{ev}/1/actual", None)], "valid")
    add("execution signaled", P, [(f"{prov}/execution_status", "signaled"), (f"{prov}/execution_exit_code", None),
                                  (f"{prov}/execution_signal", 127)], "valid")
    add("execution not applicable", P, [(f"{prov}/execution_status", "not_applicable"), (f"{prov}/execution_exit_code", None)], "valid")
    add("execution failed at 1", P, [(f"{prov}/execution_status", "failed"), (f"{prov}/execution_exit_code", 1)], "valid")
    add("manifest selection", P, [(f"{prov}/run_selection", "manifest"), (f"{prov}/run_manifest_sha256", d("manifest"))], "valid")
    add("ratio rounds half to even, down", P, [("/summary/region", {"covered": 1, "partial": None, "ratio": "0.000000", "total": 2000000})], "valid")
    add("ratio rounds half to even, up", P, [("/summary/region", {"covered": 3, "partial": None, "ratio": "0.000002", "total": 2000000})], "valid")
    add("ratio of a third", P, [("/summary/region", {"covered": 1, "partial": None, "ratio": "0.333333", "total": 3})], "valid")
    add("ratio of two thirds", P, [("/summary/region", {"covered": 2, "partial": None, "ratio": "0.666667", "total": 3})], "valid")
    add("ratio just below one is not one", P, [("/summary/region", {"covered": 999999, "partial": None, "ratio": "0.999999", "total": 1000000})], "valid")
    add("ratio that rounds up to one", P, [("/summary/region", {"covered": U64 - 1, "partial": None, "ratio": "1.000000", "total": U64})], "valid")
    add("zero denominator has no ratio", P, [("/summary/contract", {"covered": 0, "partial": None, "ratio": None, "total": 0})], "valid")
    add("partial lines", P, [("/summary/line", {"covered": 1, "partial": 2, "ratio": "0.333333", "total": 3})], "valid")
    add("comparison at_most from integrity source", A, [(f"{ev}/7/threshold_source", "integrity")], "valid")
    add("package on a root source", P, [(f"{src}/package", "app")], "valid")
    add("large tier from the command line", P, [("/resolved_configuration/coverage/limits/raw_profile/tier", {"source": "cli", "value": "large"})],
        "valid")

    # Top level.
    add("schema name", P, [("/schema", "sv0cov.indexed")])
    add("version 1.1", P, [("/version", "1.1")])
    add("capability missing", P, [("/capabilities/6",)])
    add("capability reordered", P, [("/capabilities/0", "contexts"), ("/capabilities/1", "branch-outcomes")])
    add("capability added", P, [("/capabilities/-", "x-vendor")])
    add("eligibility unknown", P, [("/evidence_eligibility", "ok")])
    add("incomplete eligibility on complete evidence", P, [("/evidence_eligibility", "incomplete")])
    add("complete evidence marked incomplete", A, [("/complete", True)])
    add("passing on incomplete evidence", A, [("/evidence_eligibility", "passing")])
    add("passing with a failed policy", P, [("/policy/passed", False)])
    add("passing with a stale source", P, [(f"{prov}/source_accuracy", "mismatch_allowed"), (f"{src}/source_state", "unavailable"),
                                           (f"{src}/observed_digest", None)])
    add("policy_failed with a passed policy", P, [("/evidence_eligibility", "policy_failed")])
    add("tool name", P, [("/tool/name", "sv0cov-fork")])
    add("tool version with a space", P, [("/tool/version", "0.1 0")])
    add("tool version non-ASCII", P, [("/tool/version", "0.1.é")])
    add("tool version empty", P, [("/tool/version", "")])
    add("tool version too long", B, [("/tool/version", "~" * 129)])
    add("tool registry digest uppercase", P, [("/tool/diagnostic_registry_sha256", "A" * 64)])
    add("tool registry revision zero", P, [("/tool/diagnostic_registry_revision", 0)])

    # Metrics.
    for name in METRICS:
        add(f"project {name} metric missing", P, [(f"/summary/{name}", None)])
    add("covered above total", P, [("/summary/region", {"covered": 4, "partial": None, "ratio": "1.000000", "total": 3})])
    add("partial on a non-line metric", P, [("/summary/region/partial", 0)])
    add("line metric without partial", P, [("/summary/line/partial", None)])
    add("covered plus partial above total", P, [("/summary/line/partial", 1)])
    add("ratio as a number", P, [("/summary/region/ratio", 1)])
    add("ratio with five digits", P, [("/summary/region/ratio", "1.00000")])
    add("ratio with seven digits", P, [("/summary/region/ratio", "1.0000000")])
    add("ratio above one", P, [("/summary/region/ratio", "1.000001")])
    add("ratio in percent", P, [("/summary/region/ratio", "100.0000")])
    add("ratio with exponent", P, [("/summary/region/ratio", "1.0000e0")])
    add("ratio wrong for the counts", P, [("/summary/branch/ratio", "0.500000")])
    add("ratio rounded half up, not to even", P, [("/summary/region", {"covered": 1, "partial": None, "ratio": "0.000001", "total": 2000000})])
    add("ratio truncated, not rounded", P, [("/summary/region", {"covered": 2, "partial": None, "ratio": "0.666666", "total": 3})])
    add("ratio present for a zero total", P, [("/summary/contract/ratio", "0.000000")])
    add("ratio absent for a nonzero total", P, [("/summary/region/ratio", None)])
    add("negative covered", P, [("/summary/region/covered", -1)])
    add("source summary metric missing", P, [(f"{src}/summary/contract", None)])
    add("function entity without a region metric", P, [("/entities/0/summary/region", None)])
    add("contract entity with a line metric", A, [("/entities/1/summary/line", {"covered": 0, "partial": 0, "ratio": None, "total": 0})])
    add("contract entity without its contract metric", A, [("/entities/1/summary/contract", None)])
    add("entity summary ratio wrong", P, [("/entities/0/summary/function/ratio", "0.000000")])

    # Sources and maps.
    add("current source with another digest", P, [(f"{src}/observed_digest", d("other"))])
    add("current source without an observed digest", P, [(f"{src}/observed_digest", None)])
    add("mismatch with equal digests", A, [(f"{src}/observed_digest", ix.all_kinds()["semantic"]["sources"][0]["digest"])])
    add("mismatch without an observed digest", A, [(f"{src}/observed_digest", None)])
    add("unavailable with an observed digest", A, [("/sources/1/observed_digest", d("x"))])
    add("observed digest not hex", P, [(f"{src}/observed_digest", "g" * 64)])
    add("source state unknown", P, [(f"{src}/source_state", "stale")])
    add("source accuracy current with a stale source", A, [(f"{prov}/source_accuracy", "current")])
    add("source accuracy mismatch with current sources", P, [(f"{prov}/source_accuracy", "mismatch_allowed"),
                                                           ("/evidence_eligibility", "diagnostic_only")])
    add("source path absolute", P, [(f"{src}/path", "/etc/passwd")])
    add("source path with parent component", P, [(f"{src}/path", "../main.sv0")])
    add("map with bindings", P, [("/maps/0/bindings", [])])
    add("map id uppercase", P, [("/maps/0/map_id", "F" * 64)])
    add("map compiler identity with a space", P, [("/maps/0/compiler_identity", "sv0c 0.1.0")])
    add("map target name with LF", P, [("/maps/0/target/name", "ma\nin")])
    add("map target kind", P, [("/maps/0/target/kind", "library")])
    add("map source indices unsorted", A, [("/maps/0/source_indices", [1, 0])])
    add("map source indices repeated", A, [("/maps/0/source_indices", [0, 0])])

    # Shared records keep their indexed rules inside a report.
    add("point id not hex", P, [("/points/0/point_id", "z" * 64)])
    add("point count flags disagree", P, [("/points/0/count/saturated", True)])
    add("region with a zero coefficient", P, [("/regions/0/counter_expression/terms/0/coefficient", 0)])
    add("outcome ordinal not its position", P, [("/branches/0/outcomes/1/ordinal", 5)])
    add("covered outcome with a zero count", P, [("/branches/0/outcomes/0/count", ix.ZERO)])
    add("contract result contradicts its counts", A, [("/contracts/0/runtime_result", "not_evaluated")])
    add("exclusion reason empty", A, [("/exclusions/0/reason", "")])
    add("context longer than 256 bytes", B, [("/contexts/0/value", "c" * 257)])
    add("saturation any without an affected record", P, [("/saturation/any", True)])
    add("accepted input with a diagnostic", P, [("/inputs/0/diagnostics", ["COV2011"])])
    add("accepted input without a run", P, [("/inputs/0/run_id", None)])
    add("input run id all zero", P, [("/inputs/0/run_id", "0" * 32)])
    add("input profile id uppercase", P, [("/inputs/0/profile_id", "A" * 32)])
    add("input name with a slash", P, [("/inputs/0/name", "a/b.sv0profraw")])
    add("line status unknown", P, [("/lines/0/status", "hit")])
    add("line region indices unsorted", A, [("/lines/0/region_indices", [3, 1])])

    # Regions and exclusions: the report-only fields.
    add("region point_ids missing a term's point", P, [("/regions/2/point_ids/0",)])
    add("region point_ids with an extra point", P, [("/regions/0/point_ids/-", "f" * 64)])
    add("region point_ids unsorted", P, [("/regions/2/point_ids", list(reversed(sorted([d("ok entry"), d("ok true")]))))])
    add("region point_ids absent", P, [("/regions/0/point_ids",)])
    add("exclusion line indices unsorted", A, [("/exclusions/1/affected/line_indices", [2, 1])])
    add("exclusion line indices repeated", A, [("/exclusions/1/affected/line_indices", [1, 1])])
    add("exclusion without line indices", A, [("/exclusions/0/affected/line_indices",)])
    add("exclusion line index at the reserved value", A, [("/exclusions/0/affected/line_indices", [U32])])

    # Policy.
    add("no integrity evaluation", P, [(f"{ev}/0",)])
    add("two integrity evaluations", P, [(f"{ev}/-", integrity())])
    add("integrity with another name", P, [(f"{ev}/0/assertion_name", "evidence")])
    add("integrity with a metric", P, [(f"{ev}/0/metric", "line")])
    add("integrity with a comparison", P, [(f"{ev}/0/comparison", "at_least"), (f"{ev}/0/limit", f(1, 1)), (f"{ev}/0/threshold_source", "integrity")])
    add("integrity with members", P, [(f"{ev}/0/members/source_indices", [0])])
    add("evidence metric outside integrity", P, [(f"{ev}/1/metric", "evidence")])
    add("exclusion_records outside an exclusion evaluation", P, [(f"{ev}/1/metric", "exclusion_records")])
    add("diff on the function metric", A, [(f"{ev}/0/metric", "function")])
    add("diff on the contract metric", A, [(f"{ev}/0/metric", "contract")])
    add("project evaluation with another name", P, [(f"{ev}/1/assertion_name", "everything")])
    add("diff evaluation with another name", A, [(f"{ev}/0/assertion_name", "changed")])
    add("exclusion evaluation with another name", A, [(f"{ev}/6/assertion_name", "exclusion")])
    add("ratchet evaluation with another name", A, [(f"{ev}/12/assertion_name", "baseline")])
    add("assertion name with a space", A, [(f"{ev}/14/assertion_name", "co re")])
    add("assertion name starting with a dash", A, [(f"{ev}/14/assertion_name", "-core")])
    add("assertion name non-ASCII", A, [(f"{ev}/14/assertion_name", "cöre")])
    add("assertion name too long", B, [(f"{ev}/1/assertion_name", "n" * 129)])
    add("assertion kind unknown", P, [(f"{ev}/1/assertion_kind", "module")])
    add("pass with a diagnostic", P, [(f"{ev}/1/diagnostics", ["COV4101"])])
    add("not_applicable with a diagnostic", A, [(f"{ev}/0/diagnostics", ["COV4102"])])
    add("fail without a diagnostic", A, [(f"{ev}/1/diagnostics", [])])
    add("ineligible without a diagnostic", A, [(f"{ev}/9/diagnostics", [])])
    add("evaluation diagnostics unsorted", A, [(f"{ev}/14/diagnostics", ["COV4102", "COV4101"])])
    add("evaluation diagnostic not a code", A, [(f"{ev}/1/diagnostics", ["E4101"])])
    add("comparison without a limit", P, [(f"{ev}/1/limit", None)])
    add("limit without a comparison", A, [(f"{ev}/15/limit", f(1, 1))])
    add("comparison without a threshold source", P, [(f"{ev}/1/threshold_source", None)])
    add("threshold source without a comparison", A, [(f"{ev}/15/threshold_source", "assertion")])
    add("a zero-denominator decision has no observation", P, [(f"{ev}/1/actual", None)], "valid")
    add("comparison unknown", P, [(f"{ev}/1/comparison", "greater")])
    add("result unknown", P, [(f"{ev}/1/result", "ok")])
    add("metric unknown", P, [(f"{ev}/1/metric", "statement")])
    add("threshold source unknown", P, [(f"{ev}/1/threshold_source", "cli")])
    add("fraction with a negative numerator", P, [(f"{ev}/1/actual/numerator", -1)])
    add("fraction as a ratio string", P, [(f"{ev}/1/actual", "1.000000")])
    add("fraction with a third field", P, [(f"{ev}/1/actual/ratio", "1.000000")])
    add("members unsorted", P, [(f"{ev}/2/members/line_indices", [0, 2, 1])])
    add("members repeated", P, [(f"{ev}/2/members/line_indices", [0, 0, 1])])
    add("members at the reserved index", P, [(f"{ev}/2/members/line_indices", [U32])])
    add("members without source_indices", P, [(f"{ev}/1/members/source_indices",)])
    add("policy passed with a failing evaluation", A, [("/policy/passed", True)])
    add("policy passed with an ineligible integrity", E, [("/policy/passed", True)])
    add("policy passed as a string", P, [("/policy/passed", "true")])

    # Provenance.
    add("manifest digest without manifest selection", P, [(f"{prov}/run_manifest_sha256", d("m"))])
    add("manifest selection without a digest", P, [(f"{prov}/run_selection", "manifest")])
    add("manifest digest not hex", B, [(f"{prov}/run_manifest_sha256", "m" * 64)])
    add("run selection none with a run", P, [(f"{prov}/run_selection", "none")])
    add("run selection unknown", P, [(f"{prov}/run_selection", "all")])
    add("run id all zero", P, [(f"{prov}/run_ids", ["0" * 32])])
    add("run id too short", P, [(f"{prov}/run_ids", ["a" * 31])])
    add("run ids unsorted", A, [(f"{prov}/run_ids", list(reversed(ix.all_kinds()["run_selection"]["selected_run_ids"])))])
    add("map ids repeated", P, [(f"{prov}/map_ids", [d("map ok"), d("map ok")])])
    add("backends unsorted", A, [(f"{prov}/backends", ["vm-v1", "native", "vm-v2"])])
    add("backends repeated", P, [(f"{prov}/backends", ["native", "native"])])
    add("backend unknown", P, [(f"{prov}/backends", ["jit"])])
    add("indexed input digest uppercase", P, [(f"{prov}/indexed_input_sha256", "B" * 64)])
    add("projection digest too short", P, [(f"{prov}/semantic_projection_sha256", "a" * 63)])
    add("indexed registry digest not hex", P, [(f"{prov}/indexed_diagnostic_registry_sha256", "-" * 64)])
    add("indexed registry revision zero", P, [(f"{prov}/indexed_diagnostic_registry_revision", 0)])
    add("passed with a nonzero exit code", P, [(f"{prov}/execution_exit_code", 1)])
    add("passed without an exit code", P, [(f"{prov}/execution_exit_code", None)])
    add("passed with a signal", P, [(f"{prov}/execution_signal", 9)])
    add("failed with exit code zero", A, [(f"{prov}/execution_exit_code", 0)])
    add("failed with exit code 256", A, [(f"{prov}/execution_exit_code", 256)])
    add("signal zero", P, [(f"{prov}/execution_status", "signaled"), (f"{prov}/execution_exit_code", None), (f"{prov}/execution_signal", 0)])
    add("signal 128", P, [(f"{prov}/execution_status", "signaled"), (f"{prov}/execution_exit_code", None), (f"{prov}/execution_signal", 128)])
    add("not applicable with an exit code", E, [(f"{prov}/execution_exit_code", 0)])
    add("execution status unknown", P, [(f"{prov}/execution_status", "killed")])
    add("source accuracy unknown", P, [(f"{prov}/source_accuracy", "stale")])
    add("provenance with a hostname", P, [(f"{prov}/hostname", "build-7")])
    add("provenance with a timestamp", P, [(f"{prov}/generated_at", 1700000000)])

    # Resolved configuration.
    c = f"{cfg}/coverage"
    add("configuration schema name", P, [(f"{cfg}/schema", "sv0cov.config")])
    add("configuration version", P, [(f"{cfg}/version", "1.1")])
    add("configuration schema declaration 1.1", P, [(f"{c}/schema/value", "1.1")])
    add("configuration schema declaration from the command line", P, [(f"{c}/schema/source", "cli")])
    add("leaf without a source", P, [(f"{c}/empty/source",)])
    add("leaf with a bare value", P, [(f"{c}/empty", "fail")])
    add("leaf source environment", P, [(f"{c}/empty/source", "env")])
    add("leaf with provenance on a table", P, [(f"{c}/integrity", {"source": "default", "value": {"saturation": "fail"}})])
    add("unknown configuration key", P, [(f"{c}/parallel", {"source": "default", "value": 1})])
    add("missing configuration key", P, [(f"{c}/reproducible_epoch",)])
    add("threshold in percent, not basis points", P, [(f"{c}/thresholds/line/value", 10001)])
    add("threshold in TOML spelling", P, [(f"{c}/thresholds/branch/value", "7500bp")])
    add("threshold negative", P, [(f"{c}/thresholds/line/value", -1)])
    add("empty policy unknown", P, [(f"{c}/empty/value", "warn")])
    add("reports empty", P, [(f"{c}/reports/value", [])])
    add("reports repeated", A, [(f"{c}/reports/value", ["json", "json"])])
    add("report format unknown", P, [(f"{c}/reports/value", ["pdf"])])
    add("output dir absolute", P, [(f"{c}/output_dir/value", "/var/cov")])
    add("output dir with a parent component", P, [(f"{c}/output_dir/value", "../cov")])
    add("output dir null", P, [(f"{c}/output_dir/value", None)])
    add("null value from the file", P, [(f"{c}/context/source", "sv0.toml")])
    add("null threshold from the command line", P, [(f"{c}/thresholds/region/source", "cli")])
    add("context longer than 4096", A, [(f"{c}/context/value", "c" * 4097), (f"{c}/context/source", "sv0.toml")])
    add("epoch above i63", B, [(f"{c}/reproducible_epoch/value", I63 + 1)])
    add("saturation policy differs from the report", A, [(f"{c}/integrity/saturation/value", "fail")])
    add("saturation policy unknown", P, [(f"{c}/integrity/saturation/value", "warn")])
    add("standard tier with a counter ceiling", P, [(f"{c}/limits/raw_profile/max_counters", {"source": "cli", "value": 5})])
    add("custom tier without a byte ceiling", A, [(f"{c}/limits/raw_profile/max_bytes", {"source": "default", "value": None})])
    add("max_counters zero", A, [(f"{c}/limits/raw_profile/max_counters/value", 0)])
    add("tier unknown", P, [(f"{c}/limits/raw_profile/tier/value", "huge")])
    add("diff without a base", A, [(f"{c}/diff/base", {"source": "default", "value": None})])
    add("diff without a threshold", A, [(f"{c}/diff/{m}", {"source": "default", "value": None}) for m in ("branch", "line", "region")])
    add("diff with a function threshold", A, [(f"{c}/diff/function", {"source": "sv0.toml", "value": 100})])
    add("diff as an empty object", P, [(f"{c}/diff", {})])
    add("ratchet without metrics", A, [(f"{c}/ratchet/metrics", {"source": "default", "value": None})])
    add("ratchet without a baseline", A, [(f"{c}/ratchet/baseline", {"source": "default", "value": None})])
    add("ratchet metrics unsorted", A, [(f"{c}/ratchet/metrics/value", ["line", "branch"])])
    add("ratchet metrics empty", A, [(f"{c}/ratchet/metrics/value", [])])
    add("ratchet baseline absolute", A, [(f"{c}/ratchet/baseline/value", "/b.json")])
    add("ratchet tolerance above 10000", A, [(f"{c}/ratchet/tolerance_basis_points/value", 10001)])
    add("scopes unsorted", A, [(f"{c}/scopes/-", {**all_kinds()["resolved_configuration"]["coverage"]["scopes"][0],
                                                   "name": {"source": "sv0.toml", "value": "a-first"}})])
    add("scope names repeated", A, [(f"{c}/scopes/-", all_kinds()["resolved_configuration"]["coverage"]["scopes"][0])])
    add("scope name with a space", A, [(f"{c}/scopes/0/name/value", "co re")])
    add("scope name from the command line", A, [(f"{c}/scopes/0/name/source", "cli")])
    add("scope name as a default", A, [(f"{c}/scopes/0/name/source", "default")])
    add("scope without a selector", A, [(f"{c}/scopes/0/{k}", {"source": "default", "value": None}) for k in ("include", "packages", "sources")])
    add("scope include empty", A, [(f"{c}/scopes/0/include/value", [])])
    add("scope packages unsorted", A, [(f"{c}/scopes/0/packages/value", ["b", "a"])])
    add("scope sources repeated", A, [(f"{c}/scopes/0/sources/value", ["src/app.sv0", "src/app.sv0"])])
    add("scope missing a metric field", A, [(f"{c}/scopes/0/contract",)])
    add("entities unsorted", A, [(f"{c}/entities/0/name/value", "zz-last")])
    add("entity kind unknown", A, [(f"{c}/entities/0/kind/value", "module")])
    add("contract entity with a line threshold", A, [(f"{c}/entities/0/line", {"source": "sv0.toml", "value": 9000})])
    add("entity without a qualified name", A, [(f"{c}/entities/0/qualified_name/value", None)])
    add("exclusion cap from the command line", A, [(f"{c}/exclusions/max_records/source", "cli")])
    add("exclusion cap above 10000", A, [(f"{c}/exclusions/line_basis_points/value", 10001)])
    add("forbidden reasons unsorted", A, [(f"{c}/exclusions/forbidden_reasons/value", ["todo", "later"])])
    add("forbidden reason as a default", A, [(f"{c}/exclusions/forbidden_reasons/source", "default")])
    add("report control true by default", P, [(f"{cfg}/report/allow_source_mismatch/value", True)])
    add("report control false from the command line", P, [(f"{cfg}/report/allow_source_mismatch/source", "cli")])
    add("report control from the file", A, [(f"{cfg}/report/allow_lossy_saturated_export/source", "sv0.toml")])
    add("report control missing", P, [(f"{cfg}/report/allow_lossy_saturated_export",)])
    add("transport in the configuration", P, [(f"{cfg}/report/output", {"source": "cli", "value": "-"})])
    return out


def documents() -> dict[str, dict]:
    return {"empty": empty(), "passing": passing(), "all-kinds": all_kinds(), "bounds": bounds()}


def artifacts() -> dict[Path, bytes]:
    out = {HERE / f"{name}.json": encode(doc) for name, doc in documents().items()}
    out[HERE / "mutations.json"] = encode({"mutations": mutations(), "schema": "sv0cov.report-structure-mutations", "version": "1.0"})
    return out


def apply(doc: dict, entry: dict) -> dict:
    """One mutation applied to a copy of its base document."""
    return ix.apply(doc, {**entry, "rehash": False})


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print("stale report fixture artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("report fixtures: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
