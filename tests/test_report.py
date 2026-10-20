# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The native report producer and its cross-validating reader (CV-229; SPEC
11, 21.3, 22.1, 22.2.1; COV-REP-003, COV-REP-018..021, AC-105).

A report built from indexed evidence reads back; it loses nothing the
evidence holds; its summaries equal an independent count; thresholds are
decided on exact integers; stale sources, saturation and incomplete
evidence can never look like passing evidence; and a single changed field
is rejected unless nothing in the report could contradict it.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES, RUN_A, U64, fixture_inputs, raw, rich_inputs, simple  # noqa: E402
from test_semantic_model import TINY, tiny  # noqa: E402

from sv0cov import diagnostics  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import CanonicalJsonError, encode  # noqa: E402
from sv0cov.formats.indexed import IndexedError  # noqa: E402
from sv0cov.formats.report import ReportError, check_report_structure  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.merge import Artifact, merge  # noqa: E402
from sv0cov.model.report import build_report, read_report  # noqa: E402

V = "0.0.0-test"
HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
REPORT = [("--format", "json")]
STALE_OK = [*REPORT, ("--allow-source-mismatch", None)]


def config(options=REPORT, toml: str = ""):
    return resolve("report", options, (HEAD + toml).encode() if toml else None)


def thresholds(**values) -> str:
    return "[tool.sv0cov.thresholds]\n" + "".join(f"{k} = {v!r}\n".replace("'", '"') for k, v in values.items())


def fixture_sources(name: str, ix: dict) -> dict[str, bytes]:
    by_digest = {hashlib.sha256(p.read_bytes()).hexdigest(): p.read_bytes() for p in (SEMANTIC / name).rglob("*.sv0")}
    return {s["path"]: by_digest[s["digest"]] for s in ix["semantic"]["sources"]}


def fixture_report(name: str, cfg=None, **kw) -> tuple[dict, dict]:
    ix = simple(name)
    return build_report(encode(ix), cfg or config(), fixture_sources(name, ix), tool_version=V, **kw), ix


def code_of(fn, *args, **kw) -> str:
    try:
        fn(*args, **kw)
    except ReportError as exc:
        return exc.code
    return "valid"


def evaluation(report: dict, metric: str, kind: str = "project") -> dict:
    (e,) = [e for e in report["policy"]["evaluations"] if e["assertion_kind"] == kind and e["metric"] == metric]
    return e


# An independent count of the five metrics, written without the producer's helpers.
def oracle(report: dict, source: int | None = None) -> dict[str, tuple]:
    def here(rec: dict) -> bool:
        return source is None or rec["source_index"] == source

    regions = [r for r in report["regions"] if r["classification"] == "user" and here(r)]
    lines = [ln for ln in report["lines"] if ln["status"] in ("covered", "partial", "uncovered") and here(ln)]
    outcomes = [o for b in report["branches"] if here(b) for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
    entry = {p["entity_index"]: p for p in report["points"] if p["kind"] == "function_entry"}
    functions = [e for e in report["entities"] if e["kind"] == "function" and here(e) and entry[e["entity_index"]]["classification"] == "user"]
    off = {i for x in report["exclusions"] for i in x["affected"]["clause_indices"]}
    clauses = [c for c in report["contracts"] if c["enforcement"] == "runtime_checked" and c["clause_index"] not in off and here(c)]
    return {
        "region": (len([r for r in regions if r["count"]["value"]]), len(regions), None),
        "line": (len([x for x in lines if x["status"] == "covered"]), len(lines), len([x for x in lines if x["status"] == "partial"])),
        "branch": (len([o for o in outcomes if o["count"]["value"]]), len(outcomes), None),
        "function": (len([e for e in functions if entry[e["entity_index"]]["count"]["value"]]), len(functions), None),
        "contract": (len([c for c in clauses if c["count_true"]["value"] or c["count_false"]["value"]]), len(clauses), None),
    }


def as_tuples(summary: dict) -> dict[str, tuple]:
    return {k: (m["covered"], m["total"], m["partial"]) for k, m in summary.items() if m is not None}


class RoundTripTest(unittest.TestCase):
    def test_every_fixture_builds_reads_back_and_passes(self) -> None:
        self.assertEqual(len(FIXTURES), 9)
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, ix = fixture_report(name)
                data = encode(report)
                self.assertEqual(read_report(data), report)
                self.assertEqual(len(report), 23)
                self.assertEqual((report["complete"], report["evidence_eligibility"], report["policy"]["passed"]), (True, "passing", True))
                self.assertEqual(report["policy"]["evaluations"], [evaluation(report, "evidence", "integrity")])
                self.assertEqual(evaluation(report, "evidence", "integrity")["result"], "pass")
                self.assertEqual({s["source_state"] for s in report["sources"]}, {"current"})
                self.assertEqual(report["resolved_configuration"], config().document())
                # The same inputs give the same bytes.
                again, _ = fixture_report(name)
                self.assertEqual(encode(again), data)
                self.assertNotIn(str(ROOT).encode(), data)

    def test_nothing_the_evidence_holds_is_lost(self) -> None:
        """COV-REP-003, COV-REP-021."""
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        report = build_report(encode(ix), config(STALE_OK), {}, tool_version=V)
        sem = ix["semantic"]
        for key in ("branches", "contexts", "contracts", "lines", "points"):
            self.assertEqual(report[key], sem[key], key)
        strip = {"regions": ("point_ids",), "entities": ("summary",), "sources": ("summary", "observed_digest", "source_state")}
        for key, extra in strip.items():
            self.assertEqual([{k: v for k, v in rec.items() if k not in extra} for rec in report[key]], sem[key], key)
        self.assertEqual([{**x, "affected": {k: v for k, v in x["affected"].items() if k != "line_indices"}} for x in report["exclusions"]],
                         sem["exclusions"])
        self.assertEqual(report["inputs"], ix["profile_inputs"])
        self.assertEqual(report["maps"], [{k: v for k, v in m.items() if k != "bindings"} for m in ix["maps"]])
        self.assertEqual({k: report["saturation"][k] for k in ("affected_point_ids", "affected_region_indices", "any", "policy")},
                         {k: sem["saturation"][k] for k in ("affected_point_ids", "affected_region_indices", "any", "policy")})
        prov = report["provenance"]
        self.assertEqual((prov["indexed_input_sha256"], prov["semantic_projection_sha256"], prov["map_ids"], prov["run_ids"],
                          prov["run_selection"], prov["backends"]),
                         (hashlib.sha256(encode(ix)).hexdigest(), ix["semantic_projection_sha256"], sem["map_ids"],
                          ix["run_selection"]["selected_run_ids"], "explicit-list", ["native", "vm-v1", "vm-v2"]))
        self.assertEqual((prov["execution_status"], prov["indexed_diagnostic_registry_sha256"]),
                         ("not_applicable", diagnostics.load_registry().sha256))
        for region in report["regions"]:
            self.assertEqual(region["point_ids"], sorted({t["point_id"] for t in region["counter_expression"]["terms"]}))
        self.assertTrue(any(t["coefficient"] < 0 for r in report["regions"] for t in r["counter_expression"]["terms"]))
        read_report(encode(report))

    def test_invalid_evidence_is_refused(self) -> None:
        ix = simple("f0")
        ix["semantic"]["lines"][0]["status"] = "uncovered" if ix["semantic"]["lines"][0]["status"] == "covered" else "covered"
        with self.assertRaises(IndexedError):
            build_report(encode(ix), config(), {})
        with self.assertRaises(IndexedError):
            build_report(b"{}\n", config(), {})


class SummaryTest(unittest.TestCase):
    """SPEC 11.2-11.5, 22.2.1; COV-REP-019."""

    def test_summaries_equal_an_independent_count(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, _ = fixture_report(name)
                self.assertEqual(as_tuples(report["summary"]), oracle(report))
                for s in report["sources"]:
                    self.assertEqual(as_tuples(s["summary"]), oracle(report, s["source_index"]))
                # The project is the sum of its sources.
                for metric in ("branch", "contract", "function", "line", "region"):
                    self.assertEqual(sum(s["summary"][metric]["total"] for s in report["sources"]), report["summary"][metric]["total"])

    def test_known_fixture_numbers(self) -> None:
        """Hand-checked against the fixture programs."""
        functions, _ = fixture_report("functions")
        self.assertEqual(as_tuples(functions["summary"])["function"], (4, 5, None))  # one function is never called
        project, _ = fixture_report("project")
        self.assertEqual([as_tuples(s["summary"])["function"] for s in project["sources"]], [(1, 1, None)] * 3)
        match, _ = fixture_report("match")
        line = match["summary"]["line"]
        self.assertEqual((line["covered"] + line["partial"] <= line["total"], line["ratio"]), (True, "0.866667"))
        self.assertEqual(match["summary"]["contract"], {"covered": 0, "partial": None, "ratio": None, "total": 0})

    def test_function_entities_count_only_what_they_own(self) -> None:
        for name in ("branches", "loops", "question", "f0"):
            report, _ = fixture_report(name)
            for e in report["entities"]:
                with self.subTest(fixture=name, entity=e["qualified_name"]):
                    n, s = e["entity_index"], e["summary"]
                    owned = [r for r in report["regions"] if r["entity_index"] == n and r["classification"] == "user"]
                    self.assertEqual((s["region"]["covered"], s["region"]["total"]), (len([r for r in owned if r["count"]["value"]]), len(owned)))
                    outs = [o for b in report["branches"] if b["entity_index"] == n for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
                    self.assertEqual((s["branch"]["covered"], s["branch"]["total"]), (len([o for o in outs if o["status"] == "covered"]), len(outs)))
                    self.assertEqual(s["function"]["total"], 1)
                    lines = {(r["source_index"], ln) for r in owned if r["line_contributing"] for ln in r["line_numbers"]}
                    self.assertEqual(s["line"]["total"], len(lines))
            # Every region and outcome belongs to exactly one function here, so the entities add up to the project.
            for metric in ("region", "branch", "function"):
                self.assertEqual(sum(e["summary"][metric]["total"] for e in report["entities"]), report["summary"][metric]["total"])

    def test_contracts_exclusions_and_synthetic_points(self) -> None:
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        report = build_report(encode(ix), config(STALE_OK), {}, tool_version=V)
        self.assertEqual(as_tuples(report["summary"]), oracle(report))
        kinds = {e["kind"] for e in report["entities"]}
        self.assertEqual(kinds, {"function", "contract"})
        for e in report["entities"]:
            if e["kind"] == "contract":
                self.assertEqual([k for k, m in e["summary"].items() if m is not None], ["contract"])
                clause = next(c for c in report["contracts"] if c["entity_index"] == e["entity_index"])
                eligible = clause["enforcement"] == "runtime_checked" and not any(
                    clause["clause_index"] in x["affected"]["clause_indices"] for x in report["exclusions"])
                self.assertEqual(e["summary"]["contract"]["total"], int(eligible))
            else:
                self.assertEqual(sorted(k for k, m in e["summary"].items() if m is not None), ["branch", "contract", "function", "line", "region"])
        # A clause counts once however often it ran, and a false outcome counts as reached.
        runtime = [c for c in report["contracts"] if c["enforcement"] == "runtime_checked"]
        self.assertTrue(any(c["count_true"]["value"] > 1 for c in runtime))
        self.assertLessEqual(report["summary"]["contract"]["covered"], len(runtime))
        # Synthetic support points and excluded regions are outside every denominator.
        self.assertTrue(any(p["classification"] == "synthetic_support" for p in report["points"]))
        self.assertEqual(report["summary"]["region"]["total"], len([r for r in report["regions"] if r["classification"] == "user"]))
        self.assertTrue(any(r["classification"] != "user" for r in report["regions"]))
        for x in report["exclusions"]:
            self.assertEqual(x["affected"]["line_indices"], sorted(set(x["affected"]["line_indices"])))


class ContractMetricTest(unittest.TestCase):
    """SPEC 12, 22.2.1; COV-MET-015. The counting rules on the CV-228 fixture, whose seven clauses have every
    disposition: mixed, true only, never evaluated, false only, statically verified, disabled, unsupported."""

    def setUp(self) -> None:
        from sv0cov.model.report import _Detail
        self.detail = _Detail
        self.doc = json.loads((ROOT / "tests" / "fixtures" / "report" / "all-kinds.json").read_bytes())

    def metric(self, covered: int, total: int) -> dict:
        ratios = {(3, 4): "0.750000", (2, 3): "0.666667", (1, 1): "1.000000", (0, 1): "0.000000", (0, 0): None}
        return {"covered": covered, "partial": None, "ratio": ratios[(covered, total)], "total": total}

    def test_only_runtime_checked_clauses_count_and_either_outcome_reaches_one(self) -> None:
        d = self.detail(self.doc)
        self.assertEqual([c["enforcement"] for c in self.doc["contracts"]],
                         ["runtime_checked"] * 4 + ["statically_verified", "disabled", "unsupported"])
        self.assertEqual([c["runtime_result"] for c in self.doc["contracts"]][:4], ["mixed", "evaluated_true", "not_evaluated", "evaluated_false"])
        self.assertEqual(d.group()["contract"], self.metric(3, 4))  # a clause that only ever failed is still reached
        self.assertEqual(d.members("contract"), [0, 1, 2, 3])
        by_entity = {e["entity_index"]: d.entity(e) for e in self.doc["entities"]}
        self.assertEqual(by_entity[0]["contract"], self.metric(3, 4))  # the function owns its four runtime clauses
        self.assertEqual([by_entity[n]["contract"] for n in (1, 2, 3, 4)],
                         [self.metric(1, 1), self.metric(1, 1), self.metric(0, 1), self.metric(1, 1)])
        self.assertEqual([by_entity[n]["contract"] for n in (5, 6, 7, 8)], [self.metric(0, 0)] * 4)
        for n in range(1, 8):
            self.assertEqual([k for k, m in by_entity[n].items() if m is not None], ["contract"])
        # A clause with no enclosing function is in the project but in no function entity.
        self.assertIsNone(self.doc["contracts"][6]["function_entity_index"])

    def test_an_excluded_runtime_clause_leaves_the_denominator(self) -> None:
        self.doc["exclusions"][2]["affected"]["clause_indices"] = [3]
        d = self.detail(self.doc)
        self.assertEqual((d.group()["contract"], d.members("contract")), (self.metric(2, 3), [0, 1, 2]))
        self.assertEqual(d.entity(self.doc["entities"][4])["contract"], self.metric(0, 0))
        self.assertEqual(d.entity(self.doc["entities"][0])["contract"], self.metric(2, 3))


class ThresholdTest(unittest.TestCase):
    """SPEC 22.1, 11.6; COV-MET-012, COV-POL-001."""

    def test_the_boundary_is_decided_on_integers(self) -> None:
        base, _ = fixture_report("f0")
        line = base["summary"]["line"]
        self.assertEqual((line["covered"], line["total"]), (14, 16))  # 87.5 %
        for value, passes in ((87, True), ("8750bp", True), ("8751bp", False), (88, False), (0, True), (100, False)):
            with self.subTest(threshold=value):
                report, _ = fixture_report("f0", config(toml=thresholds(line=value)))
                e = evaluation(report, "line")
                bp = value * 100 if isinstance(value, int) else int(value[:-2])
                self.assertEqual((e["result"], e["diagnostics"], e["actual"], e["limit"], e["comparison"], e["threshold_source"]),
                                 ("pass" if passes else "fail", [] if passes else ["COV4101"], {"denominator": 16, "numerator": 14},
                                  {"denominator": 10000, "numerator": bp}, "at_least", "project"))
                self.assertEqual((report["policy"]["passed"], report["evidence_eligibility"]),
                                 (passes, "passing" if passes else "policy_failed"))
                self.assertEqual(e["members"]["line_indices"], [x["line_index"] for x in report["lines"] if x["status"] != "non_executable"])
                read_report(encode(report))

    def test_a_rounded_ratio_never_passes_a_threshold(self) -> None:
        """84 of 99 displays as 0.848485 and is below 85 %; the display of 0.85 would be wrong to use."""
        from sv0cov.model.report import _holds
        self.assertFalse(_holds("at_least", {"numerator": 84, "denominator": 99}, {"numerator": 8500, "denominator": 10000}))
        self.assertTrue(_holds("at_least", {"numerator": 85, "denominator": 100}, {"numerator": 8500, "denominator": 10000}))
        self.assertFalse(_holds("at_least", {"numerator": U64 - 1, "denominator": U64}, {"numerator": 10000, "denominator": 10000}))
        self.assertTrue(_holds("at_least", {"numerator": U64, "denominator": U64}, {"numerator": 10000, "denominator": 10000}))

    def test_every_metric_has_its_members(self) -> None:
        report, _ = fixture_report("branches", config(toml=thresholds(function=100, region=50, line=50, branch=50)))
        got = {e["metric"]: e for e in report["policy"]["evaluations"] if e["assertion_kind"] == "project"}
        self.assertEqual(sorted(got), ["branch", "function", "line", "region"])
        key = {"branch": "branch_indices", "function": "entity_indices", "line": "line_indices", "region": "region_indices"}
        for metric, e in got.items():
            used = {k: v for k, v in e["members"].items() if v}
            self.assertEqual(list(used), [key[metric]], metric)
            self.assertEqual(e["actual"], {"denominator": report["summary"][metric]["total"], "numerator": report["summary"][metric]["covered"]})
        self.assertEqual(len(got["branch"]["members"]["branch_indices"]), len(report["branches"]))
        self.assertEqual([e["assertion_kind"] for e in report["policy"]["evaluations"]], ["integrity"] + ["project"] * 4)
        read_report(encode(report))

    def test_a_zero_denominator_follows_the_empty_policy(self) -> None:
        for empty, result, codes, eligibility in (("fail", "fail", ["COV4102"], "policy_failed"), ("pass", "pass", [], "passing")):
            with self.subTest(empty=empty):
                report, _ = fixture_report("f0", config(toml=f'empty = "{empty}"\n' + thresholds(contract=100)))
                e = evaluation(report, "contract")
                self.assertEqual((e["result"], e["diagnostics"], e["actual"], e["members"]["clause_indices"]), (result, codes, None, []))
                self.assertEqual((report["summary"]["contract"]["ratio"], report["evidence_eligibility"]), (None, eligibility))
                read_report(encode(report))

    def test_assertions_this_build_cannot_evaluate_are_refused(self) -> None:
        ix = simple("f0")
        cases = {
            "ratchet": '[tool.sv0cov.ratchet]\nbaseline = "b.json"\nmetrics = ["line"]\n',
            "exclusion cap": "[tool.sv0cov.exclusions]\nmax_records = 0\n",
        }
        for label, toml in cases.items():
            with self.subTest(case=label):
                self.assertEqual(code_of(build_report, encode(ix), config(toml=toml), fixture_sources("f0", ix)), "COV5001")

    def test_a_failed_or_signalled_test_command_fails_integrity_whatever_the_coverage(self) -> None:
        """SPEC 21.3.5, 22.5; AC-022: the coverage result is still reported, separately."""
        for execution, passes in (({"exit_code": 0, "signal": None, "status": "passed"}, True),
                                  ({"exit_code": 3, "signal": None, "status": "failed"}, False),
                                  ({"exit_code": None, "signal": 9, "status": "signaled"}, False)):
            with self.subTest(execution=execution["status"]):
                ix = build_indexed(*self.inputs(), execution=execution, tool_version=V)
                report = build_report(encode(ix), config(toml=thresholds(line=87, branch=100)), fixture_sources("f0", ix), tool_version=V)
                integrity = evaluation(report, "evidence", "integrity")
                self.assertEqual((integrity["result"], integrity["diagnostics"]), ("pass", []) if passes else ("fail", ["COV2130"]))
                self.assertTrue(report["complete"])  # collection is complete either way
                self.assertEqual((evaluation(report, "line")["result"], evaluation(report, "branch")["result"]), ("pass", "fail"))
                self.assertEqual((report["policy"]["passed"], report["evidence_eligibility"]), (False, "policy_failed"))
                self.assertEqual(report["provenance"]["execution_status"], execution["status"])
                self.assertEqual(read_report(encode(report)), report)
                clean = build_report(encode(ix), config(), fixture_sources("f0", ix), tool_version=V)
                self.assertEqual((clean["policy"]["passed"], clean["evidence_eligibility"]),
                                 (True, "passing") if passes else (False, "policy_failed"))
                # The code and the execution status must agree in both directions.
                for mutate in (lambda o: evaluation(o, "evidence", "integrity").update(diagnostics=[] if not passes else ["COV2130"]),
                               lambda o: o["provenance"].update(execution_status="passed", execution_exit_code=0, execution_signal=None)
                               if not passes else o["provenance"].update(execution_status="failed", execution_exit_code=1)):
                    bad = copy.deepcopy(clean)
                    mutate(bad)
                    self.assertIn(code_of(read_report, encode(bad)), ("COV4001", "COV4002"))
        passed = build_indexed(*self.inputs(), execution={"exit_code": 0, "signal": None, "status": "passed"}, tool_version=V)
        report = build_report(encode(passed), config(), fixture_sources("f0", passed), tool_version=V)
        self.assertEqual((report["provenance"]["execution_status"], report["provenance"]["execution_exit_code"]), ("passed", 0))
        read_report(encode(report))

    def inputs(self):
        from test_indexed_reader import map_input, profile_input
        data, m, counts = fixture_inputs("f0")
        return [map_input("f0.sv0covmap.json", data)], [profile_input("p1.sv0profraw", raw(m, counts, 1), m)]


class IntegrityTest(unittest.TestCase):
    """SPEC 21.3.8; COV-POL-006..009."""

    def test_a_stale_or_missing_source_needs_the_override_and_is_never_passing(self) -> None:
        ix = simple("f0")
        good = fixture_sources("f0", ix)
        (path,) = good
        for label, sources, state in (("edited", {path: good[path] + b"\n"}, "mismatch"), ("missing", {}, "unavailable"),
                                      ("unreadable", {path: None}, "unavailable")):
            with self.subTest(case=label):
                self.assertEqual(code_of(build_report, encode(ix), config(toml=thresholds(line=1)), sources), "COV1004")
                report = build_report(encode(ix), config(STALE_OK, thresholds(line=1)), sources, tool_version=V)
                integrity = evaluation(report, "evidence", "integrity")
                self.assertEqual((report["sources"][0]["source_state"], report["provenance"]["source_accuracy"], integrity["result"],
                                  integrity["diagnostics"], report["policy"]["passed"], report["evidence_eligibility"], report["complete"]),
                                 (state, "mismatch_allowed", "ineligible", ["COV1004"], False, "diagnostic_only", True))
                self.assertEqual(evaluation(report, "line")["result"], "pass")  # the percentage cannot override it
                self.assertEqual(report["sources"][0]["observed_digest"], None if state == "unavailable"
                                 else hashlib.sha256(good[path] + b"\n").hexdigest())
                read_report(encode(report))
        # The override with current sources changes nothing but the recorded control.
        clean = build_report(encode(ix), config(STALE_OK), good, tool_version=V)
        self.assertEqual((clean["evidence_eligibility"], clean["resolved_configuration"]["report"]["allow_source_mismatch"]),
                         ("passing", {"source": "cli", "value": True}))

    def saturated(self, policy: str, *, contract: bool = False) -> bytes:
        maps, profiles, selection = rich_inputs()
        if contract:
            from test_indexed_reader import profile_input
            sm = maps[1].map
            pts = {(p["kind"], sm["entities"][p["entity_index"]]["qualified_name"]): p["point_id"] for p in sm["points"]
                   if p["entity_index"] is not None}
            div, t = pts[("function_entry", "div")], pts[("contract_true", "div#requires0")]
            profiles.append(profile_input("e.sv0profraw", raw(sm, {div: U64, t: U64}, 9, run=RUN_A), sm))
        return encode(build_indexed(maps, profiles, run_selection=selection, tool_version=V, saturation_policy=policy))

    def test_saturation_blocks_every_check_under_the_default_policy(self) -> None:
        cfg = config(STALE_OK, thresholds(function=1, region=1, line=1, branch=1, contract=1))
        report = build_report(self.saturated("fail"), cfg, {}, tool_version=V)
        self.assertTrue(report["saturation"]["any"])
        self.assertEqual({e["result"] for e in report["policy"]["evaluations"]}, {"ineligible"})
        self.assertEqual({tuple(e["diagnostics"]) for e in report["policy"]["evaluations"] if e["assertion_kind"] == "project"}, {("COV4020",)})
        self.assertIn("COV4020", evaluation(report, "evidence", "integrity")["diagnostics"])
        self.assertFalse(report["policy"]["passed"])
        read_report(encode(report))

    def test_allow_ordinary_lets_only_the_ordinary_metrics_through(self) -> None:
        toml = '[tool.sv0cov.integrity]\nsaturation = "allow-ordinary"\n' + thresholds(function=1, region=1, line=1, branch=1, contract=1)
        cfg = config(STALE_OK, toml)
        report = build_report(self.saturated("allow-ordinary", contract=True), cfg, {}, tool_version=V)
        results = {e["metric"]: e["result"] for e in report["policy"]["evaluations"]}
        self.assertEqual({k: results[k] for k in ("function", "region", "line", "branch")}, dict.fromkeys(("function", "region", "line", "branch"), "pass"))
        self.assertEqual((results["contract"], evaluation(report, "contract")["diagnostics"]), ("ineligible", ["COV4020"]))
        self.assertEqual(report["saturation"]["eligible_metrics"], ["branch", "function", "line", "region"])
        self.assertIn("contract_counts", report["saturation"]["ineligible_uses"])
        self.assertIn("context_exact_counts", report["saturation"]["ineligible_uses"])
        self.assertEqual(report["evidence_eligibility"], "diagnostic_only")
        read_report(encode(report))
        export = build_report(self.saturated("allow-ordinary"), cfg, {}, tool_version=V, standard_export=True)
        self.assertIn("standard_exports", export["saturation"]["ineligible_uses"])
        read_report(encode(export))
        lossy = build_report(self.saturated("allow-ordinary"), config([*STALE_OK, ("--allow-lossy-saturated-export", None)], toml), {},
                             tool_version=V, standard_export=True)
        self.assertIn("COV4021", evaluation(lossy, "evidence", "integrity")["diagnostics"])
        self.assertEqual(lossy["evidence_eligibility"], "diagnostic_only")
        read_report(encode(lossy))
        # The report must be configured as the evidence was merged.
        self.assertEqual(code_of(build_report, self.saturated("fail"), cfg, {}), "COV0013")
        self.assertEqual(code_of(build_report, self.saturated("allow-ordinary"), config(STALE_OK), {}), "COV0013")

    def test_incomplete_evidence_is_reported_as_incomplete(self) -> None:
        data, m, counts = fixture_inputs("f0")
        good, cut = raw(m, counts, 1), raw(m, counts, 2)[:-9]
        srcs = {s["path"]: next(p.read_bytes() for p in (SEMANTIC / "f0").rglob("*.sv0")) for s in m["sources"]}
        cases = {
            "a rejected input": (merge([Artifact("m", data)], [Artifact("a", good), Artifact("cut", cut)], allow_rejected_inputs=True, tool_version=V),
                                 ["COV3002"]),
            "the override alone": (merge([Artifact("m", data)], [Artifact("a", good)], allow_rejected_inputs=True, tool_version=V), ["COV3002"]),
            "two undeclared runs": (merge([Artifact("m", data)], [Artifact("a", good), Artifact("b", raw(m, counts, 3, run="f" * 32))],
                                          tool_version=V), ["COV3003"]),
            "no input": (merge([], [], tool_version=V), ["COV3001", "COV3003"]),
        }
        for label, (result, codes) in cases.items():
            with self.subTest(case=label):
                self.assertFalse(result.complete)
                report = build_report(result.data, config(toml=thresholds(line=1)), srcs if result.indexed["semantic"]["sources"] else {},
                                      tool_version=V)
                integrity = evaluation(report, "evidence", "integrity")
                self.assertEqual((report["complete"], report["evidence_eligibility"], integrity["result"], integrity["diagnostics"],
                                  report["policy"]["passed"]), (False, "incomplete", "fail", codes, False))
                self.assertEqual(read_report(encode(report)), report)
        rejected = read_report(encode(build_report(cases["a rejected input"][0].data, config(), srcs, tool_version=V)))
        self.assertEqual([x["status"] for x in rejected["inputs"]], ["accepted", "incomplete"])

    def test_two_versions_of_one_source_are_both_reported(self) -> None:
        a, pa = tiny(TINY, "one")
        b, pb = tiny(TINY + "/* edited */\n", "two")
        result = merge([Artifact("a.map", encode(a)), Artifact("b.map", encode(b))],
                       [Artifact("pa", raw(a, {pa.entry: 1, pa.true: 1}, 1)), Artifact("pb", raw(b, {pb.entry: 1, pb.false: 1}, 2))], tool_version=V)
        report = build_report(result.data, config(STALE_OK), {"main.sv0": TINY.encode()}, tool_version=V)
        self.assertEqual(sorted(s["source_state"] for s in report["sources"]), ["current", "mismatch"])
        self.assertEqual(evaluation(report, "evidence", "integrity")["diagnostics"], ["COV1004", "COV3004"])
        self.assertEqual(report["evidence_eligibility"], "incomplete")
        read_report(encode(report))


class ReaderTest(unittest.TestCase):
    """COV-REP-018, COV-REP-020: every redundant fact is recomputed."""

    @classmethod
    def setUpClass(cls) -> None:
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        toml = thresholds(line=50, contract=100)
        cls.rich = build_report(encode(ix), config(STALE_OK, toml), {}, tool_version=V)
        cls.clean, _ = fixture_report("branches", config(toml=thresholds(line=50, branch=90)))
        # A smaller report with the same variety, for the exhaustive single-field corpus.
        small = build_indexed(maps[1:], profiles[2:], tool_version=V)
        cls.small = build_report(encode(small), config(STALE_OK, toml), {}, tool_version=V)

    def verdict(self, obj: dict) -> str:
        try:
            read_report(encode(obj))
        except ReportError as exc:
            return exc.code
        return "valid"

    def test_named_disagreements(self) -> None:
        def change(base, fn):
            o = copy.deepcopy(base)
            fn(o)
            return o

        c, r = self.clean, self.rich
        cases = {
            "project summary": (c, lambda o: o["summary"]["region"].update(covered=o["summary"]["region"]["covered"] - 1, ratio="0.727273")),
            "source summary": (c, lambda o: o["sources"][0]["summary"]["function"].update(covered=3, ratio="0.750000")),
            "entity summary": (c, lambda o: o["entities"][0]["summary"]["region"].update(covered=0, ratio="0.000000")),
            "line status": (c, lambda o: o["lines"][0].update(status="partial")),
            "regions reordered": (c, lambda o: o["regions"].reverse()),
            "evaluations reordered": (c, lambda o: o["policy"]["evaluations"].reverse()),
            "inputs name another map": (c, lambda o: o["inputs"][0].update(map_id="a" * 64)),
            "provenance run ids": (c, lambda o: o["provenance"].update(run_ids=["a" * 32])),
            "provenance backends": (c, lambda o: o["provenance"].update(backends=["vm-v1"])),
            "provenance map ids": (c, lambda o: o["provenance"].update(map_ids=[])),
            "threshold result flipped": (c, lambda o: o["policy"]["evaluations"][2].update(result="fail", diagnostics=["COV4101"])),
            "threshold result flipped to pass": (c, lambda o: o["policy"]["evaluations"][1].update(result="pass", diagnostics=[])),
            "threshold limit changed": (c, lambda o: o["policy"]["evaluations"][2]["limit"].update(numerator=1)),
            "threshold member dropped": (c, lambda o: o["policy"]["evaluations"][2]["members"]["line_indices"].pop()),
            "threshold without evaluation": (c, lambda o: o["policy"]["evaluations"].pop(1)),
            "evaluation without threshold": (c, lambda o: o["resolved_configuration"]["coverage"]["thresholds"]["branch"].update(
                source="default", value=None)),
            "dangling member": (c, lambda o: o["policy"]["evaluations"][2]["members"]["line_indices"].append(10**6)),
            "eligibility overstated": (r, lambda o: o.update(evidence_eligibility="incomplete", complete=False)),
            "eligibility understated": (r, lambda o: o.update(evidence_eligibility="policy_failed")),
            "integrity hides the stale source": (r, lambda o: o["policy"]["evaluations"][0]["diagnostics"].remove("COV1004")),
            "integrity result": (r, lambda o: o["policy"]["evaluations"][0].update(result="fail")),
            "complete without a finding": (c, lambda o: (o.update(complete=False, evidence_eligibility="incomplete"))),
            "saturated point not inventoried": (r, lambda o: o["saturation"]["affected_point_ids"].pop()),
            "inexact region not inventoried": (r, lambda o: o["saturation"]["affected_region_indices"].pop()),
            "ineligible use missing": (r, lambda o: o["saturation"].update(ineligible_uses=[])),
            "exclusion lines": (r, lambda o: o["exclusions"][0]["affected"].update(line_indices=[0])),
            "contract owner": (r, lambda o: o["contracts"][0].update(function_entity_index=None)
                               if o["contracts"][0]["function_entity_index"] is not None else o["contracts"][0].update(function_entity_index=0)),
            "contract count": (r, lambda o: next(x for x in o["contracts"] if x["count_true"] is not None).update(
                count_true={"by_context": [], "lower_bound": False, "saturated": False, "value": 0}, runtime_result="evaluated_false")),
            "point id": (c, lambda o: o["points"][0].update(semantic_discriminator="other")),
            "context without an input": (r, lambda o: o["contexts"].append({"context_index": len(o["contexts"]), "value": "zzz"})),
            "source owned by no map": (c, lambda o: o["maps"][0].update(source_indices=[])),
            "registry pair": (c, lambda o: o["provenance"].update(indexed_diagnostic_registry_revision=1)),
            "two inputs with one profile ID": (c, lambda o: o["inputs"].append({**o["inputs"][0], "artifact_sha256": "f" * 64, "name": "z"})),
        }
        for label, (base, fn) in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.verdict(change(base, fn)), "COV4002")
        self.assertEqual(self.verdict(c), "valid")
        self.assertEqual(self.verdict(r), "valid")

    def test_codes_must_belong_to_the_registry_the_report_names(self) -> None:
        bad = copy.deepcopy(self.rich)
        bad["policy"]["evaluations"][0]["diagnostics"] = sorted([*bad["policy"]["evaluations"][0]["diagnostics"], "COV9998"])
        self.assertEqual(self.verdict(bad), "COV4001")
        other = copy.deepcopy(self.clean)
        other["tool"]["diagnostic_registry_revision"] = 1
        self.assertEqual(self.verdict(other), "COV4001")
        registry = diagnostics.load_registry()
        newer = mock.Mock(revision=registry.revision + 1, sha256="a" * 64, entries=registry.entries)
        self.assertEqual(code_of(read_report, encode(self.clean), registry=newer), "COV4001")

    def test_scope_and_entity_evaluations_are_rederived_from_their_configuration(self) -> None:
        """CV-310: the reader works scope and entity evaluations out again from
        the resolved configuration in the report; an unconfigured, altered or
        missing one is a contradiction."""
        toml = ('[[tool.sv0cov.scopes]]\nname = "core"\ninclude = ["**"]\nline = 75\n'
                '[[tool.sv0cov.entities]]\nname = "m"\nsource = "main.sv0"\nqualified_name = "main"\nkind = "function"\n')
        good, _ = fixture_report("f0", config(toml=toml))
        self.assertEqual(self.verdict(good), "valid")
        evals = good["policy"]["evaluations"]
        n = next(i for i, e in enumerate(evals) if e["assertion_kind"] == "scope" and e["metric"] == "line")
        scope = evals[n]
        self.assertEqual((scope["threshold_source"], scope["members"]["source_indices"]), ("assertion", [0]))
        for change in ({"limit": {"denominator": 10000, "numerator": 7501}}, {"result": "fail", "diagnostics": ["COV4101"]},
                       {"members": {**scope["members"], "source_indices": []}}, {"threshold_source": "project"}):
            with self.subTest(change=sorted(change)):
                o = copy.deepcopy(good)
                o["policy"]["evaluations"][n] = {**scope, **change}
                self.assertIn(self.verdict(o), ("COV4001", "COV4002"))  # structure or re-derivation
        o = copy.deepcopy(good)
        del o["policy"]["evaluations"][n]
        self.assertEqual(self.verdict(o), "COV4002")
        o = copy.deepcopy(self.clean)
        o["policy"]["evaluations"].append({**scope, "members": {**scope["members"], "line_indices": [0]}})
        o["policy"]["evaluations"].sort(key=lambda e: (e["assertion_kind"], e["assertion_name"], e["metric"]))
        self.assertEqual(self.verdict(o), "COV4002")  # no scope is configured in this report
        # `passed` is recomputed from the evaluations.
        ok, _ = fixture_report("f0", config(toml=thresholds(line=1)))
        self.assertTrue(ok["policy"]["passed"])
        ok["policy"]["passed"], ok["evidence_eligibility"] = False, "policy_failed"
        self.assertEqual(self.verdict(ok), "COV4002")

    # Fields nothing else in a report can contradict. Each pattern is a JSON pointer with indexes replaced by N.
    PRIMARY = {
        r"/(points|regions|entities|exclusions)/N/span/(start|end)_(line|column)": "display coordinates need the source text",
        r"/(regions|entities|exclusions)/N/span/(start|end)_byte": "a span is a primary fact; only ownership and order constrain it",
        r"/regions/N/line_numbers(/N)?": "a region's lines are primary where another region already names the line",
        r"/regions/N/counter_expression/terms/N/coefficient": "an expression is primary where the count does not change",
        r"/contexts/N/value": "a context value is primary",
        r"/exclusions/N/(reason|source_index|affected/entity_indices(/N)?)": "exclusion text and entity membership are primary",
        r"/inputs/N/(artifact_sha256|byte_length|name|profile_id|context_index)": "transport facts of files the report does not hold",
        r"/maps/N/(compiler_identity|program_counter_count|target/name)": "map identity is primary",
        r"/provenance/(indexed_input_sha256|semantic_projection_sha256|indexed_diagnostic_registry_(revision|sha256))":
            "digests of artifacts outside the report",
        r"/resolved_configuration/coverage/(context|output_dir|reproducible_epoch)/value": "configuration no evidence depends on",
        r"/tool/version": "the producer's own version",
    }

    def test_a_single_changed_field_is_rejected_unless_nothing_can_contradict_it(self) -> None:
        """COV-REP-018, AC-105: the single-field mutation corpus."""
        def walk(v, p=""):
            if isinstance(v, dict):
                for k, x in v.items():
                    yield from walk(x, f"{p}/{k}")
            elif isinstance(v, list):
                yield p, v
                for n, x in enumerate(v):
                    yield from walk(x, f"{p}/{n}")
            else:
                yield p, v

        def variants(v):
            if isinstance(v, bool):
                return [not v]
            if isinstance(v, int):
                return [v + 1, v - 1] if v > 0 else [v + 1]
            if isinstance(v, str):
                return [("0" if v[0] != "0" else "1") + v[1:]] if re.fullmatch(r"[0-9a-f]{64}|[0-9a-f]{32}", v) else [v + "x"]
            if v is None:
                return [0, ""]
            out = [[v[1], v[0], *v[2:]]] if len(v) >= 2 else []
            return out + ([v[1:], v + [v[-1]]] if v else [])

        total = rejected = 0
        unexplained = []
        for pointer, value in list(walk(self.small)):
            for new in variants(value):
                o = copy.deepcopy(self.small)
                node, parts = o, pointer.split("/")[1:]
                for q in parts[:-1]:
                    node = node[int(q)] if isinstance(node, list) else node[q]
                node[int(parts[-1]) if isinstance(node, list) else parts[-1]] = new
                total += 1
                try:
                    data = encode(o)
                except CanonicalJsonError:
                    rejected += 1
                    continue
                if code_of(read_report, data) != "valid":
                    rejected += 1
                elif not any(re.fullmatch(p, re.sub(r"/\d+", "/N", pointer)) for p in self.PRIMARY):
                    unexplained.append((pointer, value, new))
        self.assertEqual(unexplained[:10], [])
        self.assertGreater(total, 1000)
        kinds = {e["kind"] for e in self.small["entities"]}
        self.assertEqual((kinds, self.small["saturation"]["any"], len(self.small["contexts"]) > 1, bool(self.small["exclusions"])),
                         ({"function", "contract"}, True, True, True))
        self.assertGreater(rejected, total * 0.8)

    def test_the_reader_runs_the_structure_layer_first(self) -> None:
        self.assertEqual(code_of(read_report, b"{}\n"), "COV4001")
        o = copy.deepcopy(self.clean)
        o["summary"]["line"]["ratio"] = "0.5"
        self.assertEqual(self.verdict(o), "COV4001")
        check_report_structure(self.rich)
        check_report_structure(self.clean)


if __name__ == "__main__":
    unittest.main()
