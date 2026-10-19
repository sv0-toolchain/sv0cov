# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The indexed semantic model (CV-221; SPEC 16.5.5, 11.1, 11.4; BL-023,
COV-MET-017, COV-FMT-041).

The model built from each reviewed fixture's map and counts equals the
hand-derived ``expected-semantic.json``. Then the rules the fixtures do not
exercise: contexts, saturation and interval lower bounds, several maps,
source-version conflicts, incompatible maps, contracts and exclusions, and
input-order independence.
"""

from __future__ import annotations

import copy
import itertools
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(SEMANTIC))

import map_samples as ms  # noqa: E402
from plan import Plan  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.indexed import check_semantic_structure  # noqa: E402
from sv0cov.formats.map import validate_map  # noqa: E402
from sv0cov.formats.rawprofile import RawProfile, decode  # noqa: E402
from sv0cov.formats.rawprofile import encode as encode_profile  # noqa: E402
from sv0cov.lines import line_records  # noqa: E402
from sv0cov.model.semantic import ModelError, build_semantic  # noqa: E402

U64 = 2**64 - 1
RUN = bytes.fromhex("0123456789abcdef0123456789abcdef")
FIXTURES = sorted(p.parent.name for p in SEMANTIC.glob("*/expected-semantic.json"))


def profile(m: dict, counts: dict[str, int], *, context: str | None = None, n: int = 1, backend: str = "native") -> RawProfile:
    """A decoded profile of map ``m`` with ``counts`` (point ID -> count),
    taken through the real encoder and decoder."""
    counter = {p["point_id"]: p["counter_index"] for p in m["points"] if p["counter_index"] is not None}
    pairs = tuple(sorted((counter[pid], v) for pid, v in counts.items() if v))
    raw = RawProfile(bytes.fromhex(m["map_id"]), RUN, n.to_bytes(16, "big"), backend, context, pairs)
    data = encode_profile(raw, m["program_counter_count"])
    return decode(data, map_counter_count=m["program_counter_count"], expected_map_id=raw.map_id)


def fixture(name: str) -> tuple[dict, dict[str, int], dict]:
    d = SEMANTIC / name
    m = validate_map((d / "expected-map.json").read_bytes())
    counts = {c["point_id"]: c["count"] for c in json.loads((d / "expected-counts.json").read_bytes())["counts"]}
    return m, counts, json.loads((d / "expected-semantic.json").read_bytes())


def by_id(sem: dict) -> dict[str, dict]:
    return {p["point_id"]: p for p in sem["points"]}


def exact(value: int, *by_context: tuple[int, int]) -> dict:
    return {"by_context": [{"context_index": c, "lower_bound": False, "saturated": False, "value": v} for c, v in by_context],
            "lower_bound": False, "saturated": False, "value": value}


def bound(value: int, *by_context: tuple[int, int]) -> dict:
    return {"by_context": [{"context_index": c, "lower_bound": True, "saturated": True, "value": v} for c, v in by_context],
            "lower_bound": True, "saturated": True, "value": value}


def tiny(text: str, target: str = "tiny") -> tuple[dict, Plan]:
    """A reviewed-style map for `fn f() -> i32 { return 1; }` plus an `if`."""
    src = {"main.sv0": text.encode()}
    p = Plan(target, src)
    f = p.function("main.sv0", "main")
    span = p.through_block("main.sv0", "if a > 0 {")
    b = p.branch(f, "if", span)
    p.region(f, "initializer", p.find("main.sv0", "let a = 1;"), f.entry)
    p.region(f, "expression", p.find("main.sv0", "a > 0"), f.entry)
    p.region(f, "branch_body", p.through_block("main.sv0", "{", after=span[0]), b["true"], lc=False)
    p.region(f, "return", p.find("main.sv0", "return 1;"), b["true"])
    p.region(f, "return", p.find("main.sv0", "return 0;"), f.entry, (b["true"], -1))
    m = p.build()
    p.entry, p.true, p.false = (p._ids[id(x)] for x in (f.entry, b["true"], b["false"]))
    return validate_map(encode(m), sources=src), p


TINY = "fn main() -> i32 {\n  let a = 1;\n  if a > 0 {\n    return 1;\n  }\n  return 0;\n}\n"


class FixtureModelTest(unittest.TestCase):
    def test_model_equals_the_expected_semantic_object(self) -> None:
        """The done-when: every reviewed fixture, CV-027's f0 first."""
        self.assertEqual(len(FIXTURES), 9)
        self.assertIn("f0", FIXTURES)
        for name in FIXTURES:
            with self.subTest(fixture=name):
                m, counts, want = fixture(name)
                got = build_semantic([m], [profile(m, counts)])
                self.assertEqual(encode(got), (SEMANTIC / name / "expected-semantic.json").read_bytes())
                self.assertEqual(got, want)
                check_semantic_structure(got)
                self.assertTrue(got["complete"])

    def test_expected_lines_are_exactly_the_lines_regions_name(self) -> None:
        """Membership needs no source file: the lines are those in some
        region's line_numbers, and the statuses agree with the source-backed
        line module on those lines (which adds the remaining physical lines
        as non_executable)."""
        for name in FIXTURES:
            with self.subTest(fixture=name):
                m, counts, want = fixture(name)
                named = sorted({(r["source_index"], n) for r in m["regions"] for n in r["line_numbers"]})
                self.assertEqual([(ln["source_index"], ln["line"]) for ln in want["lines"]], named)
                self.assertEqual([ln["line_index"] for ln in want["lines"]], list(range(len(named))))
                srcs = {s["path"]: (SEMANTIC / name / s["path"]).read_bytes() for s in m["sources"]}
                full = {(r["source_index"], r["line"]): r for r in line_records(m, counts, srcs)}
                for ln in want["lines"]:
                    self.assertEqual(full[(ln["source_index"], ln["line"])]["status"], ln["status"])
                    self.assertEqual(full[(ln["source_index"], ln["line"])]["region_indices"], ln["region_indices"])
                rest = [r["status"] for key, r in full.items() if key not in set(named)]
                self.assertEqual(set(rest) - {"non_executable"}, set())

    def test_input_order_does_not_matter(self) -> None:
        m, counts, _ = fixture("project")
        half = {pid: v // 2 for pid, v in counts.items()}
        rest = {pid: v - half[pid] for pid, v in counts.items()}
        profs = [profile(m, half, n=1, context="b"), profile(m, rest, n=2, context=None), profile(m, counts, n=3, context="a")]
        first = encode(build_semantic([m], profs))
        for perm in itertools.permutations(profs):
            self.assertEqual(encode(build_semantic([m], perm)), first)


class ContextTest(unittest.TestCase):
    def test_counts_stay_apart_by_context_and_add_in_the_aggregate(self) -> None:
        m, p = tiny(TINY)
        profs = [profile(m, {p.entry: 2, p.true: 2}, n=1, context="unit"),
                 profile(m, {p.entry: 3, p.true: 1, p.false: 2}, n=2, context=None),
                 profile(m, {p.entry: 5, p.false: 5}, n=3, context=""),
                 profile(m, {p.entry: 1, p.true: 1}, n=4, context="unit")]
        sem = build_semantic([m], profs)
        check_semantic_structure(sem)
        # Absent first, then the empty string, then bytewise order.
        self.assertEqual(sem["contexts"], [{"context_index": 0, "value": None}, {"context_index": 1, "value": ""},
                                           {"context_index": 2, "value": "unit"}])
        pts = by_id(sem)
        self.assertEqual(pts[p.entry]["count"], exact(11, (0, 3), (1, 5), (2, 3)))
        self.assertEqual(pts[p.true]["count"], exact(4, (0, 1), (2, 3)))  # context 1 never took it: omitted
        self.assertEqual(pts[p.false]["count"], exact(7, (0, 2), (1, 5)))
        after = next(r for r in sem["regions"] if r["kind"] == "return" and len(r["counter_expression"]["terms"]) == 2)
        self.assertEqual(after["count"], exact(7, (0, 2), (1, 5)))  # entry - true, per context
        outcomes = sem["branches"][0]["outcomes"]
        self.assertEqual([o["status"] for o in outcomes], ["covered", "covered"])
        self.assertEqual(outcomes[0]["count"], pts[p.true]["count"])

    def test_context_order_is_bytewise(self) -> None:
        m, p = tiny(TINY)
        values = ["z", "é", "a", "", None, "Z", "a\u0000", "aa"]
        sem = build_semantic([m], [profile(m, {p.entry: 1}, n=k + 1, context=v) for k, v in enumerate(values)])
        got = [c["value"] for c in sem["contexts"]]
        self.assertEqual(got, [None] + sorted((v for v in values if v is not None), key=lambda v: v.encode()))
        self.assertEqual(got[:2], [None, ""])

    def test_a_rejected_profiles_context_is_listed_without_counts(self) -> None:
        m, p = tiny(TINY)
        sem = build_semantic([m], [profile(m, {p.entry: 1, p.false: 1}, context="kept")], extra_contexts=["rejected", None])
        self.assertEqual([c["value"] for c in sem["contexts"]], [None, "kept", "rejected"])
        self.assertEqual(by_id(sem)[p.entry]["count"], exact(1, (1, 1)))
        check_semantic_structure(sem)

    def test_no_profile_gives_zero_counts(self) -> None:
        m, p = tiny(TINY)
        sem = build_semantic([m], [])
        self.assertEqual(sem["contexts"], [])
        self.assertTrue(all(pt["count"] == exact(0) for pt in sem["points"]))
        self.assertEqual({ln["status"] for ln in sem["lines"]}, {"uncovered", "non_executable"})
        self.assertEqual([o["status"] for o in sem["branches"][0]["outcomes"]], ["uncovered", "uncovered"])


class SaturationTest(unittest.TestCase):
    """COV-MET-017: interval lower bounds, inexact zero kept, conservative lines."""

    def test_a_saturated_counter_is_a_lower_bound(self) -> None:
        m, p = tiny(TINY)
        sem = build_semantic([m], [profile(m, {p.entry: U64, p.false: 7})])
        check_semantic_structure(sem)
        self.assertEqual(by_id(sem)[p.entry]["count"], bound(U64, (0, U64)))
        init = next(r for r in sem["regions"] if r["kind"] == "initializer")
        self.assertEqual(init["count"], bound(U64, (0, U64)))  # +entry: at least UINT64_MAX
        after = next(r for r in sem["regions"] if len(r["counter_expression"]["terms"]) == 2)
        self.assertEqual(after["count"], bound(U64, (0, U64)))  # entry - true, true exact zero
        self.assertEqual(sem["saturation"]["affected_point_ids"], [p.entry])
        self.assertEqual(sem["saturation"]["affected_region_indices"],
                         [r["region_index"] for r in sem["regions"] if r["count"]["lower_bound"]])
        self.assertTrue(sem["saturation"]["any"])
        self.assertEqual((sem["saturation"]["policy"], sem["saturation"]["eligible_metrics"]), ("fail", []))

    def test_a_saturated_subtrahend_gives_a_lower_bound_zero_and_an_uncovered_line(self) -> None:
        """entry - true with `true` saturated: nothing is proven, so the
        region is a retained inexact zero and its line is uncovered, never a
        false pass."""
        m, p = tiny(TINY)
        sem = build_semantic([m], [profile(m, {p.entry: 9, p.true: U64})])
        check_semantic_structure(sem)
        after = next(r for r in sem["regions"] if len(r["counter_expression"]["terms"]) == 2)
        self.assertEqual(after["count"], bound(0, (0, 0)))
        line = next(ln for ln in sem["lines"] if after["region_index"] in ln["region_indices"])
        self.assertEqual(line["status"], "uncovered")
        self.assertIn(after["region_index"], sem["saturation"]["affected_region_indices"])
        self.assertEqual(sem["saturation"]["affected_point_ids"], [p.true])
        self.assertEqual(sem["branches"][0]["outcomes"][0]["status"], "covered")

    def test_sums_saturate_per_context_and_in_the_aggregate(self) -> None:
        m, p = tiny(TINY)
        big = U64 - 1
        same = build_semantic([m], [profile(m, {p.entry: big}, n=1), profile(m, {p.entry: 2}, n=2)])
        self.assertEqual(by_id(same)[p.entry]["count"], bound(U64, (0, U64)))
        apart = build_semantic([m], [profile(m, {p.entry: big}, n=1, context="a"), profile(m, {p.entry: 2}, n=2, context="b")])
        # Each context is exact; only their sum passes UINT64_MAX.
        self.assertEqual(by_id(apart)[p.entry]["count"],
                         {"by_context": exact(0, (0, big), (1, 2))["by_context"], "lower_bound": True, "saturated": True, "value": U64})
        self.assertEqual(apart["saturation"]["affected_point_ids"], [p.entry])
        check_semantic_structure(apart)
        # A sum landing exactly on UINT64_MAX is saturated: a physical count of that value is never exact.
        landed = build_semantic([m], [profile(m, {p.entry: big}, n=1), profile(m, {p.entry: 1}, n=2)])
        self.assertEqual(by_id(landed)[p.entry]["count"], bound(U64, (0, U64)))
        under = build_semantic([m], [profile(m, {p.entry: big - 1}, n=1), profile(m, {p.entry: 1}, n=2)])
        self.assertEqual(by_id(under)[p.entry]["count"], exact(big, (0, big)))

    def test_allow_ordinary_lists_the_eligible_metrics_only_when_saturated(self) -> None:
        m, p = tiny(TINY)
        hot = build_semantic([m], [profile(m, {p.entry: U64})], saturation_policy="allow-ordinary")
        self.assertEqual(hot["saturation"]["eligible_metrics"], ["branch", "function", "line", "region"])
        cold = build_semantic([m], [profile(m, {p.entry: 1})], saturation_policy="allow-ordinary")
        self.assertEqual((cold["saturation"]["any"], cold["saturation"]["eligible_metrics"]), (False, []))
        for sem in (hot, cold):
            check_semantic_structure(sem)
        with self.assertRaises(ValueError):
            build_semantic([m], [], saturation_policy="ignore")

    def test_a_negative_exact_region_is_corrupt_evidence(self) -> None:
        m, p = tiny(TINY)
        with self.assertRaises(ModelError) as ctx:
            build_semantic([m], [profile(m, {p.entry: 1, p.true: 2})])  # entry - true = -1
        self.assertEqual(ctx.exception.code, "COV3002")


class SeveralMapsTest(unittest.TestCase):
    def test_two_targets_sharing_a_source_merge_into_one_definition(self) -> None:
        a, p = tiny(TINY, "one")
        b, _ = tiny(TINY, "two")
        self.assertNotEqual(a["map_id"], b["map_id"])
        sem = build_semantic([a, b], [profile(a, {p.entry: 2, p.true: 2}, n=1), profile(b, {p.entry: 3, p.false: 3}, n=2)])
        check_semantic_structure(sem)
        alone = build_semantic([a], [profile(a, {p.entry: 5, p.true: 2, p.false: 3})])
        self.assertEqual(sem["map_ids"], sorted([a["map_id"], b["map_id"]]))
        self.assertEqual({k: v for k, v in sem.items() if k != "map_ids"}, {k: v for k, v in alone.items() if k != "map_ids"})
        self.assertEqual(encode(build_semantic([b, a, a], [profile(b, {p.entry: 3, p.false: 3}, n=2), profile(a, {p.entry: 2, p.true: 2}, n=1)])),
                         encode(sem))

    def test_maps_with_different_sources_are_reindexed_together(self) -> None:
        f0, c0, _ = fixture("f0")
        pj, c1, _ = fixture("project")
        sem = build_semantic([f0, pj], [profile(f0, c0, n=1), profile(pj, c1, n=2)])
        check_semantic_structure(sem)
        # Both maps have a main.sv0, with different bytes: one path, two versions.
        self.assertEqual([s["path"] for s in sem["sources"]], ["lib/util.sv0", "main.sv0", "main.sv0", "util/util.sv0"])
        self.assertEqual(sem["diagnostics"], ["COV3004"])
        self.assertFalse(sem["complete"])
        self.assertEqual([s["source_index"] for s in sem["sources"]], [0, 1, 2, 3])
        for key, field in (("entities", "entity_index"), ("regions", "region_index"), ("branches", "branch_index"), ("lines", "line_index")):
            self.assertEqual([r[field] for r in sem[key]], list(range(len(sem[key]))), key)
        self.assertEqual(len(sem["points"]), len(f0["points"]) + len(pj["points"]))
        self.assertEqual(len(sem["regions"]), len(f0["regions"]) + len(pj["regions"]))
        # Each map's records keep their meaning: counts per region equal the single-map models.
        for m, counts in ((f0, c0), (pj, c1)):
            alone = build_semantic([m], [profile(m, counts)])
            want = sorted((json.dumps(r["counter_expression"], sort_keys=True), r["count"]["value"]) for r in alone["regions"])
            got = sorted((json.dumps(r["counter_expression"], sort_keys=True), r["count"]["value"]) for r in sem["regions"])
            self.assertTrue(all(w in got for w in want))
        self.assertEqual(sorted(p["point_id"] for p in sem["points"]), [p["point_id"] for p in sem["points"]])

    def test_a_source_version_conflict_is_kept_and_diagnosed(self) -> None:
        a, pa = tiny(TINY)
        b, pb = tiny(TINY + "/* edited */\n")
        sem = build_semantic([a, b], [profile(a, {pa.entry: 1, pa.true: 1}, n=1), profile(b, {pb.entry: 1, pb.false: 1}, n=2)])
        check_semantic_structure(sem)
        self.assertEqual([s["path"] for s in sem["sources"]], ["main.sv0", "main.sv0"])
        self.assertEqual([s["digest"] for s in sem["sources"]], sorted(s["digest"] for s in (a["sources"][0], b["sources"][0])))
        self.assertEqual((sem["diagnostics"], sem["complete"]), (["COV3004"], False))
        self.assertEqual(len(sem["entities"]), 2)

    def test_complete_follows_the_caller_and_the_models_own_findings(self) -> None:
        m, p = tiny(TINY)
        prof = [profile(m, {p.entry: 1, p.true: 1})]
        self.assertTrue(build_semantic([m], prof)["complete"])
        self.assertFalse(build_semantic([m], prof, complete=False)["complete"])
        with_diag = build_semantic([m], prof, diagnostics=["COV3003", "COV3002"])
        self.assertEqual((with_diag["diagnostics"], with_diag["complete"]), (["COV3002", "COV3003"], False))

    def test_incompatible_definitions_are_refused(self) -> None:
        a, p = tiny(TINY, "one")

        def variant(change) -> dict:
            o = copy.deepcopy(a)
            change(o)
            o["target"]["name"] = "two"
            return ms.finalize(o, fragments=False)

        cases = {
            "source ownership": lambda o: o["sources"][0].__setitem__("ownership", "dependency") or o["sources"][0].__setitem__("package", "dep"),
            "point classification": lambda o: next(x for x in o["points"] if x["point_id"] == p.false).__setitem__("semantic_discriminator", "loop"),
            "entity span": lambda o: o["entities"][0]["span"].__setitem__("end_column", 9),
            "region line flag": lambda o: o["regions"][0].__setitem__("line_contributing", not o["regions"][0]["line_contributing"]),
            "outcome name": lambda o: o["branches"][0]["outcomes"][0].__setitem__("name", "yes"),
        }
        for name, change in cases.items():
            with self.subTest(case=name), self.assertRaises(ModelError) as ctx:
                build_semantic([a, variant(change)], [])
            self.assertEqual(ctx.exception.code, "COV3002")
        # The same map ID on two different objects.
        clash = copy.deepcopy(a)
        clash["target"]["name"] = "other"
        with self.assertRaises(ModelError) as ctx:
            build_semantic([a, clash], [])
        self.assertEqual(ctx.exception.code, "COV3002")

    def test_profiles_must_belong_to_a_supplied_map_and_be_distinct(self) -> None:
        a, p = tiny(TINY, "one")
        b, _ = tiny(TINY, "two")
        with self.assertRaises(ModelError) as ctx:
            build_semantic([a], [profile(b, {p.entry: 1})])
        self.assertEqual(ctx.exception.code, "COV2111")
        with self.assertRaises(ModelError) as ctx:
            build_semantic([a], [profile(a, {p.entry: 1}, n=7), profile(a, {p.entry: 1}, n=7)])
        self.assertEqual(ctx.exception.code, "COV2112")


class ContractAndExclusionTest(unittest.TestCase):
    """The validator's sample map: a runtime-checked `requires`, an excluded
    function, and an `if`."""

    def setUp(self) -> None:
        self.m = validate_map(encode(ms.build()))
        pts = {(p["kind"], self.m["entities"][p["entity_index"]]["qualified_name"], p["outcome_ordinal"]): p["point_id"]
               for p in self.m["points"]}
        self.div, self.t, self.f = pts[("function_entry", "div", None)], pts[("contract_true", "div#requires0", None)], \
            pts[("contract_false", "div#requires0", None)]
        self.unused = pts[("function_entry", "unused", None)]

    def test_runtime_results_follow_the_two_counts(self) -> None:
        for counts, result in (({}, "not_evaluated"), ({self.t: 3}, "evaluated_true"), ({self.f: 1}, "evaluated_false"),
                               ({self.t: 3, self.f: 1}, "mixed")):
            with self.subTest(result=result):
                sem = build_semantic([self.m], [profile(self.m, {self.div: 4, **counts})])
                check_semantic_structure(sem)
                (c,) = sem["contracts"]
                self.assertEqual(c["runtime_result"], result)
                self.assertEqual((c["count_true"]["value"], c["count_false"]["value"]), (counts.get(self.t, 0), counts.get(self.f, 0)))
                self.assertEqual((c["kind"], c["enforcement"], c["clause_index"]), ("requires", "runtime_checked", 0))
                self.assertEqual(sem["entities"][c["entity_index"]]["qualified_name"], "div#requires0")
                self.assertEqual(sem["entities"][c["function_entity_index"]]["qualified_name"], "div")

    def test_non_runtime_clauses_have_no_counts(self) -> None:
        o = ms.build()
        c = o["contracts"][0]
        c.update(enforcement="statically_verified", evidence_identity="sv0c:smt:1", true_point_id=None, false_point_id=None)
        # Its two points go, and with them their counters.
        gone = {self.t, self.f}
        o["points"] = [p for p in o["points"] if p["point_id"] not in gone]
        renumber = {old: new for new, old in enumerate(sorted(p["counter_index"] for p in o["points"] if p["counter_index"] is not None))}
        for p in o["points"]:
            if p["counter_index"] is not None:
                p["counter_index"] = renumber[p["counter_index"]]
        o["program_counter_count"] = len(renumber)
        o["fragments"][0]["slice_length"] -= 2
        o["fragments"][1]["slice_base"] -= 2
        o["regions"] = [r for r in o["regions"] if not gone & {t["point_id"] for t in r["counter_expression"]["terms"]}]
        for n, r in enumerate(o["regions"]):
            r["region_index"] = n
        for x in o["exclusions"]:
            x["affected"]["region_indices"] = [n for n, r in enumerate(o["regions"]) if r["classification"] == "excluded"]
        m = validate_map(encode(ms.finalize(o)))
        sem = build_semantic([m], [])
        check_semantic_structure(sem)
        (c,) = sem["contracts"]
        self.assertEqual((c["runtime_result"], c["count_true"], c["count_false"], c["evidence_identity"]),
                         ("not_applicable", None, None, "sv0c:smt:1"))

    def test_exclusions_keep_their_affected_sets_and_excluded_lines(self) -> None:
        sem = build_semantic([self.m], [profile(self.m, {self.div: 1, self.t: 1})])
        check_semantic_structure(sem)
        self.assertEqual(len(sem["exclusions"]), len(self.m["exclusions"]))
        for got, want in zip(sem["exclusions"], self.m["exclusions"]):
            self.assertEqual(got, want)  # one map: nothing to reindex
        excluded_regions = [r["region_index"] for r in sem["regions"] if r["classification"] == "excluded"]
        self.assertTrue(excluded_regions)
        for ln in sem["lines"]:
            listed = [r for r in sem["regions"] if ln["line"] in r["line_numbers"] and r["source_index"] == ln["source_index"]]
            if all(r["classification"] == "excluded" for r in listed):
                self.assertEqual(ln["status"], "excluded")
        self.assertIn("excluded", {ln["status"] for ln in sem["lines"]})
        self.assertEqual(by_id(sem)[self.unused]["count"], exact(0))

    def test_exclusions_are_reindexed_across_maps(self) -> None:
        f0, c0, _ = fixture("loops")
        sem = build_semantic([self.m, f0], [profile(f0, c0)])
        check_semantic_structure(sem)
        (x,) = sem["exclusions"]
        for i in x["affected"]["entity_indices"]:
            self.assertEqual(sem["entities"][i]["qualified_name"], "unused")
        for i in x["affected"]["region_indices"]:
            self.assertEqual(sem["regions"][i]["classification"], "excluded")
        self.assertEqual(sem["sources"][x["source_index"]]["path"], self.m["sources"][self.m["exclusions"][0]["source_index"]]["path"])
        for c in sem["contracts"]:
            self.assertEqual(sem["entities"][c["entity_index"]]["kind"], "contract")


if __name__ == "__main__":
    unittest.main()
