# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The full indexed object and its cross-validating reader (CV-222; SPEC
16.5; COV-FMT-040, COV-MRG-011, AC-112).

Evidence assembled from maps and raw profiles reads back valid; its bytes do
not depend on input order; with the maps and profiles deleted the artifact
alone reproduces every semantic result; and any single inconsistent change
(with the projection digest recomputed, so only cross-validation can see
it) is rejected.
"""

from __future__ import annotations

import builtins
import copy
import hashlib
import itertools
import json
import shutil
import sys
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import map_samples as ms  # noqa: E402

from sv0cov import diagnostics  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.indexed import IndexedError, check_indexed_structure, projection_sha256  # noqa: E402
from sv0cov.formats.map import validate_map  # noqa: E402
from sv0cov.formats.rawprofile import RawProfile, Tier, decode  # noqa: E402
from sv0cov.formats.rawprofile import encode as encode_profile  # noqa: E402
from sv0cov.model import indexed as reader_module  # noqa: E402
from sv0cov.model.indexed import MapInput, ProfileInput, RunSelection, build_indexed, read_indexed  # noqa: E402

U64 = 2**64 - 1
RUN_A, RUN_B = "0123456789abcdef0123456789abcdef", "fedcba9876543210fedcba9876543210"
FIXTURES = sorted(p.parent.name for p in SEMANTIC.glob("*/expected-semantic.json"))


def raw(m: dict, counts: dict[str, int], n: int, *, run: str = RUN_A, context: str | None = None, backend: str = "native") -> bytes:
    """Raw profile bytes for map ``m`` with ``counts`` (point ID -> count)."""
    counter = {p["point_id"]: p["counter_index"] for p in m["points"] if p["counter_index"] is not None}
    pairs = tuple(sorted((counter[pid], v) for pid, v in counts.items() if v))
    prof = RawProfile(bytes.fromhex(m["map_id"]), bytes.fromhex(run), n.to_bytes(16, "big"), backend, context, pairs)
    return encode_profile(prof, m["program_counter_count"])


def map_input(name: str, data: bytes) -> MapInput:
    return MapInput(name, data, validate_map(data))


def profile_input(name: str, data: bytes, m: dict) -> ProfileInput:
    return ProfileInput(name, data, decode(data, map_counter_count=m["program_counter_count"], expected_map_id=bytes.fromhex(m["map_id"])))


def fixture_inputs(name: str) -> tuple[bytes, dict, dict[str, int]]:
    d = SEMANTIC / name
    data = (d / "expected-map.json").read_bytes()
    counts = {c["point_id"]: c["count"] for c in json.loads((d / "expected-counts.json").read_bytes())["counts"]}
    return data, validate_map(data), counts


def simple(name: str) -> dict:
    data, m, counts = fixture_inputs(name)
    return build_indexed([map_input(f"{name}.sv0covmap.json", data)], [profile_input("p1.sv0profraw", raw(m, counts, 1), m)],
                         tool_version="0.0.0-test")


def rich_inputs() -> tuple[list[MapInput], list[ProfileInput], RunSelection]:
    """Two maps (the `question` fixture with its loops, match and `?`
    points, and the validator's two-source sample with a contract and an
    exclusion), three backends, two runs, three contexts, and one saturated
    counter."""
    pdata, pm, pcounts = fixture_inputs("question")
    sdata = encode(ms.build())
    sm = validate_map(sdata)
    spts = {(p["kind"], sm["entities"][p["entity_index"]]["qualified_name"], p["outcome_ordinal"]): p["point_id"] for p in sm["points"]}
    div, t, f = spts[("function_entry", "div", None)], spts[("contract_true", "div#requires0", None)], \
        spts[("contract_false", "div#requires0", None)]
    pos, yes, no = spts[("function_entry", "positive", None)], spts[("branch_outcome", "positive", 0)], \
        spts[("branch_outcome", "positive", 1)]
    profiles = [
        profile_input("a.sv0profraw", raw(pm, pcounts, 1, context=None), pm),
        profile_input("b.sv0profraw", raw(pm, pcounts, 2, context="shard-1", backend="vm-v1"), pm),
        profile_input("c.sv0profraw", raw(sm, {div: 3, t: 3, pos: U64, yes: 2}, 3, run=RUN_B, context="", backend="vm-v2"), sm),
        profile_input("d.sv0profraw", raw(sm, {div: 2, t: 1, f: 1, pos: 4, no: 4}, 4, run=RUN_B, context="shard-1"), sm),
    ]
    return ([map_input("question.sv0covmap.json", pdata), map_input("sample.sv0covmap.json", sdata)], profiles,
            RunSelection("explicit-list", (RUN_B, RUN_A)))


def rich() -> dict:
    maps, profiles, selection = rich_inputs()
    return build_indexed(maps, profiles, run_selection=selection, tool_version="0.0.0-test")


def code_of(obj: dict) -> tuple[str | None, IndexedError | None]:
    """The reader's verdict on ``obj`` with its projection digest recomputed."""
    o = copy.deepcopy(obj)
    o["semantic_projection_sha256"] = projection_sha256(o["semantic"])
    try:
        read_indexed(encode(o))
    except IndexedError as exc:
        return exc.code, exc
    return None, None


class ProducerTest(unittest.TestCase):
    def test_every_fixture_reads_back_and_holds_the_expected_semantic_object(self) -> None:
        self.assertEqual(len(FIXTURES), 9)
        for name in FIXTURES:
            with self.subTest(fixture=name):
                obj = simple(name)
                data = encode(obj)
                self.assertEqual(read_indexed(data), obj)
                self.assertEqual(len(obj), 11)
                self.assertEqual(encode(obj["semantic"]), (SEMANTIC / name / "expected-semantic.json").read_bytes())
                self.assertTrue(obj["semantic"]["complete"])
                self.assertEqual((obj["diagnostics"], obj["semantic"]["diagnostics"]), ([], []))
                self.assertEqual(obj["semantic_projection_sha256"], hashlib.sha256(encode(obj["semantic"])).hexdigest())
                m = json.loads((SEMANTIC / name / "expected-map.json").read_bytes())
                (b,) = obj["maps"]
                counted = sorted((p["counter_index"], p["point_id"]) for p in m["points"] if p["counter_index"] is not None)
                self.assertEqual([(x["counter_index"], x["point_id"]) for x in b["bindings"]], counted)
                self.assertEqual((b["compiler_identity"], b["target"], b["program_counter_count"]),
                                 (m["compiler"]["identity"], m["target"], m["program_counter_count"]))
                self.assertEqual(obj["run_selection"], {"manifest_sha256": None, "mode": "implicit-single", "requested_run_ids": [],
                                                        "selected_run_ids": [RUN_A]})
                self.assertEqual(obj["execution"], {"exit_code": None, "signal": None, "status": "not_applicable"})
                self.assertEqual(obj["merge"]["limits"], {"max_bytes": 67108864, "max_counters": 4194304, "tier": "standard"})

    def test_rich_evidence_is_complete_and_valid(self) -> None:
        """AC-112's given: several maps, backends, contexts, runs, exact and
        saturated counts, a contract, an exclusion."""
        obj = rich()
        self.assertEqual(read_indexed(encode(obj)), obj)
        s = obj["semantic"]
        self.assertTrue(s["complete"])
        self.assertEqual(len(obj["maps"]), 2)
        self.assertEqual([c["value"] for c in s["contexts"]], [None, "", "shard-1"])
        self.assertEqual({r["backend"] for r in obj["profile_inputs"]}, {"native", "vm-v1", "vm-v2"})
        self.assertEqual(obj["run_selection"]["selected_run_ids"], [RUN_A, RUN_B])
        self.assertEqual(obj["run_selection"]["requested_run_ids"], [RUN_A, RUN_B])
        self.assertTrue(s["saturation"]["any"] and s["contracts"] and s["exclusions"])
        self.assertEqual(s["contracts"][0]["runtime_result"], "mixed")
        for b in obj["maps"]:
            self.assertEqual(len(b["bindings"]), b["program_counter_count"])
            self.assertEqual([x["counter_index"] for x in b["bindings"]], list(range(b["program_counter_count"])))

    def test_bytes_do_not_depend_on_input_order(self) -> None:
        maps, profiles, selection = rich_inputs()
        first = encode(build_indexed(maps, profiles, run_selection=selection, tool_version="0.0.0-test"))
        for mp in itertools.permutations(maps):
            for pp in itertools.permutations(profiles):
                again = build_indexed(mp, pp, run_selection=RunSelection("explicit-list", (RUN_A, RUN_B)), tool_version="0.0.0-test")
                self.assertEqual(encode(again), first)

    def test_exact_copies_are_inventoried_once(self) -> None:
        maps, profiles, selection = rich_inputs()
        twice = build_indexed(maps + [MapInput("zz-copy.json", maps[0].data, maps[0].map)],
                              profiles + [ProfileInput("zz-copy.sv0profraw", profiles[0].data, profiles[0].profile)],
                              run_selection=selection, tool_version="0.0.0-test")
        self.assertEqual(encode(twice), encode(rich()))

    def test_execution_tier_and_tool_are_recorded(self) -> None:
        data, m, counts = fixture_inputs("f0")
        for execution in ({"exit_code": 0, "signal": None, "status": "passed"}, {"exit_code": 3, "signal": None, "status": "failed"},
                          {"exit_code": None, "signal": 9, "status": "signaled"}):
            obj = build_indexed([map_input("m.json", data)], [profile_input("p.sv0profraw", raw(m, counts, 1), m)],
                                execution=execution, tier=Tier.large(), tool_version="1.2.3")
            self.assertEqual(read_indexed(encode(obj))["execution"], execution)
            self.assertTrue(obj["semantic"]["complete"])  # a failed program is still complete evidence
            self.assertEqual(obj["merge"]["limits"], {"max_bytes": 268435456, "max_counters": 16777216, "tier": "large"})
            reg = diagnostics.load_registry()
            self.assertEqual(obj["merge"]["tool"], {"diagnostic_registry_revision": reg.revision,
                                                    "diagnostic_registry_sha256": reg.sha256, "name": "sv0cov", "version": "1.2.3"})

    def test_incomplete_evidence(self) -> None:
        data, m, counts = fixture_inputs("f0")
        good_map, good = map_input("m.json", data), profile_input("p.sv0profraw", raw(m, counts, 1), m)
        other = profile_input("q.sv0profraw", raw(m, counts, 2, run=RUN_B), m)
        cases = {
            "no profile": (dict(map_inputs=[good_map], profile_inputs=[]), ["COV3001", "COV3003"]),
            "rejected map": (dict(map_inputs=[good_map, MapInput("bad.json", b"{}", None, ("COV1010",))], profile_inputs=[good]), ["COV3002"]),
            "unreadable map": (dict(map_inputs=[good_map, MapInput("gone.json", None, None, ("COV6002",))], profile_inputs=[good]), ["COV3002"]),
            "incomplete profile": (dict(map_inputs=[good_map], profile_inputs=[
                good, ProfileInput("cut.sv0profraw", b"SV0P", None, "incomplete", ("COV2011",), backend="vm-v1", has_context=True,
                                   context="lost", map_id=m["map_id"], profile_id="ab" * 16, run_id=RUN_A)]), ["COV3002"]),
            "rejected profile": (dict(map_inputs=[good_map], profile_inputs=[good, ProfileInput("x.sv0profraw", b"junk", None, "rejected", ("COV2110",))]),
                                 ["COV3002"]),
            "two runs, none declared": (dict(map_inputs=[good_map], profile_inputs=[good, other]), ["COV3003"]),
            "a declared run is missing": (dict(map_inputs=[good_map], profile_inputs=[good],
                                               run_selection=RunSelection("explicit-list", (RUN_A, RUN_B))), ["COV3003"]),
            "an undeclared run": (dict(map_inputs=[good_map], profile_inputs=[good, other],
                                       run_selection=RunSelection("manifest", (RUN_A,), "ab" * 32)), ["COV3003"]),
            "selection failed": (dict(map_inputs=[], profile_inputs=[], run_selection=RunSelection("none")), ["COV3001", "COV3003"]),
            "override used": (dict(map_inputs=[good_map], profile_inputs=[good], allow_rejected_inputs=True), []),
        }
        for name, (kwargs, want) in cases.items():
            with self.subTest(case=name):
                obj = build_indexed(tool_version="0.0.0-test", **kwargs)
                self.assertEqual(obj["diagnostics"], want)
                self.assertFalse(obj["semantic"]["complete"])
                self.assertEqual(read_indexed(encode(obj)), obj)
        cut = build_indexed(tool_version="0.0.0-test", **cases["incomplete profile"][0])
        rec = next(r for r in cut["profile_inputs"] if r["status"] == "incomplete")
        self.assertEqual(cut["semantic"]["contexts"][rec["context_index"]]["value"], "lost")
        self.assertEqual((rec["backend"], rec["map_id"], rec["run_id"]), ("vm-v1", m["map_id"], RUN_A))
        # The rejected profile's context holds no count.
        self.assertTrue(all(c["context_index"] != rec["context_index"] for p in cut["semantic"]["points"] for c in p["count"]["by_context"]))

    def test_declared_runs_and_a_manifest_can_be_complete(self) -> None:
        data, m, counts = fixture_inputs("f0")
        ins = dict(map_inputs=[map_input("m.json", data)],
                   profile_inputs=[profile_input("p.sv0profraw", raw(m, counts, 1), m), profile_input("q.sv0profraw", raw(m, counts, 2, run=RUN_B), m)])
        for selection in (RunSelection("explicit-list", (RUN_A, RUN_B)), RunSelection("manifest", (RUN_B, RUN_A), "cd" * 32)):
            obj = build_indexed(run_selection=selection, tool_version="0.0.0-test", **ins)
            self.assertTrue(read_indexed(encode(obj))["semantic"]["complete"])
            self.assertEqual(obj["run_selection"]["manifest_sha256"], selection.manifest_sha256)

    def test_source_version_conflict_is_incomplete_in_both_arrays(self) -> None:
        a = fixture_inputs("f0")
        b = fixture_inputs("functions")  # another main.sv0
        obj = build_indexed([map_input("a.json", a[0]), map_input("b.json", b[0])],
                            [profile_input("p.sv0profraw", raw(a[1], a[2], 1), a[1]), profile_input("q.sv0profraw", raw(b[1], b[2], 2), b[1])],
                            tool_version="0.0.0-test")
        self.assertEqual((obj["diagnostics"], obj["semantic"]["diagnostics"], obj["semantic"]["complete"]), (["COV3004"], ["COV3004"], False))
        self.assertEqual(read_indexed(encode(obj)), obj)


class ReplayTest(unittest.TestCase):
    """AC-112: with the maps and raw profiles removed, the artifact alone
    gives the same semantic results."""

    def test_the_artifact_is_enough_after_its_inputs_are_deleted(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                tmp = Path(tempfile.mkdtemp())
                try:
                    data, m, counts = fixture_inputs(name)
                    (tmp / "app.sv0covmap.json").write_bytes(data)
                    (tmp / "run.sv0profraw").write_bytes(raw(m, counts, 1))
                    mb = (tmp / "app.sv0covmap.json").read_bytes()
                    obj = build_indexed([map_input("app.sv0covmap.json", mb)],
                                        [profile_input("run.sv0profraw", (tmp / "run.sv0profraw").read_bytes(), validate_map(mb))],
                                        tool_version="0.0.0-test")
                    artifact = encode(obj)
                finally:
                    shutil.rmtree(tmp)
                self.assertFalse(tmp.exists())
                # Nothing is opened while reading: the registry is already loaded.
                diagnostics.load_registry()
                with mock.patch.object(builtins, "open", side_effect=AssertionError("the reader opened a file")), \
                        mock.patch.object(Path, "read_bytes", side_effect=AssertionError("the reader read a file")):
                    got = read_indexed(artifact)
                want = json.loads((SEMANTIC / name / "expected-semantic.json").read_bytes())
                s = got["semantic"]
                self.assertEqual([(ln["source_index"], ln["line"], ln["status"]) for ln in s["lines"]],
                                 [(ln["source_index"], ln["line"], ln["status"]) for ln in want["lines"]])
                self.assertEqual([r["count"] for r in s["regions"]], [r["count"] for r in want["regions"]])
                self.assertEqual([[o["status"] for o in b["outcomes"]] for b in s["branches"]],
                                 [[o["status"] for o in b["outcomes"]] for b in want["branches"]])
                # Each raw count is recoverable through the retained binding.
                by_id = {p["point_id"]: p["count"]["value"] for p in s["points"]}
                self.assertEqual({x["point_id"]: by_id[x["point_id"]] for x in got["maps"][0]["bindings"]}, counts)
                self.assertEqual(got["map_inputs"][0]["artifact_sha256"], hashlib.sha256(data).hexdigest())

    def test_structure_fixtures_are_not_accepted_evidence(self) -> None:
        """CV-220's hand-written documents pass the structure layer only."""
        for name in ("all-kinds", "bounds"):
            data = (ROOT / "tests" / "fixtures" / "indexed" / f"{name}.json").read_bytes()
            with self.subTest(fixture=name), self.assertRaises(IndexedError):
                read_indexed(data)
        # empty.json is real evidence of a merge that found nothing.
        empty = read_indexed((ROOT / "tests" / "fixtures" / "indexed" / "empty.json").read_bytes())
        self.assertEqual((empty["diagnostics"], empty["semantic"]["complete"]), (["COV3001", "COV3003"], False))


def pt(o: dict, kind: str, n: int = 0, **where) -> dict:
    return [p for p in o["semantic"]["points"] if p["kind"] == kind and all(p[k] == v for k, v in where.items())][n]


def swap(items: list, a: int = 0, b: int = 1) -> None:
    items[a], items[b] = items[b], items[a]


def bump(rec: dict, by: int = 1) -> None:
    """Add to a count record consistently (first context and aggregate)."""
    rec["by_context"][0]["value"] += by
    rec["value"] += by


class MutationTest(unittest.TestCase):
    """Each change keeps the document well formed (the structure layer
    accepts it) and recomputes the projection digest."""

    def setUp(self) -> None:
        self.base = rich()
        self.assertEqual(code_of(self.base)[0], None)

    def cases(self) -> dict:
        S = "semantic"

        def sem(fn):
            return lambda o: fn(o[S])

        def renumber(key: str, field: str):
            def run(o):
                swap(o[S][key])
                for n, r in enumerate(o[S][key]):
                    r[field] = n
            return run

        def first_bound(o):
            return o["maps"][0]["bindings"][0]

        def region_with_terms(s, n=1):
            return next(r for r in s["regions"] if len(r["counter_expression"]["terms"]) >= n and r["count"]["by_context"])

        def counted_point(o):
            return next(p for p in o[S]["points"] if p["count"]["by_context"] and not p["count"]["lower_bound"]
                        and p["kind"] == "function_entry")

        def add_unused_context(o):
            o[S]["contexts"].append({"context_index": len(o[S]["contexts"]), "value": "zzz"})

        def drop_binding(o):
            b = o["maps"][0]
            b["bindings"].pop()
            b["program_counter_count"] -= 1

        def unbound_user_point_keeps_its_count(o):
            # The last counter of a map bound a counted point: unbinding it leaves a count no map explains.
            b = next(b for b in o["maps"] if any(pt_["count"]["value"] for pt_ in o[S]["points"] if pt_["point_id"] == b["bindings"][-1]["point_id"]))
            b["bindings"].pop()
            b["program_counter_count"] -= 1

        def exclude_bound(o):
            p = next(p for p in o[S]["points"] if p["point_id"] == first_bound(o)["point_id"])
            p["classification"] = "statically_unreachable"

        def duplicate_profile_id(o):
            a, b = [r for r in o["profile_inputs"] if r["status"] == "accepted"][:2]
            b["profile_id"] = a["profile_id"]

        def line_drop(o):
            o[S]["lines"].pop()

        def line_add(o):
            last = o[S]["lines"][-1]
            o[S]["lines"].append({"line": last["line"] + 1000, "line_index": len(o[S]["lines"]), "region_indices": [],
                                  "source_index": last["source_index"], "status": "non_executable"})

        def flip_line(o):
            ln = next(ln for ln in o[S]["lines"] if ln["status"] == "covered")
            ln["status"] = "partial"

        def outcome_count(o):
            out = next(x for b in o[S]["branches"] for x in b["outcomes"] if x["count"]["by_context"] and not x["count"]["lower_bound"])
            bump(out["count"])

        def swap_outcome_points(o):
            b = next(b for b in o[S]["branches"] if len(b["outcomes"]) == 2)
            b["outcomes"][0]["point_id"], b["outcomes"][1]["point_id"] = b["outcomes"][1]["point_id"], b["outcomes"][0]["point_id"]
            b["outcomes"][0]["count"], b["outcomes"][1]["count"] = b["outcomes"][1]["count"], b["outcomes"][0]["count"]
            b["outcomes"][0]["status"], b["outcomes"][1]["status"] = b["outcomes"][1]["status"], b["outcomes"][0]["status"]

        def branch_gone(o):
            o[S]["branches"].pop()

        def contract_count(o):
            bump(o[S]["contracts"][0]["count_true"])

        def contract_static(o):
            c = o[S]["contracts"][0]
            c.update(enforcement="statically_verified", count_true=None, count_false=None, evidence_identity="proof", runtime_result="not_applicable")

        def contract_gone(o):
            o[S]["contracts"].pop()

        def exclusion_gone(o):
            o[S]["exclusions"].pop()

        def exclusion_points(o):
            o[S]["exclusions"][0]["affected"]["point_ids"] = []

        def exclusion_extra(o):
            a = o[S]["exclusions"][0]["affected"]
            other = next(n for n, r in enumerate(o[S]["regions"]) if r["classification"] == "user")
            a["region_indices"] = sorted(set(a["region_indices"]) | {other})

        def region_coefficient(o):
            region_with_terms(o[S])["counter_expression"]["terms"][0]["coefficient"] += 1

        def region_count(o):
            bump(region_with_terms(o[S])["count"])

        def region_unbound_term(o):
            unbound = next(p["point_id"] for p in o[S]["points"] if p["classification"] == "excluded")
            r = region_with_terms(o[S])
            r["counter_expression"]["terms"] = sorted(r["counter_expression"]["terms"] + [{"coefficient": 1, "point_id": unbound}],
                                                      key=lambda t: t["point_id"])

        def region_other_source(o):
            r = region_with_terms(o[S])
            r["source_index"] = (r["source_index"] + 1) % len(o[S]["sources"])

        def region_line(o):
            r = o[S]["regions"][0]
            r["line_numbers"] = r["line_numbers"] + [r["line_numbers"][-1] + 500]

        def region_flag(o):
            r = next(r for r in o[S]["regions"] if r["line_contributing"])
            r["line_contributing"] = False

        def point_count(o):
            bump(counted_point(o)["count"])

        def point_span(o):
            counted_point(o)["span"]["end_byte"] += 1

        def point_disc(o):
            counted_point(o)["semantic_discriminator"] = "entry2"

        def point_entity(o):
            p = pt(o, "function_entry")
            other = next(e["entity_index"] for e in o[S]["entities"] if e["kind"] == "function" and e["entity_index"] != p["entity_index"]
                         and e["source_index"] == p["source_index"])
            p["entity_index"] = other

        def point_context(o):
            counted_point(o)["count"]["by_context"][-1]["context_index"] = 9

        def exact_at_max(o):
            p = counted_point(o)
            p["count"] = {"by_context": [{"context_index": p["count"]["by_context"][0]["context_index"], "lower_bound": False,
                                          "saturated": False, "value": U64}], "lower_bound": False, "saturated": False, "value": U64}

        def saturated_below_max(o):
            p = next(p for p in o[S]["points"] if p["count"]["lower_bound"])
            p["count"]["by_context"][0]["value"] = 5

        def source_digest(o):
            o[S]["sources"][0]["digest"] = "0" * 64

        def source_path(o):
            o[S]["sources"][0]["path"] = "aaa/moved.sv0"

        def entity_name(o):
            o[S]["entities"][0]["qualified_name"] += "x"

        def dependency_without_package(o):
            o[S]["sources"][0]["ownership"] = "dependency"

        def flag_3004(o):
            o[S]["diagnostics"] = ["COV3004"]
            o[S]["complete"] = False
            o["diagnostics"] = ["COV3004"]

        def other_registry(o):
            o["merge"]["tool"]["diagnostic_registry_sha256"] = "ab" * 32

        def context_of_rejected_only(o):
            # An accepted profile moved to a context that then holds counts no accepted profile explains.
            add_unused_context(o)
            next(r for r in o["profile_inputs"] if r["context_index"] == 0)["context_index"] = 3

        return {
            # Order and positions.
            "sources swapped": (renumber("sources", "source_index"), "COV3010"),
            "source index off": (sem(lambda s: s["sources"][0].__setitem__("source_index", 1)), "COV3010"),
            "entities swapped": (sem(lambda s: swap(s["entities"])), "COV3010"),
            "entities swapped and renumbered": (renumber("entities", "entity_index"), "COV3010"),
            "contexts swapped": (sem(lambda s: swap(s["contexts"], 1, 2)), "COV3010"),
            "contexts swapped and renumbered": (renumber("contexts", "context_index"), "COV3010"),
            "points swapped": (sem(lambda s: swap(s["points"])), "COV3010"),
            "regions swapped and renumbered": (renumber("regions", "region_index"), "COV3010"),
            "lines swapped and renumbered": (renumber("lines", "line_index"), "COV3010"),
            "branches swapped and renumbered": (renumber("branches", "branch_index"), "COV3010"),
            "maps swapped": (lambda o: swap(o["maps"]), "COV3010"),
            "map inputs swapped": (lambda o: swap(o["map_inputs"]), "COV3010"),
            "profile inputs swapped": (lambda o: swap(o["profile_inputs"]), "COV3010"),
            # Sources, entities, identities.
            "source digest changed": (source_digest, "COV3010"),
            "source path changed": (source_path, "COV3010"),
            "dependency without a package": (dependency_without_package, "COV3010"),
            "entity renamed": (entity_name, "COV3010"),
            "entity moved to another source": (sem(lambda s: s["entities"][-1].__setitem__("source_index", 0)), "COV3010"),
            "point span changed": (point_span, "COV3010"),
            "point discriminator changed": (point_disc, "COV3010"),
            "point given another entity": (point_entity, "COV3010"),
            "bound point's ID replaced": (sem(lambda s: s["points"][0].__setitem__("point_id", "0" * 64)), "COV3012"),
            "entry point classified contract": (lambda o: pt(o, "function_entry").__setitem__("classification", "contract"), "COV3010"),
            "contract point classified user": (lambda o: pt(o, "contract_true").__setitem__("classification", "user"), "COV3010"),
            # Counts.
            "point count raised": (point_count, "COV3010"),
            "point count in an unknown context": (point_context, "COV3010"),
            "exact count at UINT64_MAX": (exact_at_max, "COV3010"),
            "saturated count below UINT64_MAX": (saturated_below_max, "COV3010"),
            "region count raised": (region_count, "COV3010"),
            "region coefficient changed": (region_coefficient, "COV3010"),
            "region term names an uncounted point": (region_unbound_term, "COV3010"),
            "region moved to another source": (region_other_source, "COV3010"),
            # Lines.
            "region lists another line": (region_line, "COV3010"),
            "region no longer contributes": (region_flag, "COV3010"),
            "line dropped": (line_drop, "COV3010"),
            "line added": (line_add, "COV3010"),
            "line status changed": (flip_line, "COV3010"),
            "line membership emptied": (sem(lambda s: next(ln for ln in s["lines"] if ln["region_indices"]).__setitem__("region_indices", [])), "COV3010"),
            # Branches, contracts, exclusions, saturation.
            "outcome count raised": (outcome_count, "COV3010"),
            "outcome points swapped": (swap_outcome_points, "COV3010"),
            "outcome renamed": (sem(lambda s: s["branches"][0]["outcomes"][0].__setitem__("name", "yes")), "COV3010"),
            "branch kind changed": (sem(lambda s: next(b for b in s["branches"] if b["kind"] == "if").__setitem__("kind", "loop")), "COV3010"),
            "branch removed": (branch_gone, "COV3010"),
            "contract count raised": (contract_count, "COV3010"),
            "contract made static while its points remain": (contract_static, "COV3010"),
            "contract removed": (contract_gone, "COV3010"),
            "contract given another entity": (sem(lambda s: s["contracts"][0].__setitem__("entity_index", 0)), "COV3010"),
            "exclusion removed": (exclusion_gone, "COV3010"),
            "exclusion loses its points": (exclusion_points, "COV3010"),
            "exclusion claims a user region": (exclusion_extra, "COV3010"),
            "saturated point not listed": (sem(lambda s: s["saturation"].__setitem__("affected_point_ids", [])), "COV3010"),
            "saturated region not listed": (sem(lambda s: s["saturation"].__setitem__("affected_region_indices", s["saturation"]["affected_region_indices"][1:])), "COV3010"),
            # Bindings.
            "binding names an unknown point": (lambda o: first_bound(o).__setitem__("point_id", "1" * 64), "COV3012"),
            "two counters bind one point": (lambda o: o["maps"][0]["bindings"][1].__setitem__("point_id", first_bound(o)["point_id"]), "COV3012"),
            "counted point unbound": (unbound_user_point_keeps_its_count, "COV3012"),
            "uncounted class bound": (exclude_bound, "COV3012"),
            "map ID not in the semantic object": (lambda o: o["maps"][0].__setitem__("map_id", "0" * 64), "COV3012"),
            "semantic map ID without a binding": (sem(lambda s: s["map_ids"].append("f" * 64)), "COV3012"),
            "binding record removed": (lambda o: o["maps"].pop(), "COV3012"),
            "map sources shortened": (lambda o: o["maps"][0].__setitem__("source_indices", o["maps"][0]["source_indices"][:-1]), "COV3012"),
            "map source dangling": (lambda o: o["maps"][0]["source_indices"].append(99), "COV3012"),
            # Inventory, selection, completeness.
            "accepted map input names another map": (lambda o: o["map_inputs"][0].__setitem__("map_id", "2" * 64), "COV3012"),
            "accepted map input removed": (lambda o: o["map_inputs"].pop(0), "COV3012"),
            "profile names an unaccepted map": (lambda o: o["profile_inputs"][0].__setitem__("map_id", "3" * 64), "COV3012"),
            "profile context dangling": (lambda o: o["profile_inputs"][0].__setitem__("context_index", 9), "COV3010"),
            "two accepted profiles share an ID": (duplicate_profile_id, "COV3010"),
            "context nothing decoded": (add_unused_context, "COV3010"),
            "counts in a context without an accepted profile": (context_of_rejected_only, "COV3010"),
            "selected runs changed": (lambda o: o["run_selection"].__setitem__("selected_run_ids", [RUN_A]), "COV3010"),
            "requested runs differ but complete": (lambda o: o["run_selection"].__setitem__("requested_run_ids", [RUN_A]), "COV3010"),
            "implicit single over two runs but complete": (lambda o: o["run_selection"].update(mode="implicit-single", requested_run_ids=[]), "COV3010"),
            "complete flipped": (sem(lambda s: s.__setitem__("complete", False)), "COV3010"),
            "override used but complete": (lambda o: o["merge"].__setitem__("allow_rejected_inputs", True), "COV3010"),
            "COV3001 without cause": (lambda o: (o["diagnostics"].append("COV3001"), o[S].__setitem__("complete", False)), "COV3010"),
            "COV3004 without a conflict": (flag_3004, "COV3010"),
            "code outside the registry": (lambda o: (o["diagnostics"].append("COV9999"), o[S].__setitem__("complete", False)), "COV3010"),
            "another diagnostic registry": (other_registry, "COV3010"),
        }

    def test_every_inconsistent_change_is_rejected(self) -> None:
        cases = self.cases()
        self.assertGreaterEqual(len(cases), 70)
        for name, (change, want) in cases.items():
            with self.subTest(case=name):
                o = copy.deepcopy(self.base)
                change(o)
                o["semantic_projection_sha256"] = projection_sha256(o["semantic"])
                check_indexed_structure(copy.deepcopy(o))  # still well formed: only cross-validation can object
                got, exc = code_of(o)
                self.assertEqual(got, want, str(exc))

    def test_projection_mismatch_is_reported_first(self) -> None:
        o = copy.deepcopy(self.base)
        o["semantic"]["complete"] = False
        with self.assertRaises(IndexedError) as ctx:
            read_indexed(encode(o))
        self.assertEqual(ctx.exception.code, "COV3011")

    def test_every_reader_rule_is_reached(self) -> None:
        """Each `_fail` call of the reader is raised by some case here, by
        the incomplete-evidence variants, or by the structure fixtures."""
        source = Path(reader_module.__file__).read_text().splitlines()
        sites = {n for n, line in enumerate(source, 1) if "_fail(" in line and not line.lstrip().startswith(("def ", "#"))}
        hit: set[int] = set()

        def record(exc: BaseException | None) -> None:
            if exc is not None:
                for frame in traceback.extract_tb(exc.__traceback__):
                    if frame.filename == reader_module.__file__:
                        hit.update(n for n in range(frame.lineno, (frame.end_lineno or frame.lineno) + 1) if n in sites)

        for change, _ in list(self.cases().values()) + list(EXTRA_CASES.values()):
            o = copy.deepcopy(self.base)
            change(o)
            record(code_of(o)[1])
        missed = [f"{n}: {source[n - 1].strip()[:90]}" for n in sorted(sites - hit)]
        self.maxDiff = None
        self.assertEqual(missed, [])

    def test_extra_cases_are_rejected(self) -> None:
        for name, (change, want) in EXTRA_CASES.items():
            with self.subTest(case=name):
                o = copy.deepcopy(self.base)
                change(o)
                got, exc = code_of(o)
                self.assertEqual(got, want, str(exc))


def _extra_cases() -> dict:
    """Changes that reach the remaining reader rules. Unlike the main list
    they are not all single-field edits."""
    from sv0cov.model.identity import NO_ORDINAL, EntityKind, PointIdentity, PointKind, point_id

    S = "semantic"

    def other_source(s, i):
        return (i + 1) % len(s["sources"])

    def bound_ids(o):
        return {x["point_id"] for b in o["maps"] for x in b["bindings"]}

    def region_dangling_source(o):
        o[S]["regions"][0]["source_index"] = 99

    def unbound_point_in_another_source(o):
        p = next(p for p in o[S]["points"] if p["point_id"] not in bound_ids(o))
        p["source_index"] = other_source(o[S], p["source_index"])

    def entry_names_a_contract(o):
        contract = next(e for e in o[S]["entities"] if e["kind"] == "contract")
        p = next(p for p in o[S]["points"] if p["kind"] == "function_entry" and p["source_index"] == contract["source_index"])
        p["entity_index"] = contract["entity_index"]

    def inexact_aggregate_of_exact_contexts(o):
        p = next(p for p in o[S]["points"] if p["count"]["by_context"] and not p["count"]["lower_bound"])
        p["count"].update(lower_bound=True, saturated=True)

    def term_of_another_function(o):
        s = o[S]
        r = next(r for r in s["regions"] if r["counter_expression"]["terms"])
        other = next(p["point_id"] for p in s["points"] if p["point_id"] in bound_ids(o) and p["entity_index"] != r["entity_index"])
        r["counter_expression"]["terms"] = sorted(r["counter_expression"]["terms"] + [{"coefficient": 1, "point_id": other}],
                                                  key=lambda t: t["point_id"])

    def user_region_without_terms(o):
        r = next(r for r in o[S]["regions"] if r["classification"] == "user")
        r["counter_expression"]["terms"] = []

    def unreachable_region_with_terms(o):
        next(r for r in o[S]["regions"] if r["classification"] == "user")["classification"] = "statically_unreachable"

    def negative_region(o):
        s = o[S]
        r = next(r for r in s["regions"] if any(t["coefficient"] < 0 for t in r["counter_expression"]["terms"]))
        pid = next(t["point_id"] for t in r["counter_expression"]["terms"] if t["coefficient"] < 0)
        bump(next(p for p in s["points"] if p["point_id"] == pid)["count"], 10**6)
        # Keep every other region consistent, so the negative one is what the reader meets.
        from sv0cov.expr import Count, ExprError, check_expression, evaluate_contexts

        class Zero(dict):
            def __missing__(self, key):
                return Count(0, False)

        per = {c["context_index"]: Zero() for c in s["contexts"]}
        for q in s["points"]:
            for c in q["count"]["by_context"]:
                per[c["context_index"]][q["point_id"]] = Count(c["value"], c["lower_bound"])
        for x in s["regions"]:
            try:
                x["count"] = evaluate_contexts(check_expression(x["counter_expression"]), per).to_json()
            except ExprError:
                pass

    def outcome_names_an_entry_point(o):
        o[S]["branches"][0]["outcomes"][0]["point_id"] = pt(o, "function_entry")["point_id"]

    def outcome_point_twice(o):
        b = next(b for b in o[S]["branches"] if len(b["outcomes"]) >= 2)
        b["outcomes"][1]["point_id"] = b["outcomes"][0]["point_id"]

    def outcome_of_a_synthetic_point(o):
        out = o[S]["branches"][0]["outcomes"][0]
        next(p for p in o[S]["points"] if p["point_id"] == out["point_id"])["classification"] = "synthetic_support"

    def second_true_point(o):
        s = o[S]
        t = copy.deepcopy(pt(o, "contract_true"))
        e, src = s["entities"][t["entity_index"]], s["sources"][t["source_index"]]
        t["semantic_discriminator"] = "requires:again"
        t["point_id"] = point_id(PointIdentity(src["path"], src["digest"], EntityKind.CONTRACT, e["qualified_name"], PointKind.CONTRACT_TRUE,
                                               t["span"]["start_byte"], t["span"]["end_byte"], NO_ORDINAL, "requires:again"))
        t["count"] = {"by_context": [], "lower_bound": False, "saturated": False, "value": 0}
        s["points"] = sorted(s["points"] + [t], key=lambda p: p["point_id"])

    def clause_twice(o):
        c = copy.deepcopy(o[S]["contracts"][0])
        c["clause_index"] = 1
        o[S]["contracts"].append(c)

    def static_clause_made_runtime(o):
        # Remove the clause's two points everywhere, then claim it is runtime checked.
        s = o[S]
        gone = {pt(o, "contract_true")["point_id"], pt(o, "contract_false")["point_id"]}
        s["points"] = [p for p in s["points"] if p["point_id"] not in gone]
        for b in o["maps"]:
            b["bindings"] = [x for x in b["bindings"] if x["point_id"] not in gone]
            for n, x in enumerate(b["bindings"]):
                x["counter_index"] = n
            b["program_counter_count"] = len(b["bindings"])

    def affected(o):
        return o[S]["exclusions"][0]["affected"]

    def exclusion_twice(o):
        x = copy.deepcopy(o[S]["exclusions"][0])
        x["exclusion_index"], x["reason"] = 1, x["reason"] + " (again)"
        o[S]["exclusions"].append(x)

    def exclusion_empty(o):
        for key in affected(o):
            affected(o)[key] = []

    def off_with_a_contract_entity(o):
        contract = next(e["entity_index"] for e in o[S]["entities"] if e["kind"] == "contract")
        affected(o)["entity_indices"] = sorted(set(affected(o)["entity_indices"]) | {contract})

    def region_unclaimed(o):
        affected(o)["region_indices"] = affected(o)["region_indices"][1:]

    def branch_without_its_points(o):
        affected(o)["branch_indices"] = [0]

    def source_in_no_map(o):
        s = o[S]
        s["sources"].append({"digest": "ab" * 32, "ownership": "user", "package": None, "path": "zzz/unmapped.sv0",
                             "source_index": len(s["sources"])})

    def rejected_map_names_a_map(o):
        o["map_inputs"].append({"artifact_sha256": "ee" * 32, "byte_length": 2, "diagnostics": ["COV1010"],
                                "map_id": o["maps"][0]["map_id"], "name": "bad.json", "status": "rejected"})
        o["diagnostics"] = ["COV3002"]
        o[S]["complete"] = False

    def counts_of_a_rejected_profile(o):
        # The only accepted profile of one context becomes rejected; its counts stay.
        ctx = next(c["context_index"] for c in o[S]["contexts"] if c["value"] == "")
        r = next(r for r in o["profile_inputs"] if r["context_index"] == ctx)
        r.update(status="rejected", diagnostics=["COV2110"])
        o["profile_inputs"].sort(key=lambda r: (r["status"].encode(), r["artifact_sha256"], r["name"].encode()))
        o["diagnostics"] = ["COV3002"]
        o[S]["complete"] = False

    return {
        "region with a dangling source": (region_dangling_source, "COV3010"),
        "unbound point in another source": (unbound_point_in_another_source, "COV3010"),
        "entry point names a contract entity": (entry_names_a_contract, "COV3010"),
        "inexact aggregate of exact contexts": (inexact_aggregate_of_exact_contexts, "COV3010"),
        "term of another function": (term_of_another_function, "COV3010"),
        "user region without terms": (user_region_without_terms, "COV3010"),
        "unreachable region with terms": (unreachable_region_with_terms, "COV3010"),
        "region evaluates negative": (negative_region, "COV3010"),
        "outcome names an entry point": (outcome_names_an_entry_point, "COV3010"),
        "outcome point used twice": (outcome_point_twice, "COV3010"),
        "outcome of a synthetic point": (outcome_of_a_synthetic_point, "COV3010"),
        "contract entity with two true points": (second_true_point, "COV3010"),
        "clause listed twice": (clause_twice, "COV3010"),
        "runtime clause without its points": (static_clause_made_runtime, "COV3010"),
        "exclusion with a dangling region": (lambda o: affected(o).__setitem__("region_indices", [999]), "COV3010"),
        "exclusion of an unknown point": (lambda o: affected(o).__setitem__("point_ids", ["0" * 64]), "COV3010"),
        "construct excluded twice": (exclusion_twice, "COV3010"),
        "exclusion affecting nothing": (exclusion_empty, "COV3010"),
        "contract_off over regions": (lambda o: o[S]["exclusions"][0].__setitem__("mode", "contract_off"), "COV3010"),
        "off over a clause": (lambda o: affected(o).__setitem__("clause_indices", [0]), "COV3010"),
        "excluded branch without its points": (branch_without_its_points, "COV3010"),
        "branch_off over regions": (lambda o: o[S]["exclusions"][0].__setitem__("mode", "branch_off"), "COV3010"),
        "off over a contract entity": (off_with_a_contract_entity, "COV3010"),
        "excluded region unclaimed": (region_unclaimed, "COV3010"),
        "source in no map": (source_in_no_map, "COV3012"),
        "rejected map input names a map": (rejected_map_names_a_map, "COV3010"),
        "counts of a rejected profile": (counts_of_a_rejected_profile, "COV3010"),
    }


EXTRA_CASES: dict = _extra_cases()


if __name__ == "__main__":
    unittest.main()
