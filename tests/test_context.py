# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Contexts: aggregate, per-context counts and the context filter (CV-308;
SPEC 17.4, 21.3; COV-CTX-001..004, AC-024).

The oracle for the filter is the evidence itself: the view of context ``c``
of a report must equal, unit for unit, the report built from only the
profiles that carry ``c``. The aggregate never changes because a view was
taken, equals the saturating sum of the contexts, and does not depend on
whether contexts were collected at all.
"""

from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES, U64, fixture_inputs, map_input, profile_input, raw, rich_inputs  # noqa: E402
from test_report import STALE_OK, V, config, fixture_sources  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.model.context import ContextError, context_view  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report, read_report  # noqa: E402

CONTEXTS = (None, "", "shard é", "x" * 256)


def counts_of(rec: dict | None) -> tuple | None:
    return None if rec is None else (rec["value"], rec["lower_bound"], rec["saturated"])


def units(view: dict) -> dict:
    """Everything a context view shows, without context indexes (which differ
    between a full report and a one-context report)."""
    return {
        "points": [(p["point_id"], counts_of(p["count"])) for p in view["points"]],
        "regions": [(x["region_index"], counts_of(x["count"])) for x in view["regions"]],
        "lines": [(x["line_index"], x["status"]) for x in view["lines"]],
        "outcomes": [(b["branch_index"], o["ordinal"], counts_of(o["count"]), o["status"]) for b in view["branches"] for o in b["outcomes"]],
        "contracts": [(c["clause_index"], counts_of(c["count_true"]), counts_of(c["count_false"]), c["runtime_result"])
                      for c in view["contracts"]],
        "summary": view["summary"],
        "sources": [s["summary"] for s in view["sources"]],
        "entities": [e["summary"] for e in view["entities"]],
    }


def scaled(counts: dict[str, int], k: int) -> dict[str, int]:
    """A consistent run: every count of one real run times ``k``."""
    return {pid: v * k for pid, v in counts.items()}


class FixtureContextTest(unittest.TestCase):
    """Every semantic fixture run under four contexts: absent, empty, a
    Unicode label and one of the maximum 256 bytes (COV-CTX-002/003)."""

    def build(self, name: str, which: tuple[int, ...]) -> dict:
        data, m, counts = fixture_inputs(name)
        profiles = [profile_input(f"p{k}.sv0profraw", raw(m, scaled(counts, k), k, context=CONTEXTS[k - 1]), m) for k in which]
        ix = build_indexed([map_input(f"{name}.sv0covmap.json", data)], profiles, tool_version=V)
        return build_report(encode(ix), config(), fixture_sources(name, ix), tool_version=V)

    def test_a_view_equals_the_report_of_that_context_alone(self) -> None:
        """AC-024, COV-CTX-004."""
        for name in FIXTURES:
            with self.subTest(fixture=name):
                full = self.build(name, (1, 2, 3, 4))
                self.assertEqual([c["value"] for c in full["contexts"]], list(CONTEXTS))
                for k in (1, 2, 3, 4):
                    alone = self.build(name, (k,))
                    want = units(context_view(alone, 0))
                    self.assertEqual(units(context_view(full, k - 1)), want, CONTEXTS[k - 1])
                    # The one-context report is its own aggregate.
                    self.assertEqual(want["summary"], alone["summary"])

    def test_taking_views_leaves_the_report_unchanged(self) -> None:
        """COV-CTX-004: filtering never mutates the aggregate."""
        full = self.build("boolean", (1, 2, 3, 4))
        before = copy.deepcopy(full)
        for c in full["contexts"]:
            view = context_view(full, c["context_index"])
            for p in view["points"]:
                p["count"]["value"] = 99
        self.assertEqual(full, before)
        read_report(encode(full))

    def test_the_aggregate_is_the_sum_of_the_contexts(self) -> None:
        """AC-024: the aggregate counts every context."""
        full = self.build("boolean", (1, 2, 3, 4))
        views = [context_view(full, c["context_index"]) for c in full["contexts"]]
        for n, p in enumerate(full["points"]):
            self.assertEqual(p["count"]["value"], sum(v["points"][n]["count"]["value"] for v in views))
        for n, x in enumerate(full["regions"]):
            self.assertEqual(x["count"]["value"], sum(v["regions"][n]["count"]["value"] for v in views))
        _, _, counts = fixture_inputs("boolean")
        self.assertEqual(sum(full["points"][n]["count"]["value"] for n in range(len(full["points"]))), sum(counts.values()) * 10)

    def test_the_aggregate_does_not_depend_on_context_collection(self) -> None:
        """COV-CTX-001: the same runs with and without contexts give one aggregate."""
        data, m, counts = fixture_inputs("boolean")
        reports = []
        for labels in ((None, None, None), ("a", "b", "c"), (None, "", "a")):
            profiles = [profile_input(f"p{k}.sv0profraw", raw(m, scaled(counts, k), k, context=labels[k - 1]), m) for k in (1, 2, 3)]
            ix = build_indexed([map_input("b.sv0covmap.json", data)], profiles, tool_version=V)
            reports.append(build_report(encode(ix), config(), fixture_sources("boolean", ix), tool_version=V))
        agg = [{k: r[k] for k in ("summary", "entities", "sources")} for r in reports]
        self.assertEqual(agg[0], agg[1])
        self.assertEqual(agg[0], agg[2])
        self.assertEqual([counts_of(p["count"]) for p in reports[0]["points"]], [counts_of(p["count"]) for p in reports[1]["points"]])
        self.assertEqual([len(r["contexts"]) for r in reports], [1, 3, 3])

    def test_a_partial_aggregate_line_can_be_covered_in_no_context(self) -> None:
        """A view recomputes status from its own counts: a context that never
        ran a function shows its lines uncovered."""
        data, m, counts = fixture_inputs("boolean")
        entry = {p["point_id"] for p in m["points"] if p["kind"] == "function_entry"
                 and m["entities"][p["entity_index"]]["qualified_name"] == "main"}
        only_main = {pid: v for pid, v in counts.items() if pid in entry}
        profiles = [profile_input("p1.sv0profraw", raw(m, counts, 1, context="all"), m),
                    profile_input("p2.sv0profraw", raw(m, only_main, 2, context="main"), m)]
        ix = build_indexed([map_input("b.sv0covmap.json", data)], profiles, tool_version=V)
        full = build_report(encode(ix), config(), fixture_sources("boolean", ix), tool_version=V)
        index = {c["value"]: c["context_index"] for c in full["contexts"]}
        a, b = context_view(full, index["all"]), context_view(full, index["main"])
        self.assertEqual(a["summary"]["function"]["covered"], full["summary"]["function"]["covered"])
        self.assertEqual(b["summary"]["function"]["covered"], 1)
        self.assertEqual(b["summary"]["branch"]["covered"], 0)
        self.assertGreater(full["summary"]["line"]["covered"], b["summary"]["line"]["covered"])

    def test_an_unknown_context_is_refused(self) -> None:
        full = self.build("boolean", (1,))
        with self.assertRaises(ContextError):
            context_view(full, 1)


class RichContextTest(unittest.TestCase):
    """Two maps, three backends, contracts, an exclusion and a saturated
    counter across three contexts, one of them shared by two profiles."""

    def test_a_view_equals_the_report_of_that_context_alone(self) -> None:
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        full = build_report(encode(ix), config(STALE_OK), {}, tool_version=V)
        self.assertEqual([c["value"] for c in full["contexts"]], [None, "", "shard-1"])
        for c in full["contexts"]:
            mine = [p for p in profiles if p.profile.context == c["value"]]
            ix1 = build_indexed(maps, mine, run_selection=selection, tool_version=V)
            alone = build_report(encode(ix1), config(STALE_OK), {}, tool_version=V)
            with self.subTest(context=c["value"]):
                self.assertEqual(units(context_view(full, c["context_index"])), units(context_view(alone, 0)))
        shared = context_view(full, 2)
        self.assertTrue(any(o["count"]["value"] for b in shared["branches"] for o in b["outcomes"]))
        saturated = context_view(full, 1)
        self.assertTrue(any(p["count"]["saturated"] and p["count"]["value"] == U64 for p in saturated["points"]))


if __name__ == "__main__":
    unittest.main()
