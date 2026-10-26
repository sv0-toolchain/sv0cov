# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The R1 performance budget evaluator and DEC-087 exception records
(CV-410; SPEC 24, 24.1, 24.2; COV-PERF-008/009/023/024/035/036).

Synthetic bundles over a small frozen manifest: a managed-ci-recorded gate
without its exception record is refused; a record must match the
campaigns' own facts and be accepted by a person; provisional evidence
never satisfies a gate; fewer than three recorded campaigns are not
enough; nothing pools across observed hardware, host classes, stages or
toolchain revisions; categories weigh equally; a per-fixture ceiling
failure is visible and fails the gate whatever the aggregate; a failure in
one campaign is not compensated by others; a missing, invalid, one-arm or
pending fixture makes a gate incomplete; and the real corpus today leaves
every gate incomplete rather than passing.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "bench")]

import evaluate as E  # noqa: E402
import harness as H  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402

GATES = ["execution-wall-time", "generated-artifact-size", "instrumented-compile-wall-time", "runtime-counter-memory"]
# Two categories, three fixtures in one and one in the other: equal category weight differs from fixture weight.
FIXTURES = {"a1": "alpha", "a2": "alpha", "a3": "alpha", "b1": "beta"}


def manifest(pending: tuple[str, ...] = ()) -> dict:
    return {"fixtures": [{"applicable_budgets": GATES, "category": c, "id": f, "status": "pending: x" if f in pending else "runnable-baseline"}
                         for f, c in FIXTURES.items()]}


def result(fid: str, dim: str, *, ratio: int = 1_100_000, size: tuple[int, int] = (100, 120), rss: tuple[int, int] = (1000, 2000),
           points: int = 10, valid: bool = True, arms: tuple = ("off", "on")) -> dict:
    stats = lambda wall, mem: {"rss_bytes": {"p95": mem}, "wall_ns": {"p95": wall}}  # noqa: E731
    r = {"arms": list(arms), "category": FIXTURES[fid], "facts": {"artifact_bytes": {"off": size[0], "on": size[1]}, "planned_points": points},
         "id": f"{fid}/{dim}", "invalid_slots": 0, "slots": [], "statistics": {"off": stats(1000, rss[0]), "on": stats(1000 * ratio // 1_000_000, rss[1])},
         "valid": valid}
    if arms == ("off", "on"):
        r["overhead_p95_ratio_ppm"] = ratio
    return r


class Env:
    def __init__(self, man: dict) -> None:
        self.td = tempfile.TemporaryDirectory()
        self.dir = Path(self.td.name)
        self.manifest = self.dir / "manifest.json"
        self.manifest.write_bytes(json.dumps(man).encode())
        self.n = 0

    def bundle(self, fixtures: list[dict], *, stage: str = "managed-ci-recorded", host: dict | None = None) -> Path:
        h = host or H.host_descriptor(stage, "a" * 40)
        b = {"conformance": stage == "reference-dedicated", "corpus": {"manifest_sha256": hashlib.sha256(self.manifest.read_bytes()).hexdigest()},
             "fixtures": fixtures, "host": h, "label": H.LABELS[stage], "protocol_sha256": H.PROTOCOL_SHA256,
             "schema": "sv0cov.benchmark-results", "series": H.series_key(h), "version": "1.0"}
        self.n += 1
        path = self.dir / f"b{self.n}.json"
        path.write_bytes(encode(b))
        return path

    def campaign(self, *, stage: str = "managed-ci-recorded", **overrides) -> list[Path]:
        """A complete campaign: one compile and one execute bundle; ``overrides`` maps 'fid/dim' to result() keywords."""
        out = []
        for dim in ("compile", "execute"):
            out.append(self.bundle([result(f, dim, **overrides.get(f"{f}/{dim}", {})) for f in FIXTURES], stage=stage))
        return out

    def run(self, campaigns, exception=None) -> dict:
        return E.evaluate(campaigns, exception, manifest_path=self.manifest)


def gate(ev: dict, gid: str) -> dict:
    return next(g for g in ev["gates"] if g["id"] == gid)


class EligibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(manifest())
        self.addCleanup(self.env.td.cleanup)

    def record(self, campaigns, gates=GATES) -> dict:
        rec = E.template(self.env.run(campaigns), gates)
        return {**rec, "owner": "sole maintainer", "recorded_on": "2026-10-25", "risk_accepted": "shared managed runner; variance recorded"}

    def test_a_recorded_gate_without_its_record_is_refused(self) -> None:
        cs = [self.env.campaign() for _ in range(3)]
        ev = self.env.run(cs)
        for g in GATES:
            self.assertEqual((gate(ev, g)["result"], gate(ev, g)["eligibility"]), ("pass", "refused"), g)
        self.assertFalse(ev["r1_gates_satisfied"])
        ev = self.env.run(cs, self.record(cs))
        self.assertEqual(ev["exception_problems"], [])
        for g in GATES:
            self.assertEqual(gate(ev, g)["eligibility"], "satisfied", g)
        self.assertEqual(gate(ev, "map-determinism")["result"], "no-evidence")  # not a timing
        self.assertFalse(ev["r1_gates_satisfied"])
        ev = self.env.run(cs, self.record(cs, gates=["execution-wall-time"]))
        self.assertEqual(gate(ev, "execution-wall-time")["eligibility"], "satisfied")
        self.assertEqual(gate(ev, "runtime-counter-memory")["eligibility"], "refused")  # a record covers only the gates it names

    def test_a_record_must_match_the_campaigns_and_name_a_person(self) -> None:
        cs = [self.env.campaign() for _ in range(3)]
        good = self.record(cs)
        other = [self.env.campaign(**{"a1/execute": {"ratio": 1_000_000 + i}}) for i in range(3)]  # different bytes, so other digests
        for what, rec in {
            "other bundles": {**good, "bundles": self.record(other)["bundles"]},
            "another runner": {**good, "runner_label": "elsewhere"},
            "hidden unknowns": {**good, "missing_descriptor_fields": good["missing_descriptor_fields"][1:]},
            "other variance": {**good, "measured_variance": {**good["measured_variance"], GATES[0]: {"campaign_values_ppm": [1], "spread_ppm": 0}}},
            "no owner": {**good, "owner": " "},
            "no risk": {**good, "risk_accepted": ""},
            "no date": {**good, "recorded_on": "yesterday"},
            "extra field": {**good, "waiver": True},
            "another schema": {**good, "schema": "x"},
        }.items():
            with self.subTest(what):
                ev = self.env.run(cs, rec)
                self.assertTrue(ev["exception_problems"])
                self.assertEqual({gate(ev, g)["eligibility"] for g in GATES}, {"refused"})

    def test_provisional_and_local_evidence_never_satisfy(self) -> None:
        for stage in ("managed-ci-provisional", "local-development"):
            with self.subTest(stage):
                ev = self.env.run([self.env.campaign(stage=stage) for _ in range(3)])
                self.assertEqual({gate(ev, g)["eligibility"] for g in GATES}, {"ineligible"})

    def test_three_recorded_campaigns_are_needed_and_one_dedicated_is_enough(self) -> None:
        cs = [self.env.campaign() for _ in range(2)]
        ev = self.env.run(cs, self.record(cs))
        self.assertEqual({gate(ev, g)["eligibility"] for g in GATES}, {"ineligible"})
        ev = self.env.run([self.env.campaign(stage="reference-dedicated")])
        self.assertEqual({gate(ev, g)["eligibility"] for g in GATES}, {"satisfied"})

    def test_nothing_is_pooled(self) -> None:
        h = H.host_descriptor("managed-ci-recorded", "a" * 40)
        moved = {**h, "cpu_model": "another cpu"}
        other_class = {**h, "architecture": "x86_64" if h["architecture"] != "x86_64" else "arm64"}
        other_rev = {**h, "toolchain_revision": "b" * 40}
        base = self.env.campaign()
        for what, host in (("hardware", moved), ("host class", other_class), ("toolchain", other_rev)):
            with self.subTest(what):
                odd = [self.env.bundle([result(f, d) for f in FIXTURES], host=host) for d in ("compile", "execute")]
                with self.assertRaises(E.EvaluationError):
                    self.env.run([base, odd])
        with self.assertRaises(E.EvaluationError):
            self.env.run([base, self.env.campaign(stage="managed-ci-provisional")])


class GateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.env = Env(manifest())
        self.addCleanup(self.env.td.cleanup)

    def test_the_geometric_mean_is_exact(self) -> None:
        self.assertEqual(E._geomean_ppm([1_300_000] * 3), 1_300_000)
        self.assertEqual(E._geomean_ppm([1_000_000, 4_000_000]), 2_000_000)
        self.assertEqual(E._geomean_ppm([2, 3]), 2)  # floor(sqrt 6)

    def test_categories_weigh_equally(self) -> None:
        """alpha's three fixtures at 1.30 and beta's one at 1.10: equal category weight gives
        sqrt(1.30 * 1.10) = 1.196 (pass); equal fixture weight would give 1.248 (fail)."""
        over = {f"a{i}/execute": {"ratio": 1_300_000} for i in (1, 2, 3)}
        over["b1/execute"] = {"ratio": 1_100_000}
        g = gate(self.env.run([self.env.campaign(**over)]), "execution-wall-time")
        self.assertEqual(g["result"], "pass")
        c = g["campaigns"][0]
        self.assertEqual(c["categories"], {"alpha": 1_300_000, "beta": 1_100_000})
        self.assertEqual(c["value_ppm"], 1_195_826)
        self.assertEqual(set(c["fixtures"]), set(FIXTURES))  # every fixture visible

    def test_a_fixture_ceiling_fails_whatever_the_aggregate(self) -> None:
        g = gate(self.env.run([self.env.campaign(**{"a1/execute": {"size": (100, 180)}})]), "generated-artifact-size")
        c = g["campaigns"][0]
        self.assertLessEqual(c["value_ppm"], 1_300_000)  # the aggregate alone would pass
        self.assertEqual((g["result"], c["ceiling_failures"], c["fixtures"]["a1"]["ceiling_failed"]), ("fail", ["a1"], True))

    def test_memory_per_planned_point(self) -> None:
        allowed = 16 * 10 + 8 * 1024 * 1024
        ok = gate(self.env.run([self.env.campaign(**{"a1/execute": {"rss": (0, allowed)}})]), "runtime-counter-memory")
        bad = gate(self.env.run([self.env.campaign(**{"a1/execute": {"rss": (0, allowed + 1)}})]), "runtime-counter-memory")
        self.assertEqual((ok["result"], bad["result"]), ("pass", "fail"))
        self.assertTrue(bad["campaigns"][0]["fixtures"]["a1"]["ceiling_failed"])

    def test_one_failing_campaign_is_not_compensated(self) -> None:
        good = [self.env.campaign(), self.env.campaign()]
        bad = self.env.campaign(**{f"{f}/compile": {"ratio": 1_500_000} for f in FIXTURES})
        g = gate(self.env.run([*good, bad]), "instrumented-compile-wall-time")
        self.assertEqual(g["result"], "fail")
        self.assertEqual([c["result"] for c in g["campaigns"]], ["pass", "pass", "fail"])
        self.assertEqual(g["variance"]["spread_ppm"], 400_000)

    def test_a_missing_invalid_one_arm_or_pending_fixture_is_incomplete(self) -> None:
        cases = {"invalid": self.env.campaign(**{"a1/execute": {"valid": False}}),
                 "one arm": self.env.campaign(**{"a1/execute": {"arms": ("off",)}}),
                 "missing": [self.env.bundle([result(f, "compile") for f in FIXTURES]),
                             self.env.bundle([result(f, "execute") for f in FIXTURES if f != "a2"])]}
        for what, c in cases.items():
            with self.subTest(what):
                self.assertEqual(gate(self.env.run([c]), "execution-wall-time")["result"], "incomplete")
        env = Env(manifest(pending=("b1",)))
        self.addCleanup(env.td.cleanup)
        g = gate(env.run([env.campaign()]), "execution-wall-time")
        self.assertEqual((g["result"], g["campaigns"][0]["pending"]), ("incomplete", ["b1"]))

    def test_the_real_corpus_is_not_complete_yet(self) -> None:
        """Pending fixtures (contention, verified contracts, timed merge and reports) and VM
        dispatch keep every gate incomplete today: nothing passes by omission."""
        man = json.loads(E.MANIFEST.read_bytes())
        for gid in GATES:
            runnable, pending = E._applicable(man, gid)
            with self.subTest(gid):
                self.assertTrue(pending or gid == "generated-artifact-size")
        self.assertIn("contention-shared-8t", E._applicable(man, "execution-wall-time")[1])


class CommandTest(unittest.TestCase):
    def test_the_template_is_filled_except_the_human_parts(self) -> None:
        env = Env(manifest())
        self.addCleanup(env.td.cleanup)
        cs = [env.campaign() for _ in range(3)]
        rec = E.template(env.run(cs))
        self.assertEqual((rec["owner"], rec["risk_accepted"], rec["recorded_on"]), ("", "", ""))
        self.assertEqual(rec["host_class"], E.host_class(H.host_descriptor("managed-ci-recorded")))
        self.assertEqual(len(rec["bundles"]), 6)
        self.assertTrue(E.check_exception(rec, env.run(cs)["facts"]))  # unusable until a person accepts it


if __name__ == "__main__":
    unittest.main()
