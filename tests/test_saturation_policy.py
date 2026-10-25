# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Saturation policy ``allow-ordinary`` and granular eligibility (CV-404;
SPEC 11.1, 14.2.1, 21.3.8; COV-POL-007..010, COV-POL-027, COV-INS-013,
COV-MET-017, AC-037, AC-038).

- No saturation-derived false pass: a lower bound never exceeds the true
  count, over random expressions and true counts past ``UINT64_MAX``.
- Exact-versus-saturated pairs: the same execution with a counter
  saturated may fail a threshold the exact evidence passes, never the
  reverse, for the region and line metrics and every fixture.
- ``fail`` blocks every check; ``allow-ordinary`` decides only function,
  region, line and branch, and a report with no other exact-count use is
  ``passing``; contract counts, named contexts, exports and ratchets stay
  ineligible.
- Ratchets are an exact-count use under either policy (owner decision,
  CV-404), and a baseline made under the other policy is incompatible.
- The policy and the lower bounds are visible in every human report.
"""

from __future__ import annotations

import io
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_cmd_check import Base as CheckBase  # noqa: E402
from test_indexed_reader import FIXTURES, fixture_inputs, map_input, profile_input, raw  # noqa: E402
from test_ratchet import ratchet_toml  # noqa: E402
from test_report import V, fixture_sources  # noqa: E402

from sv0cov import cli  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.expr import U64_MAX, Count, evaluate, executed  # noqa: E402
from sv0cov.formats.baseline import encode_baseline  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.html import render_html  # noqa: E402
from sv0cov.formats.terminal import render_terminal  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import baseline_body, build_report, read_report  # noqa: E402

ORDINARY = ("branch", "function", "line", "region")
HEAD = '[tool.sv0cov]\nschema = "1.0"\n'


def toml(policy: str, **thresholds: int) -> str:
    out = HEAD + f'[tool.sv0cov.integrity]\nsaturation = "{policy}"\n'
    if thresholds:
        out += "[tool.sv0cov.thresholds]\n" + "".join(f'{k} = "{v}bp"\n' for k, v in thresholds.items())
    return out


def evidence(name: str, policy: str, overrides: dict[str, int] | None = None) -> tuple[bytes, dict]:
    """Indexed bytes of fixture ``name`` with some counts replaced, and its sources."""
    data, m, counts = fixture_inputs(name)
    counts = {**counts, **(overrides or {})}
    ix = build_indexed([map_input(f"{name}.sv0covmap.json", data)], [profile_input("p1.sv0profraw", raw(m, counts, 1), m)],
                       tool_version=V, saturation_policy=policy)
    return encode(ix), fixture_sources(name, ix)


def report_of(data: bytes, sources: dict, text: str, **kw) -> dict:
    r = build_report(data, resolve("check", (), text.encode()), sources, tool_version=V, **kw)
    read_report(encode(r))
    return r


def negative_region(name: str) -> tuple[str, str] | None:
    """(subtracted point, added point) of a region ``b - a`` of the fixture, if any."""
    _, m, _ = fixture_inputs(name)
    for r in m["regions"]:
        terms = r["counter_expression"]["terms"]
        neg = [t["point_id"] for t in terms if t["coefficient"] < 0]
        pos = [t["point_id"] for t in terms if t["coefficient"] > 0]
        if len(neg) == 1 and len(pos) == 1:
            return neg[0], pos[0]
    return None


class NoFalsePassTest(unittest.TestCase):
    def test_a_lower_bound_never_exceeds_the_true_count(self) -> None:
        """COV-POL-027: over random expressions whose true value is a valid
        (nonnegative) count, saturating any inputs keeps the result a sound
        lower bound, and "executed" implies the true count is positive."""
        rng = random.Random(404)
        points = [f"{i:064x}" for i in range(6)]
        checked = 0
        while checked < 20000:
            terms = sorted((rng.choice((-3, -2, -1, 1, 2, 3)), p) for p in rng.sample(points, rng.randint(1, 4)))
            terms = sorted(((c, p) for c, p in terms), key=lambda t: t[1])
            true = {p: rng.choice((0, 1, 7, U64_MAX - 1, U64_MAX, U64_MAX + rng.randint(1, 2**70))) for _, p in terms}
            value = sum(c * true[p] for c, p in terms)
            if value < 0:
                continue  # not an execution sv0c's flow could produce
            seen = {p: Count(U64_MAX, True) if v >= U64_MAX else Count(v, False) for p, v in true.items()}
            got = evaluate(terms, seen)
            if got.inexact:
                self.assertLessEqual(got.value, value, (terms, true))
            else:
                self.assertEqual(got.value, value, (terms, true))
            if executed(got):
                self.assertGreater(value, 0, (terms, true))
            checked += 1

    def test_a_saturated_pair_fails_where_exact_evidence_passes_never_the_reverse(self) -> None:
        """Exact-versus-saturated paired thresholds over every fixture with a
        ``b - a`` region: the same execution, its counters saturated."""
        tried = 0
        for name in FIXTURES:
            pair = negative_region(name)
            if pair is None:
                continue
            a, b = pair
            exact, sources = evidence(name, "allow-ordinary", {a: 5, b: 9})
            sat, _ = evidence(name, "allow-ordinary", {a: U64_MAX, b: U64_MAX})
            with self.subTest(fixture=name):
                e = report_of(exact, sources, toml("allow-ordinary"))
                s = report_of(sat, sources, toml("allow-ordinary"))
                self.assertTrue(s["saturation"]["any"])
                for metric in ("region", "line"):
                    self.assertLessEqual(s["summary"][metric]["covered"], e["summary"][metric]["covered"], metric)
                self.assertLess(s["summary"]["region"]["covered"], e["summary"]["region"]["covered"])
                bp = e["summary"]["region"]["covered"] * 10000 // e["summary"]["region"]["total"]
                passed = report_of(exact, sources, toml("allow-ordinary", region=bp))
                conservative = report_of(sat, sources, toml("allow-ordinary", region=bp))
                result = {x["metric"]: x["result"] for x in conservative["policy"]["evaluations"] if x["assertion_kind"] == "project"}
                self.assertTrue(passed["policy"]["passed"])
                self.assertEqual(result["region"], "fail")
                tried += 1
        self.assertGreaterEqual(tried, 3)


class PolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        _, m, _ = fixture_inputs("f0")
        entry = next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")
        self.fail_data, self.sources = evidence("f0", "fail", {entry: U64_MAX})
        self.ordinary_data, _ = evidence("f0", "allow-ordinary", {entry: U64_MAX})
        self.limits = dict(function=10000, region=5000, line=5000, branch=5000)

    def test_the_default_fails_every_check_and_says_lower_bound(self) -> None:
        """AC-037."""
        r = report_of(self.fail_data, self.sources, toml("fail", **self.limits))
        self.assertEqual(r["saturation"]["policy"], "fail")
        self.assertEqual(r["saturation"]["eligible_metrics"], [])
        self.assertEqual({e["result"] for e in r["policy"]["evaluations"]}, {"ineligible"})
        self.assertEqual(r["evidence_eligibility"], "policy_failed")
        text = render_terminal(r)
        self.assertIn(f">={U64_MAX}", text)
        self.assertIn("Saturation\n----------\npolicy: fail\n", text)
        self.assertIn(f"&gt;={U64_MAX}".encode(), render_html(r, self.sources))
        point = next(p for p in r["points"] if p["count"]["saturated"])
        self.assertEqual((point["count"]["value"], point["count"]["lower_bound"]), (U64_MAX, True))

    def test_allow_ordinary_decides_the_ordinary_metrics_and_can_pass(self) -> None:
        """AC-038: with no other exact-count use the report is passing evidence."""
        r = report_of(self.ordinary_data, self.sources, toml("allow-ordinary", **self.limits))
        self.assertEqual(r["saturation"]["eligible_metrics"], list(ORDINARY))
        self.assertEqual(r["saturation"]["ineligible_uses"], [])
        results = {e["metric"]: e["result"] for e in r["policy"]["evaluations"] if e["assertion_kind"] == "project"}
        self.assertEqual(results, dict.fromkeys(ORDINARY, "pass"))
        self.assertEqual(r["evidence_eligibility"], "passing")
        self.assertEqual(r["resolved_configuration"]["coverage"]["integrity"]["saturation"],
                         {"source": "sv0.toml", "value": "allow-ordinary"})
        self.assertIn("Saturation\n----------\npolicy: allow-ordinary\n", render_terminal(r))
        # the same bytes under the other policy are refused, not reinterpreted
        with self.assertRaises(Exception):
            report_of(self.ordinary_data, self.sources, toml("fail"))

    def test_exports_stay_ineligible(self) -> None:
        r = report_of(self.ordinary_data, self.sources, toml("allow-ordinary"), standard_export=True)
        self.assertEqual(r["saturation"]["ineligible_uses"], ["standard_exports"])
        self.assertEqual(r["evidence_eligibility"], "diagnostic_only")


class RatchetTest(unittest.TestCase):
    """A ratchet is an exact-count use (owner decision, CV-404)."""

    def ratchet_report(self, data: bytes, sources: dict, policy: str, baseline_policy: str) -> dict:
        plain = report_of(evidence("f0", baseline_policy)[0], sources, toml(baseline_policy))
        body = baseline_body(plain, commit=None)
        text = ratchet_toml(metrics=ORDINARY, extra=f'[tool.sv0cov.integrity]\nsaturation = "{policy}"\n').decode()
        return report_of(data, sources, text, ratchet={"ancestor": None, "data": encode_baseline(body), "head": None})

    def test_saturation_makes_every_ratio_ineligible_under_either_policy(self) -> None:
        _, m, _ = fixture_inputs("f0")
        entry = next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")
        for policy in ("allow-ordinary", "fail"):
            with self.subTest(policy=policy):
                data, sources = evidence("f0", policy, {entry: U64_MAX})
                r = self.ratchet_report(data, sources, policy, policy)
                self.assertEqual(r["ratchet"]["state"], "ok")
                self.assertIn("ratchets", r["saturation"]["ineligible_uses"])
                ratios = [e for e in r["policy"]["evaluations"] if e["assertion_kind"] == "ratchet" and e["comparison"] == "at_least"]
                self.assertEqual({(e["result"], tuple(e["diagnostics"])) for e in ratios}, {("ineligible", ("COV4020",))})
                self.assertEqual(r["evidence_eligibility"], "diagnostic_only")

    def test_without_saturation_a_ratchet_is_decided(self) -> None:
        data, sources = evidence("f0", "allow-ordinary")
        r = self.ratchet_report(data, sources, "allow-ordinary", "allow-ordinary")
        self.assertEqual(r["saturation"]["ineligible_uses"], [])
        self.assertTrue(r["policy"]["passed"])

    def test_a_baseline_under_the_other_policy_is_incompatible(self) -> None:
        data, sources = evidence("f0", "allow-ordinary")
        r = self.ratchet_report(data, sources, "allow-ordinary", "fail")
        self.assertEqual(r["ratchet"]["state"], "incompatible")
        self.assertFalse(r["policy"]["passed"])


class CheckTest(CheckBase):
    def test_check_exits_by_policy(self) -> None:
        _, m, _ = fixture_inputs("f0")
        entry = next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")
        self.project(evidence=evidence("f0", "allow-ordinary", {entry: U64_MAX})[0])
        self.assertEqual(self.check("--saturation-policy", "allow-ordinary", "--threshold-function", "100")[0], 0)
        self.project(evidence=evidence("f0", "fail", {entry: U64_MAX})[0])
        code, _, err = self.check("--threshold-function", "100")
        self.assertEqual((code, sorted({r["code"] for r in records(err)})), (1, ["COV4020"]))


    def test_baseline_refuses_saturated_evidence(self) -> None:
        _, m, _ = fixture_inputs("f0")
        entry = next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")
        self.project(evidence=evidence("f0", "allow-ordinary", {entry: U64_MAX})[0])
        (self.cwd / "sv0.toml").write_bytes(ratchet_toml(metrics=ORDINARY, extra='[tool.sv0cov.integrity]\nsaturation = "allow-ordinary"\n'))
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["baseline", "--diagnostic-format=json-lines", "coverage.sv0covdata.json"], stdout=out, stderr=err, cwd=self.cwd)
        self.assertEqual((code, [r["code"] for r in records(err.getvalue())]), (5, ["COV4201"]))
        self.assertFalse((self.cwd / "cov").exists())
        self.put("coverage.sv0covdata.json", evidence("f0", "allow-ordinary")[0])  # the same run, unsaturated
        code = cli.main(["baseline", "coverage.sv0covdata.json"], stdout=io.StringIO(), stderr=err, cwd=self.cwd)
        self.assertEqual(code, 0, err.getvalue())
        self.assertTrue((self.cwd / "cov/baseline.json").is_file())


if __name__ == "__main__":
    unittest.main()
