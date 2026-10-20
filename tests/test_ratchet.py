# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Ratchets (CV-313; SPEC 22.4, 14.2.1; COV-POL-005, BL-051, AC-017).

- the ``sv0cov.baseline`` 1.0 artifact: round trip, its pin, and every rule;
- the comparison on every semantic fixture and on the excluded-function
  sample: exact fractions at the tolerance boundary, numerator regression,
  denominator growth, exclusion growth (AC-017), source-set change, and a
  missing, invalid, incompatible or stale baseline, each told apart in the
  report's ``ratchet`` record and failing exactly as decided;
- the reader re-deriving all of it;
- the ``baseline`` command (deltas printed before an atomic replace, refusals)
  and ``check`` against it, in and outside Git.
"""

from __future__ import annotations

import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_gitdiff import Fx, fixture_env  # noqa: E402
from test_indexed_reader import FIXTURES, simple  # noqa: E402
from test_report import V, fixture_sources  # noqa: E402
from test_scopes import Case  # noqa: E402

from sv0cov import cli, gitdiff  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.baseline import BaselineError, decode_baseline, encode_baseline, pin  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.html import check_html, render_html  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.formats.terminal import render_terminal  # noqa: E402
from sv0cov.model.report import baseline_body, build_report, excluded_units, ratchet_limit, read_report  # noqa: E402

HAVE_GIT = shutil.which("git") is not None
HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
METRICS = ("branch", "contract", "function", "line", "region")
EVIDENCE = "coverage.sv0covdata.json"
BASELINE = "cov/baseline.json"


def ratchet_toml(metrics=METRICS, tolerance: int = 0, extra: str = "") -> bytes:
    return (HEAD + extra + f'[tool.sv0cov.ratchet]\nbaseline = "{BASELINE}"\nmetrics = {json.dumps(list(metrics))}\n'
            f"tolerance_basis_points = {tolerance}\n").encode()


def cfg(**kw):
    return resolve("check", (), ratchet_toml(**kw))


def evals(report: dict) -> dict[tuple[str, str], dict]:
    return {(e["metric"], e["comparison"]): e for e in report["policy"]["evaluations"] if e["assertion_kind"] == "ratchet"}


class Base(unittest.TestCase):
    def plain(self, case: Case, config=None) -> dict:
        """The report of ``case`` with no ratchet: what a baseline is made from."""
        return build_report(case.indexed, config or resolve("check", (), None), case.sources, tool_version=V)

    def body(self, case: Case, **changes) -> dict:
        b = baseline_body(self.plain(case), commit=None)
        for path, value in changes.items():
            node = b
            *keys, last = path.split("__")
            for k in keys:
                node = node[k]
            node[last] = value
        return b

    def compare(self, case: Case, data: bytes | None, config=None, head=None, ancestor=None) -> dict:
        report = build_report(case.indexed, config or cfg(), case.sources, tool_version=V,
                              ratchet={"ancestor": ancestor, "data": data, "head": head})
        self.assertEqual(read_report(encode(report)), report)
        return report


class FormatTest(Base):
    def test_round_trip_and_pin(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                body = self.body(Case.fixture(name))
                data = encode_baseline(body)
                got = decode_baseline(data)
                self.assertEqual({k: v for k, v in got.items() if k != "baseline_sha256"}, body)
                self.assertEqual(got["baseline_sha256"], pin(got))
                self.assertEqual(encode(got), data)

    def test_every_rule(self) -> None:
        good = decode_canonical(encode_baseline(self.body(Case.fixture("project"))))

        def bad(fn, why=""):
            obj = copy.deepcopy(good)
            fn(obj)
            with self.assertRaises(BaselineError, msg=why):
                decode_baseline(encode(obj))

        bad(lambda o: o["metrics"]["line"].__setitem__("covered", 10**6), "a count changed: the pin no longer matches")
        bad(lambda o: o.__setitem__("commit", "A" * 40))
        bad(lambda o: o.__setitem__("commit", "a" * 41))
        bad(lambda o: o.__setitem__("baseline_sha256", "x" * 64))
        bad(lambda o: o.__setitem__("metric_schema", "a\tb"))
        bad(lambda o: o["tool"].__setitem__("version", "1 0"))
        bad(lambda o: o["sources"].reverse())
        bad(lambda o: o["sources"].append(o["sources"][0]))
        bad(lambda o: o["sources"][0].__setitem__("path", "../x.sv0"))
        bad(lambda o: o["sources"][0].__setitem__("digest", "q" * 64))
        bad(lambda o: o.__setitem__("schema", "sv0cov.report"))
        bad(lambda o: o.__setitem__("version", "2.0"))
        bad(lambda o: o.__setitem__("extra", 1))
        bad(lambda o: o.pop("commit"))

        def over(o):  # covered over total, re-pinned so only that rule can fail
            o["metrics"]["line"]["covered"] = o["metrics"]["line"]["total"] + 1
            o["baseline_sha256"] = pin(o)
        bad(over)
        with self.assertRaises(BaselineError):
            decode_baseline(b'{"a": 1}')  # not canonical
        with self.assertRaises(BaselineError):
            encode_baseline({**self.body(Case.fixture("f0")), "commit": "nope"})


class CompareTest(Base):
    def test_the_same_evidence_holds_on_every_fixture(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                case = Case.fixture(name)
                report = self.compare(case, encode_baseline(self.body(case)))
                t = report["ratchet"]
                self.assertEqual((t["state"], t["sources_added"], t["sources_removed"]), ("ok", [], []))
                self.assertEqual([c["outcomes"] for c in t["comparisons"]], [[]] * 5)
                for (metric, comparison), e in evals(report).items():
                    empty = comparison == "at_least" and report["summary"][metric]["total"] == 0
                    self.assertEqual((e["result"], e["diagnostics"]), ("fail", ["COV4102"]) if empty else ("pass", []), (metric, comparison))
                self.assertEqual(len(evals(report)), 11)  # five ratios, five excluded-unit counts, the records

    def test_exact_tolerance_boundary(self) -> None:
        case = Case.fixture("branches")
        now = self.plain(case)["summary"]["line"]
        self.assertTrue(0 < now["covered"] < now["total"])
        # A baseline 1 covered line better: the ratio drop in basis points, rounded up, is exactly enough.
        old = {"covered": now["covered"] + 1, "total": now["total"]}
        drop = 10000 * 1 / now["total"]
        need = -(-10000 // now["total"])  # ceil
        for tolerance, result in ((need, "pass"), (need - 1, "fail")):
            with self.subTest(tolerance=tolerance):
                b = self.body(case, metrics__line__covered=old["covered"])
                e = evals(self.compare(case, encode_baseline(b), cfg(metrics=["line"], tolerance=tolerance)))[("line", "at_least")]
                self.assertEqual(e["result"], result, drop)
                self.assertEqual(e["limit"], ratchet_limit({"covered": old["covered"], "total": old["total"]}, tolerance))
                self.assertEqual(e["diagnostics"], [] if result == "pass" else ["COV4201"])
        self.assertEqual(ratchet_limit({"covered": 1, "total": 3}, 10000), {"denominator": 1, "numerator": 0})
        self.assertEqual(ratchet_limit({"covered": 0, "total": 0}, 0), {"denominator": 1, "numerator": 0})
        self.assertEqual(ratchet_limit({"covered": 2, "total": 4}, 0), {"denominator": 2, "numerator": 1})

    def test_numerator_regression_and_denominator_growth_are_told_apart(self) -> None:
        case = Case.fixture("branches")
        now = self.plain(case)["summary"]["line"]
        # Denominator growth, ratio held: the baseline had fewer lines at a lower ratio.
        grow = self.compare(case, encode_baseline(self.body(case, metrics__line__total=now["total"] - 1,
                                                            metrics__line__covered=now["covered"] - 1)))
        line = next(c for c in grow["ratchet"]["comparisons"] if c["metric"] == "line")
        self.assertEqual(line["outcomes"], ["denominator_growth"])
        self.assertEqual(evals(grow)[("line", "at_least")]["result"], "pass")
        # Numerator regression: the same lines, more of them covered then.
        fall = self.compare(case, encode_baseline(self.body(case, metrics__line__covered=now["covered"] + 1)))
        line = next(c for c in fall["ratchet"]["comparisons"] if c["metric"] == "line")
        self.assertEqual(line["outcomes"], ["numerator_regression"])
        e = evals(fall)[("line", "at_least")]
        self.assertEqual((e["result"], e["diagnostics"], e["threshold_source"]), ("fail", ["COV4201"], "ratchet"))
        self.assertEqual(e["actual"], {"denominator": now["total"], "numerator": now["covered"]})
        self.assertFalse(fall["policy"]["passed"])
        self.assertEqual(fall["evidence_eligibility"], "policy_failed")

    def test_ac017_exclusion_growth_is_not_silently_accepted(self) -> None:
        """The sample has a function excluded by an attribute. Its baseline is the
        same program before the exclusion: one more uncovered function, no record."""
        case = Case.sample()
        now = self.plain(case)
        self.assertEqual(excluded_units(now, "function"), 1)
        self.assertEqual(len(now["exclusions"]), 1)
        f = now["summary"]["function"]
        b = self.body(case, metrics__function__total=f["total"] + 1, metrics__function__excluded=0, exclusion_records=0)
        for m in ("region", "line", "branch", "contract"):
            b["metrics"][m]["excluded"] = 0
            b["metrics"][m]["total"] += excluded_units(now, m)
        report = self.compare(case, encode_baseline(b))
        ev = evals(report)
        ratio = ev[("function", "at_least")]
        self.assertEqual(ratio["result"], "pass")  # the percentage improved...
        self.assertGreater(f["covered"] * (f["total"] + 1), f["covered"] * f["total"])
        growth = ev[("function", "at_most")]  # ...but the exclusion growth fails
        self.assertEqual((growth["result"], growth["diagnostics"]), ("fail", ["COV4201"]))
        self.assertEqual((growth["actual"], growth["limit"]), ({"denominator": 1, "numerator": 1}, {"denominator": 1, "numerator": 0}))
        self.assertEqual(growth["members"]["entity_indices"], [e["entity_index"] for e in now["entities"]
                                                                  if e["kind"] == "function" and e["summary"]["function"]["total"] == 0])
        records = ev[("exclusion_records", "at_most")]
        self.assertEqual(records["result"], "fail")
        outcomes = {c["metric"]: c["outcomes"] for c in report["ratchet"]["comparisons"]}
        self.assertIn("exclusion_growth", outcomes["function"])
        self.assertFalse(report["policy"]["passed"])
        # Accepted only by an explicit baseline update: a baseline of this report holds.
        again = self.compare(case, encode_baseline(baseline_body(now, commit=None)))
        self.assertTrue(all(e["result"] == "pass" for e in evals(again).values()))

    def test_a_source_set_change_makes_every_ratio_ineligible(self) -> None:
        case = Case.fixture("project")
        body = self.body(case)
        renamed = copy.deepcopy(body)
        renamed["sources"][0]["path"] = "lib/renamed.sv0"
        renamed["sources"].sort(key=lambda s: s["path"].encode())
        report = self.compare(case, encode_baseline(renamed))
        t = report["ratchet"]
        self.assertEqual((t["sources_added"], t["sources_removed"]), (["lib/util.sv0"], ["lib/renamed.sv0"]))
        for (metric, comparison), e in evals(report).items():
            if comparison == "at_least":
                self.assertEqual((e["result"], e["diagnostics"]), ("ineligible", ["COV4201"]), metric)
            else:
                self.assertEqual(e["result"], "pass", metric)  # exclusions did not grow
        self.assertFalse(report["policy"]["passed"])

    def test_unusable_baselines(self) -> None:
        case = Case.fixture("f0")
        good = encode_baseline(self.body(case))
        tampered = good.replace(b'"covered":', b'"covered": ', 1)
        resealed = encode_baseline(self.body(case, metric_schema="sv0cov.report 2.0"))
        allow = encode_baseline(self.body(case, saturation_policy="allow-ordinary"))
        at = encode_baseline({**self.body(case), "commit": "a" * 40})
        cases = [
            ("missing", None, {}), ("invalid", b"not json", {}), ("invalid", tampered, {}),
            ("invalid", good.replace(b'"line":{"covered":', b'"line":{"covered":1', 1), {}),
            ("incompatible", resealed, {}), ("incompatible", allow, {}),
            ("stale", at, {"head": "b" * 40, "ancestor": False}), ("stale", at, {"head": None, "ancestor": False}),
            ("ok", at, {"head": "b" * 40, "ancestor": True}),
        ]
        for state, data, git in cases:
            with self.subTest(state=state, git=git):
                report = self.compare(case, data, **git)
                t = report["ratchet"]
                self.assertEqual(t["state"], state)
                self.assertEqual(t["baseline_sha256"] is None, data is None)
                ev = evals(report)
                if state == "ok":
                    # Every comparison holds; contract is empty now and then, so it follows the empty policy (fail).
                    self.assertEqual({k for k, e in ev.items() if e["result"] != "pass"}, {("contract", "at_least")})
                    self.assertEqual(ev[("contract", "at_least")]["diagnostics"], ["COV4102"])
                    continue
                self.assertEqual(sorted(ev), sorted([(m, "none") for m in METRICS] + [("exclusion_records", "none")]))
                for e in ev.values():
                    self.assertEqual((e["result"], e["diagnostics"], e["limit"]), ("ineligible", ["COV4201"], None))
                self.assertEqual((t["comparisons"], t["sources_added"]), ([], []))

    def test_only_configured_metrics_are_evaluated(self) -> None:
        case = Case.fixture("loops")
        report = self.compare(case, encode_baseline(self.body(case)), cfg(metrics=["region", "branch"]))
        self.assertEqual(sorted(evals(report)), [("branch", "at_least"), ("branch", "at_most"), ("exclusion_records", "at_most"),
                                                 ("region", "at_least"), ("region", "at_most")])
        self.assertEqual(len(report["ratchet"]["comparisons"]), 5)  # every metric is still compared

    def test_a_ratchet_input_is_given_exactly_with_a_ratchet_policy(self) -> None:
        case = Case.fixture("f0")
        with self.assertRaises(ValueError):
            build_report(case.indexed, cfg(), case.sources, tool_version=V)
        with self.assertRaises(ValueError):
            build_report(case.indexed, resolve("check", (), None), case.sources, tool_version=V,
                         ratchet={"ancestor": None, "data": None, "head": None})
        self.assertIsNone(self.plain(case)["ratchet"])

    def test_the_reader_rederives_everything(self) -> None:
        case = Case.sample()
        now = self.plain(case)
        b = baseline_body(now, commit="c" * 40)
        b["metrics"]["line"]["covered"] = max(0, b["metrics"]["line"]["covered"] - 1)
        report = self.compare(case, encode_baseline(b), head="d" * 40, ancestor=True)
        n = next(i for i, e in enumerate(report["policy"]["evaluations"]) if e["assertion_kind"] == "ratchet")

        def edited(fn):
            r = copy.deepcopy(report)
            fn(r)
            return r

        cases = {
            "an outcome added": lambda r: r["ratchet"]["comparisons"][3]["outcomes"].append("numerator_regression"),
            "baseline counts": lambda r: r["ratchet"]["baseline"]["metrics"]["line"].__setitem__("covered", 0),
            "a source added": lambda r: r["ratchet"]["sources_added"].append("zzz.sv0"),
            "ok called stale": lambda r: r["ratchet"].__setitem__("state", "stale"),
            "ok called incompatible": lambda r: r["ratchet"].__setitem__("state", "incompatible"),
            "another schema left ok": lambda r: r["ratchet"]["baseline"].__setitem__("metric_schema", "other"),
            "an evaluation removed": lambda r: r["policy"]["evaluations"].pop(n),
            "a limit changed": lambda r: r["policy"]["evaluations"][n].__setitem__("limit", {"denominator": 1, "numerator": 0}),
            "the record removed": lambda r: r.__setitem__("ratchet", None),
        }
        for what, fn in cases.items():
            with self.subTest(what):
                with self.assertRaises(ReportError) as cm:
                    read_report(encode(edited(fn)))
                self.assertIn(cm.exception.code, ("COV4001", "COV4002"))

    def test_terminal_and_html(self) -> None:
        case = Case.sample()
        b = baseline_body(self.plain(case), commit="c" * 40)
        b["metrics"]["line"]["covered"] += 1
        b["metrics"]["line"]["total"] += 1
        report = self.compare(case, encode_baseline(b), head="d" * 40, ancestor=True)
        line = next(x for x in render_terminal(report).splitlines() if x.startswith("ratchet:"))
        self.assertIn("baseline sha256", line)
        self.assertIn("made at cccccccccccc", line)
        self.assertIn("line numerator regression", line)
        page = render_html(report, case.sources)
        check_html(page)
        self.assertIn(b"Ratchet baseline", page)
        self.assertIn(b"numerator regression", page)
        missing = self.compare(case, None)
        self.assertIn("ratchet:    no baseline", render_terminal(missing))
        check_html(render_html(missing, case.sources))


class CommandTest(unittest.TestCase):
    """``sv0cov baseline`` and ``check`` against what it wrote."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cwd = Path(tmp.name).resolve() / "proj"
        self.cwd.mkdir()
        env = mock.patch.dict(os.environ, fixture_env())
        env.start()
        self.addCleanup(env.stop)

    def project(self, name: str = "branches", toml: bytes | None = None) -> dict:
        ix = simple(name)
        for path, data in fixture_sources(name, ix).items():
            (self.cwd / path).parent.mkdir(parents=True, exist_ok=True)
            (self.cwd / path).write_bytes(data)
        (self.cwd / EVIDENCE).write_bytes(encode(ix))
        (self.cwd / "sv0.toml").write_bytes(toml or ratchet_toml(metrics=["line", "branch"]))
        return ix

    def cmd(self, *args: str) -> tuple[int, str, list[dict]]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main([args[0], "--diagnostic-format=json-lines", *args[1:]], stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), records(err.getvalue())

    def test_write_then_check_then_update(self) -> None:
        self.project()
        code, out, diags = self.cmd("check", EVIDENCE)
        self.assertEqual(code, cli.EXIT_POLICY)
        self.assertEqual({d["code"] for d in diags}, {"COV4201"})
        self.assertTrue(all({"name": "baseline", "value": "missing"} in d["facts"] for d in diags))
        code, out, diags = self.cmd("baseline", EVIDENCE)
        self.assertEqual((code, diags), (cli.EXIT_OK, []))
        self.assertIn("was none", out)
        self.assertIn("exclusion records: - -> 0", out)
        self.assertLess(out.index("metric"), out.index(f"wrote {BASELINE}"))  # the deltas come before the write
        data = (self.cwd / BASELINE).read_bytes()
        b = decode_baseline(data)
        self.assertIsNone(b["commit"])  # not a Git work tree
        self.assertEqual(os.stat(self.cwd / BASELINE).st_mode & 0o777, 0o600)
        self.assertEqual(self.cmd("check", EVIDENCE)[0], cli.EXIT_OK)
        # Updating replaces the file, prints the old values, and leaves no temporary.
        code, out, _ = self.cmd("baseline", EVIDENCE)
        self.assertEqual(code, cli.EXIT_OK)
        self.assertIn("was ok", out)
        self.assertIn("covered 0, total 0, excluded 0", out)
        self.assertEqual((self.cwd / BASELINE).read_bytes(), data)
        self.assertEqual(sorted(os.listdir(self.cwd / "cov")), ["baseline.json"])

    def test_a_failing_check_names_why(self) -> None:
        self.project()
        self.assertEqual(self.cmd("baseline", EVIDENCE)[0], cli.EXIT_OK)
        b = decode_baseline((self.cwd / BASELINE).read_bytes())
        body = {k: v for k, v in b.items() if k != "baseline_sha256"}
        body["metrics"]["line"]["covered"] += 1
        (self.cwd / BASELINE).write_bytes(encode_baseline(body))
        code, _, diags = self.cmd("check", EVIDENCE)
        self.assertEqual(code, cli.EXIT_POLICY)
        (d,) = diags
        facts = {f["name"]: f["value"] for f in d["facts"]}
        self.assertEqual((facts["metric"], facts["baseline"], facts["outcomes"]), ("line", "ok", "numerator_regression"))

    def test_refusals(self) -> None:
        self.project(toml=HEAD.encode())
        code, _, diags = self.cmd("baseline", EVIDENCE)
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_USAGE, ["COV0001"]))
        self.assertFalse((self.cwd / "cov").exists())
        self.project()
        (self.cwd / "main.sv0").write_bytes(b"changed")
        code, _, diags = self.cmd("baseline", EVIDENCE)
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_EVIDENCE, ["COV1004"]))
        self.assertFalse((self.cwd / "cov").exists())
        self.project()
        (self.cwd / "cov").mkdir()
        os.symlink(self.cwd / "elsewhere.json", self.cwd / BASELINE)
        code, _, diags = self.cmd("baseline", EVIDENCE)
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_REPORT, ["COV6002"]))  # a symlink is never replaced
        self.assertFalse((self.cwd / "elsewhere.json").exists())
        self.assertTrue((self.cwd / BASELINE).is_symlink())
        code, _, _ = self.cmd("baseline", "--quiet", EVIDENCE)
        self.assertEqual(code, cli.EXIT_USAGE)  # the deltas are always printed

    def test_baseline_is_not_advertised(self) -> None:
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(cli.main(["version", "--json"], stdout=out, stderr=err, cwd=self.cwd), 0)
        self.assertNotIn("baseline", json.loads(out.getvalue())["commands"])

    @unittest.skipUnless(HAVE_GIT, "git is not installed")
    def test_git_commit_and_staleness(self) -> None:
        f = Fx(str(self.cwd.parent), name="proj")
        self.project()
        f.commit("start")
        self.assertEqual(self.cmd("baseline", EVIDENCE)[0], cli.EXIT_OK)
        made = decode_baseline((self.cwd / BASELINE).read_bytes())["commit"]
        self.assertEqual(made, f.rev("HEAD"))
        self.assertEqual(gitdiff.head_commit(self.cwd), made)
        f.commit("baseline")
        f.w("notes.txt", "later")
        f.commit("later")
        self.assertEqual(self.cmd("check", EVIDENCE)[0], cli.EXIT_OK)  # made at an ancestor of HEAD
        f.git("checkout", "-q", "--orphan", "other")
        f.commit("unrelated history")
        code, out, diags = self.cmd("check", EVIDENCE)
        self.assertEqual(code, cli.EXIT_POLICY)
        self.assertTrue(all({"name": "baseline", "value": "stale"} in d["facts"] for d in diags))
        self.assertIn("stale baseline", out)
        self.assertTrue(gitdiff.is_ancestor(self.cwd, f.rev("HEAD"), f.rev("HEAD")))
        self.assertFalse(gitdiff.is_ancestor(self.cwd, "0" * 40, f.rev("HEAD")))
        self.assertIsNone(gitdiff.head_commit(self.cwd.parent))


if __name__ == "__main__":
    unittest.main()
