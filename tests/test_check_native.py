# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""``check`` on a native report (CV-416; owner decision D-10; SPEC 20.1,
16.5 amendment owed).

A native-report operand is read through the cross-validating reader and its
detail re-evaluated under the invoking configuration and against the
current sources. The acceptance: it gives exactly what the indexed profile
it came from gives, for every fixture and every kind of assertion (project,
scope, entity, changed-region, ratchet, exclusion, saturation, contracts,
contexts, dependency sources), whatever configuration the report was made
under. Its recorded verdict and source states are never reused; an
invalid report is invalid evidence; ``report`` and ``baseline`` still take
only an indexed profile.
"""

from __future__ import annotations

import io
import json
import shutil
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_changed as tch  # noqa: E402  (the module, so its test classes are not collected twice)
from test_cli import records  # noqa: E402
from test_cmd_check import EVIDENCE, Base  # noqa: E402
from test_indexed_reader import FIXTURES, rich, simple  # noqa: E402
from test_ratchet import ratchet_toml  # noqa: E402
from test_report import STALE_OK, V, fixture_sources, thresholds  # noqa: E402
from test_saturation_policy import evidence  # noqa: E402
from test_scopes import Case, entity, scope  # noqa: E402

from sv0cov import cli  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.expr import U64_MAX  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.model.report import baseline_body, build_report, read_report, rebuild_report  # noqa: E402
from sv0cov.formats.baseline import encode_baseline  # noqa: E402

HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
NATIVE = "coverage.json"


def cfg(toml: str = "", options=()):
    return resolve("check", tuple(options), (HEAD + toml).encode() if toml else None)


CONFIGS = {
    "default": ("", ()),
    "thresholds": (thresholds(function=100, region=80, line=90, branch=50, contract=100), ()),
    "empty fails": ('[tool.sv0cov]\nempty = "fail"\n'.replace("[tool.sv0cov]\n", "") + thresholds(contract=100), ()),
    "flag thresholds": ("", (("--threshold-line", "8750bp"), ("--threshold-branch", "67"))),
}


class EqualityTest(unittest.TestCase):
    """The model: ``rebuild_report`` of any report equals ``build_report`` of its evidence."""

    def same(self, indexed: bytes, sources: dict, made: object, now: object, **kw) -> dict:
        original = build_report(indexed, made, sources, tool_version=V, **kw)
        want = build_report(indexed, now, sources, tool_version=V, **kw)
        got = rebuild_report(encode(original), now, sources, tool_version=V, **kw)
        self.assertEqual(encode(got), encode(want))
        return got

    def test_every_fixture_under_every_pair_of_configurations(self) -> None:
        for name in FIXTURES:
            ix = simple(name)
            indexed, sources = encode(ix), fixture_sources(name, ix)
            for made, (mt, mo) in CONFIGS.items():
                for now, (nt, no) in CONFIGS.items():
                    with self.subTest(fixture=name, made=made, now=now):
                        self.same(indexed, sources, cfg(mt, mo), cfg(nt, no))

    def test_scopes_entities_contracts_and_exclusions(self) -> None:
        case = Case.sample()
        toml = (thresholds(line=50, contract=100) + scope("everything", include=["**"], branch=51)
                + scope("sign", sources=["src/sign.sv0"], branch=50) + entity("div", "src/math.sv0", "div", line=100))
        got = self.same(case.indexed, case.sources, cfg(), cfg(toml))
        kinds = {e["assertion_kind"] for e in got["policy"]["evaluations"]}
        self.assertLessEqual({"entity", "integrity", "project", "scope"}, kinds)
        self.assertTrue(got["exclusions"] and got["contracts"])

    def test_contexts_saturation_and_stale_sources(self) -> None:
        indexed = encode(rich())
        for opts in (STALE_OK, [*STALE_OK, ("--allow-lossy-saturated-export", None)]):
            with self.subTest(opts=opts):
                rcfg = resolve("report", tuple(opts))  # check cannot allow a stale source; report can
                got = self.same(indexed, {}, rcfg, rcfg, standard_export=True)
                self.assertTrue(got["saturation"]["any"])
                self.assertEqual(got["provenance"]["source_accuracy"], "mismatch_allowed")

    def test_incomplete_evidence_and_failed_commands(self) -> None:
        """The evidence findings and the execution record come back from the report."""
        from test_indexed_reader import fixture_inputs, map_input, profile_input, raw
        from sv0cov.model.indexed import build_indexed
        from sv0cov.model.merge import Artifact, merge
        data, m, counts = fixture_inputs("f0")
        good, cut = raw(m, counts, 1), raw(m, counts, 2)[:-9]
        srcs = fixture_sources("f0", simple("f0"))
        cases = {
            "a rejected input": merge([Artifact("m", data)], [Artifact("a", good), Artifact("cut", cut)], allow_rejected_inputs=True,
                                      tool_version=V).data,
            "the override alone": merge([Artifact("m", data)], [Artifact("a", good)], allow_rejected_inputs=True, tool_version=V).data,
            "two undeclared runs": merge([Artifact("m", data)], [Artifact("a", good), Artifact("b", raw(m, counts, 3, run="f" * 32))],
                                         tool_version=V).data,
            "no input": merge([], [], tool_version=V).data,
        }
        for status, execution in (("failed", {"exit_code": 3, "signal": None, "status": "failed"}),
                                  ("signaled", {"exit_code": None, "signal": 9, "status": "signaled"}),
                                  ("passed", {"exit_code": 0, "signal": None, "status": "passed"})):
            cases[status] = encode(build_indexed([map_input("m.sv0covmap.json", data)], [profile_input("a", good, m)], execution=execution,
                                                 tool_version=V))
        for label, indexed in cases.items():
            with self.subTest(case=label):
                sources = srcs if label != "no input" else {}
                got = self.same(indexed, sources, cfg(), cfg(thresholds(line=1)))
                integrity = next(e for e in got["policy"]["evaluations"] if e["assertion_kind"] == "integrity")
                if label not in ("passed",):
                    self.assertNotEqual(integrity["diagnostics"], [], label)

    def test_allow_ordinary_evidence(self) -> None:
        _, sources = evidence("f0", "allow-ordinary")
        from test_indexed_reader import fixture_inputs
        _, m, _ = fixture_inputs("f0")
        entry = next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")
        data, _ = evidence("f0", "allow-ordinary", {entry: U64_MAX})
        toml = '[tool.sv0cov.integrity]\nsaturation = "allow-ordinary"\n'
        got = self.same(data, sources, cfg(toml), cfg(toml + thresholds(function=100, line=50)))
        self.assertEqual(got["evidence_eligibility"], "passing")

    def test_dependency_sources(self) -> None:
        from test_default_scope import _sources
        from test_default_scope import DefaultScopeTest
        DefaultScopeTest.setUpClass()
        r = DefaultScopeTest.report
        got = rebuild_report(encode(r), cfg(thresholds(line=1)), _sources(), tool_version=V)
        self.assertEqual({s["ownership"] for s in got["sources"]}, {"user", "dependency"})
        self.assertEqual(got["summary"], r["summary"])  # dependency units stay out of the project, as before

    def test_changed_regions(self) -> None:
        name = "f0"
        ix = simple(name)
        indexed, sources = encode(ix), fixture_sources(name, ix)
        changes = tch.capture_record(sources, {"main.sv0": [11, 12, 16, 24]})
        dc = tch.diff_config(line=50, region=0, branch=0)
        original = build_report(indexed, dc, sources, tool_version=V, changes=changes)
        got = rebuild_report(encode(original), dc, sources, tool_version=V, changes=changes)
        self.assertEqual(encode(got), encode(original))
        self.assertTrue([e for e in got["policy"]["evaluations"] if e["assertion_kind"] == "diff"])
        # a report made without a diff policy is re-evaluated under one
        plain = build_report(indexed, cfg(), sources, tool_version=V)
        self.assertEqual(encode(rebuild_report(encode(plain), dc, sources, tool_version=V, changes=changes)), encode(original))

    def test_ratchets(self) -> None:
        case = Case.fixture("f0")
        body = baseline_body(build_report(case.indexed, cfg(), case.sources, tool_version=V), commit=None)
        rcfg = resolve("check", (), ratchet_toml())
        ratchet = {"ancestor": None, "data": encode_baseline(body), "head": None}
        want = build_report(case.indexed, rcfg, case.sources, tool_version=V, ratchet=ratchet)
        plain = build_report(case.indexed, cfg(), case.sources, tool_version=V)
        self.assertEqual(encode(rebuild_report(encode(plain), rcfg, case.sources, tool_version=V, ratchet=ratchet)), encode(want))
        self.assertEqual(want["ratchet"]["state"], "ok")

    def test_the_recorded_verdict_is_not_reused(self) -> None:
        name = "f0"
        ix = simple(name)
        indexed, sources = encode(ix), fixture_sources(name, ix)
        passing = build_report(indexed, cfg(), sources, tool_version=V)
        self.assertTrue(passing["policy"]["passed"])
        strict = rebuild_report(encode(passing), cfg(thresholds(line=100)), sources, tool_version=V)
        self.assertFalse(strict["policy"]["passed"])
        failing = build_report(indexed, cfg(thresholds(line=100)), sources, tool_version=V)
        self.assertTrue(rebuild_report(encode(failing), cfg(), sources, tool_version=V)["policy"]["passed"])

    def test_an_invalid_report_is_refused(self) -> None:
        ix = simple("f0")
        indexed, sources = encode(ix), fixture_sources("f0", ix)
        data = encode(build_report(indexed, cfg(), sources, tool_version=V))
        doc = json.loads(data)
        doc["summary"]["line"]["covered"] += 1  # a summary that disagrees with its detail
        doc["summary"]["line"]["ratio"] = "0.937500"
        for bad in (encode(doc), data[:-1], b"{}\n"):
            with self.subTest(bad=bad[:40]):
                with self.assertRaises(ReportError):
                    rebuild_report(bad, cfg(), sources, tool_version=V)


class CommandTest(Base):
    def native(self, name: str = "f0", *options) -> bytes:
        report = build_report(self.evidence, resolve("report", (("--format", "json"), *options)), self.sources, tool_version=None)
        data = encode(report)
        self.put(NATIVE, data)
        return data

    def test_check_gives_exactly_the_indexed_result(self) -> None:
        for name in FIXTURES:
            for args in ((), ("--threshold-line", "100"), ("--threshold-region", "50", "--threshold-function", "100"), ("--quiet",)):
                with self.subTest(fixture=name, args=args):
                    self.setUp()
                    self.project(name)
                    self.native(name)
                    self.assertEqual(self.check(*args, operand=NATIVE), self.check(*args))

    def test_current_sources_are_checked_again(self) -> None:
        self.project()
        self.native()
        path = next(iter(self.sources))
        self.put(path, self.sources[path] + b"// edited\n")
        code, _, err = self.check(operand=NATIVE)
        self.assertEqual((code, self.codes(err)), (5, ["COV1004"]))
        self.assertEqual(self.check(operand=NATIVE), self.check())

    def test_an_invalid_native_report_is_invalid_evidence(self) -> None:
        self.project()
        data = self.native()
        self.put(NATIVE, data.replace(b'"complete":true', b'"complete":false'))
        code, out, err = self.check(operand=NATIVE)
        (r,) = records(err)
        self.assertEqual((code, out, r["phase"]), (5, "", "collection"))
        self.assertIn(r["code"], ("COV4001", "COV4002"))

    def test_a_saturation_policy_conflict_is_a_configuration_error(self) -> None:
        self.project()
        self.native()
        code, _, err = self.check("--saturation-policy", "allow-ordinary", operand=NATIVE)
        self.assertEqual((code, self.codes(err)), (2, ["COV0013"]))

    def test_report_and_baseline_take_only_an_indexed_profile(self) -> None:
        self.project()
        self.native()
        for argv in (["report", "--format", "term", NATIVE], ["baseline", "--ratchet-baseline", "b.json", "--ratchet-metric", "line", NATIVE]):
            with self.subTest(command=argv[0]):
                err = io.StringIO()
                code = cli.main([argv[0], "--diagnostic-format=json-lines", *argv[1:]], stdout=io.StringIO(), stderr=err, cwd=self.cwd)
                (r,) = records(err.getvalue())
                self.assertEqual((code, r["code"]), (7, "COV5001"))
                self.assertIn("only check re-evaluates a native report", r["facts"][0]["value"])


@unittest.skipUnless(shutil.which("git"), "git is required")
class DiffCommandTest(unittest.TestCase):
    """A native report checked under a diff policy on a real repository."""

    setUp = tch.CheckTest.setUp
    repo = tch.CheckTest.repo
    check = tch.CheckTest.check

    def test_the_same_changed_region_result(self) -> None:
        f = self.repo(base_edits={"main.sv0": {12: b"    total = total + 99;", 16: b"    total = total - i;"}})
        native = build_report((f.project / EVIDENCE).read_bytes(), resolve("report", (("--format", "json"),)), self.sources, tool_version=None)
        (f.project / NATIVE).write_bytes(encode(native))
        args = ("--diff-base", "merge-base:main", "--diff-line", "100", "--diff-region", "0")
        want = self.check(*args)
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["check", "--diagnostic-format=json-lines", *args, NATIVE], stdout=out, stderr=err, cwd=f.project)
        self.assertEqual((code, out.getvalue(), records(err.getvalue())), want)
        self.assertEqual(want[0], cli.EXIT_POLICY)


if __name__ == "__main__":
    unittest.main()
