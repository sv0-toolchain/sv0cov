# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``check`` command (CV-231; SPEC 11.6, 20.1, 20.3, 22.1, 22.5;
COV-CLI-002, COV-CLI-004, COV-POL-001, COV-POL-006, COV-MET-012, AC-014,
AC-015, AC-037).

Thresholds are decided on exact integers at every boundary; an empty metric
follows the empty policy; evidence that is incomplete, stale, saturated or
unreadable never passes; the exit status follows SPEC 20.3; and the command
says exactly what a report of the same evidence says, and writes nothing.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_indexed_reader import FIXTURES, U64, fixture_inputs, raw, simple  # noqa: E402
from test_report import fixture_sources  # noqa: E402
from test_terminal import sections  # noqa: E402

from sv0cov import cli, cmd_check  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.terminal import render_check, render_terminal  # noqa: E402
from sv0cov.model.merge import Artifact, merge  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
METRICS = ("function", "region", "line", "branch", "contract")
EVIDENCE = "coverage.sv0covdata.json"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cwd = Path(tmp.name).resolve()

    def put(self, rel: str, data: bytes) -> Path:
        path = self.cwd / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def project(self, name: str = "f0", evidence: bytes | None = None) -> dict:
        """A project root holding the fixture's sources and its evidence."""
        ix = simple(name)
        self.sources = fixture_sources(name, ix)
        for path, data in self.sources.items():
            self.put(path, data)
        self.evidence = evidence if evidence is not None else encode(ix)
        self.put(EVIDENCE, self.evidence)
        return ix

    def check(self, *args: str, operand: str | None = EVIDENCE, fmt: str = "json-lines") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        argv = ["check", f"--diagnostic-format={fmt}", *args, *([operand] if operand is not None else [])]
        code = cli.main(argv, stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def codes(self, err: str) -> list[str]:
        return sorted(r["code"] for r in records(err))

    def tree(self) -> dict[str, bytes]:
        return {str(p.relative_to(self.cwd)): p.read_bytes() for p in sorted(self.cwd.rglob("*")) if p.is_file()}

    def report(self, *options: tuple[str, str | None], toml: str | None = None) -> dict:
        return build_report(self.evidence, resolve("check", options, toml.encode() if toml else None), self.sources)


class ThresholdTest(Base):
    def test_an_empty_policy_checks_only_integrity(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                self.setUp()
                self.project(name)
                before = self.tree()
                code, out, err = self.check()
                self.assertEqual((code, err), (0, ""))
                self.assertIn("evidence:   PASSING\n", out)
                self.assertEqual(sections(out)["Policy"][1:], ['PASS    integrity "integrity"  evidence  -         -       -                 -        -',
                                                                "policy passed"])
                self.assertEqual(self.tree(), before)  # nothing is written

    def test_every_boundary_is_decided_on_integers(self) -> None:
        """COV-POL-001, COV-MET-012: for every fixture and metric, the
        thresholds on both sides of the exact fraction."""
        decided = 0
        for name in FIXTURES:
            self.setUp()
            self.project(name)
            summary = self.report()["summary"]
            for metric in METRICS:
                covered, total = summary[metric]["covered"], summary[metric]["total"]
                if total == 0:
                    continue
                floor = covered * 10000 // total
                for bp in sorted({0, max(floor - 1, 0), floor, min(floor + 1, 10000), 10000}):
                    with self.subTest(fixture=name, metric=metric, bp=bp):
                        code, out, err = self.check(f"--threshold-{metric}", f"{bp}bp", "--quiet")
                        passes = covered * 10000 >= total * bp
                        self.assertEqual(code, 0 if passes else 1)
                        self.assertEqual(out, "")
                        if passes:
                            self.assertEqual(err, "")
                        else:
                            (r,) = records(err)
                            facts = {f["name"]: f["value"] for f in r["facts"]}
                            self.assertEqual((r["code"], r["phase"], facts), ("COV4101", "policy", {
                                "actual": f"{covered}/{total}", "assertion": "project:project", "metric": metric,
                                "required": f">= {bp}/10000", "result": "fail"}))
                        decided += 1
        self.assertGreater(decided, 100)

    def test_a_rounded_percentage_never_passes(self) -> None:
        """AC-014 in miniature: f0 has 14 of 16 lines, 87.5 %."""
        self.project()
        self.assertEqual([self.check("--threshold-line", v, "--quiet")[0] for v in ("87", "8750bp", "8751bp", "88")], [0, 0, 1, 1])
        code, out, _ = self.check("--threshold-line", "88")
        self.assertEqual(code, 1)
        self.assertRegex(out, r'\nFAIL +project "project" +line +>= 8800/10000 +14/16 +project +16 lines +COV4101\npolicy failed\n')
        self.assertIn("evidence:   POLICY FAILED\n", out)

    def test_every_failed_threshold_is_reported(self) -> None:
        self.project("branches")
        code, _, err = self.check("--threshold-line", "100", "--threshold-branch", "100", "--threshold-function", "100")
        self.assertEqual(code, 1)
        self.assertEqual(sorted((r["code"], next(f["value"] for f in r["facts"] if f["name"] == "metric")) for r in records(err)),
                         [("COV4101", "branch"), ("COV4101", "line")])

    def test_an_empty_metric_follows_the_empty_policy(self) -> None:
        """AC-015; SPEC 11.6: f0 has no contract clause."""
        self.project()
        code, out, err = self.check("--threshold-contract", "1")
        self.assertEqual((code, self.codes(err)), (1, ["COV4102"]))
        facts = {f["name"]: f["value"] for f in records(err)[0]["facts"]}
        self.assertEqual(facts, {"assertion": "project:project", "metric": "contract", "required": ">= 100/10000", "result": "fail"})
        self.assertRegex(out, r"contracts +0/0 +N/A\n")
        code, out, err = self.check("--threshold-contract", "1", "--empty", "pass")
        self.assertEqual((code, err), (0, ""))
        self.assertRegex(out, r'\nPASS +project "project" +contract +>= 100/10000 +- +project +- +-\npolicy passed\n')
        self.assertEqual(self.check("--threshold-contract", "0")[0], 1)  # even a zero threshold: the scope is empty

    def test_the_manifest_sets_thresholds_and_the_command_line_overrides_them(self) -> None:
        self.project()
        self.put("sv0.toml", (HEAD + "[tool.sv0cov.thresholds]\nline = 88\nbranch = 10\n").encode())
        code, out, err = self.check()
        self.assertEqual((code, self.codes(err)), (1, ["COV4101"]))
        self.assertEqual(len(sections(out)["Policy"]), 5)
        self.assertEqual(self.check("--threshold-line", "87")[0], 0)
        self.put("sv0.toml", (HEAD + 'empty = "pass"\n[tool.sv0cov.thresholds]\ncontract = 100\n').encode())
        self.assertEqual(self.check()[0], 0)
        self.assertEqual(self.check("--empty", "fail")[0], 1)

    def test_check_says_what_a_report_says(self) -> None:
        self.project("branches")
        options = [("--threshold-line", "90"), ("--threshold-region", "50")]
        report = self.report(*options)
        code, out, _ = self.check("--threshold-line", "90", "--threshold-region", "50")
        self.assertEqual(code, 1)
        self.assertEqual(out, render_check(report))
        full = sections(render_terminal(report))
        for title in ("Summary", "Warnings", "Policy", "Saturation"):
            self.assertEqual(sections(out)[title], full[title])
        self.assertEqual(list(sections(out)), ["Summary", "Warnings", "Policy", "Saturation"])


class EvidenceTest(Base):
    """COV-POL-006; SPEC 22.5: a passing percentage cannot override the evidence."""

    def test_a_changed_or_missing_source_is_an_integrity_failure(self) -> None:
        self.project()
        (path,) = self.sources
        self.put(path, self.sources[path] + b"\n")
        code, out, err = self.check("--threshold-line", "0")
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], r["facts"][0]["value"]), (5, "", "COV1004", f"source {path} has changed since coverage was collected"))
        (self.cwd / path).unlink()
        code, out, err = self.check()
        self.assertEqual((code, out, records(err)[0]["facts"][0]["value"]), (5, "", f"source {path} is missing or unreadable"))
        (self.cwd / path).mkdir()
        self.assertEqual(self.check()[0], 5)
        self.assertEqual(cli.main(["check", "--allow-source-mismatch", EVIDENCE], stdout=io.StringIO(), stderr=io.StringIO(), cwd=self.cwd), 2)

    def test_incomplete_evidence_never_passes(self) -> None:
        data, m, counts = fixture_inputs("f0")
        good, cut = raw(m, counts, 1), raw(m, counts, 2)[:-9]
        cases = {
            "a rejected input": (merge([Artifact("m", data)], [Artifact("a", good), Artifact("cut", cut)], allow_rejected_inputs=True), None),
            "the override alone": (merge([Artifact("m", data)], [Artifact("a", good)], allow_rejected_inputs=True), ["COV3002"]),
            "two undeclared runs": (merge([Artifact("m", data)], [Artifact("a", good), Artifact("b", raw(m, counts, 3, run="f" * 32))]), ["COV3003"]),
            "no input": (merge([], [], allow_rejected_inputs=True), ["COV3001", "COV3003"]),
        }
        for label, (result, want) in cases.items():
            with self.subTest(case=label):
                self.setUp()
                self.project(evidence=result.data)
                self.assertFalse(result.complete)
                self.assertEqual(self.check("--threshold-line", "0")[0], 5)  # no threshold can rescue it
                code, out, err = self.check()
                self.assertEqual(code, 5)
                got = self.codes(err)
                self.assertTrue(got and all(c.startswith(("COV2", "COV3")) for c in got), got)
                if want is not None:
                    self.assertEqual(got, want)
                self.assertTrue(all(r["phase"] == "policy" for r in records(err)))
                self.assertIn("evidence:   INCOMPLETE\n", out)
                self.assertIn("WARNING: the evidence is incomplete", out)
                self.assertTrue(out.endswith("no count is saturated\n") and "policy failed\n" in out)

    def saturated(self, policy: str) -> bytes:
        data, m, counts = fixture_inputs("f0")
        first = sorted(counts)[0]
        return merge([Artifact("m", data)], [Artifact("a", raw(m, {**counts, first: U64}, 1))], saturation_policy=policy).data

    def test_saturation_fails_by_default(self) -> None:
        """AC-037."""
        self.project(evidence=self.saturated("fail"))
        code, out, err = self.check()
        self.assertEqual((code, self.codes(err)), (1, ["COV4020"]))
        self.assertIn(f">={U64}", out)
        self.assertIn("a count written >=N is a lower bound", out)
        code, _, err = self.check("--threshold-line", "0")
        self.assertEqual((code, self.codes(err)), (1, ["COV4020", "COV4020"]))
        self.assertEqual(sorted(f["value"] for r in records(err) for f in r["facts"] if f["name"] == "result"), ["ineligible", "ineligible"])

    def test_allow_ordinary_lets_ordinary_metrics_decide(self) -> None:
        self.project(evidence=self.saturated("allow-ordinary"))
        self.assertEqual(self.check("--saturation-policy", "allow-ordinary", "--threshold-line", "8750bp")[0], 0)
        code, _, err = self.check("--saturation-policy", "allow-ordinary", "--threshold-line", "8751bp")
        self.assertEqual((code, self.codes(err)), (1, ["COV4101"]))

    def test_a_policy_the_evidence_was_not_merged_under_is_a_configuration_conflict(self) -> None:
        self.project(evidence=self.saturated("allow-ordinary"))
        code, out, err = self.check()
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], r["phase"]), (2, "", "COV0013", "configuration"))
        self.project(evidence=self.saturated("fail"))
        self.assertEqual(self.check("--saturation-policy", "allow-ordinary")[0], 2)

    def test_what_this_build_cannot_evaluate_is_refused(self) -> None:
        self.project()
        self.put("sv0.toml", (HEAD + '[[tool.sv0cov.scopes]]\nname = "core"\ninclude = ["src/**"]\nline = 80\n').encode())
        code, out, err = self.check()
        self.assertEqual((code, out, self.codes(err)), (7, "", ["COV5001"]))


class OperandTest(Base):
    def test_the_operand_must_be_one_readable_indexed_profile(self) -> None:
        self.project()
        self.assertEqual(self.check(operand=None)[0], 2)
        self.assertEqual(cli.main(["check", EVIDENCE, EVIDENCE], stdout=io.StringIO(), stderr=io.StringIO(), cwd=self.cwd), 2)
        self.put("bad.json", b"{}")
        self.put("cut.json", self.evidence[:-20])
        self.put("changed.json", self.evidence.replace(b'"complete":true', b'"complete":false', 1))
        (self.cwd / "dir").mkdir()
        os.symlink(self.cwd / EVIDENCE, self.cwd / "link.json")
        for operand, want in (("absent.json", "COV3010"), ("bad.json", "COV3010"), ("cut.json", "COV3010"), ("changed.json", None),
                              ("dir", "COV6002")):
            with self.subTest(operand=operand):
                code, out, err = self.check(operand=operand)
                (r,) = records(err)
                self.assertEqual((code, out, r["phase"]), (5, "", "collection"))
                if want:
                    self.assertEqual(r["code"], want)
        self.assertEqual(self.check(operand="link.json")[0], 0)
        self.assertEqual(self.check(operand=str(self.cwd / EVIDENCE))[0], 0)

    def test_a_native_report_is_not_accepted_yet(self) -> None:
        self.project()
        self.put("coverage.json", encode(self.report()))
        code, out, err = self.check(operand="coverage.json")
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], r["phase"]), (7, "", "COV5001", "invocation"))
        self.assertIn("not a native report", r["facts"][0]["value"])

    def test_an_oversized_profile_is_refused_before_it_is_read(self) -> None:
        self.project()
        with open(self.cwd / "huge.json", "wb") as f:
            f.truncate((512 << 20) + 1)
        with mock.patch.object(cmd_check, "read_indexed", side_effect=AssertionError("the file was read")):
            code, _, err = self.check(operand="huge.json")
        self.assertEqual((code, self.codes(err)), (5, ["COV6001"]))

    def test_a_result_the_reader_rejects_is_an_internal_failure(self) -> None:
        """The report is read back before any verdict is given."""
        self.project()
        real = cmd_check.build_report

        def wrong(*args, **kw):
            report = real(*args, **kw)
            report["summary"]["line"]["covered"] -= 1
            return report

        with mock.patch.object(cmd_check, "build_report", wrong):
            code, out, err = self.check()
        self.assertEqual((code, out, self.codes(err)), (8, "", ["COV8001"]))


class StreamTest(Base):
    def test_quiet_removes_the_summary_and_keeps_the_diagnostics(self) -> None:
        self.project()
        loud, quiet = self.check("--threshold-line", "100"), self.check("--threshold-line", "100", "--quiet")
        self.assertEqual((loud[0], quiet[0], quiet[1], quiet[2]), (1, 1, "", loud[2]))
        self.assertTrue(loud[1].startswith("sv0cov coverage report\n") and loud[1].endswith("\n") and not loud[1].endswith("\n\n"))

    def test_human_diagnostics_show_the_exact_fractions(self) -> None:
        self.project()
        _, _, err = self.check("--threshold-line", "100", fmt="human")
        self.assertEqual(err, "COV4101 error: Coverage threshold failed\n  actual: 14/16\n  assertion: project:project\n  metric: line\n"
                              "  required: >= 10000/10000\n  result: fail\n")

    def test_color_is_opt_in_and_only_repeats_words(self) -> None:
        self.project()
        plain = self.check("--threshold-line", "100")[1]
        self.assertNotIn("\x1b", plain)
        self.assertEqual(self.check("--threshold-line", "100", "--color", "never")[1], plain)
        colored = self.check("--threshold-line", "100", "--color", "always")[1]
        self.assertIn("\x1b[1;31mFAIL\x1b[0m", colored)
        import re
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", colored), plain)

    def test_the_installed_entry_point(self) -> None:
        """COV-CLI-002: usable on its own, from a project directory."""
        self.project()
        run = [sys.executable, "-c", "import sys; from sv0cov.cli import main; sys.exit(main())", "check"]
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        ok = subprocess.run([*run, EVIDENCE], cwd=self.cwd, env=env, capture_output=True, timeout=120)
        self.assertEqual((ok.returncode, ok.stderr), (0, b""))
        self.assertIn(b"policy passed\n", ok.stdout)
        self.assertNotIn(b"\x1b", ok.stdout)  # a pipe is not a terminal
        bad = subprocess.run([*run, "--threshold-line", "8751bp", "--diagnostic-format", "json-lines", EVIDENCE], cwd=self.cwd, env=env,
                             capture_output=True, timeout=120)
        self.assertEqual((bad.returncode, json.loads(bad.stderr)["code"]), (1, "COV4101"))


class ModelTest(unittest.TestCase):
    def test_exit_status_and_diagnostics_of_a_report_with_every_kind_of_result(self) -> None:
        report = json.loads((ROOT / "tests" / "fixtures" / "report" / "all-kinds.json").read_bytes())
        self.assertEqual(cmd_check.exit_status(report), 5)  # incomplete evidence outranks the failed thresholds
        got = cmd_check.evaluation_diagnostics(report)
        want = sum(len(e["diagnostics"]) for e in report["policy"]["evaluations"] if e["result"] in ("fail", "ineligible"))
        self.assertEqual(len(got), want)
        self.assertTrue(all(d.phase == "policy" for d in got))
        ratchet = next(d for d in got if dict(d.facts)["assertion"] == "ratchet:ratchet")
        self.assertEqual(dict(ratchet.facts), {"assertion": "ratchet:ratchet", "metric": "line", "result": "ineligible", "required": ">= 7/12"})
        passing = json.loads((ROOT / "tests" / "fixtures" / "report" / "passing.json").read_bytes())
        self.assertEqual((cmd_check.exit_status(passing), cmd_check.evaluation_diagnostics(passing)), (0, []))
        failed = json.loads(json.dumps(passing))
        failed["policy"]["evaluations"][1].update(result="fail", diagnostics=["COV4101"])
        failed["policy"]["passed"] = False
        failed["evidence_eligibility"] = "policy_failed"
        self.assertEqual(cmd_check.exit_status(failed), 1)
        self.assertEqual(cmd_check.exit_status({**passing, "evidence_eligibility": "diagnostic_only"}), 1)
        broken = json.loads(json.dumps(passing))
        broken["policy"]["evaluations"][0].update(result="fail", diagnostics=["COV3004"])
        self.assertEqual(broken["policy"]["evaluations"][0]["assertion_kind"], "integrity")
        self.assertEqual(cmd_check.exit_status(broken), 5)


if __name__ == "__main__":
    unittest.main()
