# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Exclusion audit and caps (CV-314; SPEC 18.2.2, 19.5; COV-EXC-005,
COV-EXC-025, COV-POL-025).

The sample evidence has one exclusion record, an attribute on ``unused`` in
``src/math.sv0`` with the reason ``fallback path``, removing one function,
one region and one line. Every cap is decided by exact cross multiplication
at its boundary; a record counts once however much it removes; forbidden
reasons match exactly; forbidden sources use the Section 18.3 matcher; and
the reader re-derives every evaluation.
"""

from __future__ import annotations

import copy
import io
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_report import V  # noqa: E402
from test_scopes import Case  # noqa: E402

from sv0cov import cli  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.html import check_html, render_html  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.formats.terminal import render_terminal  # noqa: E402
from sv0cov.model.report import build_report, excluded_members, excluded_units, read_report  # noqa: E402

HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
METRICS = ("branch", "contract", "function", "line", "region")
EVIDENCE = "coverage.sv0covdata.json"


def toml(**keys) -> bytes:
    body = "".join(f"{k} = {_toml(v)}\n" for k, v in keys.items())
    return (HEAD + "[tool.sv0cov.exclusions]\n" + body).encode()


def _toml(v) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(_toml(x) for x in v) + "]"
    if isinstance(v, str):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return str(v)


def evaluations(report: dict) -> dict[tuple[str, str], dict]:
    return {(e["metric"], e["comparison"]): e for e in report["policy"]["evaluations"] if e["assertion_kind"] == "exclusion"}


class Base(unittest.TestCase):
    case = Case.sample()

    def report(self, **keys) -> dict:
        r = build_report(self.case.indexed, resolve("check", (), toml(**keys)), self.case.sources, tool_version=V)
        self.assertEqual(read_report(encode(r)), r)
        return r

    def plain(self) -> dict:
        return build_report(self.case.indexed, resolve("check", (), None), self.case.sources, tool_version=V)


class CapTest(Base):
    def test_the_sample(self) -> None:
        r = self.plain()
        self.assertEqual(len(r["exclusions"]), 1)
        self.assertEqual({m: excluded_units(r, m) for m in METRICS}, {"branch": 0, "contract": 0, "function": 1, "line": 1, "region": 1})

    def test_every_metric_cap_at_its_exact_boundary(self) -> None:
        r = self.plain()
        for m in METRICS:
            units = excluded_units(r, m)
            pre = r["summary"][m]["total"] + units
            if pre == 0:
                continue
            # The least cap that admits units/pre: ceil(units * 10000 / pre).
            least = -(-units * 10000 // pre)
            for cap, result in ((least, "pass"), (least - 1, "fail"), (10000, "pass"), (0, "pass" if units == 0 else "fail")):
                if not 0 <= cap <= 10000:
                    continue
                with self.subTest(metric=m, cap=cap):
                    e = evaluations(self.report(**{f"{m}_basis_points": cap}))[(m, "at_most")]
                    self.assertEqual(e["result"], result)
                    self.assertEqual(e["actual"], {"denominator": pre, "numerator": units})
                    self.assertEqual(e["limit"], {"denominator": 10000, "numerator": cap})
                    self.assertEqual(e["threshold_source"], "exclusion")
                    self.assertEqual(e["diagnostics"], [] if result == "pass" else ["COV4101"])
                    key = {"branch": "branch_indices", "contract": "clause_indices", "function": "entity_indices",
                           "line": "line_indices", "region": "region_indices"}[m]
                    self.assertEqual(e["members"][key], excluded_members(r, m))

    def test_the_pre_exclusion_total_is_used_not_the_remaining_one(self) -> None:
        # function: 1 removed of 3 before exclusion (2 remain). 1/3 <= 33.34% passes; 1/2 would need 50%.
        e = evaluations(self.report(function_basis_points=3334))[("function", "at_most")]
        self.assertEqual((e["actual"], e["result"]), ({"denominator": 3, "numerator": 1}, "pass"))

    def test_a_zero_pre_exclusion_total_passes_without_a_fraction(self) -> None:
        f0 = Case.fixture("f0")
        r = build_report(f0.indexed, resolve("check", (), toml(contract_basis_points=0)), f0.sources, tool_version=V)
        e = evaluations(r)[("contract", "at_most")]
        self.assertEqual((e["actual"], e["result"], e["diagnostics"]), (None, "pass", []))

    def test_a_record_counts_once_whatever_it_removes(self) -> None:
        for cap, result in ((1, "pass"), (0, "fail"), (4294967295, "pass")):
            with self.subTest(cap=cap):
                e = evaluations(self.report(max_records=cap))[("exclusion_records", "at_most")]
                self.assertEqual((e["actual"], e["limit"], e["result"]),
                                 ({"denominator": 1, "numerator": 1}, {"denominator": 1, "numerator": cap}, result))

    def test_only_configured_caps_are_evaluated(self) -> None:
        self.assertEqual(sorted(evaluations(self.report(line_basis_points=10000))), [("line", "at_most")])
        self.assertEqual(evaluations(self.plain()), {})
        self.assertEqual(evaluations(self.report(forbidden_reasons=[], forbidden_sources=[])), {})

    def test_caps_are_independent_and_every_one_must_pass(self) -> None:
        r = self.report(max_records=5, function_basis_points=0, region_basis_points=10000)
        ev = evaluations(r)
        self.assertEqual({k: e["result"] for k, e in ev.items()},
                         {("exclusion_records", "at_most"): "pass", ("function", "at_most"): "fail", ("region", "at_most"): "pass"})
        self.assertFalse(r["policy"]["passed"])
        self.assertEqual(r["evidence_eligibility"], "policy_failed")


class ForbiddenTest(Base):
    def forbidden(self, **keys) -> dict:
        return evaluations(self.report(**keys))[("exclusion_records", "equal")]

    def test_reasons_match_exactly(self) -> None:
        for reasons, result in ((["fallback path"], "fail"), (["fallback"], "pass"), (["Fallback path"], "pass"),
                                (["fallback path "], "pass"), (["other", "fallback path"], "fail")):
            with self.subTest(reasons=reasons):
                e = self.forbidden(forbidden_reasons=reasons)
                self.assertEqual(e["result"], result)
                self.assertEqual(e["actual"], {"denominator": 1, "numerator": 1 if result == "fail" else 0})
                self.assertEqual(e["limit"], {"denominator": 1, "numerator": 0})

    def test_sources_use_the_gitignore_matcher(self) -> None:
        for patterns, result in ((["src/math.sv0"], "fail"), (["src/*.sv0"], "fail"), (["src/sign.sv0"], "pass"),
                                 (["*.sv0", "!math.sv0"], "pass"), (["src/", "!src/math.sv0"], "fail"),  # a child of an excluded directory stays excluded
                                 (["/math.sv0"], "pass"), (["**/math.sv0"], "fail")):
            with self.subTest(patterns=patterns):
                self.assertEqual(self.forbidden(forbidden_sources=patterns)["result"], result)

    def test_members_are_the_offending_records_sources_and_what_they_remove(self) -> None:
        r = self.report(forbidden_reasons=["fallback path"])
        e = evaluations(r)[("exclusion_records", "equal")]
        (x,) = r["exclusions"]
        self.assertEqual(e["members"]["source_indices"], [x["source_index"]])
        for key in ("branch_indices", "clause_indices", "entity_indices", "line_indices", "region_indices"):
            self.assertEqual(e["members"][key], x["affected"][key])
        clean = evaluations(self.report(forbidden_reasons=["nothing"]))[("exclusion_records", "equal")]
        self.assertEqual(set(map(len, clean["members"].values())), {0})


class ReaderAndViewTest(Base):
    def test_the_reader_rederives_every_exclusion_evaluation(self) -> None:
        r = self.report(max_records=1, function_basis_points=5000, forbidden_reasons=["x"])
        n = next(i for i, e in enumerate(r["policy"]["evaluations"]) if e["assertion_kind"] == "exclusion")

        def edited(fn):
            c = copy.deepcopy(r)
            fn(c)
            return c

        for what, fn in {
            "removed": lambda c: c["policy"]["evaluations"].pop(n),
            "a limit": lambda c: c["policy"]["evaluations"][n].__setitem__("limit", {"denominator": 1, "numerator": 9}),
            "a member": lambda c: c["policy"]["evaluations"][n]["members"]["source_indices"].append(0),
            "the reason the policy forbids": lambda c: c["resolved_configuration"]["coverage"]["exclusions"]["forbidden_reasons"]
            .__setitem__("value", ["fallback path"]),
        }.items():
            with self.subTest(what):
                with self.assertRaises(ReportError) as cm:
                    read_report(encode(edited(fn)))
                self.assertIn(cm.exception.code, ("COV4001", "COV4002"))

    def test_terminal_and_html_keep_the_audit(self) -> None:
        r = self.report(function_basis_points=0)
        text = render_terminal(r)
        self.assertIn("excluded: 1 function, 1 region, 1 line, 0 branches, 0 contracts", text)
        self.assertIn('#0 src/math.sv0:7:1 off (attribute): "fallback path"', text)
        self.assertIn("    removes 1 function, 1 region, 1 line, 0 branches, 0 contracts; ran: 0 of 1 region", text)
        self.assertIn('FAIL    exclusion "exclusions"  function  <= 0/10000  1/3', text)
        page = render_html(r, self.case.sources)
        check_html(page)
        self.assertIn(b"removes and evidence", page)
        self.assertIn(b"ran: 0 of 1 region", page)


class CheckTest(unittest.TestCase):
    def test_check_exit_and_facts(self) -> None:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            case = Case.sample()
            for path, data in case.sources.items():
                (cwd / path).parent.mkdir(parents=True, exist_ok=True)
                (cwd / path).write_bytes(data)
            (cwd / EVIDENCE).write_bytes(case.indexed)
            for body, want in ((toml(max_records=1, function_basis_points=3334), 0), (toml(function_basis_points=3333), 1),
                               (toml(forbidden_sources=["src/math.sv0"]), 1)):
                with self.subTest(body=body):
                    (cwd / "sv0.toml").write_bytes(body)
                    out, err = io.StringIO(), io.StringIO()
                    code = cli.main(["check", "--diagnostic-format=json-lines", EVIDENCE], stdout=out, stderr=err, cwd=cwd)
                    self.assertEqual(code, want, err.getvalue())
                    diags = records(err.getvalue())
                    if want:
                        (d,) = diags
                        facts = {f["name"]: f["value"] for f in d["facts"]}
                        self.assertEqual((d["code"], facts["assertion"]), ("COV4101", "exclusion:exclusions"))
                    else:
                        self.assertEqual(diags, [])


if __name__ == "__main__":
    unittest.main()
