# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The LCOV export ``sv0cov-lcov-r1-core`` (CV-401; SPEC 21.4; COV-REP-004,
COV-REP-008, COV-REP-010, AC-053).

Goldens for every semantic fixture; totals equal the native report's;
repeated renders are byte-identical; the binary line projection; excluded
and dependency units are omitted; a saturated count is refused; and the
reader rejects everything outside the profile grammar.
"""

from __future__ import annotations

import copy
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES, rich_inputs  # noqa: E402
from test_report import STALE_OK, V, config, fixture_report  # noqa: E402
from test_scopes import Case  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.lcov import LcovError, check_lcov, parse_lcov, render_lcov  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

GOLDENS = ROOT / "tests" / "fixtures" / "lcov"
ALLOWED = ("TN", "SF", "FN", "FNDA", "FNF", "FNH", "DA", "LF", "LH", "BRDA", "BRF", "BRH", "end_of_record")


def code_of(fn, *a) -> str:
    try:
        fn(*a)
    except LcovError as exc:
        return exc.code
    return "accepted"


class GoldenTest(unittest.TestCase):
    def test_goldens_are_current(self) -> None:
        p = subprocess.run([sys.executable, str(GOLDENS / "build.py")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_every_fixture_matches_its_report_and_is_deterministic(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, _ = fixture_report(name)
                data = render_lcov(report)
                self.assertEqual(data, render_lcov(copy.deepcopy(report)))
                check_lcov(data, report)
                tags = {line.split(":", 1)[0] for line in data.decode().splitlines()}
                self.assertLessEqual(tags, set(ALLOWED))  # no VER, FNL, FNA, checksum or comment (AC-053)
                project = parse_lcov(data)
                for metric in ("function", "line", "branch"):
                    total = report["summary"][metric]
                    self.assertEqual((sum(r[metric][0] for r in project), sum(r[metric][1] for r in project)),
                                     (total["covered"], total["total"]), metric)


class ProjectionTest(unittest.TestCase):
    def test_partial_lines_are_not_covered(self) -> None:
        report, _ = fixture_report("f0")
        partial = [x for x in report["lines"] if x["status"] == "partial"]
        self.assertTrue(partial)
        data = render_lcov(report).decode().splitlines()
        for x in partial:
            self.assertIn(f"DA:{x['line']},0", data)
        for x in report["lines"]:
            if x["status"] == "covered":
                self.assertIn(f"DA:{x['line']},1", data)
            if x["status"] in ("excluded", "non_executable"):
                self.assertFalse(any(d.startswith(f"DA:{x['line']},") for d in data))

    def test_exact_counts_and_branch_indexes(self) -> None:
        report, _ = fixture_report("boolean")
        rows = [line for line in render_lcov(report).decode().splitlines() if line.startswith("BRDA:")]
        outcomes = {}
        for b in report["branches"]:
            for o in b["outcomes"]:
                if o["status"] in ("covered", "uncovered"):
                    outcomes.setdefault(b["span"]["start_line"], []).append(o["count"]["value"])
        got = {}
        for row in rows:
            line, d, o, count = map(int, row[5:].split(","))
            got.setdefault(line, []).append(count)
        self.assertEqual({k: sorted(v) for k, v in got.items()}, {k: sorted(v) for k, v in outcomes.items()})
        self.assertTrue(any(len(v) > 2 for v in got.values()), "some line holds more than one decision")

    def test_excluded_functions_and_dependency_sources_are_omitted(self) -> None:
        case = Case.sample()
        report = build_report(case.indexed, config(), case.sources, tool_version=V)
        data = render_lcov(report).decode()
        self.assertNotIn(",unused", data)  # excluded by an attribute
        check_lcov(render_lcov(report), report)
        from test_default_scope import DEP_PATH, USER_PATHS, DefaultScopeTest
        DefaultScopeTest.setUpClass()
        dep_report = DefaultScopeTest.report
        sfs = [line[3:] for line in render_lcov(dep_report).decode().splitlines() if line.startswith("SF:")]
        self.assertEqual(sfs, [s["path"] for s in dep_report["sources"] if s["ownership"] == "user"])
        self.assertNotIn(DEP_PATH, sfs)
        self.assertEqual(len(sfs), len(USER_PATHS))

    def test_a_saturated_count_is_refused(self) -> None:
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        report = build_report(encode(ix), config(STALE_OK), {}, tool_version=V)
        saturated = [p for p in report["points"] if p["count"]["saturated"]]
        self.assertTrue(saturated)
        self.assertEqual(code_of(render_lcov, report), "COV4020")

    def test_a_name_lcov_cannot_carry_is_refused(self) -> None:
        report, _ = fixture_report("functions")
        report = copy.deepcopy(report)
        report["entities"][0]["qualified_name"] = "a,b"
        self.assertEqual(code_of(render_lcov, report), "COV4401")

    def test_an_empty_report_is_an_empty_tracefile(self) -> None:
        report, _ = fixture_report("functions")
        report = copy.deepcopy(report)
        for s in report["sources"]:
            s["ownership"] = "dependency"
        self.assertEqual(render_lcov(report), b"")
        self.assertEqual(parse_lcov(b""), [])


class ReaderTest(unittest.TestCase):
    GOOD = (b"TN:\nSF:a.sv0\nFN:1,f\nFN:5,g\nFNDA:2,f\nFNDA:0,g\nFNF:2\nFNH:1\nDA:1,1\nDA:2,0\nLF:2\nLH:1\n"
            b"BRDA:2,0,0,1\nBRDA:2,0,1,0\nBRDA:2,1,0,3\nBRF:3\nBRH:2\nend_of_record\n")

    def test_the_good_tracefile(self) -> None:
        self.assertEqual(parse_lcov(self.GOOD), [{"path": "a.sv0", "function": (1, 2), "line": (1, 2), "branch": (2, 3)}])

    def test_everything_outside_the_profile_is_rejected(self) -> None:
        g = self.GOOD
        cases = {
            "a VER record": g.replace(b"TN:\n", b"VER:1\nTN:\n", 1),
            "a test name": g.replace(b"TN:\n", b"TN:unit\n", 1),
            "no TN": g.replace(b"TN:\n", b"", 1),
            "an FNL extension": g.replace(b"FNF:2", b"FNL:0,1,4\nFNF:2", 1),
            "a comment": g.replace(b"LF:2", b"# note\nLF:2", 1),
            "a DA checksum": g.replace(b"DA:1,1", b"DA:1,1,abc", 1),
            "a hit count in DA": g.replace(b"DA:1,1", b"DA:1,7", 1),
            "DA line zero": g.replace(b"DA:1,1", b"DA:0,1", 1),
            "DA out of order": g.replace(b"DA:1,1\nDA:2,0", b"DA:2,0\nDA:1,1", 1),
            "a wrong FNF": g.replace(b"FNF:2", b"FNF:3", 1),
            "a wrong FNH": g.replace(b"FNH:1", b"FNH:2", 1),
            "a wrong LH": g.replace(b"LH:1", b"LH:2", 1),
            "a wrong BRF": g.replace(b"BRF:3", b"BRF:4", 1),
            "a wrong BRH": g.replace(b"BRH:2", b"BRH:1", 1),
            "FN without FNDA": g.replace(b"FNDA:0,g\n", b"", 1),
            "a decision gap": g.replace(b"BRDA:2,1,0,3", b"BRDA:2,2,0,3", 1),
            "an outcome gap": g.replace(b"BRDA:2,0,1,0", b"BRDA:2,0,2,0", 1),
            "a decision not from zero": g.replace(b"BRDA:2,0,0,1\nBRDA:2,0,1,0\nBRDA:2,1,0,3", b"BRDA:2,1,0,1", 1)
            .replace(b"BRF:3", b"BRF:1", 1).replace(b"BRH:2", b"BRH:1", 1),
            "a '-' branch count": g.replace(b"BRDA:2,0,1,0", b"BRDA:2,0,1,-", 1),
            "a leading zero": g.replace(b"FNDA:2,f", b"FNDA:02,f", 1),
            "no end_of_record": g.replace(b"end_of_record\n", b"", 1),
            "no final line feed": g[:-1],
            "a source twice": g + g,
            "two FNF": g.replace(b"FNF:2", b"FNF:2\nFNF:2", 1),
            "a record out of order": g.replace(b"FNF:2\nFNH:1\n", b"", 1).replace(b"LH:1\n", b"LH:1\nFNF:2\nFNH:1\n", 1),
            "an empty path": g.replace(b"SF:a.sv0", b"SF:", 1),
        }
        for what, data in cases.items():
            with self.subTest(what):
                self.assertEqual(code_of(parse_lcov, data), "COV4401")

    def test_check_compares_with_the_report(self) -> None:
        report, _ = fixture_report("branches")
        data = render_lcov(report)
        check_lcov(data, report)
        self.assertEqual(code_of(check_lcov, data.replace(b"LH:14", b"LH:13").replace(b"DA:5,1", b"DA:5,0", 1), report), "COV4401")
        self.assertEqual(code_of(check_lcov, data.replace(b"SF:main.sv0", b"SF:other.sv0"), report), "COV4401")


if __name__ == "__main__":
    unittest.main()
