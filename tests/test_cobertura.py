# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The Cobertura export ``sv0cov-cobertura-r1-core`` (CV-402; SPEC 21.5;
COV-REP-005, COV-REP-010, COV-REP-011, COV-REP-012, AC-051).

Goldens for every semantic fixture, each valid against the vendored,
digest-pinned ``coverage-04.dtd`` with no network; totals equal the native
report's; repeated renders are byte-identical with timestamp zero; the
binary line projection; branches on lines; packages; XML-sensitive and
unrepresentable text; saturation; and the reader rejects everything outside
the profile.
"""

from __future__ import annotations

import copy
import hashlib
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))

from dtd_validate import load_dtd, validate  # noqa: E402
from test_indexed_reader import FIXTURES, rich_inputs  # noqa: E402
from test_report import STALE_OK, V, config, fixture_report  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.cobertura import CoberturaError, check_cobertura, parse_cobertura, render_cobertura  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

GOLDENS = ROOT / "tests" / "fixtures" / "cobertura"
DTD_PATH = ROOT / "tests" / "vendor" / "cobertura" / "coverage-04.dtd"
DTD_SHA256 = "e467cb8252e20feb794fc2dedfbea7b4957921669c758f0282d525df88897917"


def code_of(fn, *a, **k) -> str:
    try:
        fn(*a, **k)
    except CoberturaError as exc:
        return exc.code
    return "accepted"


def last(data: bytes, old: bytes, new: bytes) -> bytes:
    """``data`` with its last ``old`` replaced: the class-level copy of a line."""
    i = data.rindex(old)
    return data[:i] + new + data[i + len(old):]


def shape(el) -> tuple:
    return el.tag, sorted(el.attrib.items()), [shape(c) for c in el]


def dtd():
    data = DTD_PATH.read_bytes()
    assert hashlib.sha256(data).hexdigest() == DTD_SHA256 and len(data) == 2162
    return load_dtd(data.decode("utf-8"))


class GoldenTest(unittest.TestCase):
    def test_the_vendored_dtd_is_the_pinned_one(self) -> None:
        self.assertEqual(hashlib.sha256(DTD_PATH.read_bytes()).hexdigest(), DTD_SHA256)

    def test_goldens_are_current(self) -> None:
        p = subprocess.run([sys.executable, str(GOLDENS / "build.py")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_every_fixture_is_valid_deterministic_and_matches_its_report(self) -> None:
        d = dtd()
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, _ = fixture_report(name)
                data = render_cobertura(report)
                self.assertEqual(data, render_cobertura(copy.deepcopy(report)))
                self.assertEqual(validate(d, data), [])
                check_cobertura(data, report)
                for banned in (b"<!", b"xmlns", b"<?xml-", b"]]>"):
                    self.assertNotIn(banned, data)
                self.assertEqual(data.count(b"<?"), 1)
                root = ET.fromstring(data)
                self.assertEqual(root.get("timestamp"), "0")
                self.assertEqual([s.text for s in root.iter("source")], ["."])
                for metric, (c, v) in (("line", ("lines-covered", "lines-valid")), ("branch", ("branches-covered", "branches-valid"))):
                    total = report["summary"][metric]
                    self.assertEqual((int(root.get(c)), int(root.get(v))), (total["covered"], total["total"]), metric)
                for el in root.iter():
                    if "complexity" in el.attrib:
                        self.assertEqual(el.get("complexity"), "0.0")
                    if el.tag == "class":
                        self.assertFalse(el.get("filename").startswith("/"))

    def test_the_timestamp_is_the_epoch_given(self) -> None:
        report, _ = fixture_report("f0")
        data = render_cobertura(report, timestamp=1700000000)
        self.assertEqual(ET.fromstring(data).get("timestamp"), "1700000000")
        self.assertEqual(parse_cobertura(data)["timestamp"], 1700000000)
        self.assertEqual(code_of(render_cobertura, report, timestamp=-1), "COV4401")
        self.assertEqual(code_of(render_cobertura, report, timestamp=True), "COV4401")


class ProjectionTest(unittest.TestCase):
    def test_lines_are_binary_and_methods_repeat_them(self) -> None:
        report, _ = fixture_report("f0")
        root = ET.fromstring(render_cobertura(report))
        cls = root.find("packages/package/classes/class")
        rows = {int(x.get("number")): x for x in cls.find("lines")}
        status = {x["line"]: x["status"] for x in report["lines"]}
        self.assertIn("partial", status.values())
        self.assertEqual(set(rows), {k for k, s in status.items() if s in ("covered", "partial", "uncovered")})
        for k, x in rows.items():
            self.assertEqual(x.get("hits"), "1" if status[k] == "covered" else "0", k)
        for m in cls.find("methods"):
            for x in m.find("lines"):
                y = rows[int(x.get("number"))]
                self.assertEqual(shape(x), shape(y))

    def test_conditions_count_outcomes_per_decision(self) -> None:
        report, _ = fixture_report("boolean")
        root = ET.fromstring(render_cobertura(report))
        want: dict[int, list[tuple[int, int]]] = {}
        for b in sorted(report["branches"], key=lambda b: (b["span"]["start_line"], b["branch_index"])):
            eligible = [o for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
            if eligible:
                want.setdefault(b["span"]["start_line"], []).append((sum(o["status"] == "covered" for o in eligible), len(eligible)))
        got = {}
        for x in root.find("packages/package/classes/class/lines"):
            if x.get("branch") == "true":
                conds = x.find("conditions")
                got[int(x.get("number"))] = [tuple(map(int, c.get("coverage").split("(")[1].rstrip(")").split("/"))) for c in conds]
                self.assertEqual([c.get("number") for c in conds], [str(i) for i in range(len(conds))])
                c, t = sum(a for a, _ in got[int(x.get("number"))]), sum(b for _, b in got[int(x.get("number"))])
                self.assertEqual(x.get("condition-coverage"), f"{100 * c // t}% ({c}/{t})")
            else:
                self.assertIsNone(x.find("conditions"))
        self.assertEqual(got, want)
        self.assertTrue(any(len(v) > 1 for v in got.values()), "some line holds more than one decision")

    def test_a_decision_on_a_non_executable_line_moves_to_its_first_executable_line(self) -> None:
        report, _ = fixture_report("loops")
        status = {x["line"]: x["status"] for x in report["lines"]}
        self.assertEqual(status[49], "non_executable")  # `loop {`
        lines = {int(x.get("number")): x for x in ET.fromstring(render_cobertura(report)).find("packages/package/classes/class/lines")}
        self.assertNotIn(49, lines)
        self.assertEqual(lines[50].get("branch"), "true")

    def test_packages_group_root_sources_in_bytewise_order(self) -> None:
        from test_default_scope import DEP_PATH, DefaultScopeTest
        DefaultScopeTest.setUpClass()
        report = copy.deepcopy(DefaultScopeTest.report)
        user = [s for s in report["sources"] if s["ownership"] == "user"]
        self.assertGreaterEqual(len(user), 2)
        user[0]["package"] = "zeta"
        for s in user[1:]:
            s["package"] = None
        data = render_cobertura(report)
        self.assertEqual(validate(dtd(), data), [])
        check_cobertura(data, report)
        root = ET.fromstring(data)
        self.assertEqual([p.get("name") for p in root.iter("package")], ["(root)", "zeta"])
        files = [c.get("filename") for c in root.iter("class")]
        self.assertNotIn(DEP_PATH, files)
        self.assertEqual(files, [s["path"] for s in user[1:]] + [user[0]["path"]])

    def test_xml_sensitive_text_round_trips(self) -> None:
        report, _ = fixture_report("functions")
        report = copy.deepcopy(report)
        hostile = 'a<b>&"c\'\t\nd]]>'
        f = next(e for e in report["entities"] if e["kind"] == "function")
        f["qualified_name"] = hostile
        data = render_cobertura(report)
        self.assertEqual(validate(dtd(), data), [])
        self.assertIn(hostile, [m.get("name") for m in ET.fromstring(data).iter("method")])
        self.assertIn(hostile, parse_cobertura(data)["classes"][0]["methods"])
        f["qualified_name"] = "a\x01b"
        self.assertEqual(code_of(render_cobertura, report), "COV4401")

    def test_a_saturated_count_is_refused(self) -> None:
        maps, profiles, selection = rich_inputs()
        ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
        report = build_report(encode(ix), config(STALE_OK), {}, tool_version=V)
        self.assertTrue([p for p in report["points"] if p["count"]["saturated"]])
        self.assertEqual(code_of(render_cobertura, report), "COV4020")

    def test_an_empty_report_is_an_empty_document(self) -> None:
        report, _ = fixture_report("functions")
        report = copy.deepcopy(report)
        for s in report["sources"]:
            s["ownership"] = "dependency"
        data = render_cobertura(report)
        self.assertEqual(validate(dtd(), data), [])
        self.assertIn(b"<packages/>", data)
        self.assertEqual(parse_cobertura(data)["classes"], [])


class ReaderTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.report, _ = fixture_report("f0")
        cls.good = render_cobertura(cls.report)

    def test_everything_outside_the_profile_is_rejected(self) -> None:
        g = self.good
        decl = b'<?xml version="1.0" encoding="UTF-8"?>\n'
        first_line = b'<line number="10" hits="1" branch="false"/>'
        cls_block = g[g.index(b"        <class "):g.index(b"        </class>\n") + 17]
        self.assertIn(first_line, g)
        cases = {
            "a DOCTYPE": g.replace(decl, decl + b'<!DOCTYPE coverage SYSTEM "coverage-04.dtd">\n', 1),
            "an entity": g.replace(decl, decl + b'<!DOCTYPE coverage [<!ENTITY x "y">]>\n', 1),
            "an external entity": g.replace(decl, decl + b'<!DOCTYPE coverage [<!ENTITY x SYSTEM "file:///etc/passwd">]>\n', 1),
            "an undeclared entity": g.replace(b"<source>.</source>", b"<source>&x;</source>", 1),
            "a processing instruction": g.replace(b"<sources>", b"<?pi x?><sources>", 1),
            "a comment": g.replace(b"<sources>", b"<!-- c --><sources>", 1),
            "a CDATA section": g.replace(b"<source>.</source>", b"<source><![CDATA[.]]></source>", 1),
            "no declaration": g[len(decl):],
            "another declaration": g.replace(decl, b'<?xml version="1.0"?>\n', 1),
            "no final line feed": g[:-1],
            "not UTF-8": g.replace(b'version="sv0cov-r1-core"', b'version="\xff"', 1),
            "a namespace": g.replace(b"<coverage ", b'<coverage xmlns:x="urn:x" ', 1),
            "an extension attribute": g.replace(b"<sources>", b'<sources x="1">', 1),
            "a vendor element": g.replace(b"  <sources>", b"  <properties/>\n  <sources>", 1),
            "a missing attribute": g.replace(b' complexity="0.0" version', b" version", 1),
            "another version": g.replace(b'version="sv0cov-r1-core"', b'version="2.0"', 1),
            "a timestamp that is not an integer": g.replace(b'timestamp="0"', b'timestamp="0.0"', 1),
            "a host source root": g.replace(b"<source>.</source>", b"<source>/home/x</source>", 1),
            "two sources": g.replace(b"<source>.</source>", b"<source>.</source><source>.</source>", 1),
            "an absolute filename": g.replace(b'filename="main.sv0"', b'filename="/main.sv0"', 1),
            "a parent segment": g.replace(b'filename="main.sv0"', b'filename="../main.sv0"', 1),
            "name unlike filename": g.replace(b'name="main.sv0"', b'name="Main"', 1),
            "a complexity": g.replace(b'complexity="0.0"', b'complexity="1.0"', 1),
            "a signature": g.replace(b'signature=""', b'signature="()V"', 1),
            "a rate not six digits": g.replace(b'line-rate="0.875000"', b'line-rate="0.875"', 1),
            "a wrong rate": g.replace(b'line-rate="0.875000"', b'line-rate="0.875001"', 1),
            "a wrong total": g.replace(b'lines-covered="14"', b'lines-covered="15"', 1),
            "a hit count": g.replace(first_line, b'<line number="10" hits="7" branch="false"/>', 1),
            "line zero": g.replace(first_line, b'<line number="0" hits="1" branch="false"/>', 1),
            "an implied branch attribute": g.replace(first_line, b'<line number="10" hits="1"/>', 1),
            "branch true without conditions": g.replace(first_line, b'<line number="10" hits="1" branch="true" condition-coverage="100% (1/1)"/>', 1),
            "a condition-coverage on a plain line": g.replace(first_line, b'<line number="10" hits="1" branch="false" condition-coverage="100%"/>', 1),
            "P not the floor": g.replace(b'"100% (2/2)"', b'"99% (2/2)"'),
            "C above T": g.replace(b'coverage="50% (1/2)"', b'coverage="150% (3/2)"'),
            "a condition gap": g.replace(b'<condition number="0"', b'<condition number="1"', 1),
            "a condition type": g.replace(b'type="jump"', b'type="switch"', 1),
            "condition-coverage not the sum": g.replace(b'condition-coverage="50% (1/2)"', b'condition-coverage="100% (2/2)"', 1),
            "an empty conditions": g.replace(b'<condition number="0" type="jump" coverage="50% (1/2)"/>', b"", 1),
            "a line twice": g.replace(first_line, first_line + b"\n" + first_line, 1),
            "a method line not in its class": g.replace(first_line, b'<line number="999" hits="1" branch="false"/>', 1),
            "a method line unlike its class": g.replace(first_line, b'<line number="10" hits="0" branch="false"/>', 1),
            "a class twice": g.replace(cls_block, cls_block + cls_block, 1),
            "a class line twice": last(g, first_line, first_line + b"\n" + first_line),
            "a class condition gap": last(g, b'<condition number="0"', b'<condition number="1"'),
            "a method line split unlike its class": g.replace(
                b'<condition number="0" type="jump" coverage="50% (1/2)"/>',
                b'<condition number="0" type="jump" coverage="100% (1/1)"/><condition number="1" type="jump" coverage="0% (0/1)"/>', 1),
            "text in lines": g.replace(b"<lines>", b"<lines>x", 1),
        }
        for what, data in cases.items():
            with self.subTest(what):
                self.assertNotEqual(data, g, "the mutation applies")
                self.assertEqual(code_of(parse_cobertura, data), "COV4401")

    def test_check_compares_with_the_report(self) -> None:
        check_cobertura(self.good, self.report)
        other, _ = fixture_report("branches")
        self.assertEqual(code_of(check_cobertura, self.good, other), "COV4401")
        renamed = copy.deepcopy(self.report)
        next(e for e in renamed["entities"] if e["kind"] == "function")["qualified_name"] = "other"
        self.assertEqual(code_of(check_cobertura, self.good, renamed), "COV4401")


if __name__ == "__main__":
    unittest.main()
