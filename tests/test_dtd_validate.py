# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The test-only DTD validator (tools/dtd_validate.py) and the vendored
Cobertura 0.4 DTD it checks reports against."""

from __future__ import annotations

import hashlib
import sys
import contextlib
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))

import dtd_validate as D  # noqa: E402

DTD_PATH = ROOT / "tests" / "vendor" / "cobertura" / "coverage-04.dtd"
DTD_SHA256 = "e467cb8252e20feb794fc2dedfbea7b4957921669c758f0282d525df88897917"

RATES = 'line-rate="1" branch-rate="0" complexity="0"'
COVERAGE = (
    'line-rate="1" branch-rate="0" lines-covered="1" lines-valid="1" '
    'branches-covered="0" branches-valid="0" complexity="0" version="1" timestamp="1"'
)


def doc(class_body: str = "<methods/><lines/>", coverage_attrs: str = COVERAGE, packages: str | None = None) -> bytes:
    if packages is None:
        packages = (
            f'<package name="p" {RATES}><classes>'
            f'<class name="c" filename="a.sv0" {RATES}>{class_body}</class>'
            "</classes></package>"
        )
    return (
        f'<?xml version="1.0" encoding="UTF-8"?><coverage {coverage_attrs}>'
        f"<sources><source>/src</source></sources><packages>{packages}</packages></coverage>"
    ).encode()


class CoberturaDtdTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dtd = D.load_dtd(DTD_PATH.read_text(encoding="utf-8"))

    def bad(self, xml: bytes, needle: str) -> None:
        errors = D.validate(self.dtd, xml)
        self.assertTrue(any(needle in e for e in errors), (needle, errors))

    def test_pinned_digest(self):
        self.assertEqual(hashlib.sha256(DTD_PATH.read_bytes()).hexdigest(), DTD_SHA256)

    def test_valid_document(self):
        lines = (
            '<lines><line number="1" hits="2" branch="true" condition-coverage="50% (1/2)">'
            '<conditions><condition number="0" type="jump" coverage="50%"/></conditions></line></lines>'
        )
        body = f'<methods><method name="m" signature="()" {RATES}>{lines}</method></methods>{lines}'
        self.assertEqual(D.validate(self.dtd, doc(body)), [])

    def test_valid_without_sources_and_packages(self):
        xml = f"<coverage {COVERAGE}><packages/></coverage>".encode()
        self.assertEqual(D.validate(self.dtd, xml), [])

    def test_unknown_element(self):
        self.bad(doc("<methods/><lines/><bogus/>"), "undeclared element <bogus>")

    def test_missing_required_attribute(self):
        self.bad(doc(coverage_attrs=COVERAGE.replace(' timestamp="1"', "")), "missing required attribute 'timestamp'")

    def test_undeclared_attribute(self):
        self.bad(doc(coverage_attrs=COVERAGE + ' extra="x"'), "undeclared attribute 'extra'")

    def test_wrong_child_order(self):
        self.bad(doc("<lines/><methods/>"), "do not match the content model")

    def test_package_with_two_classes_elements(self):
        pkg = f'<package name="p" {RATES}><classes/><classes/></package>'
        self.bad(doc(packages=pkg), "/coverage/packages/package")

    def test_text_inside_lines(self):
        self.bad(doc("<methods/><lines>oops</lines>"), "text not allowed")

    def test_non_empty_condition(self):
        line = (
            '<line number="1" hits="1"><conditions>'
            '<condition number="0" type="jump" coverage="50%">x</condition></conditions></line>'
        )
        self.bad(doc(f"<methods/><lines>{line}</lines>"), "EMPTY element has content")

    def test_doctype(self):
        xml = b'<!DOCTYPE coverage SYSTEM "coverage-04.dtd">' + doc()
        self.bad(xml.replace(b'<?xml version="1.0" encoding="UTF-8"?>', b""), "DOCTYPE not allowed")

    def test_internal_entity_declaration(self):
        xml = b'<!DOCTYPE coverage [<!ENTITY e "x">]><coverage/>'
        errors = D.validate(self.dtd, xml)
        self.assertIn("entity declaration not allowed", errors)

    def test_processing_instruction(self):
        xml = doc().replace(b"<sources>", b'<?pi data?><sources>')
        self.bad(xml, "processing instruction")

    def test_not_well_formed(self):
        self.bad(b"<coverage>", "not well-formed")


TOY = """
<!-- toy -->
<!ELEMENT root (a?, b*, (c | d)+, (e, f)*)>
<!ELEMENT a EMPTY>
<!ELEMENT b ANY>
<!ELEMENT c (#PCDATA)>
<!ELEMENT d (#PCDATA | a | c)*>
<!ELEMENT e EMPTY>
<!ELEMENT f EMPTY>
<!ATTLIST e id CDATA #REQUIRED kind CDATA "x" opt CDATA #IMPLIED>
"""


class ContentModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dtd = D.load_dtd(TOY)

    def ok(self, kids: str, valid: bool = True) -> None:
        errors = D.validate(self.dtd, f"<root>{kids}</root>".encode())
        errors = [e for e in errors if "undeclared element" not in e]
        self.assertEqual(errors == [], valid, (kids, errors))

    def matches(self, model: str, names: list[str]) -> bool:
        el = D._parse_model(model)
        return bool(el.regex.match("".join(n + " " for n in names)))

    def test_optional_star_plus_choice(self):
        self.ok("<c/>")
        self.ok("<a/><c/>")
        self.ok("<a/><b/><b>t<a/></b><d/>")
        self.ok("<c/><d/><c/>")
        self.ok("", valid=False)  # (c|d)+ needs one
        self.ok("<a/><a/><c/>", valid=False)  # a?
        self.ok("<c/><b/>", valid=False)  # b* is before the choice

    def test_nested_groups(self):
        self.ok("<c/><e id='1'/><f/>")
        self.ok("<c/><e id='1'/><f/><e id='2'/><f/>")
        self.ok("<c/><e id='1'/>", valid=False)
        self.ok("<c/><f/><e id='1'/>", valid=False)

    def test_empty_any_mixed(self):
        self.ok("<c/><d>text<a/>more<c>x</c></d>")
        self.ok("<c/><d><e/></d>", valid=False)  # e not in mixed
        self.ok("<c><a/></c>", valid=False)  # (#PCDATA) allows no children
        self.ok("<c>text</c>")
        self.ok("<a>x</a><c/>", valid=False)  # EMPTY
        self.ok("<b>any <c>text</c> goes</b><c/>")

    def test_attributes(self):
        self.ok("<c/><e/><f/>", valid=False)  # missing id
        self.ok("<c/><e id='1' kind='y' opt='z'/><f/>")
        self.ok("<c/><e id='1' zz='z'/><f/>", valid=False)

    def test_regex_compiler(self):
        self.assertTrue(self.matches("(a,b?,c*)", ["a", "c", "c"]))
        self.assertFalse(self.matches("(a,b?,c*)", ["b"]))
        self.assertTrue(self.matches("((a|b),(c|d)+)*", []))
        self.assertTrue(self.matches("((a|b),(c|d)+)*", ["b", "c", "d", "a", "d"]))
        self.assertFalse(self.matches("((a|b),(c|d)+)*", ["a"]))
        self.assertTrue(self.matches("(x-y.z)", ["x-y.z"]))
        self.assertFalse(self.matches("(a)", ["aa"]))

    def test_rejected_declarations(self):
        for bad in (
            '<!ENTITY x "y">',
            "<!NOTATION n SYSTEM 'u'>",
            '<!ENTITY % p "y">',
            "<!ELEMENT a (b,c|d)>",
            "<!ELEMENT a (#PCDATA|b)>",
            "<!ELEMENT a (b",
            "<!ATTLIST a x ID #REQUIRED>",
            "<!ATTLIST a x CDATA #FIXED>",
            "junk <!ELEMENT a EMPTY>",
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                D.load_dtd(bad)

    def test_cli(self):
        import tempfile

        with tempfile.TemporaryDirectory() as td:
            td = Path(td)
            (td / "t.dtd").write_text(TOY, encoding="utf-8")
            (td / "good.xml").write_text("<root><c/></root>", encoding="utf-8")
            (td / "bad.xml").write_text("<root/>", encoding="utf-8")
            self.assertEqual(D.main([str(td / "t.dtd"), str(td / "good.xml")]), 0)
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                self.assertEqual(D.main([str(td / "t.dtd"), str(td / "bad.xml")]), 1)
            self.assertIn("bad.xml", out.getvalue())


if __name__ == "__main__":
    unittest.main()
