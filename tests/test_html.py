# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The HTML report (CV-309; SPEC 20.2.1, 21.2; COV-REP-002, COV-SEC-003,
AC-020, AC-021, AC-025).

Every semantic fixture and the two-map sample render to a document that the
structural check accepts: self-contained, unable to make a request, with
links only inside itself. The check itself is shown to reject each thing it
looks for. Hostile text in every untrusted field stays text. Navigation
reaches every uncovered place through one chain. The context filter carries
exactly the numbers of :func:`context_view`. The same input gives the same
bytes.
"""

from __future__ import annotations

import copy
import json
import re
import sys
import unittest
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES, fixture_inputs, map_input, profile_input, raw, rich_inputs  # noqa: E402
from test_report import STALE_OK, V, config, fixture_report, fixture_sources  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.html import CSP, SCRIPT, STYLE, HtmlError, check_html, render_html  # noqa: E402
from sv0cov.model.context import context_view  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

HOSTILE = '<script>alert(1)</script></script><!-- "q" \'a\' &amp; \x1b[31mred\x1b[0m ‮evil‬\x00'


class Doc(HTMLParser):
    """Elements (tag, attributes, text inside) of a document."""

    def __init__(self, data: bytes) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, dict, list[str]]] = []
        self.open: list[int] = []
        self.feed(data.decode("utf-8"))
        self.close()

    def handle_starttag(self, tag, attrs):
        self.elements.append((tag, {k: v or "" for k, v in attrs}, []))
        if tag not in ("meta", "br", "input", "img", "link"):
            self.open.append(len(self.elements) - 1)

    def handle_endtag(self, tag):
        while self.open:
            i = self.open.pop()
            if self.elements[i][0] == tag:
                break

    def handle_data(self, data):
        for i in self.open:
            self.elements[i][2].append(data)

    def find(self, tag: str | None = None, **attrs) -> list[tuple[str, dict, list[str]]]:
        return [e for e in self.elements if (tag is None or e[0] == tag) and all(e[1].get(k) == v for k, v in attrs.items())]

    def by_id(self, ident: str) -> tuple[str, dict, list[str]]:
        (e,) = [e for e in self.elements if e[1].get("id") == ident]
        return e

    def text(self, e) -> str:
        return "".join(e[2])


def multi_context() -> tuple[dict, dict]:
    """The boolean fixture run twice: everything under one context, only
    `main` and `count` under the absent one."""
    data, m, counts = fixture_inputs("boolean")
    entry = {p["point_id"] for p in m["points"] if p["kind"] == "function_entry"
             and m["entities"][p["entity_index"]]["qualified_name"] in ("main", "count")}
    only = {pid: v for pid, v in counts.items() if pid in entry}
    profiles = [profile_input("p1.sv0profraw", raw(m, counts, 1, context="unit tests"), m),
                profile_input("p2.sv0profraw", raw(m, only, 2, context=None), m)]
    ix = build_indexed([map_input("b.sv0covmap.json", data)], profiles, tool_version=V)
    return build_report(encode(ix), config(), fixture_sources("boolean", ix), tool_version=V), fixture_sources("boolean", ix)


def rich() -> dict:
    maps, profiles, selection = rich_inputs()
    ix = build_indexed(maps, profiles, run_selection=selection, tool_version=V)
    return build_report(encode(ix), config(STALE_OK), {}, tool_version=V)


class RenderTest(unittest.TestCase):
    def test_every_fixture_renders_a_checked_document_and_the_same_bytes_every_time(self) -> None:
        """COV-REP-002, AC-025."""
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, ix = fixture_report(name)
                sources = fixture_sources(name, ix)
                first = render_html(report, sources)
                check_html(first)
                for _ in range(4):
                    self.assertEqual(render_html(copy.deepcopy(report), dict(sources)), first)
        page = render_html(rich(), {})
        check_html(page)

    def test_the_document_is_self_contained_and_offline(self) -> None:
        """AC-020: nothing in the document can reach outside it."""
        report, sources = multi_context()
        page = render_html(report, sources)
        doc = Doc(page)
        (csp,) = doc.find("meta", **{"http-equiv": "Content-Security-Policy"})
        self.assertEqual(csp[1]["content"], CSP)
        self.assertTrue(CSP.startswith("default-src 'none';"))
        for directive in ("connect-src 'none'", "img-src 'none'", "font-src 'none'", "form-action 'none'", "base-uri 'none'"):
            self.assertIn(directive, CSP)
        self.assertEqual([doc.text(e) for e in doc.find("style")], [STYLE])
        self.assertEqual([doc.text(e) for e in doc.find("script") if e[1].get("type") != "application/json"], [SCRIPT])
        self.assertFalse(re.search(rb"https?:|//[a-z]|url\(|@import|fetch\(|XMLHttpRequest|WebSocket|import\(|\.src\s*=|innerHTML", page))
        self.assertTrue(all(e[1]["href"].startswith("#") for e in doc.find("a")))
        self.assertEqual(doc.find("meta", name="referrer")[0][1]["content"], "no-referrer")

    def test_the_check_rejects_each_thing_it_looks_for(self) -> None:
        report, sources = multi_context()
        page = render_html(report, sources).decode("utf-8")
        mutations = {
            "an image": page.replace("<main", '<img alt="" src="data:,"><main', 1),
            "a link out": page.replace('href="#main"', 'href="https://example.com/"', 1),
            "a dangling link": page.replace('href="#main"', 'href="#nowhere"', 1),
            "an event handler": page.replace("<main", '<main onclick="x()"', 1),
            "an inline style": page.replace("<main", '<main style="color:red"', 1),
            "an unpinned script": page.replace("</body>", "<script>alert(1)</script></body>", 1),
            "a changed script": page.replace('"use strict";', '"use strict"; fetch("x");', 1),
            "a changed style": page.replace("body{margin:0;", "body{margin:0;background:url(x);", 1),
            "a duplicate id": page.replace('id="summary-h"', 'id="files"', 1),
            "no policy": page.replace("Content-Security-Policy", "X-Nothing", 1),
            "a refresh": page.replace("<title>", '<meta http-equiv="refresh" content="0"><title>', 1),
            "a form": page.replace("<main", "<form></form><main", 1),
            "no doctype": page[len("<!DOCTYPE html>\n"):],
            "a script of another type": page.replace('type="application/json"', 'type="module"', 1),
        }
        for what, bad in mutations.items():
            with self.subTest(mutation=what):
                self.assertNotEqual(bad, page)
                with self.assertRaises(HtmlError):
                    check_html(bad.encode("utf-8"))
        with self.assertRaises(HtmlError):
            check_html(b"\xff" + page.encode("utf-8"))


class InjectionTest(unittest.TestCase):
    """AC-021, COV-SEC-003: hostile text in every untrusted field stays text."""

    def test_hostile_text_everywhere_stays_text(self) -> None:
        report = rich()
        r = copy.deepcopy(report)
        for s in r["sources"]:
            s["path"] = HOSTILE + s["path"]
            s["source_state"], s["observed_digest"] = "current", s["digest"]
        for c in r["contexts"]:
            if c["value"]:
                c["value"] = HOSTILE + c["value"]
        for x in r["exclusions"]:
            x["reason"] = HOSTILE
        for e in r["entities"]:
            e["qualified_name"] = HOSTILE + e["qualified_name"]
        for i in r["inputs"]:
            i["name"] = HOSTILE
        r["tool"]["version"] = HOSTILE
        sources = {s["path"]: ("fn x() {\n" + HOSTILE + "\n}\n" * 40).encode("utf-8") for s in r["sources"]}
        page = render_html(r, sources)
        check_html(page)
        doc = Doc(page)
        tags = {e[0] for e in doc.elements}
        self.assertLessEqual(tags, {"html", "head", "meta", "title", "style", "body", "a", "header", "h1", "dl", "dt", "dd", "p",
                                    "label", "select", "option", "span", "nav", "ul", "li", "main", "section", "h2", "h3", "table",
                                    "thead", "tbody", "tr", "th", "td", "br", "ol", "kbd", "div", "footer", "script"})
        self.assertEqual(len(doc.find("script")), 2)  # the data block and the pinned script, nothing injected
        self.assertNotIn(b"<script>alert", page)
        self.assertNotIn(b"\x1b", page)
        self.assertNotIn("‮".encode("utf-8"), page)
        self.assertNotIn(b"\x00", page)
        visible = "".join(doc.text(e) for e in doc.find("td")) + "".join(doc.text(e) for e in doc.find("h3"))
        self.assertIn("<script>alert(1)</script>", visible)  # shown, as text
        self.assertIn("\\x1b[31m", visible)
        self.assertIn("\\u202e", visible)
        data = doc.find("script", type="application/json")[0]
        json.loads(doc.text(data))  # still valid JSON, and it did not end the element early
        self.assertNotIn(b"</script></script>", page)


class NavigationTest(unittest.TestCase):
    def test_one_chain_reaches_every_uncovered_place(self) -> None:
        report, sources = multi_context()
        doc = Doc(render_html(report, sources))
        want = set()
        for line in report["lines"]:
            if line["status"] in ("uncovered", "partial"):
                want.add(f"L{line['source_index']}-{line['line']}")
        for b in report["branches"]:
            if any(o["status"] == "uncovered" for o in b["outcomes"]):
                want.add(f"L{b['source_index']}-{b['span']['start_line']}")
        listed = [e[1]["href"][1:] for e in doc.elements if e[0] == "a" and e[1]["href"].startswith("#L")
                  and any(doc.elements.index(e) > doc.elements.index(o) for o in doc.find("ol"))][:len(want)]
        self.assertEqual(set(listed), want)
        chain = [e[1]["href"][1:] for e in doc.find("a") if "nx" in e[1].get("class", "")]
        self.assertEqual(len(chain), len(want))
        self.assertEqual(chain[-1], "uncovered")
        self.assertEqual(set(chain[:-1]) | {listed[0]}, want)
        for target in want:
            row = doc.by_id(target)
            self.assertEqual((row[0], row[1].get("tabindex")), ("tr", "-1"))

    def test_files_and_functions_link_to_their_sources(self) -> None:
        report, sources = multi_context()
        doc = Doc(render_html(report, sources))
        hrefs = {e[1]["href"] for e in doc.find("a")}
        for s in report["sources"]:
            self.assertIn(f"#src-{s['source_index']}", hrefs)
        for e in report["entities"]:
            if e["kind"] == "function":
                self.assertIn(f"#L{e['source_index']}-{e['span']['start_line']}", hrefs)

    def test_every_status_is_a_word(self) -> None:
        report, sources = multi_context()
        doc = Doc(render_html(report, sources))
        words = {"l-c": "covered", "l-p": "partial", "l-u": "uncovered", "l-x": "excluded", "l-n": ""}
        rows = [e for e in doc.find("tr") if e[1].get("class", "").startswith("l-")]
        self.assertEqual(len(rows), len(report["lines"]))
        self.assertIn("partial", "".join(doc.text(e) for e in doc.find("td", **{"class": "st"})))
        for row in rows:
            n = doc.elements.index(row)
            (st,) = [e for e in doc.elements[n:n + 6] if e[0] == "td" and e[1].get("class") == "st"][:1]
            self.assertEqual(doc.text(st), words[row[1]["class"]])
        self.assertTrue(any("(not taken)" in doc.text(e) for e in doc.find("span")))


class ContextFilterTest(unittest.TestCase):
    def test_the_filter_carries_the_numbers_of_each_context(self) -> None:
        report, sources = multi_context()
        doc = Doc(render_html(report, sources))
        options = doc.find("option")
        self.assertEqual([doc.text(o) for o in options], ["all contexts (aggregate)", "context (default)", 'context "unit tests"'])
        views = json.loads(doc.text(doc.find("script", type="application/json")[0]))["views"]
        codes = {"covered": "c", "partial": "p", "uncovered": "u", "non_executable": "n", "excluded": "x"}
        self.assertEqual(views[0]["l"], "".join(codes[x["status"]] for x in report["lines"]))
        for c in report["contexts"]:
            view = context_view(report, c["context_index"])
            got = views[c["context_index"] + 1]
            self.assertEqual(got["l"], "".join(codes[x["status"]] for x in view["lines"]))
            s = view["summary"]
            self.assertEqual(got["m"]["S:function:f"], f"{s['function']['covered']}/{s['function']['total']}")
            self.assertEqual(got["m"]["S:line:x"], f"{s['line']['partial']} partial")
        self.assertNotEqual(views[1]["l"], views[2]["l"])
        # Every cell the script rewrites has a value in every view.
        keys = {e[1]["data-m"] for e in doc.elements if "data-m" in e[1]}
        for v in views:
            self.assertLessEqual(keys, set(v["m"]))
        outcomes = {int(e[1]["data-o"]) for e in doc.elements if "data-o" in e[1]}
        self.assertEqual(outcomes, set(range(len(views[0]["o"]))))

    def test_one_context_has_no_filter(self) -> None:
        report, ix = fixture_report("boolean")
        doc = Doc(render_html(report, fixture_sources("boolean", ix)))
        self.assertEqual((doc.find("select"), doc.find("script", type="application/json")), ([], []))


class StructureTest(unittest.TestCase):
    """Preliminary accessibility structure (R01-G4; full WCAG 2.2 AA is R1)."""

    def test_landmarks_headings_labels_and_focus(self) -> None:
        report, sources = multi_context()
        doc = Doc(render_html(report, sources))
        self.assertEqual(doc.find("html")[0][1]["lang"], "en")
        self.assertEqual(len(doc.find("h1")), 1)
        for tag in ("header", "nav", "main", "footer"):
            self.assertEqual(len(doc.find(tag)), 1, tag)
        self.assertEqual(doc.find("nav")[0][1]["aria-label"], "Report sections")
        skip = doc.elements[[e[0] for e in doc.elements].index("a")]
        self.assertEqual((skip[1]["href"], skip[1]["class"]), ("#main", "skip"))
        self.assertTrue(all("scope" in e[1] for e in doc.find("th")))
        (select,) = doc.find("select")
        self.assertEqual(doc.find("label")[0][1]["for"], select[1]["id"])
        for e in doc.find("section"):
            self.assertEqual(doc.by_id(e[1]["aria-labelledby"])[0] in ("h2", "h3"), True)
        for e in doc.find("div", **{"class": "wrap"}):
            self.assertEqual((e[1]["tabindex"], e[1]["role"]), ("0", "region"))
            self.assertTrue(e[1]["aria-label"].startswith("source lines of "))


class SourceTest(unittest.TestCase):
    def test_an_unavailable_source_lists_its_lines_without_text(self) -> None:
        report, ix = fixture_report("boolean")
        sources = fixture_sources("boolean", ix)
        r = copy.deepcopy(report)
        r["sources"][0]["source_state"] = "unavailable"
        page = render_html(r, sources)
        check_html(page)
        doc = Doc(page)
        self.assertEqual(doc.find("table", **{"class": "src"}), [])
        self.assertIn("is not available", page.decode())
        listed = {e[1]["id"] for e in doc.find("li") if e[1].get("id", "").startswith("L0-")}
        self.assertLessEqual({f"L0-{x['line']}" for x in report["lines"] if x["source_index"] == 0}, listed)
        self.assertIn("partial", "".join(doc.text(e) for e in doc.find("li")))
        self.assertNotIn(b"seen(b)", page)

    def test_crlf_and_tabs(self) -> None:
        report, ix = fixture_report("source-text")
        page = render_html(report, fixture_sources("source-text", ix))
        check_html(page)
        self.assertNotIn(b"\\x0d", page)
        self.assertNotIn(b"\r", page)
        self.assertIn(b"\t", page)  # a tab in the source stays a tab


if __name__ == "__main__":
    unittest.main()
