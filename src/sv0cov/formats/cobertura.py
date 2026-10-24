# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The Cobertura export profile ``sv0cov-cobertura-r1-core`` (CV-402; SPEC
21.5; COV-REP-005, COV-REP-010, COV-REP-011, COV-REP-012, BL-054, BL-079).

:func:`render_cobertura` writes one XML document from a validated native
report. :func:`parse_cobertura` reads a document back under the exact
profile, which is a strict subset of the pinned Cobertura 0.4 DTD
(``coverage-04.dtd`` at commit ``e5eea867``), and :func:`check_cobertura`
additionally requires its totals to equal the report's.

The mapping:

- **Document.** An XML declaration and one ``coverage`` element; no
  ``DOCTYPE``, entity, comment, processing instruction, CDATA section,
  namespace or vendor element or attribute. ``sources`` holds exactly one
  ``source``, ``.``. ``version`` is ``sv0cov-r1-core``; ``timestamp`` is the
  reproducible-build epoch the caller supplies, ``0`` by default; every
  ``complexity`` is ``0.0`` (unavailable, not measured).
- **Packages.** Root-project (``user``) sources only, as for LCOV (SPEC
  18.1; owner decision, CV-401), grouped by their build package; a source
  without a package belongs to the reserved package ``(root)`` (owner
  decision, CV-402), which no canonical package identity can spell.
  Packages are in bytewise name order, classes in source order.
- **Classes.** One per source; ``name`` and ``filename`` are its logical
  path.
- **Methods.** One per function the native function metric counts, in
  entity order; ``name`` is the canonical qualified name and ``signature``
  is empty (no Java-signature claim). A method's lines are the class lines
  its own regions touch, repeated element for element so that either level
  reads the same status.
- **Lines.** Every executable line, ascending. ``hits`` is ``1`` exactly
  for native status ``covered``; ``partial`` and ``uncovered`` are ``0``
  (the binary projection, COV-REP-010).
- **Branches.** A decision with eligible outcomes (``covered`` or
  ``uncovered``) sits on the first line of its span, or, when that line is
  not executable (a ``loop`` header), on the first executable line inside
  its span. Such a line has ``branch="true"``, ``condition-coverage="P%
  (C/T)"`` and one ``condition`` per decision, numbered from zero in
  canonical branch order, ``type="jump"``, with its own ``P% (C/T)``. ``C``
  counts covered outcomes, ``T`` eligible ones, and ``P`` is
  ``floor(100 * C / T)``. Other lines have ``branch="false"`` and no
  ``conditions``.
- **Rates** are the exact fractions with six fractional digits, rounded
  half to even; a zero denominator is ``0.000000``. They are display values
  and never drive policy.

A saturated or lower-bound count in an exported unit is refused
(``COV4020``), as SPEC 9.6 requires for every standard export; the explicit
lossy path is CV-420. Text XML 1.0 cannot carry, or a document outside the
profile or disagreeing with its report, is ``COV4401``.
"""

from __future__ import annotations

import re
import xml.parsers.expat

from sv0cov.formats.report import ratio

PROFILE = "sv0cov-cobertura-r1-core"
VERSION = "sv0cov-r1-core"
ROOT_PACKAGE = "(root)"
SATURATED, INVALID = "COV4020", "COV4401"
ELIGIBLE = ("covered", "uncovered")
EXECUTABLE = ("covered", "partial", "uncovered")
DECLARATION = '<?xml version="1.0" encoding="UTF-8"?>\n'
# Characters XML 1.0 cannot carry (SPEC 21.5 hostile strings).
RE_NOT_XML = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f￾￿\ud800-\udfff]")
_ESCAPES = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "\t": "&#9;", "\n": "&#10;", "\r": "&#13;"}


class CoberturaError(ValueError):
    """``code``: COV4020 a count with no exact value, COV4401 an invalid document."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _attr(text: str, what: str) -> str:
    if RE_NOT_XML.search(text):
        raise CoberturaError(INVALID, f"{what} {text!r} holds a character XML 1.0 cannot carry")
    return "".join(_ESCAPES.get(c, c) for c in text)


def _rate(covered: int, total: int) -> str:
    return ratio(covered, total) or "0.000000"


def _fraction(covered: int, total: int) -> str:
    return f"{100 * covered // total}% ({covered}/{total})"


def _check_exact(count: dict, what: str) -> None:
    if count["saturated"] or count["lower_bound"]:
        raise CoberturaError(SATURATED, f"{what} has no exact count (it saturated); a standard export needs exact counts")


def _classes(r: dict) -> list[tuple[str, list[dict]]]:
    """Per package, in name order: its root-project sources as classes."""
    entry = {p["entity_index"]: p for p in r["points"] if p["kind"] == "function_entry"}
    packages: dict[str, list[dict]] = {}
    for s in r["sources"]:
        if s["ownership"] != "user":
            continue
        n = s["source_index"]
        lines = {x["line"]: {"hits": int(x["status"] == "covered"), "decisions": []}
                 for x in r["lines"] if x["source_index"] == n and x["status"] in EXECUTABLE}
        for b in sorted((b for b in r["branches"] if b["source_index"] == n), key=lambda b: (b["span"]["start_line"], b["branch_index"])):
            outcomes = [o for o in b["outcomes"] if o["status"] in ELIGIBLE]
            if not outcomes:
                continue
            where = f"branch {b['branch_index']} in {s['path']}"
            for o in outcomes:
                _check_exact(o["count"], where)
            span = b["span"]
            at = next((k for k in sorted(lines) if span["start_line"] <= k <= span["end_line"]), None)
            if at is None:
                raise CoberturaError(INVALID, f"{where} has no executable line to carry it")
            lines[at]["decisions"].append((sum(o["status"] == "covered" for o in outcomes), len(outcomes)))
        touched: dict[int, set[int]] = {}
        for x in r["lines"]:
            if x["source_index"] == n and x["line"] in lines:
                for k in x["region_indices"]:
                    touched.setdefault(r["regions"][k]["entity_index"], set()).add(x["line"])
        methods = []
        for e in r["entities"]:
            p = entry.get(e["entity_index"])
            if e["kind"] != "function" or e["source_index"] != n or p is None or p["classification"] != "user":
                continue
            _check_exact(p["count"], f"function {e['qualified_name']}")
            methods.append({"name": e["qualified_name"], "lines": sorted(touched.get(e["entity_index"], ()))})
        packages.setdefault(s["package"] or ROOT_PACKAGE, []).append({"path": s["path"], "lines": lines, "methods": methods})
    return sorted(packages.items(), key=lambda kv: kv[0].encode("utf-8"))


def _totals(lines: dict, numbers) -> tuple[int, int, int, int]:
    lc = lv = bc = bv = 0
    for k in numbers:
        x = lines[k]
        lc, lv = lc + x["hits"], lv + 1
        bc += sum(c for c, _ in x["decisions"])
        bv += sum(t for _, t in x["decisions"])
    return lc, lv, bc, bv


def _rates(t: tuple[int, int, int, int]) -> str:
    return f'line-rate="{_rate(t[0], t[1])}" branch-rate="{_rate(t[2], t[3])}"'


def _line_xml(number: int, x: dict, pad: str) -> list[str]:
    if not x["decisions"]:
        return [f'{pad}<line number="{number}" hits="{x["hits"]}" branch="false"/>']
    c, t = sum(c for c, _ in x["decisions"]), sum(t for _, t in x["decisions"])
    out = [f'{pad}<line number="{number}" hits="{x["hits"]}" branch="true" condition-coverage="{_fraction(c, t)}">',
           f"{pad}  <conditions>"]
    out += [f'{pad}    <condition number="{d}" type="jump" coverage="{_fraction(c, t)}"/>' for d, (c, t) in enumerate(x["decisions"])]
    return out + [f"{pad}  </conditions>", f"{pad}</line>"]


def _lines_xml(lines: dict, numbers: list[int], pad: str) -> list[str]:
    if not numbers:
        return [f"{pad}<lines/>"]
    out = [f"{pad}<lines>"]
    for k in numbers:
        out += _line_xml(k, lines[k], pad + "  ")
    return out + [f"{pad}</lines>"]


def render_cobertura(report: dict, *, timestamp: int = 0) -> bytes:
    """The ``sv0cov-cobertura-r1-core`` document of a validated native
    report; ``timestamp`` is the reproducible-build epoch, ``0`` by default."""
    if type(timestamp) is not int or timestamp < 0:
        raise CoberturaError(INVALID, f"timestamp {timestamp!r} is not a nonnegative integer")
    packages = _classes(report)
    body = []
    total = [0, 0, 0, 0]
    for name, classes in packages:
        sums = [0, 0, 0, 0]
        inner = []
        for c in classes:
            numbers = sorted(c["lines"])
            t = _totals(c["lines"], numbers)
            sums = [a + b for a, b in zip(sums, t)]
            path = _attr(c["path"], "source path")
            inner.append(f'        <class name="{path}" filename="{path}" {_rates(t)} complexity="0.0">')
            if not c["methods"]:
                inner.append("          <methods/>")
            else:
                inner.append("          <methods>")
                for m in c["methods"]:
                    inner.append(f'            <method name="{_attr(m["name"], "function name")}" signature="" '
                                 f'{_rates(_totals(c["lines"], m["lines"]))} complexity="0.0">')
                    inner += _lines_xml(c["lines"], m["lines"], "              ")
                    inner.append("            </method>")
                inner.append("          </methods>")
            inner += _lines_xml(c["lines"], numbers, "          ")
            inner.append("        </class>")
        total = [a + b for a, b in zip(total, sums)]
        body.append(f'    <package name="{_attr(name, "package name")}" {_rates(tuple(sums))} complexity="0.0">')
        body += ["      <classes>", *inner, "      </classes>", "    </package>"]
    head = [DECLARATION.rstrip("\n"),
            f'<coverage {_rates(tuple(total))} lines-covered="{total[0]}" lines-valid="{total[1]}" '
            f'branches-covered="{total[2]}" branches-valid="{total[3]}" complexity="0.0" version="{VERSION}" timestamp="{timestamp}">',
            "  <sources>", "    <source>.</source>", "  </sources>"]
    packages_xml = ["  <packages>", *body, "  </packages>"] if body else ["  <packages/>"]
    return ("\n".join(head + packages_xml + ["</coverage>"]) + "\n").encode("utf-8")


# ── reading ─────────────────────────────────────────────────────────────────

# The profile's element and attribute grammar: each content model and
# attribute list is the pinned DTD's, narrowed to exactly what the profile
# writes (every attribute present, one ``source``, ``conditions`` exactly
# when ``branch="true"``).
_CHILDREN = {
    "coverage": re.compile(r"sources packages"), "sources": re.compile(r"source"), "source": re.compile(r""),
    "packages": re.compile(r"(package ?)*"), "package": re.compile(r"classes"), "classes": re.compile(r"(class ?)*"),
    "class": re.compile(r"methods lines"), "methods": re.compile(r"(method ?)*"), "method": re.compile(r"lines"),
    "lines": re.compile(r"(line ?)*"), "line": re.compile(r"(conditions)?"), "conditions": re.compile(r"condition( condition)*"),
    "condition": re.compile(r""),
}
_RATES = ("line-rate", "branch-rate")
_ATTRS = {
    "coverage": {*_RATES, "lines-covered", "lines-valid", "branches-covered", "branches-valid", "complexity", "version", "timestamp"},
    "sources": set(), "source": set(), "packages": set(), "classes": set(), "methods": set(), "lines": set(), "conditions": set(),
    "package": {"name", *_RATES, "complexity"}, "class": {"name", "filename", *_RATES, "complexity"},
    "method": {"name", "signature", *_RATES, "complexity"}, "condition": {"number", "type", "coverage"},
}
_INT = re.compile(r"0|[1-9][0-9]*")
_RATE = re.compile(r"0\.[0-9]{6}|1\.000000")
_FRACTION = re.compile(r"(0|[1-9][0-9]*)% \((0|[1-9][0-9]*)/([1-9][0-9]*)\)")


class _Node:
    __slots__ = ("name", "attrs", "children", "text", "line")

    def __init__(self, name: str, attrs: dict, line: int) -> None:
        self.name, self.attrs, self.children, self.text, self.line = name, attrs, [], "", line


def _bad(node: _Node | None, detail: str) -> None:
    raise CoberturaError(INVALID, f"line {node.line}: {detail}" if node is not None else detail)


def _tree(data: bytes) -> _Node:
    if not data.startswith(DECLARATION.encode()):
        _bad(None, "the document does not begin with the profile's XML declaration")
    rest = data[len(DECLARATION):]
    if b"<!" in rest or b"<?" in rest:
        _bad(None, "a DOCTYPE, comment, CDATA section, entity or processing instruction is not allowed")
    if not data.endswith(b">\n"):
        _bad(None, "the document does not end with the root element and one line feed")
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        _bad(None, "the document is not UTF-8")
    p = xml.parsers.expat.ParserCreate("UTF-8")
    stack: list[_Node] = []
    root: list[_Node] = []

    def refuse(*_a) -> None:
        _bad(None, "markup outside the profile")

    def start(name: str, attrs: dict) -> None:
        node = _Node(name, attrs, p.CurrentLineNumber)
        if stack:
            stack[-1].children.append(node)
        elif root:
            _bad(node, "a second root element")
        else:
            root.append(node)
        stack.append(node)

    def end(_name: str) -> None:
        stack.pop()

    def text(t: str) -> None:
        if stack:
            stack[-1].text += t

    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, text
    p.ProcessingInstructionHandler = p.CommentHandler = p.StartDoctypeDeclHandler = refuse
    p.EntityDeclHandler = p.UnparsedEntityDeclHandler = p.ExternalEntityRefHandler = refuse
    p.StartCdataSectionHandler = p.SkippedEntityHandler = refuse
    try:
        p.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        _bad(None, f"not well-formed XML: {exc}")
    return root[0]


def _validate(node: _Node) -> None:
    """The node and its subtree against the profile grammar."""
    if node.name not in _CHILDREN:
        _bad(node, f"element {node.name!r} is outside the Cobertura 0.4 DTD")
    if node.name != "line" and set(node.attrs) != _ATTRS[node.name]:
        _bad(node, f"{node.name} carries attributes {sorted(node.attrs)}, the profile writes {sorted(_ATTRS[node.name])}")
    if node.name != "line" and not _CHILDREN[node.name].fullmatch(" ".join(c.name for c in node.children)):
        _bad(node, f"{node.name} holds {[c.name for c in node.children]}")
    if node.name != "source" and node.text.strip(" \n"):
        _bad(node, f"{node.name} holds text")
    for value in node.attrs.values():
        if RE_NOT_XML.search(value):
            _bad(node, "an attribute holds a character XML 1.0 cannot carry")
    for c in node.children:
        _validate(c)


def _int(node: _Node, key: str) -> int:
    v = node.attrs[key]
    if not _INT.fullmatch(v):
        _bad(node, f"{key}={v!r} is not a decimal integer")
    return int(v)


def _fraction_of(node: _Node, key: str) -> tuple[int, int]:
    m = _FRACTION.fullmatch(node.attrs[key])
    if not m or int(m.group(2)) > int(m.group(3)):
        _bad(node, f"{key}={node.attrs[key]!r} is not P% (C/T)")
    c, t = int(m.group(2)), int(m.group(3))
    if node.attrs[key] != _fraction(c, t):
        _bad(node, f"{key}={node.attrs[key]!r}: P is floor(100 * C / T)")
    return c, t


def _line(node: _Node) -> tuple[int, int, int, int]:
    """(number, hits, covered outcomes, eligible outcomes) of one line element."""
    number, hits = _int(node, "number"), _int(node, "hits")
    if number == 0 or hits > 1:
        _bad(node, "line numbers start at 1 and hits are 0 or 1")
    attrs = set(node.attrs)
    if node.attrs.get("branch") == "false" and attrs == {"number", "hits", "branch"} and not node.children:
        return number, hits, 0, 0
    if node.attrs.get("branch") != "true" or attrs != {"number", "hits", "branch", "condition-coverage"} \
            or [c.name for c in node.children] != ["conditions"]:
        _bad(node, "a line is branch=\"false\" alone, or branch=\"true\" with condition-coverage and conditions")
    c = t = 0
    for d, cond in enumerate(node.children[0].children):
        if cond.attrs["number"] != str(d) or cond.attrs["type"] != "jump":
            _bad(cond, "conditions are numbered from zero with type=\"jump\"")
        dc, dt = _fraction_of(cond, "coverage")
        c, t = c + dc, t + dt
    if _fraction_of(node, "condition-coverage") != (c, t):
        _bad(node, "condition-coverage is not the sum of its conditions")
    return number, hits, c, t


def _rated(node: _Node, t: tuple[int, int, int, int]) -> None:
    if node.attrs["line-rate"] != _rate(t[0], t[1]) or node.attrs["branch-rate"] != _rate(t[2], t[3]):
        _bad(node, f"{node.name} rates are not its lines' exact six-digit fractions")
    if "complexity" in node.attrs and node.attrs["complexity"] != "0.0":
        _bad(node, "complexity is 0.0")


def _logical(path: str) -> bool:
    parts = path.split("/")
    return not (path.startswith("/") or "\\" in path or re.match(r"[A-Za-z]:", path)
                or any(p in ("", ".", "..") for p in parts))


def parse_cobertura(data: bytes) -> dict:
    """The classes of a ``sv0cov-cobertura-r1-core`` document, each with its
    package, path, method names and line and branch totals, and the
    timestamp; raises :class:`CoberturaError` for anything outside the
    profile or inconsistent within it."""
    root = _tree(data)
    if root.name != "coverage":
        _bad(root, "the root element is coverage")
    _validate(root)
    if root.attrs["version"] != VERSION:
        _bad(root, f"version is {VERSION}")
    timestamp = _int(root, "timestamp")
    sources = root.children[0].children
    if sources[0].children or sources[0].text != ".":
        _bad(sources[0], "the one source is '.'")
    classes, seen, names = [], set(), []
    total = [0, 0, 0, 0]
    for pkg in root.children[1].children:
        name = pkg.attrs["name"]
        names.append(name.encode("utf-8"))
        sums = [0, 0, 0, 0]
        for cls in pkg.children[0].children:
            path = cls.attrs["filename"]
            if cls.attrs["name"] != path or not _logical(path) or path in seen:
                _bad(cls, f"class {path!r}: name equals filename, a unique project-relative logical path")
            seen.add(path)
            methods_node, lines_node = cls.children
            rows = {}
            last = 0
            for ln in lines_node.children:
                row = _line(ln)
                if row[0] <= last:
                    _bad(ln, "line numbers are strictly ascending")
                last = row[0]
                rows[row[0]] = (row, ln)
            t = (sum(r[1] for r, _ in rows.values()), len(rows), sum(r[2] for r, _ in rows.values()),
                 sum(r[3] for r, _ in rows.values()))
            _rated(cls, t)
            methods = []
            for m in methods_node.children:
                if m.attrs["signature"] != "" or not m.attrs["name"] or m.attrs["name"] in methods:
                    _bad(m, "a method has a unique nonempty name and an empty signature")
                mt = [0, 0, 0, 0]
                prev = 0
                for ln in m.children[0].children:
                    row = _line(ln)
                    if row[0] <= prev or row[0] not in rows or _xml_of(ln) != _xml_of(rows[row[0]][1]):
                        _bad(ln, "method lines repeat class lines, ascending")
                    prev = row[0]
                    mt = [mt[0] + row[1], mt[1] + 1, mt[2] + row[2], mt[3] + row[3]]
                _rated(m, tuple(mt))
                methods.append(m.attrs["name"])
            sums = [a + b for a, b in zip(sums, t)]
            classes.append({"package": name, "path": path, "methods": methods,
                            "line": (t[0], t[1]), "branch": (t[2], t[3])})
        _rated(pkg, tuple(sums))
        total = [a + b for a, b in zip(total, sums)]
    if names != sorted(set(names)) or any(not n for n in names):
        _bad(root, "package names are nonempty, unique and in bytewise order")
    _rated(root, tuple(total))
    got = tuple(_int(root, k) for k in ("lines-covered", "lines-valid", "branches-covered", "branches-valid"))
    if got != tuple(total):
        _bad(root, f"coverage totals {got} are not its lines' {tuple(total)}")
    return {"timestamp": timestamp, "classes": classes}


def _xml_of(node: _Node) -> tuple:
    return node.name, tuple(sorted(node.attrs.items())), tuple(_xml_of(c) for c in node.children)


def check_cobertura(data: bytes, report: dict) -> None:
    """``data`` is a valid document whose classes are exactly the report's
    root-project sources in package order, with the report's own line and
    branch fractions and one method per exported function."""
    got = parse_cobertura(data)["classes"]
    want = [(name, c) for name, classes in _classes(report) for c in classes]
    if [(g["package"], g["path"]) for g in got] != [(name, c["path"]) for name, c in want]:
        raise CoberturaError(INVALID, "the document's classes are not the report's root-project sources")
    summary = {s["path"]: s["summary"] for s in report["sources"] if s["ownership"] == "user"}
    for g, (_, c) in zip(got, want):
        if g["methods"] != [m["name"] for m in c["methods"]]:
            raise CoberturaError(INVALID, f"{c['path']}: the methods are not the report's functions")
        for metric in ("line", "branch"):
            m = summary[c["path"]][metric]
            if g[metric] != (m["covered"], m["total"]):
                raise CoberturaError(INVALID, f"{c['path']}: the {metric} fraction {g[metric][0]}/{g[metric][1]} is not the "
                                              f"report's {m['covered']}/{m['total']}")


__all__ = ["CoberturaError", "PROFILE", "ROOT_PACKAGE", "check_cobertura", "parse_cobertura", "render_cobertura"]
