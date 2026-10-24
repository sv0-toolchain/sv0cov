#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""A small standard-library DTD validator for tests.

Supports the subset the vendored Cobertura DTD uses: ``<!ELEMENT>`` with
EMPTY, ANY, ``(#PCDATA)``, mixed ``(#PCDATA|a|b)*`` and element content
(sequences, choices, groups, ``?`` ``*`` ``+``), and ``<!ATTLIST>`` with
CDATA attributes that are #REQUIRED, #IMPLIED or carry a default. Any other
declaration (ENTITY, NOTATION, parameter entities) raises ValueError.

The XML side is parsed with expat; DOCTYPEs, entity declarations, external
entity references and processing instructions are reported as errors, and
nothing is ever fetched from the network.

    tools/dtd_validate.py DTD XML...    # prints errors, exit 1 if any
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from xml.parsers import expat

_COMMENT = re.compile(r"<!--.*?-->", re.S)
_DECL = re.compile(r"""<!(\S+)((?:[^>"']|"[^"]*"|'[^']*')*)>""")
_TOKEN = re.compile(r"\s*(#PCDATA|[^\s(),|?*+]+|[(),|?*+])")


@dataclass
class Element:
    """One element declaration: ``kind`` is empty/any/mixed/children."""

    kind: str
    regex: re.Pattern | None = None  # children: matches "a b c " token strings
    mixed: frozenset = frozenset()  # mixed: allowed child names


@dataclass
class Dtd:
    elements: dict[str, Element] = field(default_factory=dict)
    attrs: dict[str, dict[str, str]] = field(default_factory=dict)  # elem -> attr -> default spec


def _model_regex(tokens: list[str]) -> str:
    """Regex over child-name tokens (each name followed by one space)."""
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def take() -> str:
        nonlocal pos
        if pos >= len(tokens):
            raise ValueError("unexpected end of content model")
        pos += 1
        return tokens[pos - 1]

    def particle() -> str:
        tok = take()
        if tok == "(":
            parts, sep = [particle()], None
            while peek() in (",", "|"):
                op = take()
                if sep not in (None, op):
                    raise ValueError("mixed ',' and '|' in one group")
                sep = op
                parts.append(particle())
            if take() != ")":
                raise ValueError("expected ')' in content model")
            body = "".join(parts) if sep != "|" else "|".join(parts)
            rx = "(?:" + body + ")"
        elif tok in ")|,?*+":
            raise ValueError(f"unexpected {tok!r} in content model")
        else:
            rx = "(?:" + re.escape(tok) + " )"
        if peek() in ("?", "*", "+"):
            rx += take()
        return rx

    rx = particle()
    if pos != len(tokens):
        raise ValueError("trailing tokens in content model")
    return rx


def _parse_model(model: str) -> Element:
    model = model.strip()
    if model in ("EMPTY", "ANY"):
        return Element(model.lower())
    tokens = _TOKEN.findall(model)
    if "".join(model.split()) != "".join(tokens):
        raise ValueError(f"bad content model {model!r}")
    if len(tokens) > 1 and tokens[0] == "(" and tokens[1] == "#PCDATA":
        star = tokens[-1] == "*"
        body = tokens[2 : -2 if star else -1]
        names = [t for t in body if t != "|"]
        if tokens[-2 if star else -1] != ")" or set(body[::2]) - {"|"} or (names and not star):
            raise ValueError(f"mixed content must be (#PCDATA|...)*: {model!r}")
        return Element("mixed", mixed=frozenset(names))
    return Element("children", regex=re.compile(_model_regex(tokens) + r"\Z"))


def load_dtd(text: str) -> Dtd:
    dtd = Dtd()
    text = _COMMENT.sub("", text)
    pos = 0
    for m in _DECL.finditer(text):
        if text[pos : m.start()].strip():
            raise ValueError(f"unsupported DTD text: {text[pos : m.start()].strip()[:40]!r}")
        pos = m.end()
        kind, body = m.group(1), m.group(2).strip()
        if kind == "ELEMENT":
            name, _, model = body.partition(" ")
            if not model.strip() or name in dtd.elements:
                raise ValueError(f"bad or duplicate ELEMENT declaration {body!r}")
            dtd.elements[name] = _parse_model(model)
        elif kind == "ATTLIST":
            parts = re.findall(r"""\"[^\"]*\"|'[^']*'|\S+""", body)
            name, rest = parts[0], parts[1:]
            if not rest or len(rest) % 3:
                raise ValueError(f"bad ATTLIST declaration {body!r}")
            for i in range(0, len(rest), 3):
                attr, atype, default = rest[i : i + 3]
                if atype != "CDATA":
                    raise ValueError(f"unsupported attribute type {atype!r}")
                if default not in ("#REQUIRED", "#IMPLIED") and default[0] not in "\"'":
                    raise ValueError(f"unsupported attribute default {default!r}")
                dtd.attrs.setdefault(name, {}).setdefault(attr, default)
        else:
            raise ValueError(f"unsupported declaration <!{kind}>")
    if text[pos:].strip():
        raise ValueError(f"unsupported DTD text: {text[pos:].strip()[:40]!r}")
    return dtd


def validate(dtd: Dtd, xml_bytes: bytes) -> list[str]:
    errors: list[str] = []
    stack: list[list] = []  # [name, children, text]

    def path() -> str:
        return "/" + "/".join(f[0] for f in stack)

    def start(name: str, attrs: dict[str, str]) -> None:
        if stack:
            stack[-1][1].append(name)
        stack.append([name, [], []])
        if name not in dtd.elements:
            errors.append(f"{path()}: undeclared element <{name}>")
        declared = dtd.attrs.get(name, {})
        for a in attrs:
            if a not in declared:
                errors.append(f"{path()}: undeclared attribute {a!r}")
        for a, spec in declared.items():
            if spec == "#REQUIRED" and a not in attrs:
                errors.append(f"{path()}: missing required attribute {a!r}")

    def end(name: str) -> None:
        _, children, text = stack[-1]
        decl = dtd.elements.get(name)
        if decl is not None:
            has_text = bool("".join(text).strip())
            if decl.kind == "empty" and (children or has_text):
                errors.append(f"{path()}: EMPTY element has content")
            elif decl.kind == "children":
                if has_text:
                    errors.append(f"{path()}: text not allowed")
                if not decl.regex.match("".join(c + " " for c in children)):
                    errors.append(f"{path()}: children ({', '.join(children)}) do not match the content model")
            elif decl.kind == "mixed":
                for c in children:
                    if c not in decl.mixed:
                        errors.append(f"{path()}: child <{c}> not allowed")
        stack.pop()

    def chars(data: str) -> None:
        if stack:
            stack[-1][2].append(data)

    parser = expat.ParserCreate()
    parser.StartElementHandler = start
    parser.EndElementHandler = end
    parser.CharacterDataHandler = chars
    parser.StartDoctypeDeclHandler = lambda *a: errors.append("DOCTYPE not allowed")
    parser.EntityDeclHandler = lambda *a: errors.append("entity declaration not allowed")
    parser.ExternalEntityRefHandler = lambda *a: errors.append("external entity reference not allowed") or 0
    parser.ProcessingInstructionHandler = lambda t, d: errors.append(f"processing instruction <?{t}?> not allowed")
    parser.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)
    try:
        parser.Parse(xml_bytes, True)
    except expat.ExpatError as exc:
        errors.append(f"not well-formed: {exc}")
    return errors


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2:
        print("usage: dtd_validate.py DTD XML...", file=sys.stderr)
        return 2
    dtd = load_dtd(Path(args[0]).read_text(encoding="utf-8"))
    bad = 0
    for name in args[1:]:
        for err in validate(dtd, Path(name).read_bytes()):
            print(f"{name}: {err}")
            bad += 1
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
