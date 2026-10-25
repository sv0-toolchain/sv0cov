#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""What GitLab's coverage visualization reads from a Cobertura document
(CV-419; SPEC 21.5; AC-051): an offline oracle, written from GitLab's
documentation and the behaviour of its parser, ``Gitlab::Ci::Parsers::
Coverage::Documents::CoberturaDocument`` in gitlab-org/gitlab
(``lib/gitlab/ci/parsers/coverage/documents/cobertura_document.rb``, last
changed by commit ``377055c14f1d44904f26bcdc1be745115703f3ae``,
2025-12-03). It is an independent re-implementation, not a copy.

GitLab's rules, as this oracle applies them:

- Only ``source``, ``package``, ``class`` and ``line`` elements are read.
  ``line`` gives ``number`` and ``hits``, each an integer (anything else
  fails the whole report); branch and condition attributes are never read.
  Every ``line`` inside a class counts, those under ``methods`` too; a
  repeated number keeps its last value.
- A ``source`` counts only when the pipeline's project path is in it: the
  text after ``<project_path>/`` (backslashes made forward slashes) is a
  candidate prefix; a source without it, such as ``.``, is dropped, and so
  is a Go toolchain source. At most 100 are tried.
- With no usable source, a class's ``filename`` (backslashes made forward
  slashes) is taken as the repository path as it stands. With sources, the
  first ``source/filename`` that is a repository path wins and is not
  offered to a later package; with no match the class is left out.
- The documented limits: a document of at most 10 MiB and at most 100
  ``source`` nodes.

:func:`visualize` returns ``{repository path: {line: hits}}``: what the
merge request diff colours, green for ``hits > 0`` and red for ``0``.
"""

from __future__ import annotations

import xml.parsers.expat

MAX_BYTES = 10 * 1024 * 1024
MAX_SOURCES = 100
GO_SOURCE = "/usr/local/go/src"


class GitLabRejects(ValueError):
    """GitLab would fail the report (``InvalidXMLError`` / ``InvalidLineInformationError``) or exceed a limit."""


def _integer(text: str) -> int:
    """Ruby ``Integer()`` on a decimal attribute: optional sign, digits, underscores between digits.
    Ruby also takes ``0x``/``0b``/``0o`` prefixes; sv0cov never writes them, so this oracle
    accepts decimal only and is stricter than GitLab there."""
    t = text.strip()
    body = t[1:] if t[:1] in "+-" else t
    if not body or not all(c.isdigit() or c == "_" for c in body) or body.startswith("_") or body.endswith("_") or "__" in body:
        raise GitLabRejects(f"invalid line information {text!r}")
    return int(t.replace("_", ""))


def visualize(data: bytes, *, project_path: str, worktree_paths: list[str]) -> dict[str, dict[int, int]]:
    if len(data) > MAX_BYTES:
        raise GitLabRejects(f"the document is {len(data)} bytes, over GitLab's 10 MiB limit")
    paths = set(worktree_paths)
    sources: list[str] = []
    source_nodes = 0
    report: dict[str, dict[int, int]] = {}
    state = {"filename": None, "lines": [], "text": None, "matched": []}

    def resolve(filename: str) -> str | None:
        name = filename.replace("\\", "/")
        if not sources:
            return name
        for prefix in sources[:MAX_SOURCES]:
            candidate = f"{prefix.rstrip('/')}/{name}" if prefix else name
            if candidate in paths:
                return candidate
        return None

    def start(name: str, attrs: dict) -> None:
        nonlocal source_nodes
        if name == "source":
            source_nodes += 1
            state["text"] = ""
        elif name == "class" and attrs.get("filename"):
            state["filename"] = resolve(attrs["filename"])
            if state["filename"] is not None:
                state["matched"].append(state["filename"])
        elif name == "line":
            state["lines"].append((_integer(attrs.get("number", "")), _integer(attrs.get("hits", ""))))

    def text(t: str) -> None:
        if state["text"] is not None:
            state["text"] += t

    def end(name: str) -> None:
        if name == "source":
            node, state["text"] = state["text"], None
            if GO_SOURCE in node:
                return
            parts = node.replace("\\", "/").split(f"{project_path}/", 1)
            if len(parts) == 2 and parts[1]:
                sources.append(parts[1])
        elif name == "class":
            if state["filename"] is not None:
                # Every <line> of the class counts, method lines included; like Ruby's Hash[pairs]
                # a repeated number keeps its last value. Lines of a dropped class stay pending and
                # land on the next matched class, as GitLab's parser leaves them.
                report.setdefault(state["filename"], {}).update(dict(state["lines"]))
                state["lines"] = []
            state["filename"] = None
        elif name == "package":
            for m in state["matched"]:
                paths.discard(m)
            state["matched"] = []

    p = xml.parsers.expat.ParserCreate()
    p.StartElementHandler, p.EndElementHandler, p.CharacterDataHandler = start, end, text
    try:
        p.Parse(data, True)
    except xml.parsers.expat.ExpatError as exc:
        raise GitLabRejects(f"invalid XML: {exc}") from None
    if source_nodes > MAX_SOURCES:
        raise GitLabRejects(f"{source_nodes} source nodes, over GitLab's 100")
    return report


__all__ = ["GitLabRejects", "MAX_BYTES", "MAX_SOURCES", "visualize"]
