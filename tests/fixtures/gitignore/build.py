# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Frozen Git conformance groups for the scope-pattern matcher (CV-310;
SPEC 18.3; COV-SCP-007, COV-SCP-008, COV-SCP-009).

``matcher-corpus.json`` is a list of groups ``{name, patterns, paths,
selected}``: ``selected`` is the subsequence of ``paths`` that Git 2.55.0
``check-ignore --no-index`` calls ignored when ``patterns`` is the root
``.gitignore`` and every path is an empty file. ``tests/test_gitignore.py``
requires ``sv0cov.gitignore.select`` to reproduce every group exactly.
(``corpus.json`` beside it is the separate CV-030 tree-shaped oracle.)

``python3 tests/fixtures/gitignore/build.py`` checks the file without Git:
it must be well formed, its inputs must equal ``GROUPS`` below, and its
recorded SHA-256 must match its contents, so a hand edit is caught. When Git
2.55.0 happens to be on PATH the check also regenerates and compares bytes.
``--write`` regenerates it and refuses unless ``git --version`` is exactly
``git version 2.55.0``. Git only ever runs with no system or global
configuration, no home directory, ``core.excludesFile`` unset and
``core.ignorecase=false``, in a fresh repository per group.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats import canonical_json  # noqa: E402

CORPUS = HERE / "matcher-corpus.json"
GIT_VERSION = "git version 2.55.0"
SCHEMA = "sv0cov.gitignore-matcher-corpus"
ENV_BASE = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "HOME": "/nonexistent",
            "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"}

BASE = ("a.sv0", "main.sv0", "src/a.sv0", "src/b.sv0", "src/gen/x.sv0", "src/gen/deep/y.sv0", "lib/src/c.sv0",
        "tests/t.sv0", "tests/unit/u.sv0", "doc/a b.sv0", "x/y/z/w.sv0", "src/foo.sv0", "foo/bar.sv0", "abc/foo/bar.sv0",
        "a/b/c/d.sv0", "ab.sv0", "axb.sv0", "a-b.sv0", "README.sv0", "src/a1.sv0", "src/aZ.sv0", "foo.sv0", "foobar/q.sv0")
SPECIAL = ("[x].sv0", "*.sv0", "src/#n.sv0", "src/!b.sv0", "#top.sv0", "!top.sv0", "sp ace.sv0", "trail .sv0", "q?.sv0",
           "a]b.sv0", "a^b.sv0", "a\u00e9.sv0", "\u00e9/\u00fc.sv0", "\u65e5\u672c/\u8a9e.sv0", "dir [1]/f.sv0", "dir *s/f.sv0")


def large(n: int) -> list[str]:
    """A deterministic nested tree of ``n`` files."""
    out = []
    for i in range(n):
        out.append(f"d{i % 7}/s{i % 5}/{'k' * (i % 3)}f{i}.{'sv0' if i % 4 else 'txt'}")
    return sorted(set(out))


GROUPS: list[tuple[str, list[str], list[str]]] = []


def g(name: str, patterns: list[str], paths: list[str] | tuple[str, ...] | None = None) -> None:
    paths = list(BASE if paths is None else paths)
    # A path that is also a directory of another path cannot share one tree: it moves to a "~files" twin group.
    dirs = {"/".join(p.split("/")[:i]) for p in paths for i in range(1, p.count("/") + 1)}
    clash = [p for p in paths if p in dirs]
    GROUPS.append((name, list(patterns), [p for p in paths if p not in dirs]))
    if clash:
        GROUPS.append((name + "~files", list(patterns), clash))


# --- blank lines, comments, trailing spaces --------------------------------------------------------------------
g("blank-only", [""])
g("spaces-only", ["   ", "\t"])
g("comment-only", ["# *.sv0", "#a.sv0"])
g("comment-then-pattern", ["# note", "*.sv0"])
g("comment-needs-first-column", [" #x", "*.sv0"], ["a.sv0", " #x", "#x"])
g("escaped-hash", ["\\#top.sv0"], SPECIAL)
g("hash-inside", ["src/#n.sv0"], SPECIAL)
g("escaped-hash-dir", ["\\#top.sv0", "!\\#top.sv0"], SPECIAL)
g("trailing-space-ignored", ["a.sv0 "])
g("trailing-spaces-ignored", ["a.sv0     "])
g("trailing-tab-kept", ["a.sv0\t"], ["a.sv0", "a.sv0\t"])
g("trailing-escaped-space", ["trail\\ .sv0"], SPECIAL)
g("trailing-escaped-space-and-more", ["trail\\  "], ["trail ", "trail", "trail  "])
g("trailing-two-escaped", ["t\\ \\ "], ["t  ", "t ", "t"])
g("leading-space-significant", [" a.sv0"], ["a.sv0", " a.sv0"])
g("inner-space", ["doc/a b.sv0"])
g("inner-space-escaped", ["doc/a\\ b.sv0"])
g("space-before-slash", ["src /"], ["src /a.sv0", "src/a.sv0"])
g("trailing-space-after-slash", ["src/ "])
g("trailing-space-after-negation", ["*.sv0", "!a.sv0 "])
g("only-bang", ["!"])
g("bang-then-space", ["! "], ["a.sv0", " a.sv0"])
g("bang-space-name", ["! a.sv0"], ["a.sv0", " a.sv0"])
g("only-slash", ["/"])
g("slash-star", ["/*"])
g("star-slash", ["*/"])
g("bang-bang", ["*.sv0", "!!a.sv0"], ["a.sv0", "!a.sv0"])
g("hash-after-bang", ["*", "!#top.sv0"], SPECIAL)

# --- negation ---------------------------------------------------------------------------------------------------
g("negate-simple", ["*.sv0", "!a.sv0"])
g("negate-then-reinclude", ["*.sv0", "!a.sv0", "a.sv0"])
g("negate-first-no-effect", ["!a.sv0", "*.sv0"])
g("negate-only", ["!a.sv0"])
g("escaped-bang", ["\\!top.sv0"], SPECIAL)
g("escaped-bang-mid", ["src/\\!b.sv0"], SPECIAL)
g("bang-mid-literal", ["src/!b.sv0"], SPECIAL)
g("negate-dir-only", ["*", "!*/"])
g("negate-star-files-only", ["*.sv0", "!src/**"])
g("negate-under-ignored-dir", ["src/", "!src/a.sv0"])
g("negate-ignored-dir-itself", ["src/", "!src/"])
g("negate-subdir-then-file", ["src/", "!src/gen/", "!src/gen/x.sv0"])
g("negate-file-under-star-dir", ["src/*", "!src/gen", "!src/gen/x.sv0"])
g("negate-wildcard", ["*", "!*.sv0"])
g("negate-and-back", ["*.sv0", "!*.sv0", "*.sv0"])
g("negate-nested-order", ["src/**", "!src/gen/**", "src/gen/deep/**"])
g("negate-dir-bang-order", ["!src/", "src/"])
g("negate-star-only-dirs", ["**/", "!src/"])
g("double-star-dirs-negated", ["**", "!**/"])
g("negate-tests", ["**/*.sv0", "!tests/"])
g("negate-one-of-bracket", ["src/[a-b].sv0", "!src/a.sv0"])

# --- anchoring and directory-only --------------------------------------------------------------------------------
g("bare-name", ["foo"])
g("bare-name-dir-only", ["foo/"])
g("leading-slash-name", ["/foo"])
g("leading-slash-dir-only", ["/foo/"])
g("middle-slash", ["foo/bar.sv0"])
g("middle-slash-nested-not-matched", ["bar.sv0"])
g("middle-slash-anchored-dir", ["src/gen"])
g("middle-slash-dir-only", ["src/gen/"])
g("middle-slash-depth2", ["gen/x.sv0"])
g("leading-and-trailing", ["/src/gen/"])
g("trailing-slash-nested-any-depth", ["gen/"])
g("trailing-slash-deep", ["deep/"])
g("trailing-slash-anchored-miss", ["/gen/"])
g("trailing-slash-file-name", ["a.sv0/"])
g("dir-name-equals-file-name", ["src"])
g("star-slash-name", ["*/bar.sv0"])
g("star-slash-star", ["*/*"])
g("star-slash-star-star", ["*/*/*"])
g("star-slash-dir", ["*/gen/"])
g("anchored-with-star-dir", ["/*/"])
g("leading-slash-star-sv0", ["/*.sv0"])
g("leading-slash-deep", ["/a/b/c/d.sv0"])
g("two-leading-slashes", ["//foo"])
g("double-slash-middle", ["foo//bar.sv0"])
g("dot-segment", ["./a.sv0"])
g("slash-only-trailing-twice", ["foo//"])
g("name-vs-prefix", ["fo"])
g("name-vs-prefix-star", ["fo*"])
g("dir-prefix-dirs-only", ["fo*/"])
g("slash-bang-combo", ["/*", "!/src", "/src/*", "!/src/gen"])

# --- wildcards ---------------------------------------------------------------------------------------------------
g("star-ext", ["*.sv0"])
g("star-alone", ["*"])
g("star-middle", ["a*b.sv0"])
g("star-prefix-suffix", ["a*.sv0"])
g("star-no-cross-slash", ["src/*.sv0"])
g("star-component-middle", ["src/*/x.sv0"])
g("star-doesnt-match-empty-component", ["src/*/x.sv0"], ["src//x.sv0".replace("//", "/e/"), "src/gen/x.sv0"])
g("question-one", ["?.sv0"])
g("question-middle", ["a?b.sv0"])
g("question-not-slash", ["src?a.sv0"], ["src/a.sv0", "srcxa.sv0"])
g("question-multi", ["??.sv0"])
g("star-and-question", ["*?.sv0"])
g("many-stars", ["a*b*c*.sv0"], ["axbxc.sv0", "a.sv0", "abc.sv0", "axbxcx.sv0"])
g("star-backtrack", ["*a*b*c*"], ["xaxbxcx", "xcxbxa", "abc", "ab", "cba", "aabbcc"])
g("star-dot-star", ["*.*"], ["a.sv0", "noext", ".hidden", "x.y.z"])
g("hidden-file-star", ["*"], [".hidden.sv0", ".cfg/x.sv0", "a.sv0"])
g("star-matches-leading-dot", ["*.sv0"], [".hidden.sv0", ".cfg/.x.sv0", "a.sv0"])
g("literal-star-file", ["\\*.sv0"], SPECIAL)
g("literal-question-file", ["q\\?.sv0"], SPECIAL)
g("star-vs-literal-star-name", ["*.sv0", "!\\*.sv0"], SPECIAL)

# --- brackets ----------------------------------------------------------------------------------------------------
g("bracket-set", ["[ab].sv0"], ["a.sv0", "b.sv0", "c.sv0", "ab.sv0"])
g("bracket-range", ["a[a-c].sv0"], ["aa.sv0", "ab.sv0", "ac.sv0", "ad.sv0", "a-.sv0"])
g("bracket-negated-bang", ["[!a]*.sv0"], ["a.sv0", "b.sv0", "ab.sv0", "ba.sv0"])
g("bracket-negated-caret", ["[^a]*.sv0"], ["a.sv0", "b.sv0", "ab.sv0", "ba.sv0"])
g("bracket-negated-no-slash", ["src[!a]a.sv0"], ["src/a.sv0", "srcxa.sv0", "srcaa.sv0"])
g("bracket-negated-range", ["[!a-m]*.sv0"], ["a.sv0", "z.sv0", "n.sv0", "m.sv0"])
g("bracket-close-first", ["[]a].sv0"], ["].sv0", "a.sv0", "b.sv0"])
g("bracket-close-first-negated", ["[!]a].sv0"], ["].sv0", "a.sv0", "b.sv0"])
g("bracket-close-first-caret", ["[^]a].sv0"], ["].sv0", "a.sv0", "b.sv0"])
g("bracket-dash-first", ["a[-z].sv0"], ["a-.sv0", "az.sv0", "ay.sv0"])
g("bracket-dash-last", ["a[z-].sv0"], ["a-.sv0", "az.sv0", "ay.sv0"])
g("bracket-dash-only", ["a[-].sv0"], ["a-.sv0", "az.sv0"])
g("bracket-reversed-range", ["a[z-a].sv0"], ["az.sv0", "aa.sv0", "am.sv0"])
g("bracket-range-end-bracket", ["a[a-]].sv0"], ["aa.sv0", "a].sv0", "a-].sv0", "a-.sv0"])
g("bracket-unterminated", ["[a-"], ["a", "b", "[a-", "[a"])
g("bracket-unterminated-simple", ["[ab"], ["a", "[ab", "b"])
g("bracket-empty", ["[]"], ["[]", "a"])
g("bracket-in-dir-name", ["dir [1]/f.sv0"], SPECIAL)
g("bracket-literal-escaped", ["\\[x\\].sv0"], SPECIAL)
g("bracket-literal-matches-set", ["[x].sv0"], SPECIAL + ("x.sv0",))
g("bracket-escape-inside", ["[\\]]b.sv0"], ["]b.sv0", "ab.sv0", "\\b.sv0"])
g("bracket-escape-dash", ["[a\\-z]"], ["a", "-", "z", "m", "b"])
g("bracket-escape-bang", ["[\\!a]"], ["!", "a", "b"])
g("bracket-multibyte-literal", ["a[\u00e9]b"], ["a\u00e9b", "aeb", "a\u00c3b"])
g("bracket-range-multibyte-bytes", ["[\u00e9-\u00fc]"], ["\u00e9", "\u00ea", "a"])
g("bracket-upper-class", ["[[:upper:]]*"], ["Abc", "abd", "1bc", "Zed.sv0"])
g("bracket-negated-class", ["[![:alpha:]]*"], ["Abc", "abd", "1bc", "_x"])
g("bracket-class-and-chars", ["[[:digit:]x]"], ["1", "x", "y", "a"])
g("bracket-class-and-range", ["[a-c[:digit:]]"], ["a", "c", "d", "5"])
g("bracket-class-bogus", ["[[:bogus:]]*"], ["a", ":", "b", "[bogus"])
g("bracket-class-unterminated", ["[[:alpha:]"], ["a", "[", ":"])
g("bracket-class-no-closing-colon", ["[[:alpha]"], ["a", ":", "["])
g("bracket-nonclass-colon-skipped", ["[[:a]"], [":", "a", "["])
g("bracket-nonclass-colon-only", ["[[:]"], [":", "["])
g("bracket-nonclass-after-chars", ["[x[:ab]"], [":", "a", "b", "x", "["])
g("bracket-nonclass-then-literal", ["[[:alpha]z]"], [":", "a", "z", "]"])
g("bracket-class-empty", ["[[::]]"], ["a", ":", "]"])
for _cls, _sample in [("alnum", "a1_ -\t"), ("alpha", "aZ1_ "), ("blank", " \tx\n"), ("cntrl", "\x01\x7fa "), ("digit", "09a "),
                      ("graph", "a!~ \x7f"), ("lower", "azAZ1"), ("print", "a ~\x7f\x01"), ("punct", "!_~a1 "),
                      ("space", " \tx_"), ("upper", "AZaz1"), ("xdigit", "0fFgG ")]:
    # one-character names; \x01 and \x7f are legal file names
    _paths = sorted({f"{c}" if c not in "/\n" else "x" for c in _sample} | {"k"})
    _parts: list[list[str]] = [[], []]  # the filesystem here may fold case: never put 'a' and 'A' in one tree
    for _p in _paths:
        _parts[0 if all(q.casefold() != _p.casefold() for q in _parts[0]) else 1].append(_p)
    for _i, _part in enumerate(_parts):
        if _part:
            g(f"class-{_cls}-{_i}", [f"[[:{_cls}:]]"], _part)
            g(f"class-{_cls}-negated-{_i}", [f"[^[:{_cls}:]]"], _part)
g("class-high-bytes", ["[[:alpha:]]", "[[:punct:]]"], ["\u00e9", "\u65e5", "a"])
g("class-between-ranges", ["[a-c[:digit:]x-z]"], ["b", "7", "y", "m"])
g("class-upper-lower-case-fold-off", ["[[:upper:]].SV0"], ["a.SV0", "B.sv0"])
g("class-upper-lower-case-fold-off-2", ["[[:upper:]].SV0"], ["A.SV0", "b.sv0"])

# --- backslash escapes -------------------------------------------------------------------------------------------
g("escape-plain-char", ["\\a.sv0"])
g("escape-star", ["\\*.sv0"], SPECIAL)
g("escape-question", ["\\?.sv0"], SPECIAL + ("?.sv0",))
g("escape-backslash", ["a\\\\b"], ["a\\b", "ab", "a\\\\b"])
g("escape-slash", ["src\\/a.sv0"])
g("escape-slash-star", ["src\\/*"])
g("escape-space-mid", ["sp\\ ace.sv0"], SPECIAL)
g("terminal-backslash", ["src\\"], ["src", "src/a.sv0", "src\\"])
g("terminal-backslash-after-slash", ["a/b\\"], ["a/b", "a/b\\", "a/b/c/d.sv0"])
g("terminal-double-backslash", ["src\\\\"], ["src\\", "src", "src/a.sv0"])
g("terminal-backslash-with-negation", ["*", "!src\\"], ["src", "src/a.sv0", "main.sv0"])
g("backslash-before-star-star", ["src/\\**"], ["src/*", "src/a.sv0", "src/**"])
g("backslash-dir-only", ["src\\/"], ["src/a.sv0"])

# --- double asterisk ---------------------------------------------------------------------------------------------
g("starstar-alone", ["**"])
g("starstar-lead-name", ["**/foo"])
g("starstar-lead-file", ["**/bar.sv0"])
g("starstar-lead-dir-only", ["**/gen/"])
g("starstar-lead-deep", ["**/deep/y.sv0"])
g("starstar-trail", ["src/**"])
g("starstar-trail-doc-abc", ["abc/**"])
g("starstar-trail-dir-only", ["src/**/"])
g("starstar-middle", ["a/**/d.sv0"])
g("starstar-middle-zero-dirs", ["src/**/a.sv0"])
g("starstar-middle-many", ["src/**/y.sv0"])
g("starstar-middle-twice", ["**/gen/**/y.sv0"])
g("starstar-all-of-it", ["**/**"])
g("starstar-repeated", ["**/**/**/**/x.sv0"])
g("starstar-slash-ext", ["**/*.sv0"])
g("starstar-slash-ext-anchored", ["/**/*.sv0"])
g("starstar-tests-ext", ["tests/**/*.sv0"])
g("starstar-not-component-after", ["src/**x"], ["src/x", "src/ax", "src/a/x"])
g("starstar-not-component-before", ["src/x**"], ["src/x", "src/xa", "src/x/a", "src/xa/b"])
g("starstar-prefix-name", ["**x.sv0"], ["x.sv0", "ax.sv0", "a/x.sv0", "a/bx.sv0"])
g("starstar-suffix-name", ["src**"], ["src/a.sv0", "srcx/a.sv0", "src", "srcx"])
g("starstar-in-name-middle", ["a**b.sv0"], ["ab.sv0", "axb.sv0", "a/b.sv0", "ax/yb.sv0"])
g("starstar-before-bracket", ["**/[ab].sv0"], ["a.sv0", "d/b.sv0", "c.sv0"])
g("starstar-lead-but-glued", ["**foo/bar.sv0"], ["foo/bar.sv0", "xfoo/bar.sv0", "a/xfoo/bar.sv0"])
g("starstar-escaped-slash", ["src/**\\/a.sv0"], ["src/a.sv0", "src/x/a.sv0"])
g("triple-star", ["***"])
g("triple-star-lead", ["***/w.sv0"])
g("triple-star-middle", ["x/***/w.sv0"])
g("triple-star-trail", ["x/***"])
g("triple-star-ext", ["***.sv0"])
g("triple-star-glued-middle", ["x/***z/w.sv0"])
g("quad-star", ["****/w.sv0"])
g("quad-star-middle", ["x/****/w.sv0"])
g("quad-star-trail", ["x/****"])
g("star-glued-after-starstar", ["x/**z/w.sv0"])
g("starstar-glued-before-slash", ["x/y**/w.sv0"], ["x/y/z/w.sv0", "x/yy/w.sv0", "x/y/w.sv0"])
g("starstar-not-pruned-by-anchor", ["a/**"], ["a/b", "a/b/c.sv0", "a/b/c/d.sv0", "ab/c.sv0"])
g("starstar-a-slash-starstar-b", ["a/**/b"], ["a/b", "a/x/b", "a/x/y/b", "ab", "a/b/c.sv0", "b"])
g("starstar-doc-foo-test", ["foo/*"], ["foo/test.sv0", "foo/test/x.sv0", "foo/bar/baz.sv0", "foo/a/b/c.sv0"])
g("starstar-lead-and-trail", ["**/src/**"])
g("starstar-case-bang", ["**", "!**/*.sv0"])
g("starstar-dir-negation", ["**/", "!**/gen/"])

# --- parent directory rule and order -----------------------------------------------------------------------------
g("parent-excluded-no-reinclude-file", ["src/", "!src/gen/x.sv0"])
g("parent-excluded-via-star", ["src/*", "!src/gen/x.sv0"])
g("parent-file-only-reinclude-ok", ["src/gen/*", "!src/gen/x.sv0"])
g("parent-file-only-reinclude-dir-star", ["*.sv0", "!src/gen/x.sv0"])
g("parent-deep-excluded", ["src/gen/deep/", "!src/gen/deep/y.sv0"])
g("parent-excluded-then-dir-reincluded", ["src/*", "!src/gen"])
g("parent-excluded-dir-then-contents-reincluded", ["src/", "!src/gen", "!src/gen/x.sv0"])
g("parent-negated-dir-contents-ignored", ["/*", "!/src", "/src/*", "!/src/gen"])
g("parent-gitignore-doc-foo-bar", ["/*", "!/foo", "/foo/*", "!/foo/bar"], ["foo/bar", "foo/baz", "foo/bar/x", "other", "foo/bar/y/z"])
g("parent-excluded-by-unanchored-name", ["gen", "!src/gen/x.sv0"])
g("parent-excluded-by-dir-only-name", ["gen/", "!x.sv0"])
g("parent-excluded-by-glob-component", ["g*", "!src/gen/deep/y.sv0"])
g("parent-top-level-only", ["tests", "!tests/t.sv0"])
g("parent-excluded-pattern-order", ["!src/a.sv0", "src/"])
g("parent-both-orders", ["src/", "!src/", "src/gen/"])
g("parent-reinclude-whole-dir-chain", ["*", "!*/", "!src/**/*.sv0"], ["src/a.sv0", "src/gen/x.sv0", "main.sv0", "src/gen/deep/y.sv0"])
g("parent-chain-doc-pattern", ["/*", "!/src", "/src/*", "!/src/gen", "/src/gen/*", "!/src/gen/deep"],
  ["src/gen/deep/y.sv0", "src/gen/x.sv0", "src/a.sv0", "main.sv0"])
g("order-last-wins-1", ["*.sv0", "!a.sv0", "src/**"])
g("order-last-wins-2", ["src/**", "*.sv0", "!src/a.sv0"])
g("order-last-wins-3", ["!*.sv0", "a.sv0"])
g("order-later-pattern-different-form", ["src", "!src/*.sv0"])
g("order-dir-only-vs-name", ["src/", "!src"])
g("order-dir-only-after-name", ["!src", "src/"])
g("order-many-flips", ["*.sv0", "!a.sv0", "a.sv0", "!a.sv0", "a.sv0", "!a.sv0"])
g("order-duplicate-lines", ["a.sv0", "a.sv0", "!a.sv0", "!a.sv0"])
g("order-comment-between", ["*.sv0", "# !a.sv0", "!b.sv0"], ["a.sv0", "b.sv0"])
g("order-blank-between", ["*.sv0", "", "!a.sv0"], ["a.sv0", "b.sv0"])

# --- official gitignore(5) examples ------------------------------------------------------------------------------
_DOC = ["doc/frotz/x.sv0", "a/doc/frotz/y.sv0", "doc/frotz", "frotz/z.sv0", "a/frotz/w.sv0", "frotz", "doc/a.html",
        "doc/b/c.html", "foo.html", "bar/foo.html", "foo.sv0", "foo/x/y.sv0", "foo/test.sv0", "foo/test/x.sv0", "abc/d.sv0",
        "abc/e/f.sv0", "a/b/c.sv0", "a/x/b/c.sv0", "a/x/y/b/c.sv0"]
g("doc-doc-frotz-slash", ["doc/frotz/"], _DOC)
g("doc-frotz-slash", ["frotz/"], _DOC)
g("doc-star-html-bang-foo", ["*.html", "!foo.html"], _DOC)
g("doc-star-bang-star-html-reverse", ["!foo.html", "*.html"], _DOC)
g("doc-star-html-bang-foo-star", ["*", "!*.html", "foo.html"], _DOC)
g("doc-foo-slash-star", ["foo/*"], _DOC)
g("doc-foo-slash-star-bang", ["foo/*", "!foo/test.sv0"], _DOC)
g("doc-starstar-foo", ["**/foo"], _DOC)
g("doc-starstar-foo-bar", ["**/foo/bar"], ["foo/bar", "a/foo/bar", "a/b/foo/bar", "foo/x/bar", "bar"])
g("doc-abc-starstar", ["abc/**"], _DOC)
g("doc-a-starstar-b", ["a/**/b"], _DOC + ["a/b"])
g("doc-slash-star-bang-foo-ordered", ["/*", "!/foo", "/foo/*", "!/foo/bar"], ["foo/bar", "foo/baz", "foo/bar/x", "other.sv0"])
g("doc-slash-doc", ["/doc"], _DOC)
g("doc-slash-frotz-slash", ["/frotz/"], _DOC)
g("doc-dot-html-in-doc", ["doc/*.html"], _DOC)
g("doc-doc-starstar-html", ["doc/**/*.html"], _DOC)
g("doc-hash-escaped-and-bang-escaped", ["\\#top.sv0", "\\!top.sv0"], SPECIAL)
g("doc-trailing-spaces-escaped", ["trail\\ .sv0", "sp ace.sv0 "], SPECIAL)

# --- case and Unicode (exact bytes, no folding, no normalization) -------------------------------------------------
_CASE = ["a.sv0", "b.SV0", "c.Sv0", "src/D.sv0", "e.Sv0", "f.sV0"]
g("case-ext-upper", ["*.SV0"], _CASE)
g("case-ext-lower", ["*.sv0"], _CASE)
g("case-dir-lower", ["src/"], _CASE)
g("case-dir-upper", ["SRC/"], _CASE)
g("case-dir-other-case", ["SRC/", "Src"], ["SRC/e.sv0", "x.sv0"])
g("case-dir-lower-only-dir", ["src/"], ["Src/f.sv0", "x.sv0"])
g("case-bracket-range", ["[a-z].sv0"], ["a.sv0", "A.sv0x", "q.sv0", "Q.sv0y"])
g("case-bracket-class-upper", ["[[:upper:]]*.sv0"], ["A.sv0", "b.sv0", "Cb.sv0"])
g("case-negate-same-case", ["*.sv0", "!B.sv0"], ["B.sv0", "c.sv0"])
g("case-negate-other-case", ["*.sv0", "!B.sv0"], ["b.sv0", "B.sv0y"])
g("unicode-literal", ["\u00e9/"], ["\u00e9/\u00fc.sv0", "e/x.sv0", "a\u00e9.sv0"])
g("unicode-star", ["*\u00fc*"], SPECIAL)
g("unicode-cjk-dir", ["\u65e5\u672c/"], SPECIAL)
g("unicode-cjk-file", ["\u8a9e.sv0"], SPECIAL)
g("unicode-cjk-star", ["\u65e5*/*"], SPECIAL)
g("unicode-question-multibyte", ["a?.sv0"], ["a\u00e9.sv0", "ab.sv0", "a\u65e5.sv0"])
g("unicode-question-two", ["a??.sv0"], ["a\u00e9.sv0", "ab.sv0", "a\u65e5.sv0", "a\u65e5\u672c.sv0"])
g("unicode-nfc-vs-nfd", ["caf\u00e9.sv0"], ["caf\u00e9.sv0", "cafe\u0301.sv0", "cafe.sv0"])
g("unicode-nfd-pattern", ["cafe\u0301.sv0"], ["caf\u00e9.sv0", "cafe\u0301.sv0"])
g("unicode-4byte", ["\U0001f600.sv0"], ["\U0001f600.sv0", "x.sv0"])
g("unicode-4byte-question", ["?.sv0"], ["\U0001f600.sv0", "x.sv0"])
g("unicode-negated-bracket", ["[!a]*.sv0"], ["\u00e9.sv0", "a.sv0", "b.sv0"])
g("unicode-backslash-escape", ["\\\u00e9.sv0"], ["\u00e9.sv0"])
g("unicode-trailing-space-escaped", ["\u00e9\\ "], ["\u00e9 ", "\u00e9"])
g("unicode-escaped-bang-hash", ["\\!\u00e9", "\\#\u00fc"], ["!\u00e9", "#\u00fc", "\u00e9"])
g("unicode-starstar", ["**/\u00fc.sv0"], SPECIAL)
g("unicode-deep", ["\u65e5\u672c/\u8a9e/**"], ["\u65e5\u672c/\u8a9e/\u00e9/x.sv0", "\u65e5\u672c/y.sv0", "\u65e5\u672c/\u8a9e/z.sv0"])

# --- awkward path characters -------------------------------------------------------------------------------------
g("chars-all-star", ["*"], SPECIAL)
g("chars-star-ext", ["*.sv0"], SPECIAL)
g("chars-dir-with-bracket", ["dir [1]/"], SPECIAL)
g("chars-dir-with-bracket-escaped", ["dir \\[1\\]/"], SPECIAL)
g("chars-dir-with-star", ["dir \\*s/"], SPECIAL)
g("chars-hash-file", ["\\#top.sv0", "#comment"], SPECIAL)
g("chars-bang-file-negation", ["*", "!\\!top.sv0"], SPECIAL)
g("chars-space-and-trailing-space", ["trail .sv0 ", "sp ace.sv0"], SPECIAL)
g("chars-question-literal", ["q[?].sv0"], SPECIAL)
g("chars-caret-and-bracket", ["a[\\^]b.sv0", "a[]]b.sv0"], SPECIAL)
g("chars-dots", ["..", ".", "a..b", "*.."], ["a..b", "..x", "x..", ".x", "x."])
g("chars-leading-dash", ["-x", "--*"], ["-x", "--y", "a-x"])
g("chars-control", ["\x01*"], ["\x01a", "a\x01", "b"])
g("chars-dollar-percent", ["$*", "%*"], ["$a", "%b", "a$"])
g("chars-braces-parens", ["{a,b}", "(x)"], ["{a,b}", "a", "b", "(x)", "x"])
g("chars-plus-eq-tilde", ["a+b", "~x", "a=b"], ["a+b", "~x", "a=b", "aab"])
g("chars-colon", ["a:b"], ["a:b", "a"])

# --- nesting and scale ---------------------------------------------------------------------------------------------
_DEEP = "/".join(f"l{i}" for i in range(40))
g("deep-nesting-name", ["l39"], [_DEEP + "/f.sv0", "l0/l1/f.sv0"])
g("deep-nesting-anchored", ["/l0/l1/l2/"], [_DEEP + "/f.sv0", "l0/l1/f.sv0", "l0/l1/l2/g.sv0"])
g("deep-nesting-starstar", ["l0/**/l39/f.sv0"], [_DEEP + "/f.sv0", "l0/l39/f.sv0", "l0/l1/l39/g.sv0"])
g("deep-nesting-parent-rule", ["l20/", "!l20/l21/l22/f.sv0"], [_DEEP + "/f.sv0", "l20/l21/l22/f.sv0", "l0/f.sv0"])
g("deep-nesting-star-chain", ["*/*/*/*/*/*/*/*/*/*/f.sv0"], [_DEEP + "/f.sv0", "a/b/c/d/e/f/g/h/i/j/f.sv0", "a/b/f.sv0"])
g("deep-nesting-extension", ["**/*.sv0"], [_DEEP + "/f.sv0", _DEEP + "/g.txt"])
_PATHS_200 = large(200)
g("large-ext", ["*.sv0"], _PATHS_200)
g("large-dir-only", ["d3/"], _PATHS_200)
g("large-negation", ["*.sv0", "!d1/**", "d1/s2/"], _PATHS_200)
g("large-mixed", ["d[0-2]/", "!d1/", "d1/s[01]/", "*.txt", "!d*/s4/*.txt", "k*f*", "**/kk/**"], _PATHS_200)
g("large-starstar", ["d2/**/f*", "!**/s3/**", "**/s3/kk*"], _PATHS_200)
g("large-1000-flat", ["f1*", "!f12*", "f123"], [f"f{i}.sv0" for i in range(1000)])
g("large-many-patterns", [f"d{i % 7}/s{i % 5}/f{i}.sv0" for i in range(0, 120, 3)] + ["!d0/**", "d0/s1/"], _PATHS_200)


def inputs() -> list[dict]:
    return [{"name": n, "patterns": p, "paths": ps} for n, p, ps in GROUPS]


def check_inputs() -> None:
    names = [g_[0] for g_ in GROUPS]
    assert len(set(names)) == len(names), "duplicate group name"
    for name, patterns, paths in GROUPS:
        assert len(set(paths)) == len(paths), f"{name}: duplicate path"
        nodes = {"/".join(p.split("/")[:i + 1]) for p in paths for i in range(p.count("/") + 1)}
        assert len({n.casefold() for n in nodes}) == len(nodes), f"{name}: case-insensitive collision"
        files = set(paths)
        for p in paths:
            parts = p.split("/")
            assert all(parts) and ".git" not in parts and ".gitignore" not in parts, f"{name}: bad path {p!r}"
            assert not any("/".join(parts[:i]) in files for i in range(1, len(parts))), f"{name}: {p!r} under a file"
            assert not set(p) & {"\x00", "\n", "\r"}, f"{name}: unsupported character in {p!r}"
        for line in patterns:
            assert not set(line) & {"\x00", "\r", "\n"}, f"{name}: bad pattern line"


def sanitized_env() -> dict[str, str]:
    env = dict(ENV_BASE)
    env["PATH"] = os.environ.get("SV0COV_GIT_PATH", os.environ.get("PATH", "/usr/bin:/bin"))
    return env


def git_version(git: str) -> str:
    out = subprocess.run([git, "--version"], capture_output=True, env=sanitized_env(), check=True)
    return out.stdout.decode().strip()


def git_select(git: str, patterns: list[str], paths: list[str]) -> list[str]:
    env = sanitized_env()
    with tempfile.TemporaryDirectory(prefix="sv0cov-gi-") as d:
        subprocess.run([git, "init", "-q", d], check=True, env=env, stdout=subprocess.DEVNULL)
        for p in paths:
            f = os.path.join(d, p)
            os.makedirs(os.path.dirname(f), exist_ok=True)
            open(f, "wb").close()
        Path(d, ".gitignore").write_bytes("".join(line + "\n" for line in patterns).encode("utf-8"))
        r = subprocess.run([git, "-c", "core.ignorecase=false", "-c", "core.excludesFile=/dev/null", "check-ignore",
                            "--no-index", "-z", "--stdin"], cwd=d, env=env, capture_output=True,
                           input=b"".join(p.encode("utf-8") + b"\0" for p in paths))
        if r.returncode not in (0, 1):
            raise SystemExit(f"git check-ignore failed: {r.stderr.decode(errors='replace')}")
        got = {x.decode("utf-8") for x in r.stdout.split(b"\0") if x}
        return [p for p in paths if p in got]


def digest(groups: list[dict]) -> str:
    return hashlib.sha256(canonical_json.encode(groups)).hexdigest()


def build(git: str) -> bytes:
    groups = [dict(case, selected=git_select(git, case["patterns"], case["paths"])) for case in inputs()]
    doc = {"schema": SCHEMA, "version": "1.0", "git": GIT_VERSION, "cases_sha256": digest(groups), "groups": groups}
    return canonical_json.encode(doc) + b"\n"


def verify_file() -> list[str]:
    """Problems with the committed file, found without running Git."""
    if not CORPUS.is_file():
        return ["missing"]
    data = CORPUS.read_bytes()
    try:
        doc = json.loads(data)
    except ValueError as exc:
        return [f"not JSON: {exc}"]
    problems = []
    if not isinstance(doc, dict) or set(doc) != {"schema", "version", "git", "cases_sha256", "groups"}:
        return ["unexpected top-level keys"]
    if doc["schema"] != SCHEMA or doc["version"] != "1.0":
        problems.append("schema or version")
    if doc["git"] != GIT_VERSION:
        problems.append(f"recorded git is {doc['git']!r}")
    groups = doc["groups"]
    if not isinstance(groups, list) or any(not isinstance(x, dict) or set(x) != {"name", "patterns", "paths", "selected"}
                                           for x in groups):
        return problems + ["malformed groups"]
    if canonical_json.encode(doc) + b"\n" != data:
        problems.append("not canonical JSON")
    if digest(groups) != doc["cases_sha256"]:
        problems.append("cases_sha256 does not match the groups (hand edit?)")
    for x in groups:
        if not set(x["selected"]) <= set(x["paths"]) or [p for p in x["paths"] if p in set(x["selected"])] != x["selected"]:
            problems.append(f"{x['name']}: selected is not a subsequence of paths")
    if [{k: x[k] for k in ("name", "patterns", "paths")} for x in groups] != inputs():
        problems.append("groups differ from GROUPS in build.py (run --write)")
    return problems


def main() -> int:
    check_inputs()
    git = shutil.which("git", path=os.environ.get("SV0COV_GIT_PATH") or os.environ.get("PATH"))
    if "--write" in sys.argv:
        if git is None:
            print("gitignore corpus: refusing to write: git not found", file=sys.stderr)
            return 2
        version = git_version(git)
        if version != GIT_VERSION:
            print(f"gitignore corpus: refusing to write: need {GIT_VERSION!r}, found {version!r}", file=sys.stderr)
            return 2
        CORPUS.write_bytes(build(git))
        print("gitignore corpus: written")
        return 0
    problems = verify_file()
    if not problems and git is not None and git_version(git) == GIT_VERSION and build(git) != CORPUS.read_bytes():
        problems.append("regeneration with Git 2.55.0 differs")
    if problems:
        print("gitignore corpus: stale: " + "; ".join(problems), file=sys.stderr)
        return 1
    print("gitignore corpus: current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
