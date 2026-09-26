# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Gitignore-compatible scope-pattern oracle cases (CV-030; SPEC 18.3, AC-100).

Each case is an ordered virtual root pattern file evaluated against one
virtual tree of logical source paths (plus their implicit parent
directories). The expected selection is not written here: it is captured
from checksum-pinned Git 2.55.0 ``check-ignore --no-index`` by
``tools/gitignore_oracle.py`` and frozen in ``corpus.json``.

``SANITY`` holds a few hand-derived expectations that the captured oracle
must agree with, as a guard against a broken capture harness.
"""

from __future__ import annotations

TREE = (
    "main.sv0",
    "README.sv0",
    "foo",
    "foo.sv0",
    "foobar/x.sv0",
    "src/main.sv0",
    "src/core/a.sv0",
    "src/core/b.sv0",
    "src/core/gen/g.sv0",
    "src/util/a.sv0",
    "src/util/deep/x/y.sv0",
    "src/core.sv0",
    "Src/main.sv0",
    "lib/a.sv0",
    "lib/src/a.sv0",
    "lib/src/core/a.sv0",
    "tests/t.sv0",
    "tests/core/a_test.sv0",
    "a/b/a/b.sv0",
    "a/x/b/c.sv0",
    "a/b.sv0",
    "abc/d.sv0",
    "doc/a.b.sv0",
    ".hidden.sv0",
    ".cfg/x.sv0",
    "#hash.sv0",
    "!bang.sv0",
    "sp ace.sv0",
    "end",
    "end ",
    "end  ",
    "[x].sv0",
    "x.sv0",
    "a1.sv0",
    "ab.sv0",
    "a-.sv0",
    "a].sv0",
    "a^.sv0",
    "a!.sv0",
    "a*b.sv0",
    "q?.sv0",
    "é.sv0",
    "é.sv0",
    "ü/ß.sv0",
    "日本/語.sv0",
)

# (id, ordered pattern lines). Each line is one pattern-file line without its LF.
CASES = (
    # comments, blanks, and literal prefixes
    ("comment/blank-and-comments", ("", "   ", "#main.sv0", "# main.sv0")),
    ("comment/escaped-hash", ("\\#hash.sv0",)),
    ("comment/hash-mid-pattern", ("a#.sv0", "*#*")),
    ("negation/escaped-bang", ("\\!bang.sv0",)),
    ("negation/bang-alone", ("!",)),
    # trailing and leading spaces
    ("space/trailing-ignored", ("main.sv0 ", "end  ")),
    ("space/trailing-escaped", ("end\\ ",)),
    ("space/trailing-two-escaped", ("end\\ \\ ",)),
    ("space/leading-significant", (" main.sv0",)),
    ("space/inner", ("sp ace.sv0",)),
    ("space/only-backslash-space", ("\\ ",)),
    # terminal backslash and escapes
    ("escape/terminal-backslash", ("main.sv0\\",)),
    ("escape/terminal-backslash-dir", ("src\\",)),
    ("escape/literal-star", ("a\\*b.sv0",)),
    ("escape/literal-question", ("q\\?.sv0",)),
    ("escape/literal-bracket", ("\\[x\\].sv0",)),
    ("escape/ordinary-char", ("m\\ain.sv0",)),
    # slash anchoring and directory-only patterns
    ("slash/no-slash-matches-any-level", ("a.sv0",)),
    ("slash/leading", ("/main.sv0",)),
    ("slash/leading-dir", ("/src",)),
    ("slash/middle-anchors", ("src/main.sv0",)),
    ("slash/middle-anchors-nested", ("core/a.sv0",)),
    ("slash/trailing-dir-only", ("core/",)),
    ("slash/trailing-dir-only-file", ("foo/", "end/")),
    ("slash/no-trailing-matches-file-and-dir", ("foo", "core")),
    ("slash/leading-and-trailing", ("/src/",)),
    ("slash/double", ("src//main.sv0",)),
    ("slash/root-only", ("/",)),
    ("slash/star-segment", ("src/*",)),
    ("slash/star-segment-file", ("src/*/a.sv0",)),
    ("slash/leading-star-segment", ("*/a.sv0",)),
    # wildcards
    ("wild/star", ("*",)),
    ("wild/star-ext", ("*.sv0",)),
    ("wild/star-in-name", ("*a*",)),
    ("wild/star-does-not-cross-slash", ("src*main.sv0", "lib*a.sv0")),
    ("wild/question", ("?.sv0",)),
    ("wild/question-two", ("a?.sv0",)),
    ("wild/question-dir", ("src/?ore/",)),
    ("wild/question-not-slash", ("src?main.sv0",)),
    ("wild/hidden-star", (".*",)),
    ("wild/hidden-nested", ("*/.*", ".cfg/")),
    # bracket expressions
    ("bracket/range", ("a[0-9].sv0",)),
    ("bracket/negated-bang", ("a[!0-9].sv0",)),
    ("bracket/negated-caret", ("a[^0-9].sv0",)),
    ("bracket/close-first", ("a[]].sv0",)),
    ("bracket/negated-close-first", ("a[!]].sv0",)),
    ("bracket/dash-only", ("a[-].sv0",)),
    ("bracket/dash-last", ("a[b-].sv0",)),
    ("bracket/literal-caret", ("a[\\^].sv0",)),
    ("bracket/literal-bang-inside", ("a[x!].sv0",)),
    ("bracket/class-alpha", ("[[:alpha:]]*.sv0",)),
    ("bracket/class-digit", ("*[[:digit:]].sv0",)),
    ("bracket/class-punct", ("a[[:punct:]].sv0",)),
    ("bracket/unknown-class", ("a[[:bogus:]].sv0",)),
    ("bracket/unclosed", ("a[b", "[x")),
    ("bracket/reversed-range", ("a[z-a].sv0",)),
    ("bracket/single-char-set", ("[x].sv0",)),
    ("bracket/escaped-in-set", ("a[\\]].sv0",)),
    ("bracket/slash-in-set", ("src[/]main.sv0",)),
    # documented and other ** forms
    ("globstar/leading", ("**/a.sv0",)),
    ("globstar/leading-path", ("**/core/a.sv0",)),
    ("globstar/leading-dir", ("**/core/",)),
    ("globstar/trailing", ("src/**",)),
    ("globstar/trailing-slash", ("src/**/",)),
    ("globstar/middle", ("a/**/b.sv0",)),
    ("globstar/middle-zero-dirs", ("src/**/main.sv0",)),
    ("globstar/alone", ("**",)),
    ("globstar/root-alone", ("/**",)),
    ("globstar/alone-slash", ("**/",)),
    ("globstar/ext", ("**/*.sv0",)),
    ("globstar/non-segment-suffix", ("src/**a.sv0",)),
    ("globstar/non-segment-prefix", ("**a.sv0",)),
    ("globstar/non-segment-middle", ("src/co**/a.sv0",)),
    ("globstar/triple", ("src/***",)),
    ("globstar/triple-alone", ("***",)),
    ("globstar/star-dot", ("**.sv0",)),
    # negation, last match, and parent pruning
    ("negation/reinclude-file", ("*.sv0", "!main.sv0")),
    ("negation/order-swapped", ("!main.sv0", "*.sv0")),
    ("negation/last-match-wins", ("main.sv0", "!main.sv0", "main.sv0")),
    ("negation/parent-excluded", ("src/", "!src/main.sv0")),
    ("negation/parent-excluded-glob", ("src/", "!src/**")),
    ("negation/contents-not-dir", ("src/*", "!src/core/")),
    ("negation/contents-reinclude-nested", ("src/**", "!src/core/**")),
    ("negation/documented-example", ("/*", "!/src/", "/src/*", "!/src/core/")),
    ("negation/dir-then-file", ("src/core/", "!src/core/a.sv0")),
    ("negation/star-then-dir", ("*", "!*/")),
    ("negation/star-then-dir-then-ext", ("*", "!*/", "!*.sv0")),
    ("negation/without-prior", ("!src/main.sv0",)),
    ("negation/escaped-then-negated", ("\\!bang.sv0", "!\\!bang.sv0")),
    # case sensitivity
    ("case/lower-dir", ("src/",)),
    ("case/upper-dir", ("SRC/",)),
    ("case/mixed", ("Src/",)),
    ("case/ext", ("*.SV0",)),
    # Unicode: exact bytes, no normalization
    ("unicode/precomposed", ("é.sv0",)),
    ("unicode/decomposed", ("é.sv0",)),
    ("unicode/question-is-one-byte", ("?.sv0", "??.sv0", "???.sv0")),
    ("unicode/bracket-multibyte", ("[é].sv0",)),
    ("unicode/dir", ("日本/",)),
    ("unicode/nested", ("*/語.sv0", "ü/**")),
    ("unicode/star", ("*ß*",)),
)

# Hand-derived expectations: case id -> exact selected set (files and dirs).
SANITY = {
    "comment/blank-and-comments": set(),
    "slash/leading": {"main.sv0"},
    # No slash: each pattern matches a basename at any depth, and no directory is excluded.
    "negation/reinclude-file": {p for p in TREE if p.endswith(".sv0") and p.rsplit("/", 1)[-1] != "main.sv0"},
    "negation/parent-excluded": {
        "src", "src/main.sv0", "src/core", "src/core/a.sv0", "src/core/b.sv0", "src/core/gen", "src/core/gen/g.sv0",
        "src/util", "src/util/a.sv0", "src/util/deep", "src/util/deep/x", "src/util/deep/x/y.sv0", "src/core.sv0",
        "lib/src", "lib/src/a.sv0", "lib/src/core", "lib/src/core/a.sv0",
    },
}


def paths() -> list[tuple[str, str]]:
    """Every tree file plus implicit parent directories, UTF-8 byte ordered."""
    out = {p: "file" for p in TREE}
    for p in TREE:
        parts = p.split("/")
        for i in range(1, len(parts)):
            out.setdefault("/".join(parts[:i]), "dir")
    return sorted(out.items(), key=lambda kv: kv[0].encode("utf-8"))
