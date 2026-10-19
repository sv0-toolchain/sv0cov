# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Gitignore-compatible scope matcher (CV-310; SPEC 18.3; COV-SCP-007,
COV-SCP-008, COV-SCP-009).

The conformance groups in ``tests/fixtures/gitignore/matcher-corpus.json`` were
produced by Git 2.55.0 (``build.py`` there); the matcher must reproduce them,
never read the working directory, repository, environment or Git, and stay
within a polynomial bound on pathological input.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tests" / "fixtures" / "gitignore"
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import config as C  # noqa: E402
from sv0cov.gitignore import Matcher, parse, select, wildmatch  # noqa: E402

CORPUS = HERE / "matcher-corpus.json"
GROUPS = json.loads(CORPUS.read_bytes())["groups"]

CHILD = """
import json, sys
sys.path.insert(0, {src!r})
from sv0cov.gitignore import select
groups = json.loads(open({corpus!r}, 'rb').read())["groups"]
out = [select(g["patterns"], g["paths"]) for g in groups]
sys.stdout.write(json.dumps(out))
"""


class CorpusTest(unittest.TestCase):
    def test_corpus_shape(self) -> None:
        doc = json.loads(CORPUS.read_bytes())
        self.assertEqual(doc["git"], "git version 2.55.0")
        self.assertGreaterEqual(len(GROUPS), 150)
        self.assertGreaterEqual(max(len(g["paths"]) for g in GROUPS), 200)
        self.assertEqual(len({g["name"] for g in GROUPS}), len(GROUPS))

    def test_every_group_matches_git(self) -> None:
        for g in GROUPS:
            with self.subTest(group=g["name"]):
                self.assertEqual(select(g["patterns"], g["paths"]), g["selected"], g["patterns"])

    def test_matcher_object_agrees_with_select(self) -> None:
        for g in GROUPS[:40]:
            m = Matcher(g["patterns"])
            self.assertEqual([p for p in g["paths"] if m.selects(p)], g["selected"], g["name"])

    def test_path_order_is_preserved_and_independent(self) -> None:
        for g in GROUPS:
            rev = list(reversed(g["paths"]))
            self.assertEqual(select(g["patterns"], rev), list(reversed(g["selected"])), g["name"])


class IsolationTest(unittest.TestCase):
    """COV-SCP-008: only the given patterns are consulted; Git is never run."""

    def expected(self) -> list:
        return [g["selected"] for g in GROUPS]

    def hostile_cwd(self, tmp: Path) -> dict[str, str]:
        (tmp / ".gitignore").write_text("*\n!keep\n")
        git = tmp / ".git"
        (git / "info").mkdir(parents=True)
        (git / "HEAD").write_text("ref: refs/heads/main\n")
        (git / "info" / "exclude").write_text("*\n")
        (tmp / "global-ignore").write_text("*\n")
        other = tmp / "other"
        (other / "repo" / ".git" / "info").mkdir(parents=True)
        (other / "repo" / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
        (other / "repo" / ".git" / "info" / "exclude").write_text("*\n")
        (other / "repo" / ".gitignore").write_text("*\n")
        return {
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "core.excludesFile",
            "GIT_CONFIG_VALUE_0": str(tmp / "global-ignore"),
            "GIT_DIR": str(other / "repo" / ".git"),
            "GIT_WORK_TREE": str(other / "repo"),
            "XDG_CONFIG_HOME": str(tmp),
        }

    def run_child(self, cwd: Path, env: dict[str, str]) -> list:
        code = CHILD.format(src=str(ROOT / "src"), corpus=str(CORPUS))
        r = subprocess.run([sys.executable, "-I", "-c", code], cwd=cwd, env=env, capture_output=True, check=False)
        self.assertEqual(r.returncode, 0, r.stderr.decode(errors="replace"))
        return json.loads(r.stdout)

    def test_hostile_working_directory_and_environment(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d).resolve()
            env = {"PATH": os.environ.get("PATH", ""), "HOME": str(tmp), **self.hostile_cwd(tmp)}
            self.assertEqual(self.run_child(tmp, env), self.expected())

    def test_in_process_with_hostile_cwd(self) -> None:
        old_cwd = os.getcwd()
        keys = ("GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_COUNT", "GIT_CONFIG_KEY_0", "GIT_CONFIG_VALUE_0", "XDG_CONFIG_HOME")
        saved = {k: os.environ.get(k) for k in keys}
        with tempfile.TemporaryDirectory() as d:
            tmp = Path(d).resolve()
            os.environ.update(self.hostile_cwd(tmp))
            try:
                os.chdir(tmp)
                self.assertEqual([select(g["patterns"], g["paths"]) for g in GROUPS], self.expected())
            finally:
                os.chdir(old_cwd)
                for k, v in saved.items():
                    if v is None:
                        os.environ.pop(k, None)
                    else:
                        os.environ[k] = v

    def test_outside_any_repository_without_git_on_path(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_child(Path(d), {"PATH": ""}), self.expected())

    def test_no_subprocess_or_filesystem_imports(self) -> None:
        import ast
        tree = ast.parse((ROOT / "src" / "sv0cov" / "gitignore.py").read_text())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add((node.module or "").split(".")[0])
            elif isinstance(node, ast.Name):
                self.assertNotIn(node.id, ("open", "environ", "getenv", "system"))
        self.assertLessEqual(mods, {"__future__", "dataclasses", "typing"})


class ComplexityTest(unittest.TestCase):
    """COV-SCP-009: no exponential backtracking."""

    BOUND = 2.0

    def timed(self, patterns: list[str], paths: list[str]) -> tuple[float, list[str]]:
        t = time.perf_counter()
        out = select(patterns, paths)
        return time.perf_counter() - t, out

    def test_nested_stars_do_not_backtrack(self) -> None:
        text = "a" * 4000
        for pat in ("*a*a*a*a*a*a*a*a*b", "a*a*a*a*a*a*a*a*a*a*a*a*a*c"):
            dt, out = self.timed([pat], [text, "d/" + text[:3990]])
            self.assertEqual(out, [], pat)
            self.assertLess(dt, self.BOUND, pat)

    def test_nested_double_stars(self) -> None:
        path = "/".join(["abcdefghij"] * 360) + "/y"
        self.assertGreaterEqual(len(path.encode()), 3900)
        for pat in ("**/**/**/**/**/x", "a/**/**/**/**/**/x", "**/ab/**/ab/**/ab/**/x", "**/*a*a*a*a*b/**/x"):
            dt, out = self.timed([pat], [path])
            self.assertEqual(out, [], pat)
            self.assertLess(dt, self.BOUND, pat)

    def test_maximum_depth_logical_path(self) -> None:
        """A 4096-byte logical path may have ~2000 components; depth must not exhaust the stack."""
        path = "/".join(["a"] * 2047) + "/f"
        self.assertLessEqual(len(path.encode()), 4096)
        # Each leading directory is matched on its own (the parent rule), so
        # these once cost depth x length; head/tail/word filters keep them cheap.
        for pats, want in ((["x"], []), (["a/"], [path]), (["/a/a/a/"], [path]), (["**/f"], [path]), (["**/b*"], []),
                           (["**/b/**"], []), (["**/a/**/c"], []), (["**/a/**/f"], [path]),
                           ([f"p{i}/*.sv0" for i in range(1000)], [])):
            dt, out = self.timed(pats, [path])
            self.assertEqual(out, want, pats)
            self.assertLess(dt, self.BOUND, pats)

    def test_pathological_with_match_at_the_end(self) -> None:
        text = "a" * 3000 + "b"
        dt, out = self.timed(["*a*a*a*a*a*a*a*b"], [text])
        self.assertEqual(out, [text])
        self.assertLess(dt, self.BOUND)

    def test_long_bracket_and_class_runs(self) -> None:
        dt, out = self.timed(["[a-z]*[[:digit:]]*[a-z]*[[:digit:]]*Q"], ["a1" * 1500])
        self.assertEqual(out, [])
        self.assertLess(dt, self.BOUND)

    def test_thousand_patterns(self) -> None:
        patterns = [f"dir{i}/**/f{i}.sv0" if i % 3 else f"!d{i}/" for i in range(1000)]
        paths = [f"dir{i}/x/y/f{i}.sv0" for i in range(0, 1000, 7)] + [f"other/{i}.sv0" for i in range(200)]
        dt, out = self.timed(patterns, paths)
        self.assertLess(dt, self.BOUND * 3)
        self.assertEqual(out, [p for p in paths if p.startswith("dir") and int(p[3:p.index("/")]) % 3])

    def test_thousand_star_patterns_against_long_paths(self) -> None:
        patterns = ["*x" * 3 + str(i) for i in range(1000)]
        dt, out = self.timed(patterns, ["a" * 300 + "/" + "b" * 300])
        self.assertEqual(out, [])
        self.assertLess(dt, self.BOUND * 3)

    def test_wildmatch_direct(self) -> None:
        dt = time.perf_counter()
        self.assertFalse(wildmatch(b"*a" * 30 + b"b", b"a" * 3000, pathname=False))
        self.assertLess(time.perf_counter() - dt, self.BOUND)


class ParseTest(unittest.TestCase):
    def one(self, line: str):
        pats = parse([line])
        self.assertEqual(len(pats), 1, line)
        return pats[0]

    def test_dropped_lines(self) -> None:
        for line in ("", "   ", "#x", "# x", "#"):
            self.assertEqual(parse([line]), [], repr(line))

    def test_trailing_spaces(self) -> None:
        self.assertEqual(self.one("a  ").text, b"a")
        self.assertEqual(self.one("a\\ ").text, b"a\\ ")
        self.assertEqual(self.one("a\\  ").text, b"a\\ ")
        self.assertEqual(self.one("a \\ ").text, b"a \\ ")
        self.assertEqual(self.one(" a").text, b" a")
        self.assertEqual(self.one("a\t").text, b"a\t")
        self.assertEqual(self.one("a\\").text, b"a\\")

    def test_negation_flags(self) -> None:
        self.assertFalse(self.one("a").negative)
        self.assertTrue(self.one("!a").negative)
        self.assertFalse(self.one("\\!a").negative)
        self.assertEqual(self.one("\\!a").text, b"\\!a")
        self.assertEqual(self.one("!!a").text, b"!a")
        self.assertTrue(self.one("!!a").negative)
        self.assertEqual(self.one("\\#a").text, b"\\#a")
        self.assertEqual(self.one("a#").text, b"a#")

    def test_slash_flags(self) -> None:
        p = self.one("a")
        self.assertEqual((p.must_be_dir, p.no_dir), (False, True))
        p = self.one("a/")
        self.assertEqual((p.must_be_dir, p.no_dir, p.text), (True, True, b"a"))
        p = self.one("/a")
        self.assertEqual((p.must_be_dir, p.no_dir, p.text), (False, False, b"a"))
        p = self.one("/a/")
        self.assertEqual((p.must_be_dir, p.no_dir, p.text), (True, False, b"a"))
        p = self.one("a/b")
        self.assertEqual((p.must_be_dir, p.no_dir, p.text), (False, False, b"a/b"))
        p = self.one("!a/b/")
        self.assertEqual((p.negative, p.must_be_dir, p.no_dir, p.text), (True, True, False, b"a/b"))

    def test_utf8_bytes(self) -> None:
        self.assertEqual(self.one("é").text, "é".encode())

    def test_wildmatch_basics(self) -> None:
        w = lambda p, t, path=True: wildmatch(p, t, pathname=path)  # noqa: E731
        self.assertTrue(w(b"a*", b"abc"))
        self.assertFalse(w(b"a*", b"a/c"))
        self.assertTrue(w(b"a*", b"a/c", False))
        self.assertTrue(w(b"a/**", b"a/b/c"))
        self.assertFalse(w(b"a/**b", b"a/x/b") and w(b"a/**b", b"a/x/c"))
        self.assertTrue(w(b"[[:digit:]]", b"7"))
        self.assertFalse(w(b"[[:digit:]]", b"/"))


class ConfigRejectionTest(unittest.TestCase):
    """A NUL, CR or LF in a pattern is rejected by configuration (COV0014)."""

    def test_rejected(self) -> None:
        for bad in ("a\x00b", "a\rb", "a\nb", "\n", "x\r\n"):
            with self.subTest(bad=bad), self.assertRaises(C.ConfigError) as cm:
                C.check_value(C.PATTERNS, [bad], "scopes.core.include")
            self.assertEqual(cm.exception.code, C.BAD_PATTERN)

    def test_accepted(self) -> None:
        self.assertEqual(C.check_value(C.PATTERNS, ["*.sv0", "!a b", "\\#x", "é/**"], "scopes.core.include"),
                         ["*.sv0", "!a b", "\\#x", "é/**"])

    def test_empty_array_rejected(self) -> None:
        with self.assertRaises(C.ConfigError):
            C.check_value(C.PATTERNS, [], "scopes.core.include")


if __name__ == "__main__":
    unittest.main()
