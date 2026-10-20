# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Git diff model of changed-region coverage (CV-311; SPEC 22.3; COV-POL-012..020,
AC-045..049).

Every fixture repository is built on the fly with real Git in a temporary
directory, with the developer's own Git configuration kept out of the fixture
commands. The module under test must work regardless of that configuration.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import gitdiff as G  # noqa: E402

HAVE_GIT = shutil.which("git") is not None


def fixture_env() -> dict[str, str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"})
    return env


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def lines(*names: str, nl: str = "\n") -> bytes:
    return "".join(n + nl for n in names).encode()


class Fx:
    """One fixture repository; the project lives in ``sub`` (empty = root)."""

    def __init__(self, td: str, sub: str = "", name: str = "repo", init: bool = True) -> None:
        self.root = (Path(td) / name).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        self.sub = sub
        self.project = self.root / sub if sub else self.root
        self.project.mkdir(parents=True, exist_ok=True)
        if init:
            self.git("init", "-q", "-b", "main")
            self.git("config", "user.name", "Fixture")
            self.git("config", "user.email", "fixture@example.invalid")
            self.git("config", "commit.gpgsign", "false")
            self.git("config", "tag.gpgsign", "false")

    def git(self, *args: str, check: bool = True, cwd: Path | None = None) -> str:
        p = subprocess.run(["git", *args], cwd=cwd or self.root, env=fixture_env(), capture_output=True)
        if check and p.returncode != 0:
            raise AssertionError(f"git {args} failed: {p.stderr.decode()}")
        return p.stdout.decode().strip()

    def w(self, rel: str, data: bytes | str) -> Path:
        p = self.project / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)
        return p

    def commit(self, msg: str = "c") -> str:
        self.git("add", "-A")
        self.git("commit", "-q", "--allow-empty", "-m", msg)
        return self.rev("HEAD")

    def rev(self, spec: str) -> str:
        return self.git("rev-parse", spec)

    def base(self, spelling: str = "main", **kw) -> G.Base:
        return G.resolve_base(self.project, spelling, **kw)

    def capture(self, paths, spelling: str = "main") -> G.Capture:
        return G.capture(self.base(spelling), paths)


def code_of(test: unittest.TestCase, fn, *a, **kw) -> G.GitDiffError:
    with test.assertRaises(G.GitDiffError) as cm:
        fn(*a, **kw)
    return cm.exception


@unittest.skipUnless(HAVE_GIT, "git is not on PATH")
class Case(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.TemporaryDirectory()
        self.td = self._td.name
        self.addCleanup(self._td.cleanup)

    def fx(self, sub: str = "", **kw) -> Fx:
        return Fx(self.td, sub, **kw)


class BaseRequired(unittest.TestCase):
    def test_missing_base_needs_no_git(self) -> None:
        """AC-045 / COV-POL-012: no spelling is COV4301, before any Git command runs."""
        for s in (None, ""):
            with self.subTest(spelling=s):
                with mock.patch.object(G.subprocess, "run", side_effect=AssertionError("git was run")):
                    e = code_of(self, G.resolve_base, Path("/nonexistent/project"), s, executable="/nonexistent/git")
                self.assertEqual(e.code, G.MISSING)
                self.assertEqual(G.MISSING, "COV4301")


class Resolve(Case):
    def test_normal_branch_merge_base_is_branch_point(self) -> None:
        """COV-POL-014 / AC-046: a feature branch resolves to the fork point."""
        for sub in ("", "proj/inner"):
            with self.subTest(sub=sub):
                f = self.fx(sub, name=f"r{len(sub)}")
                f.w("a.sv0", "x\n")
                fork = f.commit("fork")
                f.git("checkout", "-q", "-b", "feature")
                f.w("a.sv0", "y\n")
                f.commit("f1")
                f.git("checkout", "-q", "main")
                f.w("m.txt", "m\n")
                main_tip = f.commit("m1")
                f.git("checkout", "-q", "feature")
                head = f.rev("HEAD")
                b = f.base("main")
                self.assertEqual((b.merge_base, b.reference, b.head), (fork, main_tip, head))
                self.assertEqual(b.spelling, "main")
                self.assertEqual(b.toplevel, f.root)
                self.assertEqual(b.prefix, (sub + "/") if sub else "")

    def test_base_equal_head_and_head_spelling(self) -> None:
        """COV-POL-014: a base equal to HEAD has itself as merge base."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        h = f.commit()
        for sp in ("main", "HEAD", h, h[:10]):
            with self.subTest(sp=sp):
                b = f.base(sp)
                self.assertEqual((b.merge_base, b.reference, b.head), (h, h, h))

    def test_base_ahead_of_head(self) -> None:
        """COV-POL-014: a base ahead of HEAD has merge base HEAD."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        h = f.commit()
        f.git("checkout", "-q", "-b", "ahead")
        f.w("a.sv0", "y\n")
        ahead = f.commit()
        f.git("checkout", "-q", "main")
        b = f.base("ahead")
        self.assertEqual((b.merge_base, b.reference, b.head), (h, ahead, h))

    def test_annotated_tag_peels_to_commit(self) -> None:
        """COV-POL-014: a tag of a commit names that commit."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        h = f.commit()
        f.git("tag", "-a", "-m", "t", "v1")
        b = f.base("v1")
        self.assertEqual(b.reference, h)

    def test_missing_ref(self) -> None:
        """COV-POL-014 / COV-POL-016: a missing reference is COV4302."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        for sp in ("nope", "origin/main", "0" * 40, "main~5"):
            with self.subTest(sp=sp):
                self.assertEqual(code_of(self, f.base, sp).code, G.UNRESOLVED)

    def test_non_commit_objects(self) -> None:
        """COV-POL-014: a tree, a blob, or a tag of a blob is not a base."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        tree = f.rev("HEAD^{tree}")
        blob = f.git("hash-object", "-w", "a.sv0")
        f.git("tag", "blobtag", blob)
        f.git("tag", "-a", "-m", "t", "blobann", blob)
        for sp in (tree, blob, "blobtag", "blobann", "HEAD^{tree}"):
            with self.subTest(sp=sp):
                self.assertEqual(code_of(self, f.base, sp).code, G.UNRESOLVED)

    def test_option_like_spelling_is_not_an_option(self) -> None:
        """COV-POL-014: a spelling starting with '-' is a name, never an option."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        for sp in ("--output=x", "-h", "--all", "--help", "-"):
            with self.subTest(sp=sp):
                self.assertEqual(code_of(self, f.base, sp).code, G.UNRESOLVED)
        self.assertFalse((f.root / "x").exists())
        self.assertFalse((f.project / "x").exists())

    def test_not_a_repository(self) -> None:
        """COV-POL-014: repository absence is COV4302."""
        d = Path(self.td) / "plain"
        d.mkdir()
        self.assertEqual(code_of(self, G.resolve_base, d, "main").code, G.UNRESOLVED)

    def test_unborn_head(self) -> None:
        """COV-POL-014: a repository with no commit has no HEAD to compare."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        e = code_of(self, f.base, "main")
        self.assertEqual(e.code, G.UNRESOLVED)

    def test_shallow_clone_fails_even_for_head(self) -> None:
        """COV-POL-014 (owner decision): ANY shallow repository is COV4302."""
        src = self.fx(name="src")
        src.w("a.sv0", "x\n")
        src.commit("1")
        src.w("a.sv0", "y\n")
        src.commit("2")
        dst = Path(self.td) / "shallow"
        subprocess.run(["git", "clone", "-q", "--depth", "1", f"file://{src.root}", str(dst)], env=fixture_env(), check=True,
                       capture_output=True)
        for sp in ("HEAD", "main", "origin/main"):
            with self.subTest(sp=sp):
                e = code_of(self, G.resolve_base, dst, sp)
                self.assertEqual(e.code, G.UNRESOLVED)
                self.assertIn("shallow", e.detail)

    def test_no_common_ancestor(self) -> None:
        """COV-POL-014: unrelated histories are COV4302."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        f.git("checkout", "-q", "--orphan", "other")
        f.git("rm", "-rfq", ".")
        f.w("b.sv0", "z\n")
        f.commit("orphan")
        f.git("checkout", "-q", "main")
        e = code_of(self, f.base, "other")
        self.assertEqual(e.code, G.UNRESOLVED)
        self.assertIn("common ancestor", e.detail)

    def test_criss_cross_has_two_merge_bases(self) -> None:
        """COV-POL-014 / AC-046: two merge bases are COV4303 naming both, sorted."""
        f = self.fx()
        f.w("base.txt", "0\n")
        f.commit("A")
        f.git("checkout", "-q", "-b", "x")
        f.w("x.txt", "x\n")
        bx = f.commit("B")
        f.git("checkout", "-q", "main")
        f.git("checkout", "-q", "-b", "y")
        f.w("y.txt", "y\n")
        cy = f.commit("C")
        f.git("checkout", "-q", "x")
        f.git("merge", "-q", "--no-ff", "-m", "m1", cy)
        f.git("checkout", "-q", "y")
        f.git("merge", "-q", "--no-ff", "-m", "m2", bx)
        f.git("checkout", "-q", "x")
        e = code_of(self, f.base, "y")
        self.assertEqual(e.code, G.AMBIGUOUS)
        self.assertEqual(e.candidates, tuple(sorted((bx, cy))))
        self.assertEqual(len(e.candidates), 2)
        for c in e.candidates:
            self.assertIn(c, e.detail)

    def test_git_absent(self) -> None:
        """COV-POL-014: Git missing (bad executable, or none on PATH) is COV4302."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        self.assertEqual(code_of(self, f.base, "main", executable="/nonexistent/git").code, G.UNRESOLVED)
        with mock.patch.dict(os.environ, {"PATH": "/nonexistent-bin"}):
            self.assertEqual(code_of(self, f.base, "main").code, G.UNRESOLVED)
        b = f.base("main")
        self.assertEqual(code_of(self, G.capture, b, ["a.sv0"], executable="/nonexistent/git").code, G.UNRESOLVED)


class Hostile(Case):
    def _repo(self) -> Fx:
        f = self.fx("proj")
        f.w("src/a.sv0", lines(*[f"l{i}" for i in range(1, 9)]))
        f.w("src/é b.sv0", lines("p", "q", "r"))
        f.commit("base")
        f.w("src/a.sv0", lines("l1", "L2", "l3", "n1", "l4", "l5", "l6", "l7", "l8"))
        f.git("add", "-A")
        f.w("src/é b.sv0", lines("p", "Q", "r"))
        return f

    PATHS = ["src/a.sv0", "src/é b.sv0"]

    def test_hostile_config_changes_nothing(self) -> None:
        """COV-POL-013: repository configuration cannot alter the capture."""
        f = self._repo()
        clean = f.capture(self.PATHS)
        marker = Path(self.td) / "ran-marker"
        for k, v in (("diff.external", f"sh -c 'touch {marker}; exit 3'"), ("diff.hostile.textconv", f"sh -c 'touch {marker}; exit 3' #"),
                     ("diff.noprefix", "true"), ("diff.mnemonicPrefix", "true"), ("diff.relative", "true"), ("color.ui", "always"),
                     ("color.diff", "always"), ("core.quotepath", "true"), ("diff.renames", "false"), ("status.relativePaths", "true"),
                     ("diff.algorithm", "patience"), ("diff.context", "7"), ("core.pager", "false"), ("diff.renameLimit", "1"),
                     ("status.renames", "false"), ("core.excludesFile", str(Path(self.td) / "nope")),
                     ("remote.origin.url", f"ext::sh -c 'touch {marker}' #"), ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
                     ("branch.main.remote", "origin"), ("branch.main.merge", "refs/heads/main"), ("protocol.ext.allow", "always"),
                     ("fetch.recurseSubmodules", "true"), ("core.fsmonitor", "false")):
            f.git("config", k, v)
        (f.root / ".git" / "info").mkdir(exist_ok=True)
        (f.root / ".git" / "info" / "attributes").write_text("*.sv0 diff=hostile\n")
        hostile = f.capture(self.PATHS)
        self.assertEqual(hostile.record(), clean.record())
        self.assertEqual(hostile.diff, clean.diff)
        self.assertFalse(marker.exists())
        self.assertNotIn(b"\x1b[", hostile.diff)
        self.assertIn(b"--- a/proj/src/a.sv0", hostile.diff)
        self.assertIn("proj/src/é b.sv0".encode(), hostile.diff)

    def test_no_fetch_for_unknown_remote_base(self) -> None:
        """COV-POL-013: origin/main absent locally is COV4302 and the remote is never contacted."""
        f = self._repo()
        marker = Path(self.td) / "contacted"
        f.git("remote", "add", "origin", f"ext::sh -c 'touch {marker}' #")
        f.git("config", "branch.main.remote", "origin")
        f.git("config", "branch.main.merge", "refs/heads/main")
        f.git("config", "protocol.ext.allow", "always")
        for sp in ("origin/main", "@{upstream}", "@{u}", "origin/HEAD"):
            with self.subTest(sp=sp):
                self.assertEqual(code_of(self, f.base, sp).code, G.UNRESOLVED)
        self.assertFalse(marker.exists())

    def test_caller_git_env_is_ignored(self) -> None:
        """COV-POL-013: GIT_DIR / GIT_WORK_TREE / GIT_INDEX_FILE of the caller do not redirect Git."""
        f = self._repo()
        other = self.fx(name="other")
        other.w("z.sv0", "z\n")
        other.commit("o")
        clean = f.capture(self.PATHS)
        env = {"GIT_DIR": str(other.root / ".git"), "GIT_WORK_TREE": str(other.root), "GIT_INDEX_FILE": str(other.root / "idx"),
               "GIT_CEILING_DIRECTORIES": "/", "GIT_PAGER": "false", "GIT_EXTERNAL_DIFF": "false", "GIT_CONFIG_COUNT": "1",
               "GIT_CONFIG_KEY_0": "diff.noprefix", "GIT_CONFIG_VALUE_0": "true", "GIT_CONFIG_GLOBAL": "/nonexistent"}
        with mock.patch.dict(os.environ, env):
            b = f.base("main")
            c = G.capture(b, self.PATHS)
        self.assertEqual(c.record(), clean.record())
        self.assertEqual(b.toplevel, f.root)

    def test_git_environment_unit(self) -> None:
        """COV-POL-013: git_environment drops every GIT_* variable of the caller and pins local settings."""
        env = G.git_environment({"GIT_DIR": "x", "GIT_SSH": "y", "HOME": "/h", "PATH": "/p"})
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("GIT_SSH", env)
        self.assertEqual(env["HOME"], "/h")
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], os.devnull)
        self.assertEqual(env["GIT_CONFIG_NOSYSTEM"], "1")
        self.assertEqual(env["GIT_ALLOW_PROTOCOL"], "")


class CaptureStates(Case):
    def _matrix(self, sub: str) -> tuple[Fx, G.Capture]:
        f = self.fx(sub, name=f"m{len(sub)}")
        base = lines(*[f"l{i}" for i in range(1, 7)])
        for n in ("staged", "unstaged", "both", "clean"):
            f.w(f"{n}.sv0", base)
        f.commit("base")
        f.w("staged.sv0", lines("l1", "X2", "l3", "l4", "l5", "l6"))
        f.w("unstaged.sv0", lines("l1", "l2", "l3", "l4", "X5", "l6"))
        f.w("both.sv0", lines("l1", "X2", "l3", "l4", "l5", "l6"))
        f.git("add", "staged.sv0", "both.sv0", cwd=f.project)
        f.w("both.sv0", lines("l1", "X2", "l3", "l4", "l5", "X6"))
        return f, f.capture(["staged.sv0", "unstaged.sv0", "both.sv0", "clean.sv0"])

    def test_state_matrix(self) -> None:
        """COV-POL-017 / AC-047: staged, unstaged, both and clean sources are told apart."""
        for sub in ("", "p/q"):
            with self.subTest(sub=sub):
                f, c = self._matrix(sub)
                by = {s.path: s for s in c.sources}
                exp = {"staged.sv0": ("modified", True, False, (2,)), "unstaged.sv0": ("modified", False, True, (5,)),
                       "both.sv0": ("modified", True, True, (2, 6)), "clean.sv0": ("unchanged", False, False, ())}
                for name, (state, st, un, cl) in exp.items():
                    s = by[name]
                    self.assertEqual((s.state, s.staged, s.unstaged, s.changed_lines), (state, st, un, cl), name)
                    self.assertEqual(s.sha256, sha((f.project / name).read_bytes()))
                    self.assertEqual(s.repo_path, (sub + "/" if sub else "") + name)
                    self.assertIsNone(s.old_path)
                self.assertFalse(c.clean)
                self.assertEqual(c.diff_sha256, sha(c.diff))
                self.assertIn(b"X2", c.diff)
                # tuple order follows sorted paths
                self.assertEqual([s.path for s in c.sources], sorted(by))

    def test_clean_worktree_at_merge_base(self) -> None:
        """COV-POL-017: a clean worktree with HEAD == merge base has an empty diff and is clean."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        c = f.capture(["a.sv0"])
        self.assertTrue(c.clean)
        self.assertEqual(c.diff, b"")
        self.assertEqual(c.diff_sha256, sha(b""))
        self.assertEqual(c.sources[0].state, "unchanged")
        self.assertEqual(c.sources[0].changed_lines, ())
        self.assertEqual(c.sources[0].sha256, sha(b"x\n"))

    def test_clean_worktree_with_committed_branch_changes(self) -> None:
        """COV-POL-017: committed branch edits are in the diff while the worktree stays clean."""
        f = self.fx()
        f.w("a.sv0", lines("1", "2", "3"))
        f.commit()
        f.git("checkout", "-q", "-b", "feat")
        f.w("a.sv0", lines("1", "two", "3", "4"))
        f.commit()
        c = f.capture(["a.sv0"])
        self.assertTrue(c.clean)
        s = c.sources[0]
        self.assertEqual((s.state, s.staged, s.unstaged, s.changed_lines), ("modified", False, False, (2, 4)))
        self.assertNotEqual(c.diff, b"")

    def test_changed_line_shapes(self) -> None:
        """COV-POL-017: only current-side added or modified lines count; pure deletion contributes none."""
        f = self.fx()
        f.w("mod.sv0", lines("l1", "l2", "l3", "l4", "l5"))
        f.w("del.sv0", lines("l1", "l2", "l3", "l4"))
        f.w("ins.sv0", lines("l1", "l2"))
        f.commit()
        f.w("mod.sv0", lines("l1", "L2", "l3", "n1", "n2", "l4"))  # modify 2, insert 4,5, delete l5
        f.w("del.sv0", lines("l1", "l2", "l4"))
        f.w("ins.sv0", lines("l1", "a", "b", "c", "l2"))
        c = f.capture(["mod.sv0", "del.sv0", "ins.sv0"])
        by = {s.path: s.changed_lines for s in c.sources}
        self.assertEqual(by, {"mod.sv0": (2, 4, 5), "del.sv0": (), "ins.sv0": (2, 3, 4)})
        self.assertEqual({s.path: s.state for s in c.sources}["del.sv0"], "modified")

    def test_new_file_staged_is_added(self) -> None:
        """COV-POL-017: a staged new file is 'added' and every line is changed."""
        f = self.fx("proj")
        f.w("old.sv0", "x\n")
        f.commit()
        f.w("new.sv0", lines("a", "b", "c"))
        f.git("add", "proj/new.sv0")
        c = f.capture(["new.sv0"])
        s = c.sources[0]
        self.assertEqual((s.state, s.staged, s.unstaged, s.changed_lines, s.old_path), ("added", True, False, (1, 2, 3), None))

    def test_new_file_added_on_branch_and_clean(self) -> None:
        """COV-POL-017: a file added by a branch commit is 'added' with every line changed."""
        f = self.fx()
        f.w("x.sv0", "x\n")
        f.commit()
        f.git("checkout", "-q", "-b", "feat")
        f.w("n.sv0", lines("a", "b"))
        f.commit()
        s = f.capture(["n.sv0"]).sources[0]
        self.assertEqual((s.state, s.changed_lines, s.staged, s.unstaged), ("added", (1, 2), False, False))

    def test_rename_with_edits(self) -> None:
        """COV-POL-017: a rename records the old repository path and only the edited lines."""
        for sub in ("", "proj"):
            with self.subTest(sub=sub):
                f = self.fx(sub, name=f"rn{len(sub)}")
                f.w("old.sv0", lines(*[f"line{i}" for i in range(1, 11)]))
                f.commit()
                f.git("mv", (sub + "/" if sub else "") + "old.sv0", (sub + "/" if sub else "") + "new.sv0")
                f.w("new.sv0", lines(*[f"line{i}" if i != 4 else "EDIT" for i in range(1, 11)]))
                c = f.capture(["new.sv0"])
                s = c.sources[0]
                self.assertEqual(s.state, "renamed")
                self.assertEqual(s.old_path, (sub + "/" if sub else "") + "old.sv0")
                self.assertEqual(s.changed_lines, (4,))
                self.assertTrue(s.staged)

    def test_rename_without_edits(self) -> None:
        """COV-POL-017: a pure rename has the old path and no changed lines."""
        f = self.fx()
        f.w("old.sv0", lines(*[f"line{i}" for i in range(1, 6)]))
        f.commit()
        f.git("mv", "old.sv0", "new.sv0")
        c = f.capture(["new.sv0"])
        s = c.sources[0]
        self.assertEqual((s.state, s.old_path, s.changed_lines), ("renamed", "old.sv0", ()))

    def test_crlf_file(self) -> None:
        """COV-POL-017: CRLF bytes are digested exactly and lines are counted correctly."""
        f = self.fx()
        f.w("c.sv0", lines("a", "b", "c", nl="\r\n"))
        f.commit()
        data = lines("a", "B", "c", "d", nl="\r\n")
        f.w("c.sv0", data)
        s = f.capture(["c.sv0"]).sources[0]
        self.assertEqual(s.changed_lines, (2, 4))
        self.assertEqual(s.sha256, sha(data))
        self.assertIn(b"\r\n", data)

    def test_awkward_path_names(self) -> None:
        """COV-POL-017: spaces, non-ASCII, leading '#' and '-' in file names."""
        names = ["with space.sv0", "café.sv0", "#hash.sv0", "-dash.sv0", "d ir/ü ☃.sv0", "--output=x.sv0"]
        for sub in ("", "pr oj"):
            with self.subTest(sub=sub):
                f = self.fx(sub, name=f"aw{len(sub)}")
                for n in names:
                    f.w(n, lines("a", "b", "c"))
                f.commit()
                for n in names:
                    f.w(n, lines("a", "B", "c"))
                c = f.capture(names)
                self.assertEqual({s.path for s in c.sources}, set(names))
                for s in c.sources:
                    self.assertEqual((s.state, s.changed_lines, s.unstaged), ("modified", (2,), True), s.path)
                    self.assertEqual(s.sha256, sha(lines("a", "B", "c")))
                self.assertFalse((f.project / "x").exists())

    def test_deterministic_and_json(self) -> None:
        """COV-POL-017 / COV-POL-019: two captures are equal, and the record is plain sorted JSON."""
        f, c1 = self._matrix("proj")
        c2 = f.capture(["clean.sv0", "both.sv0", "unstaged.sv0", "staged.sv0"])
        self.assertEqual(c1.record(), c2.record())
        self.assertEqual(c1.diff, c2.diff)
        text = json.dumps(c1.record(), sort_keys=True)
        self.assertEqual(json.loads(text), c1.record())
        r = c1.record()
        self.assertEqual(list(r), sorted(r))
        self.assertEqual(r["diff_options"], list(G.DIFF_OPTIONS))
        self.assertEqual(r["git"]["executable_sha256"], sha(Path(shutil.which("git")).resolve().read_bytes()))
        self.assertIn("git version", r["git"]["version"])
        self.assertEqual(set(r["base"]), {"head", "merge_base", "reference", "spelling"})
        for s in r["sources"]:
            self.assertEqual(list(s), sorted(s))

    def test_duplicate_and_empty_paths(self) -> None:
        """COV-POL-017: duplicate compiled paths collapse; an empty list captures nothing."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.commit()
        self.assertEqual(len(f.capture(["a.sv0", "a.sv0"]).sources), 1)
        c = f.capture([])
        self.assertEqual((c.sources, c.diff, c.clean), ((), b"", True))

    def test_only_compiled_sources_enter_the_diff(self) -> None:
        """COV-POL-017: edits to files outside the compiled list do not enter the diff."""
        f = self.fx()
        f.w("a.sv0", "x\n")
        f.w("other.sv0", "o\n")
        f.commit()
        f.w("a.sv0", "y\n")
        f.w("other.sv0", "p\n")
        c = f.capture(["a.sv0"])
        self.assertNotIn(b"other.sv0", c.diff)
        self.assertEqual(c.diff_sha256, sha(c.diff))


class UntrackedAndBad(Case):
    def test_compiled_untracked_blocks(self) -> None:
        """COV-POL-018 / AC-048: a compiled untracked .sv0 is COV4304 naming it."""
        for sub in ("", "proj"):
            with self.subTest(sub=sub):
                f = self.fx(sub, name=f"u{len(sub)}")
                f.w("a.sv0", "x\n")
                f.commit()
                f.w("new/u.sv0", "u\n")
                b = f.base()
                e = code_of(self, G.capture, b, ["a.sv0", "new/u.sv0"])
                self.assertEqual(e.code, G.UNTRACKED)
                self.assertIn("new/u.sv0", e.detail)
                self.assertIn("untracked", e.detail)

    def test_compiled_ignored_blocks(self) -> None:
        """COV-POL-018 / AC-048: a compiled .sv0 matched by .gitignore is COV4304."""
        f = self.fx("proj")
        f.w("a.sv0", "x\n")
        f.w(".gitignore", "gen.sv0\ngen_dir/\n")
        f.commit()
        f.w("gen.sv0", "g\n")
        f.w("gen_dir/h.sv0", "h\n")
        for p in ("gen.sv0", "gen_dir/h.sv0"):
            with self.subTest(p=p):
                e = code_of(self, G.capture, f.base(), ["a.sv0", p])
                self.assertEqual(e.code, G.UNTRACKED)
                self.assertIn("ignored", e.detail)

    def test_unrelated_untracked_files_are_fine(self) -> None:
        """COV-POL-018 / AC-048: untracked files outside the compiled list play no part."""
        f = self.fx("proj")
        f.w("a.sv0", "x\n")
        f.w(".gitignore", "junk.sv0\n")
        f.commit()
        f.w("notes.txt", "n\n")
        f.w("extra.sv0", "e\n")
        f.w("junk.sv0", "j\n")
        f.w("sub/deep.sv0", "d\n")
        (f.root / "outside.txt").write_text("o\n")
        c = f.capture(["a.sv0"])
        self.assertEqual([s.path for s in c.sources], ["a.sv0"])
        self.assertTrue(c.clean)

    def test_conflicted_source(self) -> None:
        """SPEC 22.3 (owner decision): a conflicted compiled source is COV4302."""
        f = self.fx("proj")
        f.w("a.sv0", lines("1", "2", "3"))
        f.w("ok.sv0", "ok\n")
        f.commit()
        f.git("checkout", "-q", "-b", "side")
        f.w("a.sv0", lines("1", "side", "3"))
        f.commit()
        f.git("checkout", "-q", "main")
        f.w("a.sv0", lines("1", "main", "3"))
        f.commit()
        f.git("merge", "side", check=False)
        self.assertIn("UU", f.git("status", "--porcelain"))
        b = f.base("main")
        e = code_of(self, G.capture, b, ["a.sv0", "ok.sv0"])
        self.assertEqual(e.code, G.UNRESOLVED)
        self.assertIn("conflict", e.detail)
        self.assertIn("a.sv0", e.detail)
        # a conflict elsewhere does not block a capture of other sources
        self.assertEqual(len(G.capture(b, ["ok.sv0"]).sources), 1)

    def test_binary_source_by_attribute(self) -> None:
        """SPEC 22.3 (owner decision): a source Git treats as binary (attribute) is COV4302."""
        f = self.fx()
        f.w(".gitattributes", "*.sv0 binary\n")
        f.w("a.sv0", lines("1", "2"))
        f.commit()
        f.w("a.sv0", lines("1", "two"))
        e = code_of(self, f.capture, ["a.sv0"])
        self.assertEqual(e.code, G.UNRESOLVED)
        self.assertIn("binary", e.detail)

    def test_binary_source_by_nul_bytes(self) -> None:
        """SPEC 22.3 (owner decision): NUL bytes that differ from base make a source binary, COV4302."""
        f = self.fx()
        f.w("a.sv0", lines("1", "2"))
        f.commit()
        f.w("a.sv0", b"1\n\x00\x00\n")
        self.assertEqual(code_of(self, f.capture, ["a.sv0"]).code, G.UNRESOLVED)

    def test_binary_source_unchanged_is_not_an_error(self) -> None:
        """SPEC 22.3: an unchanged binary source has no diff and so nothing to refuse."""
        f = self.fx()
        f.w("a.sv0", b"1\n\x00\n")
        f.commit()
        c = f.capture(["a.sv0"])
        self.assertEqual(c.sources[0].state, "unchanged")


class Stale(Case):
    def _snap(self):
        f = self.fx("proj")
        for n in ("a.sv0", "b.sv0", "c.sv0"):
            f.w(n, f"{n}\n")
        f.commit()
        f.w("a.sv0", "changed\n")
        return f, f.capture(["a.sv0", "b.sv0", "c.sv0"])

    def test_unchanged_is_empty(self) -> None:
        """COV-POL-020 / AC-049: nothing mutated means nothing stale."""
        f, c = self._snap()
        self.assertEqual(G.stale_paths(c, f.project), [])

    def test_modified_deleted_named(self) -> None:
        """COV-POL-020 / AC-049: a mutated or deleted source is named, and only it."""
        f, c = self._snap()
        f.w("b.sv0", "b mutated\n")
        self.assertEqual(G.stale_paths(c, f.project), ["b.sv0"])
        (f.project / "c.sv0").unlink()
        self.assertEqual(G.stale_paths(c, f.project), ["b.sv0", "c.sv0"])
        f.w("a.sv0", "changed again\n")
        self.assertEqual(G.stale_paths(c, f.project), ["a.sv0", "b.sv0", "c.sv0"])

    def test_same_bytes_rewritten_is_not_stale(self) -> None:
        """COV-POL-020: stale means different bytes, not a newer mtime."""
        f, c = self._snap()
        f.w("a.sv0", "changed\n")
        self.assertEqual(G.stale_paths(c, f.project), [])

    def test_current_mapping_overrides_disk(self) -> None:
        """COV-POL-020: bytes in `current` win over the disk; absent keys fall back to the disk."""
        f, c = self._snap()
        self.assertEqual(G.stale_paths(c, f.project, {"a.sv0": b"other"}), ["a.sv0"])
        self.assertEqual(G.stale_paths(c, f.project, {"a.sv0": b"changed\n"}), [])
        (f.project / "b.sv0").unlink()
        self.assertEqual(G.stale_paths(c, f.project, {"b.sv0": b"b.sv0\n"}), [])
        self.assertEqual(G.stale_paths(c, f.project, {}), ["b.sv0"])
        self.assertEqual(G.stale_paths(c, Path(self.td) / "gone", {"a.sv0": b"changed\n", "b.sv0": b"b.sv0\n", "c.sv0": b"c.sv0\n"}), [])


class ChangedLines(unittest.TestCase):
    def test_hunk_header_forms(self) -> None:
        """SPEC 22.3: hunk headers with and without counts, count 0, multiple hunks."""
        cases = [
            (b"@@ -3 +3 @@\n-a\n+b\n", (3,)),
            (b"@@ -3,2 +3,3 @@\n-a\n-b\n+c\n+d\n+e\n", (3, 4, 5)),
            (b"@@ -3 +2,0 @@\n-gone\n", ()),
            (b"@@ -0,0 +1,2 @@\n+a\n+b\n", (1, 2)),
            (b"@@ -5,0 +6 @@\n+a\n", (6,)),
            (b"@@ -1,2 +1,0 @@\n-a\n-b\n@@ -9 +8,2 @@ ctx text\n+x\n+y\n", (8, 9)),
            (b"@@ -1 +1,0 @@\n-a\n", ()),
            (b"", ()),
            (b"diff --git a/x b/x\nindex 1..2 100644\n--- a/x\n+++ b/x\n", ()),
        ]
        for patch, exp in cases:
            with self.subTest(patch=patch):
                self.assertEqual(G.changed_lines(patch), exp)

    def test_overlapping_hunks_deduplicate_and_sort(self) -> None:
        """SPEC 22.3: result is sorted and unique."""
        self.assertEqual(G.changed_lines(b"@@ -9 +9,2 @@\n@@ -1 +1 @@\n@@ -9 +10 @@\n"), (1, 9, 10))

    def test_hunk_text_inside_content_is_not_a_header(self) -> None:
        """SPEC 22.3: only lines beginning with '@@' are headers; content lines begin with +, - or space."""
        self.assertEqual(G.changed_lines(b"@@ -1 +1 @@\n+@@ -5 +50 @@ fake\n"), (1,))


if __name__ == "__main__":
    unittest.main()
