# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The Cobertura GitLab coverage-visualization smoke (CV-419; SPEC 21.5;
AC-051, COV-REP-013).

Offline, through ``tools/gitlab_cobertura.py`` (GitLab's parser rules):
every golden resolves its project-relative paths when the sv0 project is
the repository root, keeps the binary line projection (covered green,
partial and uncovered red), carries branch data GitLab accepts and ignores,
and stays within GitLab's limits. A project in a subdirectory does not
resolve (``<source>.</source>`` names no repository prefix): documented,
and checked so a change would be noticed. The kit a maintainer pushes to
GitLab (``tools/gitlab_smoke.py``) is deterministic and agrees with the
oracle. The real observation is release evidence (CV-415).
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))

import gitlab_smoke  # noqa: E402
from gitlab_cobertura import MAX_BYTES, GitLabRejects, visualize  # noqa: E402
from test_indexed_reader import FIXTURES  # noqa: E402
from test_report import fixture_report, fixture_sources  # noqa: E402

from sv0cov.formats.cobertura import render_cobertura  # noqa: E402

GOLDENS = ROOT / "tests" / "fixtures" / "cobertura"
PROJECT = "group/sv0cov-smoke"


def expected(report: dict) -> dict[str, dict[int, int]]:
    """sv0cov's own projection: every executable line of a user source, 1 only when covered."""
    out: dict[str, dict[int, int]] = {}
    for s in report["sources"]:
        if s["ownership"] != "user":
            continue
        lines = {x["line"]: int(x["status"] == "covered") for x in report["lines"]
                 if x["source_index"] == s["source_index"] and x["status"] in ("covered", "partial", "uncovered")}
        out[s["path"]] = lines
    return out


class VisualizationTest(unittest.TestCase):
    def test_every_golden_resolves_and_keeps_the_projection(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                report, ix = fixture_report(name)
                data = (GOLDENS / f"{name}.xml").read_bytes()
                self.assertEqual(data, render_cobertura(report))
                repo = list(fixture_sources(name, ix))
                seen = visualize(data, project_path=PROJECT, worktree_paths=repo)
                self.assertEqual(seen, {k: v for k, v in expected(report).items() if v})
                self.assertLessEqual(set(seen), set(repo))  # every annotated file is a repository path
                self.assertLess(len(data), MAX_BYTES)
                self.assertEqual(data.count(b"<source>"), 1)

    def test_partial_lines_are_red_and_branch_data_is_ignored(self) -> None:
        report, ix = fixture_report("f0")
        seen = visualize(render_cobertura(report), project_path=PROJECT, worktree_paths=list(fixture_sources("f0", ix)))["main.sv0"]
        partial = [x["line"] for x in report["lines"] if x["status"] == "partial"]
        self.assertTrue(partial)
        for line in partial:
            self.assertEqual(seen[line], 0)
        self.assertIn(b'branch="true"', render_cobertura(report))  # present, accepted, and not drawn

    def test_a_project_in_a_subdirectory_does_not_resolve(self) -> None:
        """``<source>.</source>`` carries no repository prefix, so GitLab takes the
        logical path as the repository path: annotations attach only when the
        sv0 project is the repository root. Recorded with mismatch M11."""
        report, ix = fixture_report("f0")
        repo = [f"pkg/app/{p}" for p in fixture_sources("f0", ix)]
        seen = visualize(render_cobertura(report), project_path=PROJECT, worktree_paths=repo)
        self.assertEqual(set(seen), {"main.sv0"})
        self.assertFalse(set(seen) & set(repo))


class OracleTest(unittest.TestCase):
    """The oracle's own rules, so a change in it is deliberate."""

    def doc(self, sources: list[str], classes: list[tuple[str, list[tuple[str, str]]]]) -> bytes:
        src = "".join(f"<source>{s}</source>" for s in sources)
        cls = "".join(f'<class filename="{f}"><lines>' + "".join(f'<line number="{n}" hits="{h}"/>' for n, h in lines) + "</lines></class>"
                      for f, lines in classes)
        return f'<?xml version="1.0"?><coverage><sources>{src}</sources><packages><package><classes>{cls}</classes></package></packages></coverage>'.encode()

    def test_sources_with_the_project_path_prefix_resolve(self) -> None:
        data = self.doc(["/builds/group/proj/pkg/app"], [("main.sv0", [("1", "3")])])
        self.assertEqual(visualize(data, project_path="group/proj", worktree_paths=["pkg/app/main.sv0"]), {"pkg/app/main.sv0": {1: 3}})
        self.assertEqual(visualize(data, project_path="group/proj", worktree_paths=["main.sv0"]), {})  # no match: the class is dropped

    def test_invalid_hits_reject_the_report(self) -> None:
        for bad in ("1.5", "x", "", "1e3"):
            with self.subTest(hits=bad):
                with self.assertRaises(GitLabRejects):
                    visualize(self.doc([], [("a", [("1", bad)])]), project_path="g/p", worktree_paths=["a"])

    def test_limits(self) -> None:
        with self.assertRaises(GitLabRejects):
            visualize(b" " * (MAX_BYTES + 1), project_path="g/p", worktree_paths=[])
        with self.assertRaises(GitLabRejects):
            visualize(self.doc(["x"] * 101, []), project_path="g/p", worktree_paths=[])


class KitTest(unittest.TestCase):
    def test_the_kit_is_deterministic_and_agrees_with_the_oracle(self) -> None:
        a, b = gitlab_smoke.kit(), gitlab_smoke.kit()
        self.assertEqual(a, b)
        self.assertEqual(sorted(a), [".gitlab-ci.yml", "EXPECTED.md", "cobertura.xml", "main.sv0", "observation.json"])
        self.assertEqual(a["cobertura.xml"], (GOLDENS / "f0.xml").read_bytes())
        self.assertIn(b"coverage_format: cobertura", a[".gitlab-ci.yml"])
        report, ix = fixture_report("f0")
        table = a["EXPECTED.md"].decode()
        for line, hit in expected(report)["main.sv0"].items():
            self.assertIn(f"| `main.sv0` | {line} |", table)
            row = next(r for r in table.splitlines() if r.startswith(f"| `main.sv0` | {line} |"))
            self.assertTrue(row.endswith("green |" if hit else "red |"), row)
        self.assertIsNone(json.loads(a["observation.json"])["observed_on"])

    def test_the_command_writes_a_new_directory_only(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "kit"
            p = subprocess.run([sys.executable, str(ROOT / "tools" / "gitlab_smoke.py"), "--out", str(out)], capture_output=True, text=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue((out / "EXPECTED.md").is_file())
            again = subprocess.run([sys.executable, str(ROOT / "tools" / "gitlab_smoke.py"), "--out", str(out)], capture_output=True, text=True)
            self.assertNotEqual(again.returncode, 0)


if __name__ == "__main__":
    unittest.main()
