# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Gitignore scope-pattern oracle corpus (CV-030; SPEC 18.3, AC-100)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tests" / "fixtures" / "gitignore"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import cases as C  # noqa: E402

from sv0cov.model.logical import check_logical_path  # noqa: E402

CORPUS = HERE / "corpus.json"


class CaseDefinitionTest(unittest.TestCase):
    def test_tree_is_logical_paths(self) -> None:
        self.assertEqual(len(set(C.TREE)), len(C.TREE))
        for p in C.TREE:
            check_logical_path(p)
            self.assertNotEqual(p.rsplit("/", 1)[-1], ".gitignore")
        files = set(C.TREE)
        self.assertFalse({p for p, kind in C.paths() if kind == "dir"} & files, "a path is both file and directory")

    def test_patterns_are_valid_config_strings(self) -> None:
        ids = [cid for cid, _ in C.CASES]
        self.assertEqual(len(set(ids)), len(ids))
        for cid, lines in C.CASES:
            self.assertTrue(lines, cid)
            for line in lines:
                self.assertFalse(set(line) & {"\x00", "\r", "\n"}, cid)

    def test_sanity_cases_exist(self) -> None:
        ids = {cid for cid, _ in C.CASES}
        self.assertLessEqual(set(C.SANITY), ids)


@unittest.skipUnless(CORPUS.is_file(), "corpus.json not captured yet (needs Git 2.55.0)")
class CorpusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = json.loads(CORPUS.read_bytes())

    def test_corpus_matches_cases_and_pin(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "tools" / "gitignore_oracle.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.corpus["git"]["version"], "2.55.0")
        self.assertRegex(self.corpus["git"]["source"]["sha256"], r"^[0-9a-f]{64}$")

    def test_results_cover_every_case_and_agree_with_sanity(self) -> None:
        by = {r["id"]: r for r in self.corpus["results"]}
        self.assertEqual(list(by), [cid for cid, _ in C.CASES])
        paths = {p for p, _ in C.paths()}
        for cid, r in by.items():
            self.assertLessEqual(set(r["selected"]), paths, cid)
            self.assertLessEqual(set(r["selected"]), set(r["matched_line"]), cid)
        for cid, expected in C.SANITY.items():
            self.assertEqual(set(by[cid]["selected"]), expected, cid)


if __name__ == "__main__":
    unittest.main()
