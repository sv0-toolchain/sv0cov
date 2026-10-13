# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``clean`` command (CV-232; SPEC 18.4, 20.2.2).

It removes the output directory when everything in it is sv0cov's, and
otherwise removes nothing: no symlink is followed or removed, nothing
unknown is deleted, and nothing outside the output directory is touched.
"""

from __future__ import annotations

import io
import os
import shutil
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_cmd_check import EVIDENCE, HEAD, Base  # noqa: E402
from test_indexed_reader import fixture_inputs, raw  # noqa: E402

from sv0cov import cli, cmd_clean  # noqa: E402

RUN = "0123456789abcdef0123456789abcdef"
TEMP = ".sv0cov-tmp-" + "ab" * 16


class CleanBase(Base):
    def run_cli(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main([argv[0], "--diagnostic-format=json-lines", *argv[1:]], stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def clean(self, *args: str) -> tuple[int, str, str]:
        return self.run_cli("clean", *args)

    def snapshot(self) -> dict[str, object]:
        """Every path below the project, without following anything."""
        out: dict[str, object] = {}
        for base, dirs, files in os.walk(self.cwd, followlinks=False):
            for name in dirs + files:
                path = Path(base) / name
                rel = str(path.relative_to(self.cwd))
                out[rel] = ("link", os.readlink(path)) if path.is_symlink() else "dir" if path.is_dir() else (
                    path.read_bytes() if path.is_file() else "special")
        return out

    def refused(self, *args: str) -> list[str]:
        """Clean must refuse, change nothing, and say why."""
        before = self.snapshot()
        code, out, err = self.clean(*args)
        self.assertEqual((code, out), (5, ""))
        self.assertEqual(self.snapshot(), before)
        got = records(err)
        self.assertTrue(got and all((r["code"], r["phase"]) == ("COV6002", "publication") for r in got))
        return [r["facts"][0]["value"] for r in got]

    def everything(self, root: str = ".sv0cov") -> None:
        """One of every kind of thing sv0cov puts in an output directory."""
        self.put(f"{root}/coverage.sv0covdata.json", b"{}")
        for name in cmd_clean.REPORT_FILES:
            self.put(f"{root}/reports/{name}", b"r")
        for directory, files in cmd_clean.SUPPORT.items():
            for name in files:
                self.put(f"{root}/reports/{directory}/{name}", b"s")
        self.put(f"{root}/runs/{RUN}/coverage.sv0covdata.json", b"{}")
        self.put(f"{root}/runs/{RUN}/build/obj/deep/a.o", b"o")
        self.put(f"{root}/runs/{RUN}/reports/coverage.html", b"h")
        self.put(f"{root}/runs/{RUN}/any name at all.bin", b"x")
        self.put(f"{root}/{TEMP}", b"t")
        self.put(f"{root}/reports/{TEMP}/coverage.txt", b"t")
        self.put(f"{root}/runs/{TEMP}/x", b"t")


class RemovalTest(CleanBase):
    def test_nothing_to_clean(self) -> None:
        self.put("src/main.sv0", b"fn main() {}\n")
        before = self.snapshot()
        self.assertEqual(self.clean(), (0, "nothing to clean: .sv0cov does not exist\n", ""))
        self.assertEqual(self.clean("--output-dir", "a/b/c"), (0, "nothing to clean: a/b/c does not exist\n", ""))
        (self.cwd / "a").mkdir()
        self.assertEqual(self.clean("--output-dir", "a/b/c")[0], 0)
        self.assertEqual(self.clean("--quiet"), (0, "", ""))
        self.assertEqual(self.snapshot(), {**before, "a": "dir"})

    def test_everything_sv0cov_puts_there_is_removed_and_nothing_else(self) -> None:
        self.put("src/main.sv0", b"fn main() {}\n")
        self.put("out/coverage.json", b"an explicit destination")
        self.put("sv0.toml", HEAD.encode())
        keep = self.snapshot()
        self.everything()
        files = sum(1 for v in self.snapshot().values() if isinstance(v, bytes)) - 3
        dirs = sum(1 for v in self.snapshot().values() if v == "dir") - 2
        self.assertEqual(self.clean(), (0, f"removed .sv0cov: {files} files, {dirs} directories\n", ""))
        self.assertEqual(self.snapshot(), keep)
        self.assertEqual(self.clean()[1], "nothing to clean: .sv0cov does not exist\n")

    def test_an_empty_output_directory_is_removed(self) -> None:
        (self.cwd / ".sv0cov").mkdir()
        self.assertEqual(self.clean(), (0, "removed .sv0cov: 0 files, 1 directories\n", ""))
        self.assertEqual(self.snapshot(), {})

    def test_the_configured_directory_is_the_one_cleaned(self) -> None:
        self.everything("build/cov")
        self.everything(".sv0cov")
        other = {k: v for k, v in self.snapshot().items() if k.startswith(".sv0cov")}
        self.assertEqual(self.clean("--output-dir", "build/cov")[0], 0)
        self.assertEqual(self.snapshot(), {**other, "build": "dir"})  # the parent is the user's
        self.put("sv0.toml", (HEAD + 'output_dir = ".sv0cov"\n').encode())
        self.assertEqual(self.clean("--quiet"), (0, "", ""))
        self.assertEqual(sorted(self.snapshot()), ["build", "sv0.toml"])

    def test_what_the_commands_publish_is_what_clean_removes(self) -> None:
        """merge, report (file, bundle directory) and clean, end to end."""
        self.project()
        data, m, counts = fixture_inputs("f0")
        self.put("in/f0.sv0covmap.json", data)
        self.put("in/a.sv0profraw", raw(m, counts, 1))
        project = self.snapshot()
        self.assertEqual(self.run_cli("merge", "in")[0], 0)
        self.assertEqual(self.run_cli("report", "--format", "term", ".sv0cov/coverage.sv0covdata.json")[0], 0)
        self.assertEqual(self.run_cli("report", "--format", "json", ".sv0cov/coverage.sv0covdata.json")[0], 0)
        self.assertEqual(self.run_cli("check", ".sv0cov/coverage.sv0covdata.json")[0], 0)
        self.assertEqual(self.clean(), (0, "removed .sv0cov: 3 files, 2 directories\n", ""))
        self.assertEqual(self.snapshot(), project)
        self.assertEqual(self.run_cli("merge", "in")[0], 0)  # and the directory can be used again
        self.assertEqual(self.run_cli("report", "--format", "term", "--format", "json", ".sv0cov/coverage.sv0covdata.json")[0], 0)
        self.assertEqual(self.clean()[0], 0)
        self.assertEqual(self.snapshot(), project)


class RefusalTest(CleanBase):
    """SPEC 18.4: symlink traversal, project-root deletion and unrecognized targets."""

    def test_an_unrecognized_entry_stops_everything(self) -> None:
        cases = {
            "notes.txt": ("file", ".sv0cov/notes.txt is not something sv0cov puts there"),
            "cache": ("dir", ".sv0cov/cache is not something sv0cov puts there"),
            "reports/extra.html": ("file", ".sv0cov/reports/extra.html is not something sv0cov puts there"),
            "reports/lcov-stdout-support/lcov.info": ("file", None),
            "reports/nested": ("dir", None),
            "runs/not-a-run-id": ("dir", ".sv0cov/runs/not-a-run-id is not something sv0cov puts there"),
            "runs/" + "AB" * 16: ("dir", None),
            f"runs/{RUN}x": ("dir", None),
            "runs/stray-file": ("file", None),
            ".sv0cov-tmp-short": ("file", None),
            f"{TEMP}x": ("file", None),
        }
        for rel, (kind, want) in cases.items():
            with self.subTest(entry=rel):
                self.setUp()
                self.everything()
                path = self.cwd / ".sv0cov" / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.mkdir() if kind == "dir" else path.write_bytes(b"?")
                details = self.refused()
                self.assertEqual(len(details), 1)
                if want:
                    self.assertEqual(details, [want])

    def test_a_known_name_of_the_wrong_type_is_not_recognized(self) -> None:
        for make in ("reports-file", "indexed-dir", "run-file", "report-dir"):
            with self.subTest(case=make):
                self.setUp()
                root = self.cwd / ".sv0cov"
                root.mkdir()
                if make == "reports-file":
                    (root / "reports").write_bytes(b"x")
                elif make == "indexed-dir":
                    (root / "coverage.sv0covdata.json").mkdir()
                elif make == "run-file":
                    self.put(f".sv0cov/runs/{RUN}", b"x")
                else:
                    (root / "reports" / "coverage.txt").mkdir(parents=True)
                self.assertEqual(len(self.refused()), 1)

    def test_no_symlink_is_followed_or_removed(self) -> None:
        places = (".sv0cov/link", ".sv0cov/reports/coverage.txt", ".sv0cov/coverage.sv0covdata.json", ".sv0cov/reports",
                  f".sv0cov/runs/{RUN}", f".sv0cov/runs/{RUN}/build/link", f".sv0cov/{TEMP}")
        for place in places:
            for target in ("file", "dir", "dangling"):
                with self.subTest(place=place, target=target):
                    self.setUp()
                    self.put("outside/keep.txt", b"precious")
                    self.put(".sv0cov/reports/coverage.json", b"r")
                    path = self.cwd / place
                    if path.is_dir():
                        shutil.rmtree(path)
                    elif path.exists():
                        path.unlink()
                    path.parent.mkdir(parents=True, exist_ok=True)
                    os.symlink(self.cwd / {"file": "outside/keep.txt", "dir": "outside", "dangling": "nowhere"}[target], path)
                    self.assertEqual(self.refused(), [f"{place} is a symlink"])
                    self.assertEqual((self.cwd / "outside/keep.txt").read_bytes(), b"precious")

    def test_the_output_directory_itself_may_not_be_a_symlink_or_reached_through_one(self) -> None:
        self.put("real/reports/coverage.txt", b"r")
        os.symlink(self.cwd / "real", self.cwd / ".sv0cov")
        self.assertEqual(self.refused(), [".sv0cov is a symlink or not a directory"])
        self.put("deep/cov/reports/coverage.txt", b"r")
        os.symlink(self.cwd / "deep", self.cwd / "alias")
        (detail,) = self.refused("--output-dir", "alias/cov")
        self.assertIn("'alias' is a symlink or not a directory", detail)
        self.put("plain", b"a file")
        self.assertEqual(self.refused("--output-dir", "plain"), ["plain is a symlink or not a directory"])
        self.assertEqual(len(self.refused("--output-dir", "plain/under")), 1)

    def test_the_project_root_and_anything_outside_it_cannot_be_named(self) -> None:
        self.put("src/main.sv0", b"x")
        before = self.snapshot()
        for value in (".", "..", "../elsewhere", "/tmp", "a/../..", "a/./b", ""):
            with self.subTest(output_dir=value):
                code, out, err = self.clean("--output-dir", value)
                self.assertEqual((code, out), (2, ""))
                self.assertEqual(records(err)[0]["phase"], "configuration" if records(err)[0]["code"] != "COV0001" else "invocation")
        self.put("sv0.toml", (HEAD + 'output_dir = "."\n').encode())
        self.assertEqual(self.clean()[0], 2)
        self.assertEqual(self.snapshot(), {**before, "sv0.toml": (HEAD + 'output_dir = "."\n').encode()})
        self.assertEqual(self.clean("extra-operand")[0], 2)

    def test_special_files_and_bottomless_trees_are_refused(self) -> None:
        self.put(f".sv0cov/runs/{RUN}/a", b"x")
        os.mkfifo(self.cwd / f".sv0cov/runs/{RUN}/pipe")
        self.assertEqual(self.refused(), [f".sv0cov/runs/{RUN}/pipe is not a regular file or a directory"])
        os.unlink(self.cwd / f".sv0cov/runs/{RUN}/pipe")
        deep = self.cwd / f".sv0cov/runs/{RUN}"
        for _ in range(cmd_clean.MAX_DEPTH):
            deep = deep / "d"
        deep.mkdir(parents=True)
        (detail,) = self.refused()
        self.assertIn(f"is nested deeper than {cmd_clean.MAX_DEPTH} directories", detail)

    def test_every_refusal_is_reported_up_to_a_bound(self) -> None:
        self.everything()
        for n in range(3):
            self.put(f".sv0cov/unknown-{n}", b"?")
        self.assertEqual(self.refused(), [f".sv0cov/unknown-{n} is not something sv0cov puts there" for n in range(3)])
        for n in range(3, 30):
            self.put(f".sv0cov/unknown-{n:02d}", b"?")
        details = self.refused()
        self.assertEqual(len(details), cmd_clean.MAX_REPORTED + 1)
        self.assertIn("10 more entries were refused", details)

    def test_a_tree_that_changes_under_clean_stops_it(self) -> None:
        self.everything()
        real = cmd_clean._scan

        def scan_then_add(*args, **kw):
            plan = real(*args, **kw)
            if args[2] == ".sv0cov":  # after the whole tree was examined, something appears
                self.put(".sv0cov/reports/late.txt", b"new")
            return plan

        with mock.patch.object(cmd_clean, "_scan", scan_then_add):
            code, out, err = self.clean()
        self.assertEqual((code, out, [r["code"] for r in records(err)]), (5, "", ["COV6002"]))
        self.assertIn(".sv0cov/reports changed while it was being removed", records(err)[0]["facts"][0]["value"])
        self.assertEqual((self.cwd / ".sv0cov/reports/late.txt").read_bytes(), b"new")  # what clean did not examine survives

        def scan_then_swap(*args, **kw):
            plan = real(*args, **kw)
            if args[2] == ".sv0cov":
                victim = self.cwd / f".sv0cov/runs/{RUN}/build"
                os.rename(victim, self.cwd / "moved")
                os.symlink(self.cwd / "outside", victim)
            return plan

        self.setUp()
        self.everything()
        self.put("outside/obj/deep/a.o", b"precious")
        with mock.patch.object(cmd_clean, "_scan", scan_then_swap):
            code, _, err = self.clean()
        self.assertEqual(code, 5)
        self.assertEqual((self.cwd / "outside/obj/deep/a.o").read_bytes(), b"precious")
        self.assertTrue((self.cwd / f".sv0cov/runs/{RUN}/build").is_symlink())

    def test_the_level_table(self) -> None:
        level = cmd_clean.ROOT_LEVEL
        self.assertIs(cmd_clean._child_level(level, "coverage.sv0covdata.json", False), True)
        self.assertIsNone(cmd_clean._child_level(level, "coverage.sv0covdata.json", True))
        self.assertIsNone(cmd_clean._child_level(level, "coverage.txt", False))  # a report file belongs in reports/
        reports = cmd_clean._child_level(level, "reports", True)
        self.assertEqual(sorted(n for n in cmd_clean.REPORT_FILES if cmd_clean._child_level(reports, n, False) is True),
                         sorted(cmd_clean.REPORT_FILES))
        self.assertEqual(len(cmd_clean.REPORT_FILES), 11)
        runs = cmd_clean._child_level(level, "runs", True)
        self.assertEqual(cmd_clean._child_level(runs, RUN, True), cmd_clean.FREE)
        self.assertIsNone(cmd_clean._child_level(runs, RUN, False))
        self.assertIs(cmd_clean._child_level(cmd_clean.FREE, "anything", False), True)
        self.assertEqual(EVIDENCE, cmd_clean.INDEXED_NAME)


if __name__ == "__main__":
    unittest.main()
