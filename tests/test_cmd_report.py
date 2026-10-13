# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``report`` command (CV-232; SPEC 20.2, 20.3, 21; COV-CLI-002,
COV-CLI-008, COV-REP-016).

Every row of the destination matrix; formats come only from ``--format``;
nothing is ever replaced; stdout carries one artifact and nothing else; and
what is published is exactly what the report producer and the terminal
view give for that evidence.
"""

from __future__ import annotations

import io
import os
import re
import stat
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_cmd_check import EVIDENCE, HEAD, Base  # noqa: E402
from test_indexed_reader import FIXTURES, fixture_inputs, raw  # noqa: E402

from sv0cov import cli, cmd_report  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.terminal import render_terminal, terminal_bytes  # noqa: E402
from sv0cov.model.merge import Artifact, merge  # noqa: E402
from sv0cov.model.report import build_report, read_report  # noqa: E402

GOLDEN = ROOT / "tests" / "fixtures" / "terminal"
TXT, JSON = ".sv0cov/reports/coverage.txt", ".sv0cov/reports/coverage.json"
SGR = re.compile(r"\x1b\[[0-9;]*m")


class ReportBase(Base):
    def run_report(self, *args: str, operand: str | None = EVIDENCE) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        argv = ["report", "--diagnostic-format=json-lines", *args, *([operand] if operand is not None else [])]
        code = cli.main(argv, stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def expected(self, *options: tuple[str, str | None]) -> tuple[bytes, bytes]:
        """The terminal and native bytes the producer gives for the project's evidence."""
        config = resolve("report", [("--format", "json"), *options])
        report = build_report(self.evidence, config, {p: (self.cwd / p).read_bytes() for p in self.sources})
        return terminal_bytes(report), encode(report)

    def modes(self, *paths: str) -> list[int]:
        return [stat.S_IMODE((self.cwd / p).stat().st_mode) for p in paths]

    def published(self) -> list[str]:
        base = set(self.sources) | {EVIDENCE}
        return sorted(str(p.relative_to(self.cwd)) for p in self.cwd.rglob("*") if str(p.relative_to(self.cwd)) not in base
                      and not any(str(p.relative_to(self.cwd)).startswith(str(Path(s).parent) + "/") and Path(s).parent != Path(".")
                                  for s in base if p.is_dir()))


class DestinationTest(ReportBase):
    """SPEC 20.2.2, one test per row."""

    def test_one_format_and_no_output_uses_the_default_file(self) -> None:
        for name in FIXTURES:
            with self.subTest(fixture=name):
                self.setUp()
                self.project(name)
                txt, native = self.expected()
                self.assertEqual(self.run_report("--format", "term"), (0, f"wrote {TXT}\n", ""))
                self.assertEqual((self.cwd / TXT).read_bytes(), txt)
                gold = (GOLDEN / f"fixture-{name}.txt").read_bytes()
                self.assertEqual(txt[txt.index(b"\nSummary\n"):], gold[gold.index(b"\nSummary\n"):])
                self.assertEqual(self.run_report("--format", "json"), (0, f"wrote {JSON}\n", ""))
                self.assertEqual((self.cwd / JSON).read_bytes(), native)
                read_report(native)
                self.assertEqual(self.modes(".sv0cov", ".sv0cov/reports", TXT, JSON), [0o700, 0o700, 0o600, 0o600])
                self.assertEqual([p for p in self.published() if "sv0cov" in p], [".sv0cov", ".sv0cov/reports", JSON, TXT])

    def test_one_format_and_a_path_names_the_file_exactly(self) -> None:
        self.project()
        txt, native = self.expected()
        (self.cwd / "out").mkdir()
        self.assertEqual(self.run_report("--format", "json", "--output", "out/r.data"), (0, "wrote out/r.data\n", ""))
        self.assertEqual((self.cwd / "out/r.data").read_bytes(), native)
        absolute = str(self.cwd / "out" / "t")
        self.assertEqual(self.run_report("--format", "term", "--output", absolute), (0, f"wrote {absolute}\n", ""))
        self.assertEqual((self.cwd / "out/t").read_bytes(), txt)
        self.assertEqual(self.modes("out/r.data", "out/t"), [0o600, 0o600])
        self.assertFalse((self.cwd / ".sv0cov").exists())  # an explicit destination creates nothing managed
        self.assertEqual(sorted(os.listdir(self.cwd / "out")), ["r.data", "t"])  # no temporary is left

    def test_one_format_and_a_dash_writes_only_the_artifact_to_stdout(self) -> None:
        self.project()
        txt, native = self.expected()
        before = self.tree()
        self.assertEqual(self.run_report("--format", "json", "--output", "-"), (0, native.decode(), ""))
        self.assertEqual(self.run_report("--format", "term", "--output", "-"), (0, txt.decode(), ""))
        self.assertEqual(self.run_report("--format", "term", "--output", "-", "--quiet"), (0, txt.decode(), ""))  # not incidental
        self.assertEqual(self.tree(), before)

    def test_several_formats_and_a_path_make_one_bundle_directory(self) -> None:
        self.project()
        txt, native = self.expected()
        code, out, err = self.run_report("--format", "json", "--format", "term", "--output", "bundle")
        self.assertEqual((code, out, err), (0, "wrote bundle (coverage.txt, coverage.json)\n", ""))
        self.assertEqual({p.name: p.read_bytes() for p in (self.cwd / "bundle").iterdir()}, {"coverage.txt": txt, "coverage.json": native})
        self.assertEqual(self.modes("bundle", "bundle/coverage.txt", "bundle/coverage.json"), [0o700, 0o600, 0o600])
        self.assertFalse((self.cwd / ".sv0cov").exists())

    def test_several_formats_and_a_dash_are_invalid(self) -> None:
        self.project()
        before = self.tree()
        code, out, err = self.run_report("--format", "json", "--format", "term", "--output", "-")
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], self.tree()), (2, "", "COV0001", before))

    def test_several_formats_and_no_output_make_the_default_bundle(self) -> None:
        self.project()
        txt, native = self.expected()
        self.assertEqual(self.run_report("--format", "term", "--format", "json"),
                         (0, "wrote .sv0cov/reports (coverage.txt, coverage.json)\n", ""))
        self.assertEqual(((self.cwd / TXT).read_bytes(), (self.cwd / JSON).read_bytes()), (txt, native))
        self.assertEqual(sorted(os.listdir(self.cwd / ".sv0cov")), ["reports"])
        self.assertEqual(self.modes(".sv0cov", ".sv0cov/reports"), [0o700, 0o700])

    def test_the_configured_output_directory_is_used(self) -> None:
        self.project()
        self.assertEqual(self.run_report("--format", "term", "--output-dir", "build/cov")[1], "wrote build/cov/reports/coverage.txt\n")
        self.put("sv0.toml", (HEAD + 'output_dir = "target"\n').encode())
        self.assertEqual(self.run_report("--format", "json")[1], "wrote target/reports/coverage.json\n")
        self.assertEqual(self.run_report("--format", "json", "--output-dir", "/abs")[0], 2)


class SelectionTest(ReportBase):
    """COV-CLI-008."""

    def test_request_order_does_not_change_what_is_published(self) -> None:
        self.project()
        self.assertEqual(self.run_report("--format", "json", "--format", "term", "--output", "a")[0], 0)
        self.assertEqual(self.run_report("--format", "term", "--format", "json", "--output", "b")[0], 0)
        self.assertEqual(*[{p.name: p.read_bytes() for p in (self.cwd / d).iterdir()} for d in ("a", "b")])

    def test_formats_come_only_from_the_option(self) -> None:
        self.project()
        self.put("sv0.toml", (HEAD + 'reports = ["html", "lcov"]\n').encode())
        self.assertEqual(self.run_report()[0], 2)  # the option is required; the configured list is for run
        self.assertEqual(self.run_report("--format", "term")[0], 0)  # and is not read
        self.assertEqual(sorted(os.listdir(self.cwd / ".sv0cov/reports")), ["coverage.txt"])
        for bad in (("--format", "term", "--format", "term"), ("--format", "term,json"), ("--format", "text"), ("--report", "term"),
                    ("--format", "term", "--threshold-line", "80"), ("--format",)):
            with self.subTest(args=bad):
                code, out, err = self.run_report(*bad)
                self.assertEqual((code, out), (2, ""))
                self.assertIn(records(err)[0]["code"], ("COV0001", "COV0012"))
        self.assertEqual(cli.main(["report", "--format", "term", EVIDENCE, EVIDENCE], stdout=io.StringIO(), stderr=io.StringIO(), cwd=self.cwd), 2)

    def test_a_format_this_build_lacks_is_refused_before_anything_is_read(self) -> None:
        self.project()
        before = self.tree()
        for fmt in ("html", "lcov", "cobertura"):
            for extra in ((), ("--format", "term")):
                with self.subTest(format=fmt, extra=extra):
                    code, out, err = self.run_report("--format", fmt, *extra, operand="absent.json")
                    (r,) = records(err)
                    self.assertEqual((code, out, r["code"], r["phase"]), (7, "", "COV5001", "invocation"))
                    self.assertIn({"name": "format", "value": fmt}, r["facts"])
        self.assertEqual(self.tree(), before)
        self.assertEqual(cmd_report.IMPLEMENTED, ("term", "json"))
        self.assertEqual(list(cmd_report.FILENAMES.items()), [("term", "coverage.txt"), ("html", "coverage.html"), ("json", "coverage.json"),
                                                               ("lcov", "lcov.info"), ("cobertura", "cobertura.xml")])


class CollisionTest(ReportBase):
    """SPEC 20.2.3: there is no replace."""

    def occupy(self, rel: str, how: str) -> None:
        path = self.cwd / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if how == "file":
            path.write_bytes(b"mine")
        elif how == "directory":
            path.mkdir()
        elif how == "symlink":
            (self.cwd / "elsewhere").write_bytes(b"target")
            os.symlink(self.cwd / "elsewhere", path)
        else:
            os.symlink(self.cwd / "nowhere", path)

    def test_an_existing_destination_is_never_replaced(self) -> None:
        shapes = {
            "default file": (("--format", "term"), TXT),
            "default bundle": (("--format", "term", "--format", "json"), ".sv0cov/reports"),
            "explicit file": (("--format", "json", "--output", "r.json"), "r.json"),
            "explicit bundle": (("--format", "term", "--format", "json", "--output", "b"), "b"),
        }
        for label, (args, dest) in shapes.items():
            for how in ("file", "directory", "symlink", "dangling"):
                with self.subTest(shape=label, existing=how):
                    self.setUp()
                    self.project()
                    self.occupy(dest, how)
                    before = self.tree()
                    link = os.readlink(self.cwd / dest) if how in ("symlink", "dangling") else None
                    # The destination is refused before the evidence is even looked for.
                    for operand in (EVIDENCE, "absent.json"):
                        code, out, err = self.run_report(*args, operand=operand)
                        (r,) = records(err)
                        self.assertEqual((code, out, r["code"], r["phase"]), (6, "", "COV4010", "publication"))
                    self.assertEqual(self.tree(), before)
                    if link is not None:
                        self.assertEqual(os.readlink(self.cwd / dest), link)

    def test_a_second_report_into_the_default_directory(self) -> None:
        self.project()
        self.assertEqual(self.run_report("--format", "term")[0], 0)
        self.assertEqual(self.run_report("--format", "json")[0], 0)  # another file beside it
        self.assertEqual(self.run_report("--format", "term")[0], 6)
        self.assertEqual(self.run_report("--format", "term", "--format", "json")[0], 6)  # the bundle would be the directory itself

    def test_an_explicit_parent_must_exist_and_a_managed_one_may_not_be_a_symlink(self) -> None:
        self.project()
        code, _, err = self.run_report("--format", "term", "--output", "no/such/file")
        self.assertEqual((code, records(err)[0]["code"]), (6, "COV4011"))
        self.assertFalse((self.cwd / "no").exists())
        (self.cwd / "real").mkdir()
        os.symlink(self.cwd / "real", self.cwd / ".sv0cov")
        code, _, err = self.run_report("--format", "term")
        self.assertEqual((code, records(err)[0]["code"]), (6, "COV6002"))
        self.assertEqual(os.listdir(self.cwd / "real"), [])

    def test_a_failed_validation_publishes_nothing(self) -> None:
        from unittest import mock
        for args in (("--format", "term"), ("--format", "term", "--format", "json"), ("--format", "term", "--output", "-"),
                     ("--format", "term", "--output", "-", "--color", "always"), ("--format", "term", "--output", "t.txt")):
            with self.subTest(args=args):
                self.setUp()
                self.project()
                before = self.tree()
                with mock.patch.object(cmd_report, "terminal_bytes", return_value=b"bad \x1b[2J\n"):
                    code, out, err = self.run_report(*args)
                self.assertEqual((code, out, records(err)[0]["code"]), (6, "", "COV4011"))
                self.assertEqual(self.tree(), before)  # no file, final or temporary


    def test_bytes_the_reader_or_the_text_check_rejects_are_not_published(self) -> None:
        from unittest import mock
        real = cmd_report.load_report

        def damaged(ctx, **kw):
            report, encoded = real(ctx, **kw)
            return report, encoded.replace(b'"complete":true', b'"complete":false', 1)

        for patch, args in ((mock.patch.object(cmd_report, "load_report", damaged), ("--format", "json")),
                            (mock.patch.object(cmd_report, "load_report", damaged), ("--format", "json", "--output", "-")),
                            (mock.patch.object(cmd_report, "load_report", damaged), ("--format", "term", "--format", "json")),
                            (mock.patch.object(cmd_report, "terminal_bytes", return_value=b"no final newline"), ("--format", "term"))):
            with self.subTest(args=args):
                self.setUp()
                self.project()
                before = self.tree()
                with patch:
                    code, out, err = self.run_report(*args)
                self.assertEqual((code, out, records(err)[0]["code"]), (6, "", "COV4011"))
                self.assertEqual(self.tree(), before)


class EvidenceTest(ReportBase):
    def test_a_stale_source_needs_the_override_and_is_then_diagnostic_only(self) -> None:
        self.project()
        (path,) = self.sources
        self.put(path, self.sources[path] + b"\n")
        code, out, err = self.run_report("--format", "json")
        self.assertEqual((code, out, records(err)[0]["code"]), (5, "", "COV1004"))
        self.assertFalse((self.cwd / ".sv0cov").exists())
        self.assertEqual(self.run_report("--format", "json", "--format", "term", "--allow-source-mismatch")[0], 0)
        report = read_report((self.cwd / JSON).read_bytes())
        self.assertEqual((report["evidence_eligibility"], report["provenance"]["source_accuracy"], report["sources"][0]["source_state"]),
                         ("diagnostic_only", "mismatch_allowed", "mismatch"))
        self.assertEqual((self.cwd / JSON).read_bytes(), self.expected(("--allow-source-mismatch", None))[1])
        text = (self.cwd / TXT).read_text()
        self.assertIn("evidence:   DIAGNOSTIC ONLY\n", text)
        self.assertIn(f"WARNING: source {path} does not match the evidence", text)

    def test_a_report_of_incomplete_evidence_is_still_a_report(self) -> None:
        data, m, counts = fixture_inputs("f0")
        result = merge([Artifact("m", data)], [Artifact("a", raw(m, counts, 1)), Artifact("cut", raw(m, counts, 2)[:-9])],
                       allow_rejected_inputs=True)
        self.project(evidence=result.data)
        self.assertEqual(self.run_report("--format", "term", "--format", "json")[0], 0)
        report = read_report((self.cwd / JSON).read_bytes())
        self.assertEqual((report["complete"], report["evidence_eligibility"], report["policy"]["passed"]), (False, "incomplete", False))
        self.assertIn("evidence:   INCOMPLETE\n", (self.cwd / TXT).read_text())

    def test_operand_faults(self) -> None:
        self.project()
        self.put("bad.json", b"{}")
        self.put("native.json", self.expected()[1])
        for operand, want in (("absent.json", (5, "COV3010")), ("bad.json", (5, "COV3010")), ("native.json", (7, "COV5001"))):
            with self.subTest(operand=operand):
                code, out, err = self.run_report("--format", "json", operand=operand)
                self.assertEqual((code, records(err)[0]["code"], out), (*want, ""))
        self.assertEqual(self.run_report("--format", "json", operand=None)[0], 2)
        self.assertFalse((self.cwd / ".sv0cov").exists())

    def test_a_report_records_its_own_configuration(self) -> None:
        self.project()
        self.put("sv0.toml", (HEAD + "[tool.sv0cov.thresholds]\nline = 100\n").encode())
        self.assertEqual(self.run_report("--format", "json")[0], 0)  # a failing policy does not fail the command
        report = read_report((self.cwd / JSON).read_bytes())
        self.assertEqual(report["resolved_configuration"]["schema"], "sv0cov.resolved-configuration")
        self.assertEqual(report["resolved_configuration"]["report"]["allow_source_mismatch"], {"source": "default", "value": False})


class StreamTest(ReportBase):
    def test_quiet_removes_only_the_incidental_line(self) -> None:
        self.project()
        self.assertEqual(self.run_report("--format", "term", "--quiet"), (0, "", ""))
        self.assertTrue((self.cwd / TXT).is_file())

    def test_color_reaches_stdout_only_and_only_repeats_words(self) -> None:
        self.project()
        txt, _ = self.expected()
        colored = self.run_report("--format", "term", "--output", "-", "--color", "always")[1]
        self.assertIn("\x1b[32mPASSING\x1b[0m", colored)
        self.assertEqual(SGR.sub("", colored), txt.decode())
        self.assertEqual(self.run_report("--format", "term", "--output", "-", "--color", "never")[1], txt.decode())
        self.assertEqual(self.run_report("--format", "json", "--output", "-", "--color", "always")[1], self.expected()[1].decode())
        self.assertEqual(self.run_report("--format", "term", "--color", "always")[0], 0)
        self.assertEqual((self.cwd / TXT).read_bytes(), txt)  # a file is always colorless
        self.assertEqual(self.run_report("--format", "term", "--format", "json", "--output", "b", "--color", "always")[0], 0)
        self.assertEqual((self.cwd / "b/coverage.txt").read_bytes(), txt)

    def test_a_stdout_that_cannot_take_the_artifact_is_a_publication_failure(self) -> None:
        self.project()

        class Closed(io.StringIO):
            def write(self, _text: str) -> int:
                raise BrokenPipeError

        err = io.StringIO()
        code = cli.main(["report", "--diagnostic-format=json-lines", "--format", "json", "--output", "-", EVIDENCE], stdout=Closed(), stderr=err,
                        cwd=self.cwd)
        self.assertEqual((code, records(err.getvalue())[0]["code"]), (6, "COV4011"))

    def test_the_command_runs_on_its_own(self) -> None:
        """COV-CLI-002."""
        self.project("branches")
        txt, native = self.expected()
        run = [sys.executable, "-c", "import sys; from sv0cov.cli import main; sys.exit(main())", "report"]
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
        p = subprocess.run([*run, "--format", "term", "--output", "-", EVIDENCE], cwd=self.cwd, env=env, capture_output=True, timeout=120)
        self.assertEqual((p.returncode, p.stderr, p.stdout), (0, b"", txt))  # a pipe is not a terminal: no color
        p = subprocess.run([*run, "--format", "json", "--format", "term", EVIDENCE], cwd=self.cwd, env=env, capture_output=True, timeout=120)
        self.assertEqual((p.returncode, p.stdout), (0, b"wrote .sv0cov/reports (coverage.txt, coverage.json)\n"))
        self.assertEqual((self.cwd / JSON).read_bytes(), native)
        closed = subprocess.run(f"{' '.join(map(repr, run))} --format json --output - {EVIDENCE} | true; exit ${{PIPESTATUS[0]}}", shell=True,
                                executable="/bin/bash", cwd=self.cwd, env=env, capture_output=True, timeout=120)
        self.assertIn(closed.returncode, (0, 6))  # the reader may be gone before or after the write
        self.assertEqual(render_terminal(read_report(native)).encode(), txt)


if __name__ == "__main__":
    unittest.main()
