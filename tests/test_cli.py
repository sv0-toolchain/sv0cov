# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The command framework (CV-225; SPEC 18.2.3, 20.1-20.3, 20.5.2;
COV-CLI-004, COV-CLI-007, COV-CLI-009).

Argument splitting, the per-command usage-error matrix, exit codes, the two
diagnostic formats on stderr, ``--quiet`` and ``--color``.
"""

from __future__ import annotations

import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import cli  # noqa: E402
from sv0cov import config as C  # noqa: E402
from sv0cov.console import Console  # noqa: E402
from sv0cov.diagnostics import Diagnostic, load_registry, validate_record  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.invocation import Invocation, color_mode, diagnostic_format, split  # noqa: E402

RUN = "0123456789abcdef0123456789abcdef"
# A valid invocation of each command, restated from SPEC 20.1.
BASE = {
    "run": (["run"], ["--", "true"]),
    "merge": (["merge"], ["a.sv0profraw"]),
    "report": (["report", "--format", "json"], ["cov.json"]),
    "check": (["check"], ["cov.json"]),
    "clean": (["clean"], []),
    "doctor": (["doctor"], []),
    "version": (["version"], []),
}
SAMPLE = {"--color": "never", "--diagnostic-format": "json-lines", "--run-id": RUN, "--expect-run": RUN, "--format": "html",
          "--output-dir": "o", "--report": "json", "--empty": "pass", "--context": "c", "--reproducible-epoch": "1",
          "--saturation-policy": "fail", "--raw-profile-tier": "large", "--ratchet-tolerance-basis-points": "1",
          "--diff-base": "HEAD", "--ratchet-baseline": "b.json", "--ratchet-metric": "line", "--raw-profile-max-counters": "1",
          "--raw-profile-max-bytes": "1", "--run-manifest": "m.json", "--output": "out", "--toolchain-root": "/r"}


class Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


def run(*args: str, cwd: Path | None = None, files: dict[str, bytes] | None = None, tty: bool = False) -> tuple[int, str, str]:
    out, err = io.StringIO(), (Tty() if tty else io.StringIO())
    with tempfile.TemporaryDirectory() as tmp:
        d = cwd or Path(tmp)
        for name, data in (files or {}).items():
            (d / name).write_bytes(data)
        code = cli.main(list(args), stdout=out, stderr=err, cwd=d)
    return code, out.getvalue(), err.getvalue()


def records(err: str) -> list[dict]:
    """The JSON Lines records on stderr, each checked to be one canonical, valid diagnostic."""
    out = []
    for line in err.splitlines(keepends=True):
        obj = decode_canonical(line.encode())
        assert encode(obj) == line.encode()
        assert len(obj) == 11
        validate_record(obj)
        out.append(obj)
    return out


def argv(command: str, *extra: str) -> list[str]:
    head, tail = BASE[command]
    return [*head, *extra, *tail]


def value_args(name: str) -> list[str]:
    opt = C.OPTION[name]
    if opt.arity == "flag":
        return [name]
    return [name, SAMPLE.get(name, "85")]


class SplitTest(unittest.TestCase):
    def test_forms(self) -> None:
        self.assertEqual(split(["merge", "--output=o.json", "--expect-run", RUN, "a", "--quiet", "b"]),
                         Invocation("merge", (("--output", "o.json"), ("--expect-run", RUN), ("--quiet", None)), ("a", "b"), ()))
        # A value is whatever follows, even when it looks like an option; an empty value is a value.
        self.assertEqual(split(["run", "--context", "--quiet", "--context=", "--", "x"]).options,
                         (("--context", "--quiet"), ("--context", "")))
        self.assertEqual(split(["run", "--context=a=b", "--", "x"]).options, (("--context", "a=b"),))
        self.assertEqual(split(["merge", "--output", "-", "x"]).options, (("--output", "-"),))
        # After --, operands may begin with a dash.
        self.assertEqual(split(["merge", "--", "-odd", "--quiet"]).operands, ("-odd", "--quiet"))
        self.assertEqual(split(["merge", "-"]).operands, ("-",))

    def test_the_test_command_is_kept_as_an_argv_vector(self) -> None:
        """SPEC 20.4."""
        hostile = ["sh", "-c", "echo $HOME; rm -rf *", "--quiet", "--", "a b", "", "`id`", "--diagnostic-format=json-lines"]
        inv = split(["run", "--quiet", "--", *hostile])
        self.assertEqual((inv.test_command, inv.options, inv.operands), (tuple(hostile), (("--quiet", None),), ()))

    def test_usage_errors(self) -> None:
        cases = {
            "no command": [],
            "unknown command": ["frobnicate"],
            "alias": ["rep", "x"],
            "case": ["Run", "--", "x"],
            "option before the command": ["--quiet", "run", "--", "x"],
            "unknown option": ["merge", "--bogus", "x"],
            "abbreviated option": ["merge", "--out", "o", "x"],
            "short option": ["merge", "-q", "x"],
            "single-dash long": ["merge", "-quiet", "x"],
            "flag with a value": ["merge", "--quiet=yes", "x"],
            "valued option at the end": ["merge", "x", "--output"],
            "the separator is not a value": ["run", "--context", "--", "x"],
            "the separator is not a value (merge)": ["merge", "--output", "--", "x"],
            "run without separator": ["run", "true"],
            "run with nothing after it": ["run", "--"],
            "run with an operand": ["run", "x", "--", "true"],
            "merge without input": ["merge"],
            "merge with only options": ["merge", "--quiet"],
            "report without input": ["report", "--format", "json"],
            "report with two inputs": ["report", "--format", "json", "a", "b"],
            "check with two inputs": ["check", "a", "--", "b"],
            "check without input": ["check"],
            "clean with an operand": ["clean", "x"],
            "doctor with an operand": ["doctor", "x"],
            "version with an operand": ["version", "x"],
            "version with operands after the separator": ["version", "--", "x"],
        }
        for label, args in cases.items():
            with self.subTest(case=label), self.assertRaises(C.ConfigError) as ctx:
                split(args)
            self.assertEqual(ctx.exception.code, "COV0001", label)

    def test_diagnostic_format_is_read_like_the_launcher_reads_it(self) -> None:
        cases = [
            ([], "human"),
            (["version"], "human"),
            (["version", "--diagnostic-format=json-lines"], "json-lines"),
            (["version", "--diagnostic-format", "json-lines"], "json-lines"),
            (["--diagnostic-format=json-lines", "bogus"], "json-lines"),
            (["version", "--diagnostic-format=json-lines", "--diagnostic-format=human"], "human"),
            (["version", "--diagnostic-format=human", "--diagnostic-format", "json-lines"], "json-lines"),
            (["version", "--diagnostic-format=JSON-LINES"], "human"),
            (["version", "--diagnostic-format=json-lines", "--diagnostic-format=xml"], "human"),
            (["version", "--diagnostic-format"], "human"),
            (["run", "--", "--diagnostic-format=json-lines"], "human"),
            (["run", "--diagnostic-format", "--", "json-lines"], "human"),
            (["run", "--diagnostic-format=json-lines", "--", "--diagnostic-format=human"], "json-lines"),
        ]
        for args, want in cases:
            self.assertEqual(diagnostic_format(args), want, args)
        for args, want in ((["merge"], "auto"), (["merge", "--color=never"], "never"), (["merge", "--color", "always"], "always"),
                           (["merge", "--color=never", "--color=blue"], "auto"), (["run", "--", "--color=never"], "auto"),
                           (["merge", "--color=always", "--color", "never"], "never")):
            self.assertEqual(color_mode(args), want, args)


class ExitCodeTest(unittest.TestCase):
    """COV-CLI-004."""

    def test_the_codes_are_the_specified_ones(self) -> None:
        self.assertEqual([cli.EXIT_OK, cli.EXIT_POLICY, cli.EXIT_USAGE, cli.EXIT_BUILD, cli.EXIT_TEST, cli.EXIT_EVIDENCE,
                          cli.EXIT_REPORT, cli.EXIT_UNSUPPORTED, cli.EXIT_INTERNAL], list(range(9)))

    def test_a_valid_invocation_of_an_unimplemented_command_is_unsupported(self) -> None:
        pending = [c for c in C.COMMANDS if c not in cli.HANDLERS]
        self.assertEqual(sorted(cli.HANDLERS), ["check", "merge", "version"])
        for command in pending:
            with self.subTest(command=command):
                code, out, err = run(*argv(command, "--diagnostic-format=json-lines"))
                (rec,) = records(err)
                self.assertEqual((code, out, rec["code"], rec["phase"]), (7, "", "COV5001", "invocation"))
                self.assertIn({"name": "command", "value": command}, rec["facts"])

    def test_a_handler_gets_the_resolved_invocation_and_its_code_is_returned(self) -> None:
        seen = {}

        def handler(ctx: cli.Context) -> int:
            seen.update(operands=ctx.invocation.operands, line=ctx.config.leaf("thresholds.line"), controls=ctx.config.controls,
                        quiet=ctx.console.quiet, color=ctx.console.color, tier=ctx.config.tier().name)
            ctx.console.say("summary")
            return cli.EXIT_POLICY

        toml = b'[tool.sv0cov]\nschema = "1.0"\n[tool.sv0cov.thresholds]\nline = 85\n[tool.sv0cov.limits.raw_profile]\ntier = "large"\n'
        with mock.patch.dict(cli.HANDLERS, {"merge": handler}):
            code, out, err = run("merge", "--color=never", "x", "--expect-run", RUN, "y", files={"sv0.toml": toml})
        self.assertEqual((code, out, err), (1, "summary\n", ""))
        self.assertEqual(seen["operands"], ("x", "y"))
        self.assertEqual((seen["line"].value, seen["line"].source, seen["tier"]), (8500, "sv0.toml", "large"))
        self.assertEqual((seen["controls"], seen["quiet"], seen["color"]), ({"--color": "never", "--expect-run": [RUN]}, False, "never"))

    def test_an_unexpected_exception_is_an_internal_failure_that_discloses_only_its_type(self) -> None:
        def handler(ctx: cli.Context) -> int:
            raise RuntimeError("secret /home/user/token=abc")

        with mock.patch.dict(cli.HANDLERS, {"clean": handler}):
            code, out, err = run("clean", "--diagnostic-format", "json-lines")
        (rec,) = records(err)
        self.assertEqual((code, out, rec["code"], rec["phase"], rec["facts"]),
                         (8, "", "COV8001", "internal", [{"name": "exception", "value": "RuntimeError"}]))
        self.assertNotIn("secret", err)

    def test_an_invalid_registry_is_an_internal_failure(self) -> None:
        from sv0cov.diagnostics import RegistryError
        with mock.patch("sv0cov.console.load_registry", side_effect=RegistryError("bad digest")):
            code, out, err = run("frobnicate")
        self.assertEqual((code, out), (8, ""))
        self.assertTrue(err.startswith("COV8002 error: Diagnostic registry is invalid\n"))


class UsageMatrixTest(unittest.TestCase):
    """COV-CLI-007: per-command usage errors, exit 2, before anything else."""

    def assert_usage(self, args: list[str], subject: str | None = None) -> None:
        code, out, err = run(*args, "--diagnostic-format=json-lines") if "--" not in args else \
            run(args[0], "--diagnostic-format=json-lines", *args[1:])
        recs = records(err)
        self.assertEqual((code, out, [r["code"] for r in recs], recs[0]["phase"]), (2, "", ["COV0001"], "invocation"), args)
        if subject is not None:
            self.assertIn({"name": "subject", "value": subject}, recs[0]["facts"], args)

    def test_every_base_invocation_is_accepted_by_the_usage_checks(self) -> None:
        for command in C.COMMANDS:
            code, _, err = run(*argv(command))
            self.assertEqual(code, {"version": 0, "merge": 5, "check": 5}.get(command, 7), (command, err))

    def test_every_option_on_every_command(self) -> None:
        accepted = refused = 0
        for command in C.COMMANDS:
            for opt in C.OPTIONS:
                if command == "report" and opt.name == "--format":
                    continue
                with self.subTest(command=command, option=opt.name):
                    args = argv(command, *value_args(opt.name))
                    if command in opt.commands:
                        code, _, err = run(*args)
                        # Accepted by the usage layer: any failure left is a configuration relation, never COV0001.
                        self.assertNotIn("COV0001", err, args)
                        self.assertIn(code, (0, 2, 5, 7), args)
                        accepted += 1
                    else:
                        self.assert_usage(args, opt.name)
                        refused += 1
        self.assertEqual(refused, sum(len(C.COMMANDS) - len(o.commands) for o in C.OPTIONS))
        self.assertEqual(accepted, sum(len(o.commands) for o in C.OPTIONS) - 1)

    def test_repeats_conflicts_and_comma_lists(self) -> None:
        for opt in C.OPTIONS:
            command = next(c for c in opt.commands)
            if opt.arity != "repeatable" and not (command == "report" and opt.name == "--format"):
                with self.subTest(option=opt.name):
                    self.assert_usage(argv(command, *value_args(opt.name), *value_args(opt.name)), opt.name)
        self.assert_usage(argv("run", "--context", "a", "--no-context"))
        self.assert_usage(argv("merge", "--expect-run", RUN, "--run-manifest", "m.json"))
        self.assert_usage(argv("merge", "--expect-run", RUN, "--expect-run", RUN), "--expect-run")
        self.assert_usage(["report", "x"], "--format")
        self.assert_usage(["report", "--format", "json,html", "x"], "--format")
        self.assert_usage(["report", "--format", "json", "--format", "json", "x"], "--format")
        self.assert_usage(["report", "--report", "json", "--format", "json", "x"], "--report")
        self.assert_usage(argv("run", "--report", "json,html"), "--report")
        self.assert_usage(argv("run", "--format", "json"), "--format")
        self.assert_usage(argv("merge", "--color", "sometimes"), "--color")
        self.assert_usage(argv("merge", "--diagnostic-format", "xml"), "--diagnostic-format")
        self.assert_usage(argv("run", "--run-id", RUN.upper()), "--run-id")
        self.assert_usage(argv("version", "--quiet"), "--quiet")
        self.assert_usage(argv("clean", "--color", "never"), "--color")

    def test_configuration_errors_are_exit_2_in_the_configuration_phase(self) -> None:
        head = b'[tool.sv0cov]\nschema = "1.0"\n'
        cases = {
            "COV0002": head + b"empty = \n",
            "COV0010": b"[tool.sv0cov]\n",
            "COV0011": head + b"bogus = 1\n",
            "COV0012": head + b'empty = "maybe"\n',
            "COV0013": head + b'[tool.sv0cov.limits.raw_profile]\ntier = "custom"\n',
            "COV0015": head + b"[tool.sv0cov.thresholds]\nline = 101\n",
        }
        for want, data in cases.items():
            for command in cli.PROJECT_COMMANDS:
                with self.subTest(code=want, command=command):
                    code, out, err = run(*argv(command, "--diagnostic-format=json-lines"), files={"sv0.toml": data})
                    (rec,) = records(err)
                    self.assertEqual((code, out, rec["code"], rec["phase"]), (2, "", want, "configuration"))
        # A value error on the command line names the option.
        code, _, err = run(*argv("check", "--threshold-line", "85%", "--diagnostic-format=json-lines"))
        (rec,) = records(err)
        self.assertEqual((code, rec["code"]), (2, "COV0015"))
        self.assertIn({"name": "subject", "value": "--threshold-line"}, rec["facts"])
        # A usage error wins over a broken file; an unreadable manifest is a configuration error.
        code, _, err = run("merge", "--diagnostic-format=json-lines", files={"sv0.toml": b"[tool.sv0cov]\n"})
        self.assertEqual([r["code"] for r in records(err)], ["COV0001"])
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "sv0.toml").mkdir()
            code, _, err = run(*argv("check", "--diagnostic-format=json-lines"), cwd=Path(tmp))
            self.assertEqual((code, [r["code"] for r in records(err)]), (2, ["COV0002"]))

    def test_version_and_doctor_do_not_read_the_project(self) -> None:
        broken = {"sv0.toml": b"[tool.sv0cov]\nnot toml"}
        self.assertEqual(run("version", files=broken)[0], 0)
        self.assertEqual(run("doctor", files=broken)[0], 7)
        self.assertEqual(run("check", "x", files=broken)[0], 2)


class StreamTest(unittest.TestCase):
    """SPEC 20.2, 20.5.2; COV-CLI-009."""

    def test_human_is_the_default_and_goes_to_stderr(self) -> None:
        code, out, err = run("merge")
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(err.splitlines()[0], "COV0001 error: Invalid command-line invocation")
        self.assertIn("  subject: merge", err)
        self.assertNotIn("\x1b", err)

    def test_every_command_supports_both_formats(self) -> None:
        for command in C.COMMANDS:
            for form in (["--diagnostic-format=json-lines"], ["--diagnostic-format", "json-lines"]):
                with self.subTest(command=command, form=form):
                    code, out, err = run(command, *form, "--bogus")
                    (rec,) = records(err)
                    self.assertEqual((code, out, rec["code"], rec["schema"], rec["version"]), (2, "", "COV0001", "sv0cov.diagnostic", "1.0"))
                    self.assertEqual(rec["message"], load_registry().entry("COV0001").title)
            code, out, err = run(command, "--diagnostic-format=human", "--bogus")
            self.assertTrue(err.startswith("COV0001 error: "), command)

    def test_json_lines_carry_nothing_else(self) -> None:
        code, out, err = run("merge", "--quiet", "--color=always", "--diagnostic-format=json-lines", "--expect-run", "zz", "x", tty=True)
        self.assertEqual((code, out), (2, ""))
        self.assertEqual(len(records(err)), 1)
        self.assertNotIn("\x1b", err)
        self.assertTrue(err.endswith("\n") and "\n\n" not in err)

    def test_quiet_suppresses_incidental_output_only(self) -> None:
        def handler(ctx: cli.Context) -> int:
            ctx.console.say("progress")
            ctx.console.write_artifact(b'{"artifact":true}\n')
            ctx.console.report(Diagnostic("COV3003", "merge", facts=(("detail", "x"),)))
            return cli.EXIT_EVIDENCE

        with mock.patch.dict(cli.HANDLERS, {"merge": handler}):
            loud = run("merge", "x")
            quiet = run("merge", "--quiet", "x")
            lines = run("merge", "--quiet", "--diagnostic-format=json-lines", "x")
        self.assertEqual(loud[:2], (5, 'progress\n{"artifact":true}\n'))
        self.assertEqual(quiet[:2], (5, '{"artifact":true}\n'))
        self.assertEqual(quiet[2], loud[2])
        self.assertTrue(quiet[2].startswith("COV3003 error: Run selection failed\n"))
        self.assertEqual([r["code"] for r in records(lines[2])], ["COV3003"])

    def test_color_applies_only_to_human_text_on_a_terminal(self) -> None:
        # A usage error honors the request too.
        self.assertNotIn("\x1b", run("merge", "--color=never", tty=True)[2])
        self.assertIn("\x1b[1;31mCOV0001 error\x1b[0m: ", run("merge", "--color", "always")[2])
        self.assertIn("\x1b", run("merge", tty=True)[2])
        for args, tty, colored in ((["--color=always"], False, True), (["--color=always"], True, True), (["--color=auto"], True, True),
                                   (["--color=auto"], False, False), ([], True, True), ([], False, False), (["--color=never"], True, False)):
            # The option is given with a later usage error, so the handler-side setting is exercised through a handler.
            def handler(ctx: cli.Context) -> int:
                ctx.console.report(Diagnostic("COV3001", "merge"))
                return 5

            with mock.patch.dict(cli.HANDLERS, {"merge": handler}):
                code, out, err = run("merge", *args, "x", tty=tty)
            self.assertEqual("\x1b[" in err, colored, (args, tty))
            stripped = err.replace("\x1b[1;31m", "").replace("\x1b[0m", "")
            self.assertEqual(stripped, "COV3001 error: No accepted coverage profile\n", (args, tty))


class ProcessTest(unittest.TestCase):
    """The same behaviour from a real process: exit status and raw stream bytes."""

    def process(self, *args: str) -> subprocess.CompletedProcess:
        boot = "import sys; sys.path.insert(0, sys.argv.pop(1)); from sv0cov.cli import main; sys.exit(main())"
        with tempfile.TemporaryDirectory() as tmp:
            return subprocess.run([sys.executable, "-I", "-B", "-c", boot, str(ROOT / "src"), *args], cwd=tmp, capture_output=True, timeout=60)

    def test_exit_status_and_streams(self) -> None:
        p = self.process("merge", "--diagnostic-format=json-lines", "--expect-run", "nope", "x")
        self.assertEqual((p.returncode, p.stdout), (2, b""))
        (rec,) = records(p.stderr.decode())
        self.assertEqual(rec["code"], "COV0001")
        p = self.process("report", "--format", "json", "cov.json")
        self.assertEqual((p.returncode, p.stdout), (7, b""))
        self.assertTrue(p.stderr.startswith(b"COV5001 error: Unsupported installation or platform\n"))
        self.assertNotIn(b"\x1b", p.stderr)  # a pipe is not a terminal
        p = self.process("version", "--json", "--diagnostic-format", "json-lines")
        self.assertEqual((p.returncode, p.stderr), (0, b""))
        self.assertEqual(p.stdout, cli.version_manifest())
        p = self.process("run", "--bogus", "--", "--diagnostic-format=json-lines")
        self.assertEqual(p.returncode, 2)
        self.assertTrue(p.stderr.startswith(b"COV0001 error: "))


class ConsoleTest(unittest.TestCase):
    def console(self, **kw) -> tuple[Console, io.StringIO, io.StringIO]:
        out, err = io.StringIO(), io.StringIO()
        return Console(out, err, **kw), out, err

    def test_diagnostics_are_ordered_by_phase_then_code_and_emitted_once(self) -> None:
        c, _, err = self.console(diagnostic_format="json-lines")
        for d in (Diagnostic("COV8001", "internal"), Diagnostic("COV4101", "policy"), Diagnostic("COV3002", "merge", facts=(("name", "b"),)),
                  Diagnostic("COV3001", "merge"), Diagnostic("COV3002", "merge", facts=(("name", "a"),)), Diagnostic("COV0001", "invocation"),
                  Diagnostic("COV3001", "merge"), Diagnostic("COV0012", "configuration")):
            c.report(d)
        c.flush()
        got = [(r["phase"], r["code"], [f["value"] for f in r["facts"]]) for r in records(err.getvalue())]
        self.assertEqual(got, [("invocation", "COV0001", []), ("configuration", "COV0012", []), ("merge", "COV3001", []),
                               ("merge", "COV3002", ["a"]), ("merge", "COV3002", ["b"]), ("policy", "COV4101", []),
                               ("internal", "COV8001", [])])
        # A second flush adds only what is new.
        c.report(Diagnostic("COV3001", "merge"))
        c.report(Diagnostic("COV4011", "publication"))
        c.flush()
        self.assertEqual([r["code"] for r in records(err.getvalue())][7:], ["COV4011"])
        c.flush()
        self.assertEqual(len(records(err.getvalue())), 8)

    def test_human_text_neutralizes_terminal_controls_even_with_color(self) -> None:
        c, _, err = self.console(color="always")
        c.report(Diagnostic("COV0001", "invocation", facts=(("detail", "bad \x1b[2J\x07 value"),)))
        c.flush()
        text = err.getvalue()
        self.assertEqual(text.count("\x1b"), 2)  # the two color sequences, nothing from the fact
        self.assertIn("bad \\x1b[2J\\x07 value", text)

    def test_unknown_modes_are_refused(self) -> None:
        with self.assertRaises(ValueError):
            Console(io.StringIO(), io.StringIO(), diagnostic_format="xml")
        with self.assertRaises(ValueError):
            Console(io.StringIO(), io.StringIO(), color="blue")
        with self.assertRaises(ValueError):
            self.console()[0].configure(quiet=False, color="blue")

    def test_fact_text_is_always_a_valid_fact(self) -> None:
        for raw in ("plain", "a\x00b\rc\nd", "\udcff surrogate from a bad argv byte", "é" * 5000, ""):
            text = cli.fact_text(raw)
            self.assertLessEqual(len(text.encode("utf-8")), 4096)
            Diagnostic("COV0001", "invocation", facts=(("detail", text),)).to_json()
        self.assertEqual(cli.fact_text("a\x00b\rc\nd"), "a?b?c?d")
        code, _, err = run("merge", "--context=\udcff", "x", "--diagnostic-format=json-lines")
        self.assertEqual((code, len(records(err))), (2, 1))


if __name__ == "__main__":
    unittest.main()
