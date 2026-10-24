# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``run`` command, first half (CV-233; SPEC 14.3, 20.2.2, 20.4, 23.3;
COV-CLI-001, COV-CLI-003, COV-SEC-006, AC-018, AC-098).

The toolchain driver is replaced here by a small recording stand-in, so
these tests need no compiler: they pin what sv0cov itself does (the run
ID, the reservation, the two environments, the exact argv, the exit
status). The real driver, compiler and runtime are exercised by sv0c's
coverage gate.
"""

from __future__ import annotations

import io
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_indexed_reader import fixture_inputs  # noqa: E402

from sv0cov import cli, cmd_run  # noqa: E402
from sv0cov.formats.export_manifest import verify_export  # noqa: E402
from sv0cov.model.indexed import read_indexed  # noqa: E402
from sv0cov.model.report import read_report  # noqa: E402

HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
RUN = "0123456789abcdef0123456789abcdef"
ZERO = "0" * 32
PY = sys.executable
# Arguments a shell would change: spaces, quotes, globs, substitutions, operators, a newline, an empty one.
HOSTILE = ["a b", "$(touch pwned)", "`touch pwned`", "*", "~", "; touch pwned", "| cat", "&& false", "> pwned", "$HOME", "'q'", '"d"',
           "line\nbreak", "", "--", "-n", "tab\there", "\\", "é✓"]

# The stand-in driver: records how it was called, then "builds" a program that records how it was run.
DRIVER = r'''#!{py}
import json, os, sys
a = sys.argv[1:]
import stat
null = os.fstat(0)
record = {{"argv": a, "cwd": os.getcwd(), "env": dict(os.environ),
          "stdin_is_null": stat.S_ISCHR(null.st_mode) and null.st_rdev == os.stat(os.devnull).st_rdev}}
open(os.environ["FAKE_RECORD"] + ".build", "w").write(json.dumps(record))
mode = os.environ.get("FAKE_MODE", "ok")
print("driver says hello")
print("driver warns", file=sys.stderr)
if mode == "fail":
    sys.exit(9)
exe, cmap = a[a.index("-o") + 1], a[a.index("--coverage-map") + 1]
if mode != "no-map":
    open(cmap, "wb").write(open(os.environ["FAKE_MAP"], "rb").read() if mode != "bad-map" else b"{{}}")
if mode != "no-exe":
    open(exe, "w").write("""#!{py}
import json, os, signal, sys
open(os.environ["FAKE_RECORD"] + ".run", "w").write(json.dumps({{"argv": sys.argv, "cwd": os.getcwd(), "env": dict(os.environ)}}))
print("program output")
sys.stdout.flush()
sys.path[:0] = [{src!r}, {tests!r}]
from test_indexed_reader import fixture_inputs, raw
from sv0cov.formats.rawprofile import decode
_, m, counts = fixture_inputs("f0")
run, where = os.environ["SV0COV_RUN_ID"], os.environ["SV0COV_PROFILE_DIR"]
def put(n, run_id=run, cut=0, temp=False, **kw):
    data = raw(m, counts, n, run=run_id, **kw)
    name = run_id + "-" + decode(data).profile_id.hex() + ".sv0profraw"
    open(os.path.join(where, "." + name + ".tmp-1234" if temp else name), "wb").write(data[:len(data) - cut])
ctx = {{}} if "SV0COV_CONTEXT" not in os.environ else {{"context": os.environ["SV0COV_CONTEXT"]}}
for step in os.environ.get("FAKE_PROFILES", "ok").split(","):
    if step == "ok": put(1, **ctx)
    elif step == "second": put(2, **ctx)
    elif step == "cut": put(3, cut=9)
    elif step == "temp": put(4, temp=True)
    elif step == "foreign": put(5, run_id="f" * 32)
if os.environ.get("FAKE_MUTATE"):  # a test that edits a compiled source while it runs
    open(os.environ["FAKE_MUTATE"], "ab").write(b"// edited during the run\\n")
if os.environ.get("FAKE_SIGNAL"):
    os.kill(os.getpid(), int(os.environ["FAKE_SIGNAL"]))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
""")
    os.chmod(exe, 0o644 if mode == "not-executable" else 0o755)
'''


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = Path(tmp.name).resolve()
        self.cwd = self.top / "demo"
        self.cwd.mkdir()
        (self.cwd / "main.sv0").write_bytes((ROOT / "tests" / "fixtures" / "semantic" / "f0" / "main.sv0").read_bytes())
        self.driver = self.top / "sv0"
        self.driver.write_text(DRIVER.format(py=PY, src=str(ROOT / "src"), tests=str(ROOT / "tests")))
        self.driver.chmod(0o755)
        self.map_file = self.top / "map.json"
        self.map_file.write_bytes(fixture_inputs("f0")[0])
        self.record = str(self.top / "record")
        self.environ = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.top), "FAKE_RECORD": self.record, "FAKE_MAP": str(self.map_file),
                        "KEEP_ME": "kept"}

    def run_cli(self, *args: str, env: dict | None = None, driver: object = "default", cwd: Path | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        found = self.driver if driver == "default" else driver
        with mock.patch.dict(os.environ, {**self.environ, **(env or {})}, clear=True), \
                mock.patch.object(cmd_run, "toolchain_driver", lambda: found):
            before = dict(os.environ)
            code = cli.main(["run", "--diagnostic-format=json-lines", *args], stdout=out, stderr=err, cwd=cwd or self.cwd)
            self.assertEqual(dict(os.environ), before)  # the caller's own environment is never changed
        return code, out.getvalue(), err.getvalue()

    def recorded(self, which: str) -> dict:
        return json.loads(Path(f"{self.record}.{which}").read_text())

    def run_dirs(self) -> list[str]:
        runs = self.cwd / ".sv0cov" / "runs"
        return sorted(os.listdir(runs)) if runs.is_dir() else []


class LifecycleTest(Base):
    def test_reserve_build_and_execute(self) -> None:
        code, out, err = self.run_cli("--", "demo", "one", "two")
        (run_id,) = self.run_dirs()
        run_dir = self.cwd / ".sv0cov" / "runs" / run_id
        self.assertRegex(run_id, r"\A[0-9a-f]{32}\Z")
        self.assertEqual((code, err), (0, ""))
        lines = out.splitlines()
        self.assertEqual(lines[:3], [f"run {run_id}: built demo; running the test command", "program output", "sv0cov coverage report"])
        self.assertEqual(lines[-1], f"run {run_id}: merged 1 of 1 profiles; evidence and reports are in .sv0cov/runs/{run_id}")
        self.assertIn("evidence:   PASSING", lines)
        self.assertIn("execution:  passed (exit 0)", lines)
        self.assertEqual(sorted(os.listdir(run_dir)), ["bin", "build.log", "coverage.sv0covdata.json", "maps", "profiles"])
        modes = [stat.S_IMODE((self.cwd / p).stat().st_mode) for p in (".sv0cov", ".sv0cov/runs", f".sv0cov/runs/{run_id}",
                                                                      f".sv0cov/runs/{run_id}/bin", f".sv0cov/runs/{run_id}/maps",
                                                                      f".sv0cov/runs/{run_id}/profiles", f".sv0cov/runs/{run_id}/build.log")]
        self.assertEqual(modes, [0o700] * 6 + [0o600])
        self.assertEqual(sorted((run_dir / "build.log").read_text().splitlines()), ["driver says hello", "driver warns"])  # not on our streams
        build = self.recorded("build")
        self.assertEqual(build["argv"], ["native-compile", "--coverage=instrument", "--coverage-map", str(run_dir / "maps/demo.sv0covmap.json"),
                                         "-o", str(run_dir / "bin/demo"), "--project", "."])
        self.assertEqual(build["cwd"], str(self.cwd))
        self.assertTrue(build["stdin_is_null"])  # the build cannot read what was meant for the test command
        ran = self.recorded("run")
        self.assertEqual((ran["argv"][1:], ran["cwd"]), (["one", "two"], str(self.cwd)))

    def test_the_tier_reaches_the_build(self) -> None:
        self.run_cli("--raw-profile-tier", "large", "--", "demo")
        self.assertIn("--coverage-tier=large", self.recorded("build")["argv"])
        (self.cwd / "sv0.toml").write_text(HEAD + '[tool.sv0cov.limits.raw_profile]\ntier = "custom"\nmax_counters = 7\nmax_bytes = 4096\n')
        self.run_cli("--", "demo")
        argv = self.recorded("build")["argv"]
        self.assertEqual(argv[4:9], ["--coverage-tier=custom", "--coverage-max-counters", "7", "--coverage-max-bytes", "4096"])

    def test_quiet_keeps_the_test_commands_own_output(self) -> None:
        code, out, err = self.run_cli("--quiet", "--", "demo")
        self.assertEqual((code, out, err), (0, "program output\n", ""))

    def test_other_programs_and_scripts_reach_the_instrumented_program_by_name(self) -> None:
        """The run's bin directory is first on the child's PATH."""
        script = self.cwd / "tests.sh"
        script.write_text("#!/bin/sh\nexec demo from-script\n")
        script.chmod(0o755)
        for argv in (("./tests.sh",), (str(script),), ("/bin/sh", "-c", "demo from-script"), ("env", "demo", "from-script")):
            with self.subTest(argv=argv):
                Path(self.record + ".run").unlink(missing_ok=True)
                self.assertEqual(self.run_cli("--", *argv)[0], 0)
                ran = self.recorded("run")
                self.assertEqual(ran["argv"][1:], ["from-script"])
                run_dir = self.cwd / ".sv0cov/runs" / ran["env"]["SV0COV_RUN_ID"]
                self.assertEqual(ran["env"]["PATH"].split(os.pathsep)[0], str(run_dir / "bin"))
                self.assertEqual(ran["env"]["PATH"].split(os.pathsep)[1:], self.environ["PATH"].split(os.pathsep))


class RunIdTest(Base):
    """SPEC 14.3."""

    def test_the_default_is_secure_random_and_never_from_the_environment(self) -> None:
        seen = set()
        for _ in range(3):
            self.run_cli("--", "demo", env={"SV0COV_RUN_ID": RUN})
            seen.add(self.recorded("run")["env"]["SV0COV_RUN_ID"])
        self.assertEqual(len(seen), 3)
        self.assertNotIn(RUN, seen)
        self.assertEqual(sorted(seen), self.run_dirs())
        with mock.patch.object(cmd_run.os, "urandom", lambda n: bytes(range(1, n + 1))):
            self.assertEqual(cmd_run.new_run_id(), "0102030405060708090a0b0c0d0e0f10")

    def test_no_entropy_or_an_all_zero_draw_aborts_before_anything_exists(self) -> None:
        def broken(_n: int) -> bytes:
            raise OSError("no entropy")

        for source in (broken, lambda n: bytes(n), lambda n: b"\x01" * 8, mock.Mock(side_effect=NotImplementedError)):
            with self.subTest(source=source):
                with mock.patch.object(cmd_run.os, "urandom", source):
                    code, out, err = self.run_cli("--", "demo")
                (r,) = records(err)
                self.assertEqual((code, out, r["code"], r["phase"]), (8, "", "COV2002", "execution"))
                self.assertFalse((self.cwd / ".sv0cov").exists())
                self.assertFalse(Path(self.record + ".build").exists())

    def test_an_explicit_run_id_is_used_and_validated(self) -> None:
        self.assertEqual(self.run_cli("--run-id", RUN, "--", "demo")[0], 0)
        self.assertEqual((self.run_dirs(), self.recorded("run")["env"]["SV0COV_RUN_ID"]), ([RUN], RUN))
        for bad in (ZERO, RUN.upper(), RUN[:-1], RUN + "0", "g" * 32, ""):
            with self.subTest(run_id=bad):
                code, out, err = self.run_cli("--run-id", bad, "--", "demo")
                self.assertEqual((code, out), (2, ""))
        self.assertEqual(self.run_dirs(), [RUN])

    def test_an_existing_run_directory_is_a_collision(self) -> None:
        self.assertEqual(self.run_cli("--run-id", RUN, "--", "demo")[0], 0)
        Path(self.record + ".build").unlink()
        before = sorted(str(p) for p in self.cwd.rglob("*"))
        code, out, err = self.run_cli("--run-id", RUN, "--", "demo")
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], r["phase"]), (5, "", "COV4010", "publication"))
        self.assertFalse(Path(self.record + ".build").exists())  # before the build
        self.assertEqual(sorted(str(p) for p in self.cwd.rglob("*")), before)
        # A generated ID that happens to exist is the same collision, not a retry.
        with mock.patch.object(cmd_run.os, "urandom", lambda n: bytes.fromhex(RUN)):
            self.assertEqual(self.run_cli("--", "demo")[0], 5)

    def test_the_run_directory_is_never_reached_through_a_symlink(self) -> None:
        (self.top / "elsewhere").mkdir()
        os.symlink(self.top / "elsewhere", self.cwd / ".sv0cov")
        code, _, err = self.run_cli("--", "demo")
        self.assertEqual((code, records(err)[0]["code"]), (5, "COV6002"))
        self.assertEqual(os.listdir(self.top / "elsewhere"), [])
        os.unlink(self.cwd / ".sv0cov")
        self.assertEqual(self.run_cli("--output-dir", "build/cov", "--run-id", RUN, "--", "demo")[0], 0)
        self.assertTrue((self.cwd / "build/cov/runs" / RUN / "bin/demo").is_file())


class EnvironmentTest(Base):
    """COV-SEC-006, AC-098."""

    POISON = {"SV0COV_RUN_ID": "f" * 32, "SV0COV_PROFILE_DIR": "/tmp/attacker", "SV0COV_REQUIRED": "0", "SV0COV_CONTEXT": "smuggled",
              "SV0COV_THRESHOLD_LINE": "0", "SV0COV_SATURATION_POLICY": "allow-ordinary", "SV0COV_": "bare", "SV0COV_OUTPUT_DIR": "/tmp/x",
              "SV0COV_REPORTS": "html", "sv0cov_lower": "x"}

    def test_every_reserved_variable_is_removed_and_only_the_transport_is_set(self) -> None:
        self.run_cli("--", "demo", env=self.POISON)
        ran, build = self.recorded("run")["env"], self.recorded("build")["env"]
        (run_id,) = self.run_dirs()
        reserved = {k: v for k, v in ran.items() if k.upper().startswith("SV0COV_")}
        self.assertEqual(reserved, {"SV0COV_PROFILE_DIR": str(self.cwd / ".sv0cov/runs" / run_id / "profiles"), "SV0COV_RUN_ID": run_id,
                                    "SV0COV_REQUIRED": "1"})
        self.assertEqual([k for k in build if k.upper().startswith("SV0COV_")], [])  # the build gets no transport at all
        self.assertEqual((ran["KEEP_ME"], build["KEEP_ME"], ran["HOME"]), ("kept", "kept", str(self.top)))
        self.assertEqual(build["PATH"], self.environ["PATH"])

    def test_the_context_comes_only_from_resolved_configuration(self) -> None:
        cases = (((), None, None), (("--context", "shard 1"), None, "shard 1"), (("--context", ""), None, ""),
                 ((), 'context = "from file"\n', "from file"), (("--no-context",), 'context = "from file"\n', None),
                 (("--context", "cli wins"), 'context = "from file"\n', "cli wins"))
        for args, toml, want in cases:
            with self.subTest(args=args, toml=toml):
                self.setUp()
                if toml:
                    (self.cwd / "sv0.toml").write_text(HEAD + toml)
                self.assertEqual(self.run_cli(*args, "--", "demo", env=self.POISON)[0], 0)
                self.assertEqual(self.recorded("run")["env"].get("SV0COV_CONTEXT"), want)

    def test_ambient_variables_change_no_policy(self) -> None:
        from sv0cov.config_resolve import resolve
        toml = (HEAD + "[tool.sv0cov.thresholds]\nline = 80\n").encode()
        with mock.patch.dict(os.environ, self.POISON):
            poisoned = resolve("run", [("--threshold-branch", "70")], toml).to_bytes()
        self.assertEqual(poisoned, resolve("run", [("--threshold-branch", "70")], toml).to_bytes())
        doc = json.loads(poisoned)["coverage"]
        self.assertEqual((doc["thresholds"]["line"], doc["thresholds"]["branch"], doc["integrity"]["saturation"]),
                         ({"source": "sv0.toml", "value": 8000}, {"source": "cli", "value": 7000}, {"source": "default", "value": "fail"}))

    def test_the_environment_builders(self) -> None:
        base = {"PATH": "/usr/bin", "A": "1", **self.POISON}
        frozen = dict(base)
        env = cmd_run.child_environment(base, profile_dir="/p", run_id=RUN, context=None, bin_dir="/run/bin")
        self.assertEqual(env, {"PATH": "/run/bin" + os.pathsep + "/usr/bin", "A": "1", "SV0COV_PROFILE_DIR": "/p", "SV0COV_RUN_ID": RUN,
                               "SV0COV_REQUIRED": "1"})
        self.assertEqual(cmd_run.child_environment({}, profile_dir="/p", run_id=RUN, context="", bin_dir="/b")["PATH"], "/b")
        self.assertEqual(cmd_run.child_environment({}, profile_dir="/p", run_id=RUN, context="")["SV0COV_CONTEXT"], "")
        self.assertEqual(cmd_run.build_environment(base), {"PATH": "/usr/bin", "A": "1"})
        self.assertEqual(base, frozen)
        self.assertEqual(set(cmd_run.TRANSPORT), {"SV0COV_PROFILE_DIR", "SV0COV_RUN_ID", "SV0COV_CONTEXT", "SV0COV_REQUIRED"})


class ArgvTest(Base):
    """COV-CLI-003, AC-018; SPEC 20.4."""

    def test_every_argument_reaches_the_child_unchanged(self) -> None:
        code, _, _ = self.run_cli("--", "demo", *HOSTILE)
        self.assertEqual(code, 0)
        self.assertEqual(self.recorded("run")["argv"][1:], HOSTILE)
        self.assertEqual(sorted(p.name for p in self.cwd.iterdir()), [".sv0cov", "main.sv0"])  # nothing was interpreted
        self.assertFalse((self.top / "pwned").exists())

    def test_sv0cov_options_after_the_separator_belong_to_the_command(self) -> None:
        tail = ["--quiet", "--run-id", ZERO, "--diagnostic-format=json-lines", "--", "--output-dir", "/"]
        self.assertEqual(self.run_cli("--", "demo", *tail)[0], 0)
        self.assertEqual(self.recorded("run")["argv"][1:], tail)

    def test_no_shell_is_involved_unless_the_user_names_one(self) -> None:
        with mock.patch.object(subprocess, "Popen", wraps=subprocess.Popen) as popen:
            self.run_cli("--", "demo", "a b")
        build_call, call = popen.call_args_list  # the build, then the test command
        self.assertFalse(build_call.kwargs.get("shell", False))
        self.assertEqual((call.args[0], call.kwargs["shell"]), (["demo", "a b"], False))
        self.assertEqual(self.run_cli("--", "demo; true")[0], 2)  # one program name, not a command line
        self.assertEqual(self.run_cli("--", "/bin/sh", "-c", 'test "$1" = "x y"', "sh", "x y")[0], 5)  # an explicit shell is the user's; it ran no instrumented program

    def test_a_command_that_cannot_be_found_stops_before_anything_is_created(self) -> None:
        (self.cwd / "plain.txt").write_text("not executable")
        for argv in (("no-such-program-xyz",), ("./missing",), ("./plain.txt",), ("./",), ("",)):
            with self.subTest(argv=argv):
                code, out, err = self.run_cli("--", *argv)
                (r,) = records(err)
                self.assertEqual((code, out, r["code"], r["phase"]), (2, "", "COV0001", "invocation"))
        self.assertFalse((self.cwd / ".sv0cov").exists())
        self.assertFalse(Path(self.record + ".build").exists())
        self.assertEqual(self.run_cli()[0], 2)  # no separator, no command
        self.assertEqual(self.run_cli("--")[0], 2)
        self.assertEqual(self.run_cli("stray", "--", "demo")[0], 2)

    def test_the_project_name_must_be_a_plain_file_name(self) -> None:
        for name in ("has space", "semi;colon", "-dash", "é"):
            with self.subTest(name=name):
                cwd = self.top / name
                cwd.mkdir()
                code, _, err = self.run_cli("--", "true", cwd=cwd)
                self.assertEqual((code, records(err)[0]["code"]), (2, "COV0001"))
                self.assertEqual(os.listdir(cwd), [])
        self.assertEqual(cmd_run.project_name(self.cwd), "demo")


class BuildTest(Base):
    def test_a_build_that_fails_or_leaves_too_little_is_exit_3(self) -> None:
        cases = {"fail": ("COV1020", "status 9"), "no-map": ("COV1020", "no coverage map"), "no-exe": ("COV1020", "no executable"),
                 "bad-map": (None, "does not accept"), "not-executable": ("COV1020", "not executable")}
        for mode, (code_want, text) in cases.items():
            with self.subTest(mode=mode):
                self.setUp()
                code, out, err = self.run_cli("--", "demo", env={"FAKE_MODE": mode})
                (r,) = records(err)
                self.assertEqual((code, out, r["phase"]), (3, "", "build"))
                if code_want:
                    self.assertEqual(r["code"], code_want)
                self.assertIn(text, next(f["value"] for f in r["facts"] if f["name"] == "detail"))
                self.assertFalse(Path(self.record + ".run").exists())  # the test command never ran
                (run_id,) = self.run_dirs()
                self.assertIn("driver warns", (self.cwd / ".sv0cov/runs" / run_id / "build.log").read_text())

    def test_without_a_toolchain_checkout_run_is_unsupported(self) -> None:
        code, out, err = self.run_cli("--", "demo", driver=None)
        (r,) = records(err)
        self.assertEqual((code, out, r["code"], r["phase"]), (7, "", "COV5001", "build"))
        self.assertFalse((self.cwd / ".sv0cov").exists())

    def test_the_driver_is_found_from_this_checkout_and_never_from_the_environment(self) -> None:
        found = cmd_run.toolchain_driver()
        expected = ROOT.parent / "scripts" / "sv0"
        self.assertEqual(found, expected if expected.is_file() else None)
        with mock.patch.dict(os.environ, {"PATH": str(self.top), "SV0": str(self.driver), "SV0COV_DRIVER": str(self.driver)}):
            self.assertEqual(cmd_run.toolchain_driver(), found)

    def test_the_driver_must_be_a_real_executable_file(self) -> None:
        root = self.top / "toolchain"
        module = root / "sv0cov" / "src" / "sv0cov" / "cmd_run.py"
        module.parent.mkdir(parents=True)
        (root / "scripts").mkdir()
        driver = root / "scripts" / "sv0"
        with mock.patch.object(cmd_run, "__file__", str(module)):
            self.assertIsNone(cmd_run.toolchain_driver())  # absent
            driver.write_text("#!/bin/sh\n")
            driver.chmod(0o644)
            self.assertIsNone(cmd_run.toolchain_driver())  # not executable
            driver.chmod(0o755)
            self.assertEqual(cmd_run.toolchain_driver(), driver)
            driver.unlink()
            os.symlink(self.driver, driver)
            self.assertIsNone(cmd_run.toolchain_driver())  # a symlink is not the tracked file
            driver.unlink()
            driver.mkdir()
            self.assertIsNone(cmd_run.toolchain_driver())

    def test_what_run_leaves_is_what_clean_removes(self) -> None:
        self.assertEqual(self.run_cli("--", "demo")[0], 0)
        self.assertEqual(self.run_cli("--", "demo", env={"FAKE_MODE": "fail"})[0], 3)
        out, err = io.StringIO(), io.StringIO()
        self.assertEqual(cli.main(["clean"], stdout=out, stderr=err, cwd=self.cwd), 0, err.getvalue())
        self.assertEqual(sorted(p.name for p in self.cwd.iterdir()), ["main.sv0"])


class OutcomeTest(Base):
    """COV-CLI-004, COV-INS-008, AC-022; SPEC 20.3: pass, policy fail, test fail, killed."""

    def outcome(self, *args: str, **env: str) -> tuple[int, str, list[dict], Path]:
        self.setUp()
        code, out, err = self.run_cli(*args, "--", "demo", env=env)
        (run_id,) = self.run_dirs()
        return code, out, records(err), self.cwd / ".sv0cov" / "runs" / run_id

    def indexed(self, run_dir: Path) -> dict:
        return read_indexed((run_dir / "coverage.sv0covdata.json").read_bytes())

    def test_pass(self) -> None:
        handlers = {n: signal.getsignal(n) for n in cmd_run.FORWARDED}
        code, out, recs, run_dir = self.outcome(FAKE_PROFILES="ok,second")
        self.assertEqual({n: signal.getsignal(n) for n in cmd_run.FORWARDED}, handlers)  # forwarding ends with the command
        self.assertEqual((code, recs), (0, []))
        ix = self.indexed(run_dir)
        self.assertEqual(ix["execution"], {"exit_code": 0, "signal": None, "status": "passed"})
        self.assertEqual(ix["run_selection"]["mode"], "explicit-list")
        self.assertEqual(ix["run_selection"]["selected_run_ids"], [run_dir.name])
        self.assertEqual(([r["status"] for r in ix["profile_inputs"]], ix["semantic"]["complete"]), (["accepted", "accepted"], True))
        self.assertIn("merged 2 of 2 profiles", out)
        self.assertEqual(stat.S_IMODE((run_dir / "coverage.sv0covdata.json").stat().st_mode), 0o600)
        # What run publishes is what merge gives for the same files and run.
        cli_out = io.StringIO()
        self.assertEqual(cli.main(["merge", str(run_dir / "maps"), str(run_dir / "profiles"), "--expect-run", run_dir.name, "--output", "again.json"],
                                  stdout=cli_out, stderr=io.StringIO(), cwd=self.cwd), 0)
        again = read_indexed((self.cwd / "again.json").read_bytes())
        self.assertEqual({k: v for k, v in again.items() if k != "execution"}, {k: v for k, v in ix.items() if k != "execution"})

    def test_policy_fail(self) -> None:
        code, out, recs, run_dir = self.outcome("--threshold-line", "8751bp")
        self.assertEqual((code, [r["code"] for r in recs]), (1, ["COV4101"]))
        self.assertIn("evidence:   POLICY FAILED", out)
        self.assertRegex(out, r'\nFAIL +project "project" +line +>= 8751/10000 +14/16 ')
        self.assertTrue((run_dir / "coverage.sv0covdata.json").is_file())
        self.assertEqual(self.outcome("--threshold-line", "8750bp")[0], 0)

    def test_test_fail(self) -> None:
        """AC-022: exit 4, and the coverage policy result is still reported, separately."""
        for status in (1, 3, 255):
            with self.subTest(status=status):
                code, out, recs, run_dir = self.outcome(FAKE_EXIT=str(status))
                self.assertEqual((code, [r["code"] for r in recs]), (4, ["COV2130"]))
                self.assertEqual(self.indexed(run_dir)["execution"], {"exit_code": status, "signal": None, "status": "failed"})
                self.assertIn(f"run {run_dir.name}: the test command exited with status {status}", out)
                self.assertIn(f"execution:  failed (exit {status})", out)
                self.assertRegex(out, r'\nFAIL +integrity "integrity" +evidence .* COV2130\n')
        code, out, recs, _ = self.outcome("--threshold-line", "100", "--threshold-branch", "0", FAKE_EXIT="1")
        self.assertEqual((code, sorted(r["code"] for r in recs)), (4, ["COV2130", "COV4101"]))
        self.assertRegex(out, r'\nFAIL +project "project" +line ')
        self.assertRegex(out, r'\nPASS +project "project" +branch ')

    def test_prefer_coverage_exit_is_explicit_and_needs_a_coverage_failure(self) -> None:
        self.assertEqual(self.outcome("--prefer-coverage-exit", "--threshold-line", "100", FAKE_EXIT="2")[0], 1)
        self.assertEqual(self.outcome("--threshold-line", "100", FAKE_EXIT="2")[0], 4)
        self.assertEqual(self.outcome("--prefer-coverage-exit", "--threshold-line", "0", FAKE_EXIT="2")[0], 4)  # coverage did not fail
        self.assertEqual(self.outcome("--prefer-coverage-exit", FAKE_EXIT="2")[0], 4)
        self.assertEqual(self.outcome("--prefer-coverage-exit", "--threshold-line", "100")[0], 1)
        self.assertEqual(self.outcome("--prefer-coverage-exit", "--threshold-line", "100", FAKE_SIGNAL="9")[0], 1)
        self.assertEqual(self.outcome("--prefer-coverage-exit")[0], 0)

    def test_killed_after_its_profile_was_published(self) -> None:
        for number in (9, 15, 1):
            with self.subTest(signal=number):
                code, out, recs, run_dir = self.outcome(FAKE_SIGNAL=str(number))
                self.assertEqual((code, [r["code"] for r in recs]), (128 + number, ["COV2130"]))
                self.assertEqual(self.indexed(run_dir)["execution"], {"exit_code": None, "signal": number, "status": "signaled"})
                self.assertIn(f"the test command was ended by signal {number}", out)
                self.assertIn(f"execution:  signaled (signal {number})", out)

    def test_an_interrupted_run_is_never_zero_coverage(self) -> None:
        """COV-INS-008: no profile, a cut one, an uncommitted temporary or a foreign one is incomplete evidence."""
        # profiles the program leaves -> (a code that must be reported, how many were accepted)
        cases = {"none": ("COV3001", "0 of 0"), "temp": ("COV2011", "0 of 1"), "cut": (None, "0 of 1"), "ok,temp": ("COV2011", "1 of 2"),
                 "ok,cut": (None, "1 of 2"), "ok,foreign": ("COV3003", "2 of 2"), "foreign": ("COV3003", "1 of 1")}
        for profiles, (want, usable) in cases.items():
            for extra, exit_want in (({}, 5), ({"FAKE_SIGNAL": "9"}, 137), ({"FAKE_EXIT": "3"}, 4)):
                with self.subTest(profiles=profiles, extra=extra):
                    code, out, recs, run_dir = self.outcome("--threshold-line", "0", "--report", "term", "--report", "json",
                                                            FAKE_PROFILES=profiles, **extra)
                    self.assertEqual(code, exit_want)
                    codes = sorted({r["code"] for r in recs})
                    self.assertTrue(codes and all(c[:4] in ("COV2", "COV3") for c in codes), codes)
                    if want is not None:
                        self.assertIn(want, codes)
                    self.assertTrue(all(r["phase"] == "merge" for r in recs))
                    self.assertIn(f"the evidence is incomplete ({usable} profiles accepted) and was not reported", out)
                    self.assertNotIn("sv0cov coverage report", out)
                    self.assertNotIn("%", out)  # no percentage of any kind
                    self.assertEqual(sorted(os.listdir(run_dir)), ["bin", "build.log", "maps", "profiles"])  # nothing was published
        named = self.outcome(FAKE_PROFILES="ok,temp")[2]
        self.assertTrue(any(f["name"] == "name" and ".tmp-" in f["value"] for f in named[0]["facts"]))

    def test_a_source_changed_since_the_build_is_an_integrity_failure(self) -> None:
        self.setUp()
        real = cmd_run.execute

        def edit_then_run(*args, **kw):
            status = real(*args, **kw)
            (self.cwd / "main.sv0").write_bytes((self.cwd / "main.sv0").read_bytes() + b"\n")
            return status

        with mock.patch.object(cmd_run, "execute", edit_then_run):
            code, out, err = self.run_cli("--", "demo")
        (r,) = records(err)
        self.assertEqual((code, r["code"]), (5, "COV1004"))
        self.assertNotIn("sv0cov coverage report", out)

    def test_final_status(self) -> None:
        f = cmd_run.final_status
        # (test status, sv0cov's own stage, coverage failed, prefer) -> exit
        table = {(0, 0, False, False): 0, (0, 1, True, False): 1, (0, 5, False, False): 5, (0, 6, False, False): 6, (0, 1, True, True): 1,
                 (3, 1, False, False): 4, (3, 1, True, False): 4, (3, 5, False, False): 4, (3, 6, True, False): 4, (3, 1, True, True): 1,
                 (3, 1, False, True): 4, (3, 5, False, True): 4, (-9, 1, False, False): 137, (-15, 5, False, False): 143,
                 (-9, 1, True, True): 1, (-2, 1, False, True): 130, (255, 0, False, False): 4}
        for args, want in table.items():
            self.assertEqual(f(*args), want, args)
        self.assertEqual(cmd_run.execution_record(0), {"exit_code": 0, "signal": None, "status": "passed"})
        self.assertEqual(cmd_run.execution_record(7), {"exit_code": 7, "signal": None, "status": "failed"})
        self.assertEqual(cmd_run.execution_record(-11), {"exit_code": None, "signal": 11, "status": "signaled"})


class ReportSelectionTest(Base):
    """COV-CLI-008, COV-REP-016: run uses resolved `reports` or a replacing --report."""

    def test_default_is_the_terminal_report_on_stdout(self) -> None:
        code, out, _ = self.run_cli("--", "demo")
        (run_id,) = self.run_dirs()
        self.assertEqual(code, 0)
        self.assertIn("sv0cov coverage report\n", out)
        self.assertFalse((self.cwd / ".sv0cov/runs" / run_id / "reports").exists())
        self.assertNotIn("\x1b", out)
        colored = self.run_cli("--color", "always", "--", "demo")[1]
        self.assertIn("\x1b[32mPASSING\x1b[0m", colored)

    def test_nonterminal_reports_are_one_bundle_in_the_run_directory(self) -> None:
        cases = ((("--report", "json"), None, False), (("--report", "json", "--report", "term"), None, True),
                 ((), 'reports = ["json"]\n', False), (("--report", "term"), 'reports = ["json"]\n', None))
        for args, toml, term in cases:
            with self.subTest(args=args, toml=toml):
                self.setUp()
                if toml:
                    (self.cwd / "sv0.toml").write_text(HEAD + toml)
                code, out, err = self.run_cli(*args, "--threshold-line", "100", "--", "demo")
                (run_id,) = self.run_dirs()
                run_dir = self.cwd / ".sv0cov/runs" / run_id
                self.assertEqual((code, [r["code"] for r in records(err)]), (1, ["COV4101"]))
                self.assertEqual("sv0cov coverage report" in out, bool(term) or term is None)
                if term is None:  # the option replaced the configured list: no bundle
                    self.assertFalse((run_dir / "reports").exists())
                    continue
                self.assertEqual(os.listdir(run_dir / "reports"), ["coverage.json"])
                self.assertEqual([stat.S_IMODE((run_dir / p).stat().st_mode) for p in ("reports", "reports/coverage.json")], [0o700, 0o600])
                report = read_report((run_dir / "reports/coverage.json").read_bytes())
                self.assertEqual((report["evidence_eligibility"], report["provenance"]["run_ids"], report["provenance"]["execution_status"]),
                                 ("policy_failed", [run_id], "passed"))
                self.assertEqual(report["resolved_configuration"]["coverage"]["thresholds"]["line"], {"source": "cli", "value": 10000})
                self.assertEqual(report["provenance"]["indexed_input_sha256"],
                                 __import__("hashlib").sha256((run_dir / "coverage.sv0covdata.json").read_bytes()).hexdigest())

    def test_html_joins_the_bundle(self) -> None:
        """AC-103: term and HTML selected: the terminal report is printed and
        one self-contained coverage.html is published beside the native report."""
        from sv0cov.formats.html import check_html
        (self.cwd / "sv0.toml").write_text(HEAD + 'reports = ["term", "html", "json"]\n')
        code, out, err = self.run_cli("--", "demo")
        (run_id,) = self.run_dirs()
        run_dir = self.cwd / ".sv0cov/runs" / run_id
        self.assertEqual(code, 0)
        self.assertIn("sv0cov coverage report", out)
        self.assertEqual(sorted(os.listdir(run_dir / "reports")), ["coverage.html", "coverage.json"])
        self.assertEqual(stat.S_IMODE((run_dir / "reports/coverage.html").stat().st_mode), 0o600)
        page = (run_dir / "reports/coverage.html").read_bytes()
        check_html(page)
        report = read_report((run_dir / "reports/coverage.json").read_bytes())
        self.assertIn(report["provenance"]["indexed_input_sha256"].encode(), page)

    def test_quiet_removes_the_terminal_report_and_no_diagnostic(self) -> None:
        code, out, err = self.run_cli("--quiet", "--threshold-line", "100", "--", "demo")
        self.assertEqual((code, out, [r["code"] for r in records(err)]), (1, "program output\n", ["COV4101"]))

    def test_standard_exports_join_the_bundle_with_native_json_and_manifests(self) -> None:
        (self.cwd / "sv0.toml").write_text(HEAD + 'reports = ["cobertura", "lcov"]\n')
        code, out, err = self.run_cli("--", "demo")
        (run_id,) = self.run_dirs()
        run_dir = self.cwd / ".sv0cov/runs" / run_id
        self.assertEqual(code, 0, err)
        self.assertEqual(sorted(os.listdir(run_dir / "reports")),
                         ["cobertura.manifest.json", "cobertura.xml", "coverage.json", "lcov.info", "lcov.manifest.json"])
        files = {n: (run_dir / "reports" / n).read_bytes() for n in os.listdir(run_dir / "reports")}
        indexed = (run_dir / "coverage.sv0covdata.json").read_bytes()
        for fmt, primary in (("lcov", "lcov.info"), ("cobertura", "cobertura.xml")):
            m = verify_export(files[f"{fmt}.manifest.json"], files[primary], files["coverage.json"], names=(primary, "coverage.json"),
                              indexed=indexed)
            self.assertEqual(m["format"], fmt)

        self.assertEqual(self.run_cli("--report", "term", "--report", "term", "--", "demo")[0], 2)
        self.assertEqual(self.run_cli("--format", "term", "--", "demo")[0], 2)  # --format belongs to report


class ProcessTest(Base):
    def test_real_descriptors_carry_the_childs_output(self) -> None:
        """With real streams the child writes straight to them, in order with sv0cov's own lines."""
        boot = ("import sys; sys.path.insert(0, sys.argv[1]); from sv0cov import cli, cmd_run; from pathlib import Path; "
                "cmd_run.toolchain_driver = lambda: Path(sys.argv[2]); sys.exit(cli.main(sys.argv[3:]))")
        p = subprocess.run([PY, "-c", boot, str(ROOT / "src"), str(self.driver), "run", "--", "demo", *HOSTILE], cwd=self.cwd,
                           env={**self.environ, "SV0COV_RUN_ID": RUN, "FAKE_EXIT": "5"}, capture_output=True, timeout=120)
        self.assertEqual(p.returncode, 4)
        self.assertTrue(p.stderr.startswith(b"COV2130 error: Test command failed\n"))
        lines = p.stdout.decode().splitlines()
        self.assertEqual(lines[1], "program output")
        self.assertRegex(lines[0], r"\Arun [0-9a-f]{32}: built demo; running the test command\Z")
        self.assertRegex(lines[2], r"the test command exited with status 5")
        self.assertEqual(lines[3], "sv0cov coverage report")
        self.assertEqual(self.recorded("run")["argv"][1:], HOSTILE)
        self.assertNotEqual(self.recorded("run")["env"]["SV0COV_RUN_ID"], RUN)


    def test_a_signal_sent_to_sv0cov_reaches_the_test_command(self) -> None:
        """SPEC 23.3: the command is ended, and sv0cov still reports what the run left."""
        boot = ("import sys; sys.path.insert(0, sys.argv[1]); from sv0cov import cli, cmd_run; from pathlib import Path; "
                "cmd_run.toolchain_driver = lambda: Path(sys.argv[2]); sys.exit(cli.main(sys.argv[3:]))")
        ready = self.top / "ready"
        sleeper = ("import pathlib, signal, time; signal.signal(signal.SIGINT, signal.SIG_DFL); "
                   f"pathlib.Path({str(ready)!r}).write_text('x'); time.sleep(60)")
        for number, name in ((signal.SIGTERM, "SIGTERM"), (signal.SIGINT, "SIGINT"), (signal.SIGHUP, "SIGHUP")):
            with self.subTest(signal=name):
                ready.unlink(missing_ok=True)
                p = subprocess.Popen([PY, "-c", boot, str(ROOT / "src"), str(self.driver), "run", "--diagnostic-format=json-lines", "--",
                                      PY, "-c", sleeper], cwd=self.cwd, env=self.environ, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                deadline = time.monotonic() + 60
                while not ready.exists() and time.monotonic() < deadline:
                    time.sleep(0.05)
                self.assertTrue(ready.exists())
                p.send_signal(number)  # to sv0cov only, not to the process group
                out, err = p.communicate(timeout=30)
                self.assertEqual(p.returncode, 128 + number)
                self.assertIn(f"the test command was ended by signal {int(number)}".encode(), out)
                self.assertIn(b"the evidence is incomplete (0 of 0 profiles accepted) and was not reported", out)
                self.assertEqual([r["code"] for r in records(err.decode())], ["COV3001", "COV3003"])


if __name__ == "__main__":
    unittest.main()
