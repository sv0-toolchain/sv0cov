# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Repository-local launcher: controlled-PATH corpus (CV-031; SPEC 20.6.4, AC-120).

Each case runs ``scripts/sv0cov`` with a PATH made only of temporary
directories, so no host interpreter outside the case can be selected. The
real interpreter is the one running this test; fakes are small shell scripts.
Every bootstrap failure must emit exactly one diagnostic whose bytes equal
the Python renderer's, in both formats, with nothing on stdout.
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
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.diagnostics import Diagnostic, render_human, render_json_line  # noqa: E402

LAUNCHER = ROOT / "scripts" / "sv0cov"
REAL = os.path.realpath(sys.executable)
MINOR = sys.version_info.minor
NAME = f"python3.{MINOR}"
OTHER = "python3.13" if MINOR == 14 else "python3.14"
HOST_OS = "darwin" if sys.platform == "darwin" else "linux"
FOREIGN_OS = "linux" if HOST_OS == "darwin" else "darwin"
ARCH = os.uname().machine


def expected(code: str, candidate: str, reason: str, fmt: str) -> bytes:
    obj = Diagnostic(code, "invocation", facts=(("candidate", candidate), ("reason", reason))).to_json()
    return render_json_line(obj) if fmt == "json-lines" else render_human(obj).encode()


class LauncherTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(os.path.realpath(self._tmp.name))

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def dir(self, name: str) -> Path:
        d = self.tmp / name
        d.mkdir(exist_ok=True)
        return d

    def link(self, d: Path, name: str, target: str) -> Path:
        p = d / name
        p.symlink_to(target)
        return p

    def script(self, d: Path, name: str, body: str) -> Path:
        p = d / name
        p.write_text("#!/bin/sh\n" + body)
        p.chmod(0o755)
        return p

    def fake(self, d: Path, name: str, fields: str) -> Path:
        """A fake interpreter printing a probe line; ``{hex}`` is its own physical path."""
        p = d / name
        hexpath = str(p).encode().hex()
        return self.script(d, name, f"printf '%s\\n' \"{fields.format(hex=hexpath)}\"\n")

    def run_launcher(self, path: str, *args: str, env: dict | None = None, cwd: Path | None = None) -> subprocess.CompletedProcess:
        e = {"PATH": path, "HOME": str(self.tmp)}
        e.update(env or {})
        return subprocess.run([str(LAUNCHER), *args], env=e, capture_output=True, cwd=cwd or self.tmp, timeout=30)

    def assert_bootstrap(self, path: str, code: str, candidate: str, reason: str) -> None:
        for fmt, args in (("human", ["version"]), ("json-lines", ["--diagnostic-format", "json-lines", "version"])):
            r = self.run_launcher(path, *args)
            self.assertEqual(r.stdout, b"", fmt)
            self.assertEqual(r.stderr, expected(code, candidate, reason, fmt), fmt)
            self.assertEqual(r.returncode, 8 if code == "COV8001" else 7, fmt)

    # --- selection -------------------------------------------------------

    def test_selects_the_real_interpreter(self) -> None:
        d = self.dir("a")
        self.link(d, NAME, REAL)
        r = self.run_launcher(str(d), "version", "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        manifest = json.loads(r.stdout)
        runtime = manifest["implementation"]["runtime"]
        self.assertEqual(runtime["version"].split(".")[:2], ["3", str(MINOR)])
        self.assertEqual(r.stderr, b"")

    def test_link_chain_and_duplicate_entries(self) -> None:
        a, b = self.dir("a"), self.dir("b")
        self.link(b, "hop", REAL)
        self.link(a, NAME, "../b/hop")
        r = self.run_launcher(f"{a}:{self.tmp / 'missing'}:{a}:{b}", "version")
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_version_priority_is_absolute(self) -> None:
        a, b = self.dir("a"), self.dir("b")
        if MINOR == 14:  # an earlier (misnamed) python3.13 is never considered
            self.link(a, "python3.13", REAL)
            self.link(b, "python3.14", REAL)
            self.assertEqual(self.run_launcher(f"{a}:{b}", "version").returncode, 0)
        else:  # a misnamed python3.14 later in PATH still wins, and fails
            self.link(a, "python3.13", REAL)
            self.link(b, "python3.14", REAL)
            self.assert_bootstrap(f"{a}:{b}", "COV0016", "python3.14", "minor_mismatch")

    def test_misnamed_interpreter(self) -> None:
        d = self.dir("a")
        self.link(d, OTHER, REAL)
        self.assert_bootstrap(str(d), "COV0016", OTHER, "minor_mismatch")

    def test_no_candidate(self) -> None:
        d = self.dir("a")
        self.link(d, "python3", REAL)
        self.link(d, "python", REAL)
        self.link(d, f"python3.{MINOR}.0", REAL)
        self.assert_bootstrap(str(d), "COV0016", "none", "no_candidate")

    # --- unsafe PATH and targets ------------------------------------------

    def test_relative_and_empty_entries(self) -> None:
        d = self.dir("a")
        self.link(d, NAME, REAL)
        self.assert_bootstrap(f"{d}:relative", "COV6002", "none", "relative_path_entry")
        self.assert_bootstrap(f".:{d}", "COV6002", "none", "relative_path_entry")
        self.assert_bootstrap(f"{d}::{d}", "COV6002", "none", "empty_path_entry")
        self.assert_bootstrap(f"{d}:", "COV6002", "none", "empty_path_entry")
        self.assert_bootstrap("", "COV6002", "none", "empty_path_entry")

    def test_broken_link_does_not_fall_through(self) -> None:
        a, b = self.dir("a"), self.dir("b")
        self.link(a, NAME, str(self.tmp / "nowhere"))
        self.link(b, NAME, REAL)
        self.assert_bootstrap(f"{a}:{b}", "COV6002", NAME, "broken_link")

    def test_link_cycle(self) -> None:
        d = self.dir("a")
        self.link(d, "x", "y")
        self.link(d, "y", "x")
        self.link(d, NAME, "x")
        self.assert_bootstrap(str(d), "COV6002", NAME, "link_chain_too_long")

    def test_nonregular_and_nonexecutable(self) -> None:
        a, b = self.dir("a"), self.dir("b")
        (a / NAME).mkdir()
        self.assert_bootstrap(str(a), "COV6002", NAME, "not_regular")
        (b / NAME).write_bytes(REAL.encode())
        (b / NAME).chmod(0o644)
        self.assert_bootstrap(str(b), "COV6002", NAME, "not_executable")

    def test_shim_is_rejected(self) -> None:
        d = self.dir("a")
        self.script(d, NAME, f'exec "{REAL}" "$@"\n')
        self.assert_bootstrap(str(d), "COV6002", NAME, "executable_mismatch")

    # --- probe results ------------------------------------------------------

    def test_fake_probe_results(self) -> None:
        cases = [
            ("sv0cov-probe-1 pypy 3 {m} 0 64 {os} {arch} {hex}", "COV0016", "not_cpython"),
            ("sv0cov-probe-1 cpython 4 {m} 0 64 {os} {arch} {hex}", "COV0016", "major_mismatch"),
            ("sv0cov-probe-1 cpython 3 {m} 0 32 {os} {arch} {hex}", "COV0016", "not_64bit"),
            ("sv0cov-probe-1 cpython 3 {m} 0 64 {fos} {arch} {hex}", "COV5001", "host_mismatch"),
            ("sv0cov-probe-1 cpython 3 {m} 0 64 {os} sparc {hex}", "COV5001", "host_mismatch"),
            ("sv0cov-probe-1 cpython 3 {m} 0 64 {os} {arch} 00", "COV6002", "executable_mismatch"),
            ("sv0cov-probe-1 cpython 3 {m}", "COV8001", "probe_output_malformed"),
            ("sv0cov-probe-1 cpython 3 {m} 00 64 {os} {arch} {hex}", "COV8001", "probe_output_malformed"),
            ("sv0cov-probe-1 cpython 3 {m} 0 64 {os} {arch} {hex} extra", "COV8001", "probe_output_malformed"),
            ("something else", "COV0016", "probe_failed"),
        ]
        for i, (line, code, reason) in enumerate(cases):
            with self.subTest(reason=reason, i=i):
                d = self.dir(f"f{i}")
                fields = line.format(m=MINOR, os=HOST_OS, fos=FOREIGN_OS, arch=ARCH, hex="{hex}")
                self.fake(d, NAME, fields)
                self.assert_bootstrap(str(d), code, NAME, reason)

    def test_probe_failure_exit(self) -> None:
        d = self.dir("a")
        self.script(d, NAME, "exit 3\n")
        self.assert_bootstrap(str(d), "COV0016", NAME, "probe_failed")

    def test_probe_output_limit(self) -> None:
        d = self.dir("a")
        self.script(d, NAME, "i=0; while [ $i -lt 100 ]; do printf '%080d\\n' 0; i=$((i+1)); done\n")
        self.assert_bootstrap(str(d), "COV6001", NAME, "probe_output_limit")

    def test_probe_timeout(self) -> None:
        d = self.dir("a")
        self.script(d, NAME, "exec /bin/sleep 30\n")
        start = time.monotonic()
        r = self.run_launcher(str(d), "version")
        self.assertLess(time.monotonic() - start, 15)
        self.assertEqual(r.stderr, expected("COV6001", NAME, "probe_timeout", "human"))
        self.assertEqual(r.returncode, 7)

    # --- isolation ----------------------------------------------------------

    def test_ambient_python_configuration_is_ignored(self) -> None:
        d = self.dir("a")
        self.link(d, NAME, REAL)
        evil = self.dir("evil")
        pkg = evil / "sv0cov"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("raise SystemExit('shadowed')\n")
        (pkg / "cli.py").write_text("raise SystemExit('shadowed')\n")
        env = {"PYTHONPATH": str(evil), "PYTHONSTARTUP": str(pkg / "cli.py"), "PYTHONHOME": str(evil), "PYTHONSAFEPATH": "0"}
        r = self.run_launcher(str(d), "version", env=env, cwd=evil)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith(b"sv0cov "))

    def test_argv_after_double_dash_is_not_a_format_request(self) -> None:
        d = self.dir("a")
        self.fake(d, NAME, "something else")
        r = self.run_launcher(str(d), "run", "--", "--diagnostic-format=json-lines")
        self.assertEqual(r.stderr, expected("COV0016", NAME, "probe_failed", "human"))

    # --- the files themselves ------------------------------------------------

    def test_launchers_are_generated_and_identical(self) -> None:
        r = subprocess.run([sys.executable, str(ROOT / "tools" / "launchergen.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(LAUNCHER.read_bytes(), (ROOT / "scripts" / "sv0cov-python").read_bytes())

    @unittest.skipUnless((ROOT / ".git").exists(), "not a git checkout")
    def test_tracked_mode_100755(self) -> None:
        out = subprocess.run(["git", "ls-files", "-s", "scripts"], cwd=ROOT, capture_output=True, text=True, check=True).stdout
        modes = {line.split("\t")[1]: line.split()[0] for line in out.splitlines()}
        self.assertEqual(modes, {"scripts/sv0cov": "100755", "scripts/sv0cov-python": "100755"})


if __name__ == "__main__":
    unittest.main()
