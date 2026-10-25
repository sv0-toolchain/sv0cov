# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Privacy and determinism of every output (CV-424; SPEC 21.6, 23;
COV-MAP-011, COV-SEC-005, COV-REP-006).

One workflow drives every command that writes something public: ``run``
(maps, profiles, the indexed profile, the report bundle with both standard
exports), ``merge``, ``report`` in every format and every destination
(file, bundle, stdout and its support directory), ``check`` on an indexed
profile and on a native report, ``baseline``, ``version --json`` and
``doctor --json``. It runs in a fresh isolated interpreter under an
environment full of marked host, user and process values, from a project
whose absolute path is marked too.

- **Privacy scan.** No artifact, stdout or stderr holds the project's
  absolute path (as given or resolved), the home directory, the temporary
  directory, a marked user, host, login or shell name, the interpreter's or
  driver's path, or any absolute path under a host root.
- **Repeat renders.** The same workflow in a second project at another
  absolute path, under other host values, gives byte-identical artifacts,
  stdout, stderr and exit statuses: absolute parent directories and host
  facts never reach an output (SPEC 21.6 gate 2). The two workflows run in
  separate processes with different user, host, time zone and locale, so
  this is also the check that no process fact (a PID, a clock, a locale)
  reaches an output; a raw decimal PID is too short to scan for reliably.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import fixture_inputs, raw  # noqa: E402
from test_report import fixture_sources  # noqa: E402
from test_security import FAKE_DRIVER  # noqa: E402

from sv0cov.formats.rawprofile import decode  # noqa: E402

RUN = "0123456789abcdef0123456789abcdef"
INDEXED = ".sv0cov/coverage.sv0covdata.json"
RATCHET = '[tool.sv0cov]\nschema = "1.0"\n[tool.sv0cov.ratchet]\nbaseline = "cov/baseline.json"\nmetrics = ["line"]\n'

# Every public-output command, in order; each entry is (name, argv).
STEPS = [
    ("run", ["run", "--run-id", RUN, "--report", "term", "--report", "html", "--report", "json", "--report", "lcov",
             "--report", "cobertura", "--", "f0"]),
    ("merge", ["merge", "in"]),
    ("bundle", ["report", "--format", "term", "--format", "html", "--format", "json", "--format", "lcov", "--format", "cobertura",
                "--output", "out/bundle", INDEXED]),
    ("lcov-file", ["report", "--format", "lcov", "--output", "out/x.info", INDEXED]),
    ("cobertura-file", ["report", "--format", "cobertura", "--output", "out/x.xml", INDEXED]),
    ("html-file", ["report", "--format", "html", "--output", "out/x.html", INDEXED]),
    ("term-stdout", ["report", "--format", "term", "--output", "-", INDEXED]),
    ("json-stdout", ["report", "--format", "json", "--output", "-", INDEXED]),
    ("lcov-stdout", ["report", "--format", "lcov", "--output", "-", INDEXED]),
    ("cobertura-stdout", ["report", "--format", "cobertura", "--output", "-", INDEXED]),
    ("check", ["check", "--threshold-line", "100", INDEXED]),
    ("check-native", ["check", "--threshold-line", "100", "out/bundle/coverage.json"]),
    ("check-missing", ["check", "absent.json"]),
    ("version", ["version", "--json"]),
    ("doctor", ["doctor", "--json"]),
]

SCRIPT = r'''
import io, json, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from sv0cov import cli, cmd_run
cmd_run.toolchain_driver = lambda: Path(sys.argv[3])
cwd, out = Path(sys.argv[2]), {}
for name, argv in json.loads(sys.argv[4]):
    o, e = io.StringIO(), io.StringIO()
    out[name] = [cli.main([argv[0], "--diagnostic-format=json-lines", *argv[1:]], stdout=o, stderr=e, cwd=cwd), o.getvalue(), e.getvalue()]
    if name == "merge":  # the baseline is written by its own command, with a ratchet policy in force
        (cwd / "sv0.toml").write_text(sys.argv[5])
        o, e = io.StringIO(), io.StringIO()
        out["baseline"] = [cli.main(["baseline", "--diagnostic-format=json-lines", ".sv0cov/coverage.sv0covdata.json"], stdout=o, stderr=e,
                                    cwd=cwd), o.getvalue(), e.getvalue()]
        (cwd / "sv0.toml").unlink()
print(json.dumps({"pid": __import__("os").getpid(), "results": out}))
'''


class Workflow:
    """One project at a marked absolute path and the outputs of every step."""

    def __init__(self, top: Path, tag: str) -> None:
        self.tag = tag
        self.home = top / f"home-{tag}"
        self.tmp = top / f"tmp-{tag}"
        self.cwd = top / f"projects-{tag}" / "f0"
        for d in (self.home, self.tmp, self.cwd / "in", self.cwd / "out"):
            d.mkdir(parents=True)
        self.map_bytes, m, counts = fixture_inputs("f0")
        ix = json.loads(self.map_bytes)
        for path, data in fixture_sources("f0", {"semantic": {"sources": ix["sources"]}}).items():
            (self.cwd / path).parent.mkdir(parents=True, exist_ok=True)
            (self.cwd / path).write_bytes(data)
        (self.cwd / "in" / "f0.sv0covmap.json").write_bytes(self.map_bytes)
        data = raw(m, counts, 1)
        p = decode(data)
        (self.cwd / "in" / f"{p.run_id.hex()}-{p.profile_id.hex()}.sv0profraw").write_bytes(data)
        self.driver = top / f"driver-{tag}" / "sv0"
        self.driver.parent.mkdir()
        self.driver.write_text(FAKE_DRIVER.format(py=sys.executable, map=str(self.cwd / "in" / "f0.sv0covmap.json"), src=str(ROOT / "src"),
                                                  tests=str(ROOT / "tests")))
        self.driver.chmod(0o755)

    def env(self) -> dict[str, str]:
        t = self.tag
        return {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "TMPDIR": str(self.tmp), "USER": f"privuser{t}",
                "LOGNAME": f"privlogin{t}", "USERNAME": f"privuser{t}", "HOSTNAME": f"privhost{t}", "HOST": f"privhost{t}",
                "PWD": str(self.cwd), "OLDPWD": str(self.home), "SHELL": f"/bin/privshell{t}", "TZ": "UTC" if t == "a" else "Asia/Kathmandu",
                "LANG": "C.UTF-8" if t == "a" else "de_DE.UTF-8"}

    def run(self) -> tuple[dict, int]:
        p = subprocess.run([sys.executable, "-I", "-B", "-c", SCRIPT, str(ROOT / "src"), str(self.cwd), str(self.driver), json.dumps(STEPS),
                            RATCHET], capture_output=True, text=True, timeout=600, env=self.env(), cwd=str(self.cwd))
        if p.returncode != 0:
            raise AssertionError(p.stderr[-3000:])
        out = json.loads(p.stdout.strip().splitlines()[-1])
        return out["results"], out["pid"]

    def files(self) -> dict[str, bytes]:
        """Every file sv0cov wrote, by project-relative path."""
        out = {}
        for base in (".sv0cov", "out", "cov"):
            for p in sorted((self.cwd / base).rglob("*")) if (self.cwd / base).exists() else ():
                rel = str(p.relative_to(self.cwd))
                if p.is_file() and not rel.startswith(f".sv0cov/runs/{RUN}/bin/"):  # the built program is the project's, not sv0cov's
                    out[rel] = p.read_bytes()
        return out


class PrivacyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        tmp = tempfile.mkdtemp(prefix="privtop-")
        cls.addClassCleanup(shutil.rmtree, tmp)
        top = Path(tmp)
        cls.a, cls.b = Workflow(top, "a"), Workflow(top / "elsewhere" / "deeper", "b")
        cls.results_a, cls.pid_a = cls.a.run()
        cls.results_b, cls.pid_b = cls.b.run()
        cls.files_a, cls.files_b = cls.a.files(), cls.b.files()

    def test_every_step_ran(self) -> None:
        codes = {k: v[0] for k, v in self.results_a.items()}
        self.assertEqual(codes, {"run": 0, "merge": 0, "baseline": 0, "bundle": 0, "lcov-file": 0, "cobertura-file": 0, "html-file": 0,
                                 "term-stdout": 0, "json-stdout": 0, "lcov-stdout": 0, "cobertura-stdout": 0, "check": 1, "check-native": 1,
                                 "check-missing": 5, "version": 0, "doctor": 0})
        names = set(self.files_a)
        for expected in (f".sv0cov/runs/{RUN}/coverage.sv0covdata.json", f".sv0cov/runs/{RUN}/reports/lcov.manifest.json",
                         f".sv0cov/runs/{RUN}/reports/cobertura.xml", ".sv0cov/coverage.sv0covdata.json", "out/bundle/coverage.html",
                         "out/x.info.manifest.json", "out/x.xml.sv0cov.json", ".sv0cov/reports/lcov-stdout-support/lcov.manifest.json",
                         ".sv0cov/reports/cobertura-stdout-support/coverage.json", "cov/baseline.json"):
            self.assertIn(expected, names)
        self.assertTrue(any(n.endswith(".sv0covmap.json") for n in names) and any(n.endswith(".sv0profraw") for n in names))

    def markers(self, w: Workflow) -> list[str]:
        t = w.tag
        found = [str(w.cwd), str(w.cwd.resolve()), str(w.cwd.parent), str(w.home), str(w.tmp), str(w.driver), sys.executable,
                 f"privuser{t}", f"privlogin{t}", f"privhost{t}", f"privshell{t}", "privtop-"]
        return found

    def test_no_output_holds_a_host_path_or_host_user_or_process_fact(self) -> None:
        """COV-MAP-011, COV-SEC-005."""
        for w, results, files, pid in ((self.a, self.results_a, self.files_a, self.pid_a), (self.b, self.results_b, self.files_b, self.pid_b)):
            outputs = {f"file {k}": v for k, v in files.items()}
            for name, (_, out, err) in results.items():
                outputs[f"{name} stdout"], outputs[f"{name} stderr"] = out.encode(), err.encode()
            for where, data in outputs.items():
                for marker in self.markers(w):
                    with self.subTest(where=where, marker=marker):
                        self.assertNotIn(marker.encode(), data)
                with self.subTest(where=where, check="absolute path"):
                    text = data.decode("utf-8", "replace")
                    self.assertIsNone(re.search(r"(?<![\w.])/(?:Users|home|private|tmp|var|root)/", text), where)

    def test_a_second_project_elsewhere_gives_the_same_bytes(self) -> None:
        """COV-REP-006 and SPEC 21.6 gate 2: same input, other parent directory and host facts."""
        self.assertEqual(sorted(self.files_a), sorted(self.files_b))
        for name in self.files_a:
            with self.subTest(file=name):
                self.assertEqual(self.files_a[name], self.files_b[name])
        for step in self.results_a:
            with self.subTest(step=step):
                self.assertEqual(self.results_a[step], self.results_b[step])


if __name__ == "__main__":
    unittest.main()
