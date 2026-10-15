# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The R0 security suite (CV-237; SPEC 23, R0-G5; COV-SEC-001, COV-SEC-002,
COV-SEC-003, COV-SEC-006, AC-098).

Four properties, each across every command rather than one at a time:

- **No network.** Every command runs end to end in a fresh isolated
  interpreter whose audit hook ends the process on any socket, DNS, URL or
  mail event; production code imports no networking module. Where the CI
  removes the network namespace itself, a test proves the host really has
  no network.
- **Containment.** No command reads or writes through a symlink that leaves
  the project, whatever the path names; logical paths in artifacts cannot
  climb out.
- **Injection.** Hostile text (terminal controls, line breaks, bidirectional
  controls, quotes, markup) in a context value, a file name or a
  diagnostic fact reaches every output escaped, and canonical JSON gives it
  back unchanged.
- **Environment poisoning.** Every command gives byte-identical results and
  exit statuses under a hostile environment and a clean one.

Several earlier suites test one command each (``test_cmd_run``,
``test_cmd_clean``, ``test_publish``, ``test_terminal``); this one is the
cross-command gate.
"""

from __future__ import annotations

import ast
import errno
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_indexed_reader import fixture_inputs, raw  # noqa: E402
from test_report import fixture_sources  # noqa: E402

from sv0cov import cli  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.map import MapError, map_id, validate_map  # noqa: E402
from sv0cov.formats.rawprofile import decode  # noqa: E402
from sv0cov.model.indexed import read_indexed  # noqa: E402

RUN = "0123456789abcdef0123456789abcdef"
NETWORK_MODULES = {"socket", "_socket", "ssl", "_ssl", "http", "urllib.request", "ftplib", "smtplib", "imaplib", "poplib", "nntplib",
                   "telnetlib", "xmlrpc", "socketserver", "asyncio", "webbrowser"}
NETWORK_EVENTS = ("socket.__new__", "socket.connect", "socket.bind", "socket.getaddrinfo", "socket.gethostbyname", "socket.gethostbyaddr",
                  "socket.getnameinfo", "socket.sendto", "socket.sendmsg", "urllib.Request", "http.client.connect", "http.client.send",
                  "ftplib.connect", "smtplib.connect", "imaplib.open", "poplib.connect", "nntplib.connect", "webbrowser.open")
HOSTILE = "ctx\x1b[2J\x1b]0;title\x07\r\nnext\u202eevil\"quote'</script>]]>&amp;\\"

# Runs every command in one isolated interpreter (as the launcher does: -I -B) under an audit hook.
# argv: src, project dir, fake driver; prints a JSON summary on the real stdout's last line.
BOOT = r'''
import io, json, os, sys
NET = set(json.loads(sys.argv[4]))
seen_spawn = []
def hook(event, args):
    if event in NET:
        os.write(2, ("NETWORK " + event + "\n").encode())
        os._exit(99)
    if event == "subprocess.Popen":
        seen_spawn.append(os.path.basename(str(args[0])))
sys.addaudithook(hook)
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from sv0cov import cli, cmd_run
cmd_run.toolchain_driver = lambda: Path(sys.argv[3])
cwd = Path(sys.argv[2])
codes = {}
def run(name, *argv):
    out, err = io.StringIO(), io.StringIO()
    codes[name] = cli.main(list(argv), stdout=out, stderr=err, cwd=cwd)
run("merge", "merge", "in")
run("report", "report", "--format", "term", "--format", "json", ".sv0cov/coverage.sv0covdata.json")
run("report-stdout", "report", "--format", "json", "--output", "-", ".sv0cov/coverage.sv0covdata.json")
run("check", "check", "--threshold-line", "0", ".sv0cov/coverage.sv0covdata.json")
run("version", "version", "--json")
run("doctor", "doctor", "--json")
run("run", "run", "--run-id", "%s", "--", "f0")
run("clean", "clean")
loaded = sorted(m for m in sys.modules if m.split(".")[0] in {"socket", "_socket", "ssl", "_ssl", "http", "ftplib", "smtplib", "xmlrpc",
                                                               "asyncio", "socketserver", "webbrowser"} or m == "urllib.request")
print(json.dumps({"codes": codes, "loaded": loaded, "spawned": seen_spawn}))
''' % RUN

FAKE_DRIVER = r'''#!{py}
import os, sys
a = sys.argv[1:]
exe, cmap = a[a.index("-o") + 1], a[a.index("--coverage-map") + 1]
open(cmap, "wb").write(open({map!r}, "rb").read())
open(exe, "w").write("""#!{py}
import os, sys
sys.path[:0] = [{src!r}, {tests!r}]
from test_indexed_reader import fixture_inputs, raw
from sv0cov.formats.rawprofile import decode
_, m, counts = fixture_inputs("f0")
data = raw(m, counts, 1, run=os.environ["SV0COV_RUN_ID"])
open(os.path.join(os.environ["SV0COV_PROFILE_DIR"], os.environ["SV0COV_RUN_ID"] + "-" + decode(data).profile_id.hex() + ".sv0profraw"), "wb").write(data)
""")
os.chmod(exe, 0o755)
'''


class Project(unittest.TestCase):
    """A project holding the f0 fixture's source, its map and one profile."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.top = Path(tmp.name).resolve()
        self.cwd = self.top / "f0"
        self.cwd.mkdir()
        self.map_bytes, self.m, self.counts = fixture_inputs("f0")
        ix = json.loads(self.map_bytes)
        for path, data in fixture_sources("f0", {"semantic": {"sources": ix["sources"]}}).items():
            self.put(path, data)
        self.put("in/f0.sv0covmap.json", self.map_bytes)
        self.profile(1)

    def put(self, rel: str, data: bytes) -> Path:
        path = self.cwd / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def profile(self, n: int, **kw) -> bytes:
        data = raw(self.m, self.counts, n, **kw)
        p = decode(data)
        self.put(f"in/{p.run_id.hex()}-{p.profile_id.hex()}.sv0profraw", data)
        return data

    def cli(self, *argv: str, fmt: str = "json-lines") -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main([argv[0], f"--diagnostic-format={fmt}", *argv[1:]], stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def snapshot(self, base: Path) -> dict[str, object]:
        out: dict[str, object] = {}
        for here, dirs, files in os.walk(base, followlinks=False):
            for name in dirs + files:
                p = Path(here) / name
                out[str(p.relative_to(base))] = ("link", os.readlink(p)) if p.is_symlink() else "dir" if p.is_dir() else p.read_bytes()
        return out


class NoNetworkTest(Project):
    """COV-SEC-001."""

    def test_every_command_runs_without_a_network_event(self) -> None:
        driver = self.top / "sv0"
        driver.write_text(FAKE_DRIVER.format(py=sys.executable, map=str(self.cwd / "in" / "f0.sv0covmap.json"), src=str(ROOT / "src"),
                                             tests=str(ROOT / "tests")))
        driver.chmod(0o755)
        p = subprocess.run([sys.executable, "-I", "-B", "-c", BOOT, str(ROOT / "src"), str(self.cwd), str(driver), json.dumps(NETWORK_EVENTS)],
                           capture_output=True, text=True, timeout=300, env={"PATH": os.environ.get("PATH", ""), "HOME": str(self.top)})
        self.assertNotIn("NETWORK", p.stderr)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        summary = json.loads(p.stdout.strip().splitlines()[-1])
        self.assertEqual(summary["codes"], {"merge": 0, "report": 0, "report-stdout": 0, "check": 0, "version": 0, "doctor": 0, "run": 0,
                                            "clean": 0})
        self.assertEqual(summary["loaded"], [])  # not one networking module was even imported
        self.assertEqual(summary["spawned"], ["sv0", "f0"])  # only the driver and the test command were started

    def test_the_audit_hook_would_have_seen_a_network_call(self) -> None:
        probe = "import socket; socket.getaddrinfo('localhost', 80)"
        p = subprocess.run([sys.executable, "-I", "-c", BOOT.split("sys.path.insert")[0] + probe, "", "", "", json.dumps(NETWORK_EVENTS)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual((p.returncode, p.stderr.strip()), (99, "NETWORK socket.getaddrinfo"))

    def test_production_code_imports_no_networking_module(self) -> None:
        found = []
        for path in sorted((ROOT / "src" / "sv0cov").rglob("*.py")):
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ""] if isinstance(node, ast.ImportFrom) else []
                for name in names:
                    if name.split(".")[0] in {m.split(".")[0] for m in NETWORK_MODULES} - {"urllib"} or name == "urllib.request":
                        found.append(f"{path.relative_to(ROOT)}: {name}")
        self.assertEqual(found, [])

    @unittest.skipUnless(os.environ.get("SV0COV_REQUIRE_NETWORK_DENIAL") == "1", "set by the CI step that removes the network namespace")
    def test_the_host_really_has_no_network(self) -> None:
        """In CI this suite also runs in a network namespace with nothing in it."""
        for address in (("192.0.2.1", 9), ("1.1.1.1", 53)):
            with self.subTest(address=address), self.assertRaises(OSError) as ctx:
                socket.create_connection(address, timeout=2).close()
            self.assertIn(ctx.exception.errno, (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EACCES, errno.EPERM, None))


class ContainmentTest(Project):
    """COV-SEC-002: nothing is read or written through a symlink that leaves the project."""

    def evidence(self) -> None:
        self.assertEqual(self.cli("merge", "in")[0], 0)

    def test_a_source_that_resolves_outside_the_project_is_refused(self) -> None:
        self.evidence()
        secret = self.top / "outside" / "main.sv0"
        secret.parent.mkdir()
        secret.write_bytes((self.cwd / "main.sv0").read_bytes())  # even the right bytes: it is not the project's file
        (self.cwd / "main.sv0").unlink()
        os.symlink(secret, self.cwd / "main.sv0")
        for argv in (("check", ".sv0cov/coverage.sv0covdata.json"), ("report", "--format", "json", ".sv0cov/coverage.sv0covdata.json"),
                     ("report", "--format", "json", "--allow-source-mismatch", "--output", "-", ".sv0cov/coverage.sv0covdata.json")):
            with self.subTest(argv=argv):
                code, out, err = self.cli(*argv)
                (r,) = records(err)
                self.assertEqual((code, out, r["code"]), (5, "", "COV6002"))
                self.assertIn("resolves outside the project", r["facts"][0]["value"])
        os.unlink(self.cwd / "main.sv0")
        os.symlink(self.cwd / "main.sv0.real", self.cwd / "main.sv0")  # a loop-free link that stays inside is fine
        (self.cwd / "main.sv0.real").write_bytes(secret.read_bytes())
        self.assertEqual(self.cli("check", ".sv0cov/coverage.sv0covdata.json")[0], 0)
        os.unlink(self.cwd / "main.sv0")
        os.symlink("main.sv0", self.cwd / "main.sv0")  # a loop
        # A loop is not an escape; it cannot be read, so the source is unavailable.
        self.assertIn(records(self.cli("check", ".sv0cov/coverage.sv0covdata.json")[2])[0]["code"], ("COV1004", "COV6002"))

    def test_a_symlinked_directory_on_the_way_out_is_refused_too(self) -> None:
        self.evidence()
        m = json.loads(self.map_bytes)
        self.assertEqual([s["path"] for s in m["sources"]], ["main.sv0"])
        (self.top / "elsewhere").mkdir()
        os.rename(self.cwd / "main.sv0", self.top / "elsewhere" / "main.sv0")
        # The project root itself reached through a symlink is still the project.
        alias = self.top / "alias"
        os.symlink(self.cwd, alias)
        out, err = io.StringIO(), io.StringIO()
        os.symlink(self.top / "elsewhere" / "main.sv0", self.cwd / "main.sv0")
        self.assertEqual(cli.main(["check", ".sv0cov/coverage.sv0covdata.json"], stdout=out, stderr=err, cwd=alias), 5)
        self.assertIn("COV6002", err.getvalue())

    def test_managed_output_is_never_written_through_a_symlink(self) -> None:
        outside = self.top / "outside"
        outside.mkdir()
        os.symlink(outside, self.cwd / ".sv0cov")
        self.evidence() if False else None
        for argv, want in ((("merge", "in"), 5), (("report", "--format", "json", "evidence.json"), 6), (("clean",), 5)):
            with self.subTest(argv=argv):
                if argv[0] == "report":
                    self.put("evidence.json", encode(read_indexed(self.merged())))
                code, _, err = self.cli(*argv)
                self.assertEqual((code, [r["code"] for r in records(err)]), (want, ["COV6002"]))
                self.assertEqual(os.listdir(outside), [])

    def merged(self) -> bytes:
        from sv0cov.model.merge import Artifact, merge

        prof = next(p for p in (self.cwd / "in").iterdir() if p.suffix == ".sv0profraw")
        return merge([Artifact("f0.sv0covmap.json", self.map_bytes)], [Artifact(prof.name, prof.read_bytes())]).data

    def test_artifacts_cannot_name_a_path_outside_the_project(self) -> None:
        m = json.loads(self.map_bytes)
        for path in ("../main.sv0", "/etc/passwd", "a/../../b.sv0", "./main.sv0", "a//b.sv0", "a\\b.sv0", "C:/x.sv0", "a/\x00.sv0", ""):
            with self.subTest(path=path):
                bad = json.loads(json.dumps(m))
                bad["sources"][0]["path"] = path
                bad["map_id"] = map_id(bad)
                with self.assertRaises(MapError) as ctx:
                    validate_map(encode(bad))
                self.assertEqual(ctx.exception.code, "COV1010")

    def test_merge_does_not_follow_symlinks_found_in_a_directory(self) -> None:
        secret = self.top / "secret.sv0profraw"
        secret.write_bytes(self.profile(2))
        os.symlink(secret, self.cwd / "in" / ("f" * 32 + "-" + "e" * 32 + ".sv0profraw"))
        code, _, err = self.cli("merge", "in")
        self.assertEqual(code, 5)
        self.assertIn("COV6002", [r["code"] for r in records(err)])


class InjectionTest(Project):
    """COV-SEC-003: hostile text reaches every output escaped, and JSON gives it back unchanged."""

    def test_a_hostile_context_through_merge_report_and_check(self) -> None:
        for p in (self.cwd / "in").glob("*.sv0profraw"):
            p.unlink()
        self.profile(3, context=HOSTILE)
        self.assertEqual(self.cli("merge", "in")[0], 0)
        evidence = (self.cwd / ".sv0cov/coverage.sv0covdata.json").read_bytes()
        self.assertIn(HOSTILE, [c["value"] for c in read_indexed(evidence)["semantic"]["contexts"]])
        code, out, _ = self.cli("report", "--format", "term", "--format", "json", "--output", "both", ".sv0cov/coverage.sv0covdata.json")
        self.assertEqual(code, 0)
        native, text = (self.cwd / "both/coverage.json").read_bytes(), (self.cwd / "both/coverage.txt").read_bytes()
        # JSON: no raw control byte, and the exact string comes back.
        self.assertFalse([b for b in native if b < 0x20 and b != 0x0A])
        self.assertEqual(encode(decode_canonical(native)), native)
        self.assertIn(HOSTILE, [c["value"] for c in decode_canonical(native)["contexts"]])
        # Terminal: no control, no reordering character, no extra line.
        for data in (text, self.cli("report", "--format", "term", "--output", "-", "--color", "always", ".sv0cov/coverage.sv0covdata.json")[1]
                     .encode()):
            stripped = data.replace(b"\x1b[0m", b"").replace(b"\x1b[1m", b"").replace(b"\x1b[32m", b"").replace(b"\x1b[33m", b"")
            self.assertFalse([c for c in stripped.decode() if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F or c in "\u202e"])
        self.assertIn(r'"ctx\x1b[2J\x1b]0;title\x07\x0d\x0anext\u202eevil\"quote' + "'</script>]]>&amp;" + "\\\\" + '"', text.decode())
        self.assertEqual(self.cli("check", ".sv0cov/coverage.sv0covdata.json")[0], 0)

    def test_a_hostile_file_name_in_a_diagnostic(self) -> None:
        name = "x\x1b[31mred\u202e\nline.sv0profraw"
        bad = self.put(f"in/{name}", b"not a profile")
        self.assertTrue(bad.exists())
        code, _, err = self.cli("merge", "in", fmt="human")
        self.assertEqual(code, 5)
        self.assertNotIn("\x1b[31m", err)
        self.assertNotIn("\u202e", err)
        self.assertTrue(all(not line.startswith("line.sv0profraw") for line in err.splitlines()))
        code, _, err = self.cli("merge", "in")
        recs = records(err)  # each record is one canonical line
        self.assertEqual(len(recs), len(err.splitlines()))


class EnvironmentTest(Project):
    """AC-098, COV-SEC-006: a hostile environment changes no result."""

    POISON = {"SV0COV_RUN_ID": "f" * 32, "SV0COV_PROFILE_DIR": "/nonexistent", "SV0COV_REQUIRED": "0", "SV0COV_CONTEXT": "smuggled",
              "SV0COV_THRESHOLD_LINE": "100", "SV0COV_OUTPUT_DIR": "/tmp/elsewhere", "SV0COV_REPORTS": "html", "SV0COV_SATURATION": "allow-ordinary",
              "SV0COV_": "", "sv0cov_lower": "x", "LANG": "tr_TR.UTF-8", "LC_ALL": "C", "TZ": "Pacific/Kiritimati", "NO_COLOR": "1",
              "FORCE_COLOR": "3", "CLICOLOR_FORCE": "1", "TERM": "xterm-256color", "COLUMNS": "7", "PYTHONPATH": "/nonexistent",
              "PYTHONIOENCODING": "latin-1", "SOURCE_DATE_EPOCH": "1", "GIT_DIR": "/nonexistent", "CC": "false", "SV0_CC": "false"}

    def run_all(self, env: dict[str, str]) -> dict[str, object]:
        """Every read-only and publishing command, in a fresh isolated interpreter, from a fresh copy of the project."""
        import shutil

        work = self.top / f"work-{len(env)}"
        shutil.copytree(self.cwd, work / "f0", symlinks=True)
        script = r'''
import io, json, sys
sys.path.insert(0, sys.argv[1])
from pathlib import Path
from sv0cov import cli
cwd, out = Path(sys.argv[2]), {}
for name, argv in json.loads(sys.argv[3]):
    o, e = io.StringIO(), io.StringIO()
    out[name] = [cli.main(argv, stdout=o, stderr=e, cwd=cwd), o.getvalue(), e.getvalue()]
print(json.dumps(out))
'''
        steps = [("merge", ["merge", "in"]), ("merge-stdout", ["merge", "in", "--output", "-"]),
                 ("report", ["report", "--format", "term", "--format", "json", ".sv0cov/coverage.sv0covdata.json"]),
                 ("term", ["report", "--format", "term", "--output", "-", ".sv0cov/coverage.sv0covdata.json"]),
                 ("check", ["check", ".sv0cov/coverage.sv0covdata.json"]), ("check-fail", ["check", "--threshold-line", "100", ".sv0cov/coverage.sv0covdata.json"]),
                 ("version", ["version", "--json"]), ("doctor", ["doctor", "--json"]), ("bad", ["merge", "--diagnostic-format", "json-lines", "nothing"])]
        p = subprocess.run([sys.executable, "-I", "-B", "-c", script, str(ROOT / "src"), str(work / "f0"), json.dumps(steps)],
                           capture_output=True, text=True, timeout=300, env=env)
        self.assertEqual(p.returncode, 0, p.stderr[-2000:])
        results = json.loads(p.stdout)
        files = {k: v for k, v in self.snapshot(work / "f0").items() if k.startswith(".sv0cov")}
        return {"results": results, "files": files}

    def test_every_command_ignores_a_hostile_environment(self) -> None:
        clean = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.top)}
        poisoned = {**clean, **self.POISON, "HOME": str(self.top / "nohome"), "TMPDIR": str(self.top)}
        a, b = self.run_all(clean), self.run_all(poisoned)
        self.assertEqual(a, b)
        codes = {k: v[0] for k, v in a["results"].items()}
        self.assertEqual(codes, {"merge": 0, "merge-stdout": 0, "report": 0, "term": 0, "check": 0, "check-fail": 1, "version": 0, "doctor": 0,
                                 "bad": 5})
        self.assertNotIn("\x1b", a["results"]["term"][1])  # NO_COLOR or FORCE_COLOR: color is only --color
        self.assertNotIn("smuggled", repr(a))


if __name__ == "__main__":
    unittest.main()
