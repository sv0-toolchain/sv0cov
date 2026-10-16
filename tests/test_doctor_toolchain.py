# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The toolchain doctor D009 to D018 (CV-242; SPEC 20.7; COV-CLI-011, AC-117).

sv0cov's own CI has no sv0 toolchain, so these tests build a throwaway root:
a Git repository with the exact ``.gitmodules`` entry, an ``sv0cov``
submodule commit carrying the registry, a sealed policy naming it, and a fake
``scripts/sv0`` that answers ``native-compile``, ``vm-native-compile`` and
``vm-run`` the way the real driver does: it publishes the real map of the
smoke fixture (``fixtures/doctor/smoke``) and programs that write raw
profiles with the oracle's counts. The fake reads a fault from its state
directory, so every probe can be made to fail on its own fault.

The real driver end to end is the root's ``./scripts/sv0 coverage doctor``
test (``scripts/verify_sv0cov_toolchain_doctor.py`` in sv0-toolchain).
"""

from __future__ import annotations

import io
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
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402

from sv0cov import capabilities, cli, probes, toolchain  # noqa: E402
from sv0cov.diagnostics import load_registry  # noqa: E402
from sv0cov.formats import doctor  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.compatibility import seal  # noqa: E402
from sv0cov.formats.version_manifest import build, current_host  # noqa: E402
from sv0cov.model import inventory as inv  # noqa: E402

SMOKE = ROOT / "tests" / "fixtures" / "doctor" / "smoke"
TOOL_VERSION = "0.4.0"
GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid",
           "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.invalid"}

FAKE_DRIVER = r'''#!@PYTHON@ -I
"""A stand-in for sv0-toolchain's scripts/sv0 (tests/test_doctor_toolchain.py)."""
import os, sys, time
from pathlib import Path
STATE = Path("@STATE@")
sys.path.insert(0, "@SRC@")
fault = (STATE / "fault").read_text() if (STATE / "fault").exists() else ""
args = sys.argv[1:]
PROGRAM = """#!@PYTHON@ -I
import os, sys
sys.path.insert(0, "@SRC@")
sys.argv[1:] = ["@BACKEND@"]
exec(open("@STATE@/profile.py").read())
"""

if fault == "slow":
    time.sleep(5)
if fault == "chatty":
    sys.stdout.write("x" * 4096)
if args[0] == "native-compile":
    mode, out = args[1], Path(args[3])
    if fault == "build-fails":
        sys.exit(1)
    WHICH = "map" if mode == "--coverage=map" else "native"
    data = Path("@MAP@").read_bytes()
    if fault == "map-" + WHICH:
        data = data.replace(b'"name":"sv0c"', b'"name":"sv0x"')
    Path(str(out) + ".sv0covmap.json").write_bytes(data)
    out.write_text(PROGRAM.replace("@BACKEND@", "native"))
    out.chmod(0o755)
elif args[0] == "vm-native-compile":
    out = Path(args[3])
    data = Path("@MAP@").read_bytes()
    if fault == "map-vm":
        data = data.replace(b'"name":"sv0c"', b'"name":"sv0x"')
    stem = out.with_suffix("")
    Path(str(stem) + ".sv0covmap.json").write_bytes(data)
    Path(str(stem) + ".sv0covbind.json").write_text("{}")
    out.write_text("bytecode")
elif args[0] == "vm-run":
    sys.argv[1:] = ["vm-v1"]
    exec(open("@STATE@/profile.py").read())
else:
    sys.exit(2)
'''

PROFILE = r'''
import json, os, sys
from pathlib import Path
from sv0cov.formats.rawprofile import RawProfile, encode
backend = sys.argv[1]
state = Path("@STATE@")
fault = (state / "fault").read_text() if (state / "fault").exists() else ""
if fault == "exit-" + backend:
    sys.exit(3)
if fault == "no-profile-" + backend:
    sys.exit(0)
m = json.loads(Path("@MAP@").read_bytes())
oracle = json.loads(Path("@ORACLE@").read_bytes())
counts = {c["point_id"]: c["count"] for c in oracle["counts"]}
if fault == "counts-" + backend:
    counts = {k: v + 1 for k, v in counts.items()}
pairs = tuple(sorted((p["counter_index"], counts[p["point_id"]]) for p in m["points"] if counts.get(p["point_id"])))
run_id = bytes.fromhex(os.environ["SV0COV_RUN_ID"])
profile_id = os.urandom(16)
context = "other" if fault == "context-" + backend else None  # same counts, another semantic projection
data = encode(RawProfile(bytes.fromhex(m["map_id"]), run_id, profile_id, backend, context, pairs), m["program_counter_count"])
Path(os.environ["SV0COV_PROFILE_DIR"], f"{run_id.hex()}-{profile_id.hex()}.sv0profraw").write_bytes(data)
'''


def git(cwd: Path, *args: str) -> str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")} | GIT_ENV
    return subprocess.run(["git", "-c", "commit.gpgsign=false", "-c", "init.defaultBranch=main", "-c", "protocol.file.allow=always", *args],
                          cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def policy_for(revision: str, **changes) -> dict:
    reg = load_registry()
    obj = {
        "allowed_diagnostic_registries": [{"revision": reg.revision, "sha256": reg.sha256}],
        "allowed_implementation_languages": ["python"],
        "default_implementation_language": "python",
        "expected_artifact_versions": {f: ["1.0"] for f in sorted(inv.ARTIFACT_FAMILIES)},
        "expected_revision": revision,
        "expected_tool": {"name": "sv0cov", "version": TOOL_VERSION},
        "required_backends": [],
        "required_bytecode_profiles": [],
        "required_commands": ["version"],
        "required_features": [],
        "required_hosts": list(inv.HOSTS),
        "schema": "sv0cov.compatibility",
        "submodule_path": "sv0cov",
        "version": "1.0",
        "version_manifest_version": "1.0",
    }
    obj.update(changes)
    return obj


class FakeRoot:
    """A throwaway sv0-toolchain root whose submodule is this sv0cov's registry at one commit."""

    def __init__(self, base: Path) -> None:
        self.base, self.root, self.state = base, base / "root", base / "state"
        self.state.mkdir()
        upstream = base / "upstream"
        (upstream / "registries").mkdir(parents=True)
        shutil.copyfile(ROOT / "registries" / "diagnostics-v1.json", upstream / "registries" / "diagnostics-v1.json")
        git(upstream, "init", "-q")
        git(upstream, "add", "-A")
        git(upstream, "commit", "-q", "-m", "sv0cov")
        self.revision = git(upstream, "rev-parse", "HEAD")
        self.root.mkdir()
        git(self.root, "init", "-q")
        git(self.root, "submodule", "add", "-q", str(upstream), "sv0cov")
        (self.root / ".gitmodules").write_text('[submodule "sv0cov"]\n\tpath = sv0cov\n\turl = git@github.com:sv0-toolchain/sv0cov.git\n')
        (self.root / "compatibility").mkdir()
        self.write_policy()
        subs = {"@PYTHON@": sys.executable, "@STATE@": str(self.state), "@SRC@": str(ROOT / "src"),
                "@MAP@": str(SMOKE / "doctor-r1-smoke.sv0covmap.json"), "@ORACLE@": str(ROOT / toolchain.ORACLE)}
        driver = FAKE_DRIVER
        profile = PROFILE
        for k, v in subs.items():
            driver, profile = driver.replace(k, v), profile.replace(k, v)
        (self.state / "profile.py").write_text(profile)
        (self.root / "scripts").mkdir()
        (self.root / "scripts" / "sv0").write_text(driver)
        (self.root / "scripts" / "sv0").chmod(0o755)
        git(self.root, "add", "-A")
        git(self.root, "commit", "-q", "-m", "root")

    def write_policy(self, **changes) -> None:
        (self.root / "compatibility" / "sv0cov.json").write_bytes(seal(policy_for(self.revision, **changes)))

    def fault(self, name: str) -> None:
        (self.state / "fault").write_text(name)

    def manifest(self, **changes) -> bytes:
        reg = load_registry()
        args = dict(tool_version=TOOL_VERSION, revision=self.revision, runtime_version=capabilities.runtime_version(), host=current_host(),
                    registry_revision=reg.revision, registry_sha256=reg.sha256, advertised=capabilities.ADVERTISED)
        args.update(changes)
        return build(**args)


def outcome(data: bytes) -> dict[str, tuple]:
    return {p["id"]: (p["status"], p["diagnostic_code"]) for p in decode_canonical(data)["probes"]}


def facts(data: bytes, pid: str) -> dict:
    (p,) = [p for p in decode_canonical(data)["probes"] if p["id"] == pid]
    return {f["name"]: f["value"] for f in p["facts"]}


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.fake = FakeRoot(Path(os.path.realpath(tmp.name)))

    def doctor(self, **kw) -> bytes:
        kw.setdefault("manifest", self.fake.manifest())
        return probes.run(toolchain_root=self.fake.root, **kw)


class PassTest(Base):
    def test_every_probe_passes_and_the_bytes_are_stable(self) -> None:
        first = self.doctor()
        obj = doctor.validate(first)
        self.assertEqual((obj["mode"], obj["status"]), ("toolchain", "pass"))
        self.assertEqual(obj["summary"], {"failed": 0, "not_applicable": 1, "passed": 17, "skipped": 0, "total": 18})
        self.assertEqual(outcome(first)["D016"], ("not_applicable", None))  # SPEC 15.6: vm-v2 is not advertised
        self.assertEqual(self.doctor(), first)  # fresh profile IDs, the same aggregate (D-12)
        self.assertEqual(obj["toolchain"], {"root_revision": git(self.fake.root, "rev-parse", "HEAD"), "root_worktree": "clean",
                                            "submodule_revision": self.fake.revision, "submodule_worktree": "clean"})
        self.assertEqual(obj["compatibility_policy"], decode_canonical((self.fake.root / "compatibility" / "sv0cov.json").read_bytes()))

    def test_facts(self) -> None:
        data = self.doctor()
        m = decode_canonical((SMOKE / "doctor-r1-smoke.sv0covmap.json").read_bytes())
        self.assertEqual(facts(data, "D010"), {"expected_revision": self.fake.revision})
        self.assertEqual(facts(data, "D013"), {"fixture_id": "doctor-r1-smoke", "map_id": m["map_id"]})
        projection = {facts(data, p)["semantic_projection_sha256"] for p in ("D014", "D015", "D017")}
        self.assertEqual(len(projection), 1)
        self.assertEqual(set(facts(data, "D018")), {"fixture_id", "native_report_sha256"})

    def test_no_path_reaches_the_result(self) -> None:
        data = self.doctor()
        for path in (self.fake.base, self.fake.root, Path(tempfile.gettempdir()).resolve()):
            self.assertNotIn(str(path).encode(), data)

    def test_the_private_directory_is_removed(self) -> None:
        made = []
        real = tempfile.mkdtemp

        def spy(**kw):
            made.append(real(**kw))
            return made[-1]

        with mock.patch.object(probes.tempfile, "mkdtemp", spy):
            self.doctor()
        self.assertEqual(len(made), 1)
        self.assertFalse(Path(made[0]).exists())


class FaultTest(Base):
    """Each fault fails its own probe, skips what depends on it, and leaves the rest alone."""

    def assert_fails(self, pid: str, code: str, skipped: tuple[str, ...], data: bytes | None = None) -> None:
        data = data if data is not None else self.doctor()
        got = outcome(data)
        self.assertEqual(got[pid], ("fail", code), got)
        for other, (status, _) in got.items():
            if other == pid:
                continue
            want = "skipped" if other in skipped else "not_applicable" if other == "D016" else "pass"
            self.assertEqual(status, want, f"{other} after a {pid} fault: {got}")
        obj = doctor.validate(data)
        self.assertEqual([(d["code"], d["facts"]) for d in obj["diagnostics"]], [(code, [{"name": "probe_id", "value": pid}])])

    ALL_AFTER_D010 = ("D011", "D012", "D013", "D014", "D015", "D017", "D018")
    SMOKE_AFTER_D013 = ("D014", "D015", "D017", "D018")

    def test_policy(self) -> None:
        policy = self.fake.root / "compatibility" / "sv0cov.json"
        good = policy.read_bytes()
        for label, change in (("missing", lambda: policy.unlink()), ("noncanonical", lambda: policy.write_bytes(good + b"\n")),
                              ("oversized", lambda: policy.write_bytes(good[:-1] + b" " * 70000 + b"\n"))):
            with self.subTest(policy=label):
                change()
                data = self.doctor()
                self.assert_fails("D009", "COV5002", ("D010", *self.ALL_AFTER_D010), data)
                self.assertIsNone(decode_canonical(data)["compatibility_policy"])
                policy.write_bytes(good)
        moved = self.fake.base / "policy.json"
        policy.rename(moved)
        policy.symlink_to(moved)
        self.assert_fails("D009", "COV6002", ("D010", *self.ALL_AFTER_D010))

    def test_submodule(self) -> None:
        sub = self.fake.root / "sv0cov"
        cases = {
            "another revision": lambda: self.fake.write_policy(expected_revision="0" * 39 + "1"),
            "dirty": lambda: (sub / "scratch").write_text("x"),
            "an extra .gitmodules key": lambda: (self.fake.root / ".gitmodules").write_text(
                '[submodule "sv0cov"]\n\tpath = sv0cov\n\turl = git@github.com:sv0-toolchain/sv0cov.git\n\tbranch = main\n'),
            "an https URL": lambda: (self.fake.root / ".gitmodules").write_text(
                '[submodule "sv0cov"]\n\tpath = sv0cov\n\turl = https://github.com/sv0-toolchain/sv0cov.git\n'),
            "HEAD elsewhere": lambda: git(sub, "commit", "-q", "--allow-empty", "-m", "x"),
        }
        for label, change in cases.items():
            with self.subTest(fault=label):
                with tempfile.TemporaryDirectory() as tmp:
                    self.fake = FakeRoot(Path(os.path.realpath(tmp)))
                    sub = self.fake.root / "sv0cov"
                    change()
                    self.assert_fails("D010", "COV5002", self.ALL_AFTER_D010)

    def test_registry(self) -> None:
        self.fake.write_policy(allowed_diagnostic_registries=[{"revision": 1, "sha256": "a" * 64}])
        self.assert_fails("D011", "COV5002", ("D012", "D013", *self.SMOKE_AFTER_D013))

    def test_compatibility(self) -> None:
        for label, manifest in (("product version", self.fake.manifest(tool_version="0.4.1")),
                                ("revision", self.fake.manifest(revision="1" * 40))):
            with self.subTest(manifest=label):
                self.assert_fails("D012", "COV5002", ("D013", *self.SMOKE_AFTER_D013), self.doctor(manifest=manifest))

    def test_smoke(self) -> None:
        native_only = ("D017", "D018")
        cases = {
            "build-fails": ("D013", "COV1020", self.SMOKE_AFTER_D013),
            "map-map": ("D013", "COV1010", self.SMOKE_AFTER_D013),
            "map-native": ("D014", "COV1013", native_only),
            "exit-native": ("D014", "COV2130", native_only),
            "no-profile-native": ("D014", "COV2010", native_only),
            "counts-native": ("D014", "COV5004", native_only),
            "map-vm": ("D015", "COV1013", native_only),
            "exit-vm-v1": ("D015", "COV2130", native_only),
            "counts-vm-v1": ("D015", "COV5004", native_only),
            "context-vm-v1": ("D017", "COV5004", ("D018",)),
        }
        for fault, (pid, code, skipped) in cases.items():
            with self.subTest(fault=fault):
                self.fake.fault(fault)
                self.assert_fails(pid, code, skipped)
        (self.fake.state / "fault").unlink()

    def test_fixture_and_oracle(self) -> None:
        real = toolchain.load_oracle

        def other(data):
            return {**real(data), "source_sha256": "0" * 64}

        with mock.patch.object(toolchain, "load_oracle", other):
            self.assert_fails("D013", "COV1004", self.SMOKE_AFTER_D013)

    def test_bounds(self) -> None:
        for fault, patch in (("slow", {"CHILD_SECONDS": 1}), ("chatty", {"CHILD_OUTPUT": 1024})):
            with self.subTest(fault=fault), mock.patch.multiple(toolchain, **patch):
                self.fake.fault(fault)
                self.assert_fails("D013", "COV6001", self.SMOKE_AFTER_D013)
        with mock.patch.object(toolchain, "TOTAL_SECONDS", 0):
            (self.fake.state / "fault").unlink()
            self.assert_fails("D013", "COV6001", self.SMOKE_AFTER_D013)

    def test_a_failing_fixed_policy(self) -> None:
        with mock.patch.object(toolchain, "CHECK_TOML", toolchain.CHECK_TOML + b"contract = 100\n"):
            data = self.doctor()
        self.assertEqual(outcome(data)["D018"][0], "fail")
        self.assertNotEqual(outcome(data)["D018"][1], "COV5004")

    def test_the_driver_is_never_searched_for(self) -> None:
        (self.fake.root / "scripts" / "sv0").unlink()
        decoy = self.fake.base / "bin"
        decoy.mkdir()
        (decoy / "sv0").write_text("#!/bin/sh\nexit 0\n")
        (decoy / "sv0").chmod(0o755)
        with mock.patch.dict(os.environ, {"PATH": f"{decoy}{os.pathsep}{os.environ['PATH']}"}):
            got = outcome(self.doctor())
        self.assertEqual(got["D013"], ("fail", "COV5002"))


class ProjectionTest(unittest.TestCase):
    """D-12: the D018 digest ignores what is particular to one execution, and nothing else."""

    def report(self) -> dict:
        return {"inputs": [{"artifact_sha256": "a" * 64, "backend": "vm-v1", "name": "x-1", "profile_id": "1" * 32, "run_id": "2" * 32, "status": "accepted"},
                           {"artifact_sha256": "b" * 64, "backend": "native", "name": "x-2", "profile_id": "3" * 32, "run_id": "2" * 32, "status": "accepted"}],
                "provenance": {"indexed_input_sha256": "c" * 64, "run_ids": ["2" * 32], "backends": ["native", "vm-v1"]},
                "summary": {"line": 1}}

    def test_projection(self) -> None:
        r = self.report()
        other = self.report()
        other["inputs"].reverse()
        for record in other["inputs"]:
            record.update(artifact_sha256="d" * 64, name="y", profile_id="4" * 32, run_id="5" * 32)
        other["provenance"].update(indexed_input_sha256="e" * 64, run_ids=["5" * 32])
        project = lambda x: encode(toolchain.report_projection(x))  # noqa: E731
        self.assertEqual(project(r), project(other))
        for change in (lambda x: x["summary"].update(line=2), lambda x: x["provenance"].update(backends=["native"]),
                       lambda x: x["inputs"][0].update(status="rejected")):
            changed = self.report()
            change(changed)
            self.assertNotEqual(project(changed), project(r))


class CommandTest(Base):
    def run_cli(self, *args: str, cwd: Path | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(capabilities, "revision", lambda: self.fake.revision), \
                mock.patch.object(capabilities, "tool_version", lambda: TOOL_VERSION):
            code = cli.main(["doctor", *args], stdout=out, stderr=err, cwd=cwd or self.fake.base)
        return code, out.getvalue(), err.getvalue()

    def test_json_human_and_exit(self) -> None:
        code, out, err = self.run_cli("--toolchain-root", "root", "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(doctor.validate(out.encode())["status"], "pass")
        code, out, _ = self.run_cli("--toolchain-root", str(self.fake.root))
        self.assertEqual(code, 0)
        self.assertIn("D018  pass     Merge, native-report, and check smoke", out)
        self.assertIn("doctor (toolchain): pass: 17 passed, 0 failed, 0 skipped, 1 not applicable", out)

    def test_a_failure_is_exit_7_and_stderr_agrees(self) -> None:
        self.fake.fault("counts-native")
        code, out, err = self.run_cli("--toolchain-root", "root", "--json", "--diagnostic-format=json-lines")
        obj = doctor.validate(out.encode())
        self.assertEqual((code, obj["status"]), (7, "fail"))
        self.assertEqual(records(err), obj["diagnostics"])

    def test_the_root_must_be_a_real_directory(self) -> None:
        (self.fake.base / "link").symlink_to(self.fake.root)
        (self.fake.base / "file").write_text("x")
        for given in ("missing", "link", "file"):
            with self.subTest(root=given):
                code, out, err = self.run_cli("--toolchain-root", given, "--diagnostic-format=json-lines")
                self.assertEqual((code, out, [r["code"] for r in records(err)]), (2, "", ["COV0001"]))
                self.assertNotIn(str(self.fake.base), err)


if __name__ == "__main__":
    unittest.main()
