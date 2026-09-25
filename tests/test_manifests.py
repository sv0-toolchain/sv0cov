# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Compatibility policy (CV-020), version manifest (CV-021), doctor (CV-022).

SPEC 20.6, 20.6.1, 20.7; COV-FMT-043, COV-FMT-044, COV-CLI-010,
AC-114, AC-115, AC-117.
"""

from __future__ import annotations

import copy
import getpass
import io
import os
import socket
import sys
import unittest
from contextlib import redirect_stderr
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import cli  # noqa: E402
from sv0cov.diagnostics import load_registry  # noqa: E402
from sv0cov.formats import doctor  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.compatibility import PolicyError, policy_digest, seal, validate_policy  # noqa: E402
from sv0cov.formats.version_manifest import Advertised, ManifestError, build, manifest_digest, validate_manifest  # noqa: E402
from sv0cov.model import inventory as inv  # noqa: E402

REG = load_registry()
FIXTURES = ROOT / "tests" / "fixtures" / "doctor"


def policy(version: str = "0.1.0", **changes) -> dict:
    pre = inv.is_pre_r1(version)
    obj = {
        "allowed_diagnostic_registries": [{"revision": REG.revision, "sha256": REG.sha256}],
        "allowed_implementation_languages": ["python"],
        "default_implementation_language": "python",
        "expected_artifact_versions": {f: ["1.0"] for f in sorted(inv.ARTIFACT_FAMILIES)},
        "expected_revision": "a" * 40,
        "expected_tool": {"name": "sv0cov", "version": version},
        "required_backends": ["native", "vm-v1"] if pre else list(inv.BACKENDS),
        "required_bytecode_profiles": ["sv0vm-v1-coverage"] if pre else list(inv.BYTECODE_PROFILES),
        "required_commands": ["version"] if pre else list(inv.COMMANDS),
        "required_features": [] if pre else list(inv.FEATURES),
        "required_hosts": list(inv.HOSTS),
        "schema": "sv0cov.compatibility",
        "submodule_path": "sv0cov",
        "version": "1.0",
        "version_manifest_version": "1.0",
    }
    obj.update(changes)
    return obj


def synthetic_manifest(version: str = "0.1.0", advertised: Advertised | None = None) -> bytes:
    pre = inv.is_pre_r1(version)
    adv = advertised or (
        Advertised(("version",), ("native", "vm-v1"), ("sv0vm-v1-coverage",), ())
        if pre
        else Advertised(inv.COMMANDS, inv.BACKENDS, inv.BYTECODE_PROFILES, inv.FEATURES)
    )
    return build(
        tool_version=version,
        revision="a" * 40,
        runtime_version="3.13.0",
        host={"architecture": "arm64", "operating_system": "macos"},
        registry_revision=REG.revision,
        registry_sha256=REG.sha256,
        advertised=adv,
    )


class PolicyTest(unittest.TestCase):
    def test_pre_r1_and_r1_policies(self) -> None:
        for version in ("0.1.0", "1.0.0", "2.3.4"):
            with self.subTest(version=version):
                obj = validate_policy(seal(policy(version)))
                self.assertEqual(obj["compatibility_sha256"], policy_digest(obj))

    def test_rejections(self) -> None:
        r1 = "1.0.0"
        cases = {
            "unsorted hosts": policy(required_hosts=list(reversed(inv.HOSTS))),
            "duplicate command": policy(required_commands=["version", "version"]),
            "R1 missing command": policy(r1, required_commands=["version"]),
            "R1 missing feature": policy(r1, required_features=list(inv.FEATURES[:-1])),
            "pre-R1 with vm-v2": policy(required_backends=["native", "vm-v1", "vm-v2"]),
            "pre-R1 with v2 profile": policy(required_bytecode_profiles=list(inv.BYTECODE_PROFILES)),
            "unknown feature": policy(required_features=["telemetry"]),
            "two registries": policy(allowed_diagnostic_registries=[{"revision": 1, "sha256": REG.sha256}, {"revision": 2, "sha256": "b" * 64}]),
            "sv0 language": policy(allowed_implementation_languages=["python", "sv0"]),
            "sv0 default": policy(default_implementation_language="sv0"),
            "short revision": policy(expected_revision="a" * 39),
            "uppercase revision": policy(expected_revision="A" * 40),
            "leading-zero version": policy(expected_tool={"name": "sv0cov", "version": "01.0.0"}),
            "two-part version": policy(expected_tool={"name": "sv0cov", "version": "1.0"}),
            "prerelease version": policy(expected_tool={"name": "sv0cov", "version": "1.0.0-rc1"}),
            "v prefix": policy(expected_tool={"name": "sv0cov", "version": "v1.0.0"}),
            "artifact version 1.1": policy(expected_artifact_versions={f: ["1.0", "1.1"] for f in sorted(inv.ARTIFACT_FAMILIES)}),
            "missing family": policy(expected_artifact_versions={f: ["1.0"] for f in sorted(inv.ARTIFACT_FAMILIES)[1:]}),
            "wrong submodule path": policy(submodule_path="tools/sv0cov"),
            "extra key": policy(branch="main"),
        }
        for name, obj in cases.items():
            with self.subTest(case=name):
                body = {k: v for k, v in obj.items()}
                body["compatibility_sha256"] = policy_digest(body)
                with self.assertRaises(PolicyError):
                    validate_policy(encode(body))

    def test_self_digest_mismatch(self) -> None:
        obj = decode_canonical(seal(policy()))
        obj["expected_revision"] = "b" * 40
        with self.assertRaises(PolicyError):
            validate_policy(encode(obj))

    def test_size_bound_checked_first(self) -> None:
        with self.assertRaises(PolicyError):
            validate_policy(b" " * 65537)


class ManifestTest(unittest.TestCase):
    def test_synthetic_manifests(self) -> None:
        for version in ("0.1.0", "1.0.0"):
            with self.subTest(version=version):
                obj = validate_manifest(synthetic_manifest(version))
                self.assertEqual(obj["manifest_sha256"], manifest_digest(obj))

    def test_running_manifest(self) -> None:
        data = cli.version_manifest()
        obj = validate_manifest(data)
        self.assertEqual(obj["commands"], ["version"])
        self.assertEqual(obj["implementation"]["language"], "python")
        self.assertEqual(data, cli.version_manifest())  # byte-identical on repeat

    def test_running_manifest_is_private(self) -> None:
        text = cli.version_manifest().decode()
        for secret in {str(Path.home()), str(ROOT), getpass.getuser(), socket.gethostname(), os.getcwd()}:
            if len(secret) > 3:
                self.assertNotIn(secret, text)

    def test_rejections(self) -> None:
        base = decode_canonical(synthetic_manifest("0.1.0"))
        cases = {
            "pre-R1 advertises vm-v2": dict(backends=["native", "vm-v1", "vm-v2"]),
            "unsorted commands": dict(commands=["version", "check"]),
            "unknown command": dict(commands=["coverage"]),
            "fewer hosts": dict(supported_hosts=list(inv.HOSTS[:3])),
            "python 3.12 runtime": dict(implementation={"language": "python", "revision": "a" * 40, "runtime": {"name": "cpython", "version": "3.12.1"}}),
            "non-canonical runtime": dict(implementation={"language": "python", "revision": "a" * 40, "runtime": {"name": "cpython", "version": "3.13.01"}}),
            "pypy": dict(implementation={"language": "python", "revision": "a" * 40, "runtime": {"name": "sv0", "version": "3.13.0"}}),
            "python versions trimmed": dict(supported_python_versions=["3.14"]),
            "windows host": dict(host={"architecture": "x86_64", "operating_system": "windows"}),
            "extra key": dict(hostname="box"),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                obj = copy.deepcopy(base)
                obj.update(change)
                obj["manifest_sha256"] = manifest_digest(obj)
                with self.assertRaises(ManifestError):
                    validate_manifest(encode(obj))
        r1 = decode_canonical(synthetic_manifest("1.0.0"))
        r1["features"] = r1["features"][:-1]
        r1["manifest_sha256"] = manifest_digest(r1)
        with self.assertRaises(ManifestError):
            validate_manifest(encode(r1))
        tampered = copy.deepcopy(base)
        tampered["commands"] = []
        with self.assertRaises(ManifestError):
            validate_manifest(encode(tampered))


class VersionCommandTest(unittest.TestCase):
    def run_cli(self, *args: str) -> tuple[int, bytes, str]:
        out, err = io.BytesIO(), io.StringIO()

        class Stdout:
            buffer = out

            def write(self, s: str) -> None:
                out.write(s.encode())

            def flush(self) -> None:
                pass

        old = sys.stdout
        sys.stdout = Stdout()
        try:
            with redirect_stderr(err):
                code = cli.main(list(args))
        finally:
            sys.stdout = old
        return code, out.getvalue(), err.getvalue()

    def test_json_stdout_is_exactly_the_manifest(self) -> None:
        code, out, err = self.run_cli("version", "--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, cli.version_manifest())

    def test_human_form(self) -> None:
        code, out, _ = self.run_cli("version")
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith(b"sv0cov 0.0.0 (python, cpython "))

    def test_usage_errors(self) -> None:
        for args in (("version", "--jsn"), ("version", "--json", "--json"), ("run",), ()):
            with self.subTest(args=args):
                code, out, err = self.run_cli(*args)
                self.assertEqual((code, out), (2, b""))
                self.assertIn("COV0001", err)


def standalone_pass() -> bytes:
    manifest = decode_canonical(synthetic_manifest())
    passing = {
        "D001": ("pass", {"manifest_sha256": manifest["manifest_sha256"]}),
        "D002": ("pass", {"registry_revision": REG.revision, "registry_sha256": REG.sha256}),
        "D003": ("pass", {"validated_schema_count": 8}),
        "D004": ("pass", {"validated_member_count": 40}),
        "D005": ("pass", {"host": "macos-arm64"}),
        "D006": ("pass", {"language": "python", "runtime_name": "cpython", "runtime_version": "3.13.0"}),
        "D007": ("pass", {}),
        "D008": ("pass", {"validated_member_count": 2}),
    }
    return doctor.build(mode="standalone", manifest=manifest, policy=None, toolchain=None, results=passing, registry=REG)


def toolchain_d012_fail() -> bytes:
    manifest = decode_canonical(synthetic_manifest())
    pol = decode_canonical(seal(policy()))
    results = {
        "D001": ("pass", {"manifest_sha256": manifest["manifest_sha256"]}),
        "D002": ("pass", {"registry_revision": REG.revision, "registry_sha256": REG.sha256}),
        "D003": ("pass", {"validated_schema_count": 8}),
        "D004": ("pass", {"validated_member_count": 40}),
        "D005": ("pass", {"host": "macos-arm64"}),
        "D006": ("pass", {"language": "python", "runtime_name": "cpython", "runtime_version": "3.13.0"}),
        "D007": ("pass", {}),
        "D008": ("pass", {"validated_member_count": 2}),
        "D009": ("pass", {"compatibility_sha256": pol["compatibility_sha256"]}),
        "D010": ("pass", {"expected_revision": pol["expected_revision"]}),
        "D011": ("pass", {"registry_revision": REG.revision, "registry_sha256": REG.sha256}),
        "D012": ("fail", "COV5002"),
    }
    toolchain = {"root_revision": "c" * 40, "root_worktree": "clean", "submodule_revision": "a" * 40, "submodule_worktree": "clean"}
    return doctor.build(mode="toolchain", manifest=manifest, policy=pol, toolchain=toolchain, results=results, registry=REG)


GOLDENS = {"standalone-pass.json": standalone_pass, "toolchain-d012-fail.json": toolchain_d012_fail}


class DoctorTest(unittest.TestCase):
    def test_goldens_are_frozen(self) -> None:
        for name, fn in GOLDENS.items():
            with self.subTest(golden=name):
                self.assertEqual(fn(), (FIXTURES / name).read_bytes())

    def test_standalone_derivation(self) -> None:
        obj = doctor.validate(standalone_pass(), registry=REG)
        self.assertEqual(obj["status"], "pass")
        self.assertEqual(obj["summary"], {"failed": 0, "not_applicable": 10, "passed": 8, "skipped": 0, "total": 18})
        self.assertTrue(all(p["status"] == "not_applicable" for p in obj["probes"][8:]))

    def test_dependency_skips(self) -> None:
        obj = doctor.validate(toolchain_d012_fail(), registry=REG)
        status = {p["id"]: (p["status"], p["blocked_by"]) for p in obj["probes"]}
        # Worked by hand from the SPEC 20.7 prerequisite table.
        self.assertEqual(status["D012"], ("fail", []))
        self.assertEqual(status["D013"], ("skipped", ["D012"]))
        self.assertEqual(status["D014"], ("skipped", ["D013"]))
        self.assertEqual(status["D015"], ("skipped", ["D013"]))
        self.assertEqual(status["D016"], ("not_applicable", []))  # vm-v2 not advertised (SPEC 15.6)
        self.assertEqual(status["D017"], ("skipped", ["D014", "D015"]))
        self.assertEqual(status["D018"], ("skipped", ["D014", "D015", "D017"]))
        self.assertEqual(obj["summary"], {"failed": 1, "not_applicable": 1, "passed": 11, "skipped": 5, "total": 18})
        self.assertEqual(obj["status"], "fail")
        self.assertEqual([(d["code"], d["facts"]) for d in obj["diagnostics"]], [("COV5002", [{"name": "probe_id", "value": "D012"}])])

    def test_builder_refuses_inconsistent_results(self) -> None:
        manifest = decode_canonical(synthetic_manifest())
        with self.assertRaises(doctor.DoctorError):
            doctor.build(mode="standalone", manifest=manifest, policy=None, toolchain=None, results={}, registry=REG)

    def test_rejections(self) -> None:
        base = decode_canonical(toolchain_d012_fail())

        def reseal(obj):
            obj["doctor_sha256"] = doctor.doctor_digest(obj)
            return encode(obj)

        def probe(obj, pid):
            return next(p for p in obj["probes"] if p["id"] == pid)

        mutations = {
            "skipped probe claims pass": lambda o: probe(o, "D013").update(status="pass", blocked_by=[]),
            "wrong blocked_by": lambda o: probe(o, "D017").__setitem__("blocked_by", ["D014"]),
            "facts on skipped": lambda o: probe(o, "D013").__setitem__("facts", [{"name": "fixture_id", "value": "doctor-r1-smoke"}]),
            "fail without code": lambda o: probe(o, "D012").__setitem__("diagnostic_code", None),
            "pass with extra fact": lambda o: probe(o, "D007").__setitem__("facts", [{"name": "x", "value": 1}]),
            "wrong pass fact value": lambda o: probe(o, "D005").__setitem__("facts", [{"name": "host", "value": "linux-x86_64"}]),
            "missing diagnostic": lambda o: o.__setitem__("diagnostics", []),
            "summary mismatch": lambda o: o["summary"].__setitem__("passed", 12),
            "status mismatch": lambda o: o.__setitem__("status", "pass"),
            "D009 not applicable": lambda o: probe(o, "D009").update(status="not_applicable", facts=[]),
            "reordered probes": lambda o: o["probes"].reverse(),
            "toolchain null in toolchain mode": lambda o: o.__setitem__("toolchain", None),
            "revision without worktree": lambda o: o["toolchain"].__setitem__("root_worktree", "unavailable"),
            "unknown code": lambda o: probe(o, "D012").__setitem__("diagnostic_code", "COV9999"),
        }
        for name, fn in mutations.items():
            with self.subTest(case=name):
                obj = copy.deepcopy(base)
                fn(obj)
                with self.assertRaises(doctor.DoctorError):
                    doctor.validate(reseal(obj), registry=REG)
        stale = copy.deepcopy(base)
        stale["mode"] = "toolchain"
        stale["summary"]["total"] = 18
        stale["doctor_sha256"] = "0" * 64
        with self.assertRaises(doctor.DoctorError):
            doctor.validate(encode(stale), registry=REG)

    def test_bootstrap_probes_must_pass(self) -> None:
        manifest = decode_canonical(synthetic_manifest())
        results = {"D001": ("fail", "COV8001"), "D002": ("pass", {"registry_revision": REG.revision, "registry_sha256": REG.sha256}), "D007": ("pass", {})}
        with self.assertRaises(doctor.DoctorError):
            doctor.build(mode="standalone", manifest=manifest, policy=None, toolchain=None, results=results, registry=REG)


if __name__ == "__main__":
    if "--write-goldens" in sys.argv:
        FIXTURES.mkdir(parents=True, exist_ok=True)
        for name, fn in GOLDENS.items():
            (FIXTURES / name).write_bytes(fn())
    else:
        unittest.main()
