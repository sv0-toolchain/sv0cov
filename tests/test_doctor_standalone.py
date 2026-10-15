# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The standalone doctor (CV-235; SPEC 20.7; COV-CLI-011).

The real probes reproduce the frozen standalone golden byte for byte when
they observe what the golden records; on this host they pass and give the
same bytes every time; every probe fails on the fault it is for and on no
other; and the command's three outputs (JSON, human, stderr) agree.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_manifests import FIXTURES, standalone_pass, synthetic_manifest  # noqa: E402

from sv0cov import capabilities, cli, probes  # noqa: E402
from sv0cov.diagnostics import load_registry  # noqa: E402
from sv0cov.formats import doctor  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical  # noqa: E402

GOLDEN_SEEN = probes.Observed(host={"architecture": "arm64", "operating_system": "macos"}, language="python", runtime_name="cpython",
                              runtime_version="3.13.0")


def status(data: bytes) -> dict[str, tuple]:
    return {p["id"]: (p["status"], p["diagnostic_code"], tuple(p["blocked_by"])) for p in decode_canonical(data)["probes"]}


def installed_copy(base: Path) -> probes.Layout:
    """The package laid out as a wheel installs it: resources beneath the package."""
    site = base / "site"
    shutil.copytree(ROOT / "src" / "sv0cov", site / "sv0cov", ignore=shutil.ignore_patterns("__pycache__"))
    for logical in probes.RESOURCES:
        target = site / "sv0cov" / "_resources" / logical
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / logical, target)
    return probes.Layout(site / "sv0cov", site / "sv0cov" / "_resources")


class GoldenTest(unittest.TestCase):
    def test_the_standalone_golden_is_reproduced_by_the_real_probes(self) -> None:
        """CV-235's acceptance: the probes, observing what the golden records, give its exact bytes."""
        data = probes.run_standalone(manifest=synthetic_manifest(), observed=GOLDEN_SEEN)
        self.assertEqual(data, (FIXTURES / "standalone-pass.json").read_bytes())
        self.assertEqual(data, standalone_pass())

    def test_this_host_passes_and_the_bytes_are_stable(self) -> None:
        first, second = probes.run_standalone(), probes.run_standalone()
        self.assertEqual(first, second)
        obj = doctor.validate(first)
        self.assertEqual((obj["status"], obj["mode"], obj["summary"]),
                         ("pass", "standalone", {"failed": 0, "not_applicable": 10, "passed": 8, "skipped": 0, "total": 18}))
        facts = {p["id"]: {f["name"]: f["value"] for f in p["facts"]} for p in obj["probes"]}
        man = obj["version_manifest"]
        self.assertEqual(facts["D001"], {"manifest_sha256": man["manifest_sha256"]})
        self.assertEqual(facts["D003"], {"validated_schema_count": 13})
        self.assertEqual(facts["D004"], {"validated_member_count": len(probes.MODULES) + len(probes.RESOURCES)})
        self.assertEqual(facts["D005"], {"host": f"{man['host']['operating_system']}-{man['host']['architecture']}"})
        self.assertEqual(facts["D006"]["runtime_version"], man["implementation"]["runtime"]["version"])
        self.assertEqual(facts["D008"], {"validated_member_count": 2})
        text = first.decode()
        for private in (str(ROOT), os.environ.get("HOME", "/nonexistent"), tempfile.gettempdir()):
            self.assertNotIn(private, text)
        self.assertEqual(man["commands"], list(capabilities.ADVERTISED.commands))


class InventoryTest(unittest.TestCase):
    """The fixed logical members are the real ones: a new module or schema must be added here."""

    def test_modules_are_exactly_the_import_package(self) -> None:
        actual = sorted((str(p.relative_to(ROOT / "src")) for p in (ROOT / "src" / "sv0cov").rglob("*.py") if "__pycache__" not in p.parts),
                        key=str.encode)
        self.assertEqual(list(probes.MODULES), actual)

    def test_schemas_and_runtime_are_exactly_the_canonical_ones(self) -> None:
        self.assertEqual(list(probes.SCHEMAS), sorted(p.name for p in (ROOT / "schemas").glob("*.schema.json")))
        for logical, digest in probes.RUNTIME_SHA256.items():
            self.assertEqual(hashlib.sha256((ROOT / logical).read_bytes()).hexdigest(), digest, logical)
        self.assertEqual(sorted(probes.RUNTIME_SHA256), sorted(f"runtime/c/{p.name}" for p in (ROOT / "runtime" / "c").glob("sv0cov_rt.*")))

    def test_every_resource_is_mapped_into_the_wheel(self) -> None:
        import tomllib
        mapping = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
        for logical in probes.RESOURCES:
            top = logical.split("/")[0]
            self.assertTrue(mapping.get(top) == f"sv0cov/_resources/{top}" or mapping.get(logical) == f"sv0cov/_resources/{logical}", logical)

    def test_an_installed_layout_gives_the_same_counts(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            layout = installed_copy(Path(tmp))
            self.assertEqual(probes.d003_schemas(layout), {"validated_schema_count": 13})
            self.assertEqual(probes.d004_layout(layout), {"validated_member_count": len(probes.MODULES) + len(probes.RESOURCES)})
            self.assertEqual(probes.d008_runtime(layout), {"validated_member_count": 2})


class FaultTest(unittest.TestCase):
    """Each probe fails on its own fault, its dependents are skipped, and nothing else changes."""

    PASSING = {f"D00{n}": ("pass", None, ()) for n in range(1, 9)}

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.base = Path(tmp.name)
        self.layout = installed_copy(self.base)

    def run_with(self, *, observed=GOLDEN_SEEN, layout=None, origin=True) -> dict:
        layout = layout or self.layout
        package = layout.package if origin else self.base / "elsewhere"
        with mock.patch.object(probes.sv0cov, "__file__", str(package / "__init__.py")):
            data = probes.run_standalone(manifest=synthetic_manifest(), observed=observed, layout=layout)
        obj = doctor.validate(data)
        self.assertEqual([r["code"] for r in obj["diagnostics"]], sorted(p["diagnostic_code"] for p in obj["probes"] if p["status"] == "fail"))
        return {k: v for k, v in status(data).items() if k <= "D008"}

    def expect(self, got: dict, **changes: tuple) -> None:
        self.assertEqual(got, {**self.PASSING, **changes})

    def test_the_copy_passes(self) -> None:
        self.expect(self.run_with())

    def test_schema_faults(self) -> None:
        schema = self.layout.resource("schemas/sv0cov.report-1.0.schema.json")
        good = schema.read_bytes()
        cases = {
            "one changed byte": good.replace(b'"maxLength":4096', b'"maxLength":4097', 1),
            "another draft": good.replace(b"draft/2020-12", b"draft/2019-09", 1),
            "duplicate key": good[:-2] + b',"$ref":"#"}\n',
            "not JSON": b"{",
            "not an object": b"[]",
        }
        for label, data in cases.items():
            with self.subTest(fault=label):
                schema.write_bytes(data)
                self.expect(self.run_with(), D003=("fail", "COV5004", ()))
        schema.write_bytes(good)
        self.expect(self.run_with())
        # Bytes the generated validator agrees with must still be a draft 2020-12 object without duplicate keys.
        validator = self.layout.module("sv0cov/_generated/validators/sv0cov_report_1_0.py")
        header = validator.read_text()
        for label, data in (("another draft", good.replace(b"draft/2020-12", b"draft/2019-09", 1)),
                            ("duplicate key", good[:-2] + b',"$ref":"#"}\n'), ("not an object", b"[]\n")):
            with self.subTest(consistent_fault=label):
                schema.write_bytes(data)
                validator.write_text(re.sub(r"(# schema-sha256: )[0-9a-f]{64}", lambda m: m.group(1) + hashlib.sha256(data).hexdigest(), header))
                self.expect(self.run_with(), D003=("fail", "COV5004", ()))

    def test_layout_faults_skip_the_runtime_probe(self) -> None:
        member = self.layout.module("sv0cov/cmd_report.py")
        cases = {"missing module": lambda: member.unlink(), "module is a symlink": lambda: (shutil.copyfile(member, self.base / "real.py"), member.unlink(), os.symlink(self.base / "real.py", member)),
                 "module is a directory": lambda: (member.unlink(), member.mkdir()),
                 "missing registry": lambda: self.layout.resource(probes.REGISTRY).unlink()}
        for label, fault in cases.items():
            with self.subTest(fault=label):
                self.setUp()
                member = self.layout.module("sv0cov/cmd_report.py")
                fault()
                self.expect(self.run_with(), D004=("fail", "COV5004", ()), D008=("skipped", None, ("D004",)))
        self.setUp()
        self.layout.resource("schemas/sv0cov.map-1.0.schema.json").unlink()  # a missing schema is both a bundle and a layout fault
        self.expect(self.run_with(), D003=("fail", "COV5004", ()), D004=("fail", "COV5004", ()), D008=("skipped", None, ("D004",)))

    def test_runtime_source_faults(self) -> None:
        source = self.layout.resource("runtime/c/sv0cov_rt.c")
        source.write_bytes(source.read_bytes() + b"\n")
        self.expect(self.run_with(), D008=("fail", "COV5004", ()))

    def test_host_and_runtime_faults(self) -> None:
        other = probes.Observed(host={"architecture": "x86_64", "operating_system": "linux"}, runtime_version="3.13.0", runtime_name="cpython")
        self.expect(self.run_with(observed=other), D005=("fail", "COV5001", ()))
        for runtime, code in ((("cpython", "3.12.4"), "COV0016"), (("pypy", "3.13.0"), "COV0016"), (("cpython", "3.13.1"), "COV5004"),
                              (("cpython", "3.14.0"), "COV5004")):
            with self.subTest(runtime=runtime):
                seen = probes.Observed(host=GOLDEN_SEEN.host, runtime_name=runtime[0], runtime_version=runtime[1])
                self.expect(self.run_with(observed=seen), D006=("fail", code, ()))
        self.expect(self.run_with(origin=False), D006=("fail", "COV5004", ()))

    def test_private_storage_faults(self) -> None:
        mkdtemp = tempfile.mkdtemp

        def loose(prefix: str = "") -> str:
            path = mkdtemp(prefix=prefix, dir=self.base)
            os.chmod(path, 0o755)
            return path

        with mock.patch.object(probes.tempfile, "mkdtemp", loose):
            self.expect(self.run_with(), D007=("fail", "COV6002", ()))

        def littered(prefix: str = "") -> str:
            path = mkdtemp(prefix=prefix, dir=self.base)
            Path(path, "left-over").write_bytes(b"x")
            return path

        with mock.patch.object(probes.tempfile, "mkdtemp", littered):
            self.expect(self.run_with(), D007=("fail", "COV5004", ()))
        made = []

        def tracked(prefix: str = "") -> str:
            made.append(mkdtemp(prefix=prefix, dir=self.base))
            return made[-1]

        with mock.patch.object(probes.tempfile, "mkdtemp", tracked):
            self.run_with()
        self.assertFalse(Path(made[0]).exists())  # removed before the aggregate is built

    def test_bootstrap_failures_build_no_aggregate(self) -> None:
        with self.assertRaises(probes.Bootstrap):
            probes.run_standalone(manifest=synthetic_manifest()[:-5], observed=GOLDEN_SEEN, layout=self.layout)
        other = load_registry()
        with self.assertRaises(probes.Bootstrap):
            probes.run_standalone(manifest=synthetic_manifest(), observed=GOLDEN_SEEN, layout=self.layout,
                                  registry=mock.Mock(revision=other.revision + 1, sha256="b" * 64, entries=other.entries))
        with mock.patch.object(probes, "load_registry", side_effect=probes.RegistryError("broken")):
            with self.assertRaises(probes.Bootstrap):
                probes.run_standalone(manifest=synthetic_manifest(), observed=GOLDEN_SEEN, layout=self.layout)
        with mock.patch.object(probes.shutil, "rmtree", side_effect=OSError("busy")):
            with self.assertRaises(probes.Bootstrap):
                probes.run_standalone(manifest=synthetic_manifest(), observed=GOLDEN_SEEN, layout=self.layout)


class CommandTest(unittest.TestCase):
    def run_cli(self, *args: str, cwd: Path | None = None) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            code = cli.main(["doctor", *args], stdout=out, stderr=err, cwd=cwd or Path(tmp))
        return code, out.getvalue(), err.getvalue()

    def test_json_is_the_aggregate_and_nothing_else(self) -> None:
        code, out, err = self.run_cli("--json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out.encode(), probes.run_standalone())
        self.assertEqual(self.run_cli("--json", "--quiet")[1], out)  # --quiet never removes explicit JSON

    def test_human_form_names_every_probe(self) -> None:
        code, out, err = self.run_cli()
        lines = out.splitlines()
        self.assertEqual((code, err, len(lines)), (0, "", 19))
        self.assertEqual([ln[:4] for ln in lines[:18]], [p.id for p in doctor.PROBES])
        self.assertTrue(all(" pass " in ln for ln in lines[:8]) and all(" n/a " in ln for ln in lines[8:18]))
        self.assertEqual(lines[18], "doctor (standalone): pass: 8 passed, 0 failed, 0 skipped, 10 not applicable")
        self.assertEqual(self.run_cli("--quiet"), (0, "", ""))

    def test_a_failure_is_exit_7_and_every_output_agrees(self) -> None:
        real = probes.run_standalone

        def broken(**kw):
            return real(observed=probes.Observed(runtime_version="3.12.9"), **kw)

        with mock.patch.object(cli.cmd_doctor.probes, "run_standalone", broken):
            code, out, err = self.run_cli("--json", "--diagnostic-format=json-lines")
            human = self.run_cli()
        obj = doctor.validate(out.encode())
        self.assertEqual((code, obj["status"]), (7, "fail"))
        self.assertEqual(records(err), obj["diagnostics"])
        self.assertEqual([(r["code"], r["facts"]) for r in records(err)], [("COV0016", [{"name": "probe_id", "value": "D006"}])])
        self.assertEqual(human[0], 7)
        self.assertIn("D006  FAIL     Active implementation and runtime identity (COV0016)", human[1])
        self.assertIn("doctor (standalone): fail: 7 passed, 1 failed, 0 skipped, 10 not applicable", human[1])
        self.assertTrue(human[2].startswith("COV0016 error: Unsupported Python interpreter\n"))

    def test_a_bootstrap_failure_is_exit_8_with_no_json(self) -> None:
        with mock.patch.object(cli.cmd_doctor.probes, "run_standalone", side_effect=probes.Bootstrap("D001: no manifest")):
            code, out, err = self.run_cli("--json", "--diagnostic-format=json-lines")
        self.assertEqual((code, out, [r["code"] for r in records(err)]), (8, "", ["COV8001"]))

    def test_toolchain_mode_is_not_in_this_build(self) -> None:
        code, out, err = self.run_cli("--toolchain-root", ".", "--diagnostic-format=json-lines")
        self.assertEqual((code, out, [r["code"] for r in records(err)]), (7, "", ["COV5001"]))
        self.assertEqual(self.run_cli("--toolchain-root", ".", "--toolchain-root", ".")[0], 2)

    def test_project_configuration_is_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "sv0.toml").write_text("this is not TOML [[[")
            self.assertEqual(self.run_cli(cwd=Path(tmp))[0], 0)

    def test_usage(self) -> None:
        for args in (("extra",), ("--json=1",), ("--format", "term"), ("--output", "x")):
            with self.subTest(args=args):
                self.assertEqual(self.run_cli(*args)[0], 2)


if __name__ == "__main__":
    unittest.main()
