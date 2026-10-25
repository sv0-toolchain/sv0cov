# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Export commit manifests and standard-export publication (CV-403; SPEC
16.6, 20.2.1-20.2.3, 21.4, 21.5; COV-FMT-037, COV-REP-014, AC-052, AC-104).

The manifest fixtures and the single-change corpus; a whole export set is
verified against its artifacts, its configuration and its indexed input,
and any mutation of either makes it incomplete; and ``report`` publishes
LCOV and Cobertura with their native JSON and manifest in every layout:
bundle, one file, stdout.
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import subprocess
import sys
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_cmd_check import EVIDENCE  # noqa: E402
from test_cmd_report import ReportBase  # noqa: E402
from test_indexed_reader import rich_inputs  # noqa: E402
from test_report import STALE_OK, V, config, fixture_report  # noqa: E402

from sv0cov import cli  # noqa: E402
from sv0cov.exports import ExportStop, bundle, render, single  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.cobertura import render_cobertura  # noqa: E402
from sv0cov.formats.export_manifest import (  # noqa: E402
    FORMATS, ManifestError, build_manifest, configuration_sha256, decode_manifest, verify_export)
from sv0cov.formats.lcov import render_lcov  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "export-manifest"
REPORTS = ".sv0cov/reports"


def code_of(fn, *a, **k) -> str:
    try:
        fn(*a, **k)
    except ManifestError as exc:
        return exc.code
    return "valid"


def export_set(fmt: str = "lcov", name: str | None = "lcov.info") -> tuple[dict, bytes, bytes, bytes, bytes]:
    """(report, indexed, primary, native, manifest) for ``f0``."""
    report, ix = fixture_report("f0")
    primary = render_lcov(report) if fmt == "lcov" else render_cobertura(report)
    native = encode(report)
    return report, encode(ix), primary, native, build_manifest(fmt, report, primary=primary, primary_name=name, native=native,
                                                               native_name="coverage.json")


class ManifestTest(unittest.TestCase):
    def test_fixtures_are_current(self) -> None:
        p = subprocess.run([sys.executable, str(FIXTURES / "build.py")], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)

    def test_the_fixtures_are_the_closed_fourteen_member_record(self) -> None:
        for path in sorted(FIXTURES.glob("*.manifest.json")):
            with self.subTest(path.name):
                data = path.read_bytes()
                m = decode_manifest(data)
                self.assertEqual(encode(m), data)
                self.assertEqual(len(m), 14)
                self.assertEqual([a["role"] for a in m["artifacts"]], ["primary", "native"])
                f = FORMATS[m["format"]]
                self.assertEqual((m["omissions"], m["placeholders"], m["projections"]), (f["omissions"], f["placeholders"], f["projections"]))
                for key in ("omissions", "placeholders", "projections"):
                    self.assertEqual(m[key], sorted(m[key], key=str.encode))
                stdout = path.name.endswith("-stdout.manifest.json")
                self.assertEqual((m["artifacts"][0]["destination"], m["artifacts"][0]["name"] is None), ("stdout", True) if stdout
                                 else ("file", False))
                self.assertEqual((m["artifacts"][1]["destination"], m["context_projection"], m["saturation_disposition"]),
                                 ("file", "aggregate", "exact"))

    def test_the_exact_spec_arrays(self) -> None:
        """SPEC 16.6's table, restated."""
        self.assertEqual(FORMATS["lcov"]["omissions"], ["contract_coverage", "exclusion_inventory", "named_contexts", "partial_line_state",
                                                        "provenance_detail", "region_coverage", "saturation_qualifiers"])
        self.assertEqual(FORMATS["lcov"]["projections"], ["branch_outcomes_as_brda", "contexts_aggregated", "line_status_binary_covered_only",
                                                          "zero_denominators_as_zero"])
        self.assertEqual(FORMATS["cobertura"]["placeholders"], ["complexity_unavailable_as_0.0", "java_signature_unavailable_as_empty"])
        self.assertEqual(len(FORMATS["cobertura"]["omissions"]), 9)
        self.assertEqual(len(FORMATS["cobertura"]["projections"]), 8)
        self.assertTrue(FORMATS["cobertura"]["compatibility_reference"].endswith(
            "sha256:e467cb8252e20feb794fc2dedfbea7b4957921669c758f0282d525df88897917"))

    def test_the_single_change_corpus(self) -> None:
        rows = json.loads((FIXTURES / "mutations.json").read_text())
        self.assertGreater(len(rows), 250)
        for row in rows:
            with self.subTest(base=row["base"], what=row["what"]):
                self.assertEqual(code_of(decode_manifest, row["manifest"].encode("utf-8", "surrogatepass")), row["result"])
        whats = {r["what"] for r in rows}
        for needed in ("a byte-order mark", "a duplicate key", "a trailing byte", "an unknown member", "artifacts reversed", "the other omissions"):
            self.assertIn(needed, whats)


class ExportSetTest(unittest.TestCase):
    def test_a_complete_set_verifies(self) -> None:
        for fmt, name in (("lcov", "lcov.info"), ("cobertura", "cobertura.xml"), ("lcov", None), ("cobertura", None)):
            with self.subTest(fmt=fmt, name=name):
                report, indexed, primary, native, manifest = export_set(fmt, name)
                m = verify_export(manifest, primary, native, names=(name, "coverage.json"), indexed=indexed)
                self.assertEqual(m["indexed_input_sha256"], hashlib.sha256(indexed).hexdigest())
                self.assertEqual(m["report_configuration_sha256"], hashlib.sha256(encode(report["resolved_configuration"])).hexdigest())
                self.assertEqual(m["artifacts"][1]["sha256"], hashlib.sha256(native).hexdigest())

    def test_any_mutation_of_the_set_makes_it_incomplete(self) -> None:
        """AC-104: artifact, input and configuration mutation."""
        report, indexed, primary, native, manifest = export_set()
        other, _ = fixture_report("f0", config(STALE_OK))  # the same evidence under another configuration
        other_native = encode(other)
        rebound = json.loads(manifest)
        rebound["artifacts"][1].update(byte_length=len(other_native), sha256=hashlib.sha256(other_native).hexdigest())
        cases = {
            "a primary byte": (manifest, primary.replace(b"LH:", b"LH:1", 1), native, None),
            "a truncated primary": (manifest, primary[:-1], native, None),
            "a native byte": (manifest, primary, native.replace(b'"complete":true', b'"complete":false'), None),
            "another indexed input": (manifest, primary, native, indexed + b" "),
            "another configuration": (encode(rebound), primary, other_native, None),
            "a wrong length": (encode({**json.loads(manifest), "artifacts": [{**json.loads(manifest)["artifacts"][0], "byte_length": len(primary) + 1},
                                                                            json.loads(manifest)["artifacts"][1]]}), primary, native, None),
            "a manifest byte": (manifest.replace(b'"aggregate"', b'"aggregatE"'), primary, native, None),
            "an empty manifest": (b"", primary, native, None),
        }
        for what, (m, p, n, ix) in cases.items():
            with self.subTest(what):
                self.assertEqual(code_of(verify_export, m, p, n, indexed=ix), "COV4402")
        self.assertNotEqual(configuration_sha256(other), configuration_sha256(report))
        self.assertEqual(code_of(verify_export, manifest, primary, native, names=("other.info", "coverage.json")), "COV4402")

    def test_the_primary_must_match_its_report(self) -> None:
        report, _, _, native, _ = export_set()
        branches, _ = fixture_report("branches")
        wrong = render_lcov(branches)
        manifest = build_manifest("lcov", report, primary=wrong, primary_name="lcov.info", native=native, native_name="coverage.json")
        self.assertEqual(code_of(verify_export, manifest, wrong, native), "COV4402")

    def test_saturation_refuses_without_the_lossy_flag(self) -> None:
        """The lossy matrix is tests/test_lossy_export.py (CV-420)."""
        maps, profiles, selection = rich_inputs()
        indexed = encode(build_indexed(maps, profiles, run_selection=selection, tool_version=V))
        for opts, code, status in ((STALE_OK, "COV4020", cli.EXIT_REPORT),):
            report = build_report(indexed, config(opts), {}, standard_export=True, tool_version=V)
            for fmt in ("lcov", "cobertura"):
                with self.subTest(fmt=fmt, opts=opts):
                    with self.assertRaises(ExportStop) as ctx:
                        render(fmt, report, timestamp=0)
                    self.assertEqual((ctx.exception.diagnostic.code, ctx.exception.status), (code, status))

    def test_a_bundle_shares_one_native_report(self) -> None:
        report, _, _, native, _ = export_set()
        files, checks = bundle(["json", "lcov", "cobertura"], report, native, timestamp=0, tier="standard")
        self.assertEqual(sorted(files), ["cobertura.manifest.json", "cobertura.xml", "coverage.json", "lcov.info", "lcov.manifest.json"])
        for name, check in checks.items():
            check(files[name])
        s = single("cobertura", report, native, basename="c.xml", timestamp=7, tier="standard")
        self.assertEqual((s["native_name"], s["manifest_name"]), ("c.xml.sv0cov.json", "c.xml.manifest.json"))
        self.assertEqual(ET.fromstring(s["primary"]).get("timestamp"), "7")
        s["check_manifest"](s["manifest"])


class PublicationTest(ReportBase):
    """``report`` with LCOV and Cobertura (SPEC 20.2.2, 20.2.3)."""

    def verify(self, manifest: str, primary: bytes, native: str, names) -> dict:
        return verify_export((self.cwd / manifest).read_bytes(), primary, (self.cwd / native).read_bytes(), names=names,
                             indexed=self.evidence)

    def test_one_export_and_no_output_publishes_three_files(self) -> None:
        self.project()
        for fmt, name in (("lcov", "lcov.info"), ("cobertura", "cobertura.xml")):
            with self.subTest(fmt=fmt):
                code, out, err = self.run_report("--format", fmt)
                self.assertEqual((code, err), (0, ""))
                self.assertEqual(out, f"wrote {REPORTS}/{name} (with {name}.sv0cov.json and {name}.manifest.json)\n")
                p = f"{REPORTS}/{name}"
                m = self.verify(p + ".manifest.json", (self.cwd / p).read_bytes(), p + ".sv0cov.json", (name, name + ".sv0cov.json"))
                self.assertEqual(m["format"], fmt)
                self.assertEqual(self.modes(p, p + ".sv0cov.json", p + ".manifest.json"), [0o600] * 3)
        self.assertEqual(sorted(os.listdir(self.cwd / REPORTS)), ["cobertura.xml", "cobertura.xml.manifest.json", "cobertura.xml.sv0cov.json",
                                                                  "lcov.info", "lcov.info.manifest.json", "lcov.info.sv0cov.json"])

    def test_one_export_and_a_path(self) -> None:
        self.project()
        (self.cwd / "out").mkdir()
        self.assertEqual(self.run_report("--format", "cobertura", "--output", "out/c.xml", "--reproducible-epoch", "1700000000")[0], 0)
        self.assertEqual(sorted(os.listdir(self.cwd / "out")), ["c.xml", "c.xml.manifest.json", "c.xml.sv0cov.json"])
        primary = (self.cwd / "out/c.xml").read_bytes()
        self.assertEqual(ET.fromstring(primary).get("timestamp"), "1700000000")
        self.verify("out/c.xml.manifest.json", primary, "out/c.xml.sv0cov.json", ("c.xml", "c.xml.sv0cov.json"))
        self.assertFalse((self.cwd / ".sv0cov").exists())

    def test_one_export_on_stdout_publishes_its_support_afterwards(self) -> None:
        self.project()
        code, out, err = self.run_report("--format", "lcov", "--output", "-")
        self.assertEqual((code, err), (0, ""))
        support = f"{REPORTS}/lcov-stdout-support"
        self.assertEqual(sorted(os.listdir(self.cwd / support)), ["coverage.json", "lcov.manifest.json"])
        m = self.verify(f"{support}/lcov.manifest.json", out.encode(), f"{support}/coverage.json", (None, "coverage.json"))
        self.assertEqual((m["artifacts"][0]["destination"], m["artifacts"][0]["name"]), ("stdout", None))
        self.assertEqual(self.modes(support), [0o700])
        # a second stdout export collides with the support directory before anything is written
        code, out, err = self.run_report("--format", "lcov", "--output", "-")
        self.assertEqual((code, out, records(err)[0]["code"]), (6, "", "COV4010"))

    def test_a_stdout_that_fails_publishes_no_manifest(self) -> None:
        self.project()

        class Closed(io.StringIO):
            def write(self, _text: str) -> int:
                raise BrokenPipeError

        err = io.StringIO()
        code = cli.main(["report", "--diagnostic-format=json-lines", "--format", "cobertura", "--output", "-", EVIDENCE], stdout=Closed(),
                        stderr=err, cwd=self.cwd)
        self.assertEqual((code, records(err.getvalue())[0]["code"]), (6, "COV4011"))
        self.assertFalse((self.cwd / REPORTS / "cobertura-stdout-support").exists())

    def test_a_support_file_that_fails_validation_is_a_publication_failure(self) -> None:
        """Regression (CV-420): this escaped as an internal error (COV8001, exit 8)."""
        from unittest import mock

        from sv0cov import cmd_report

        def bad(*a, **k):
            s = single(*a, **k)

            def refuse(_data: bytes) -> None:
                raise ManifestError("refused")

            return {**s, "check_manifest": refuse}

        self.project()
        with mock.patch.object(cmd_report, "single", bad):
            code, out, err = self.run_report("--format", "lcov", "--output", "-")
        self.assertEqual((code, out, records(err)[0]["code"]), (6, "", "COV4011"))
        self.assertFalse((self.cwd / REPORTS / "lcov-stdout-support").exists())

    def test_a_bundle_holds_every_export_and_the_shared_native_report(self) -> None:
        self.project()
        txt, native = self.expected()
        code, out, err = self.run_report("--format", "cobertura", "--format", "term", "--format", "lcov", "--format", "json", "--output", "b")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(out, "wrote b (coverage.txt, coverage.json, lcov.info, lcov.manifest.json, cobertura.xml, cobertura.manifest.json)\n")
        files = {p.name: p.read_bytes() for p in (self.cwd / "b").iterdir()}
        self.assertEqual((files["coverage.txt"], files["coverage.json"]), (txt, native))
        for fmt, name in (("lcov", "lcov.info"), ("cobertura", "cobertura.xml")):
            verify_export(files[f"{fmt}.manifest.json"], files[name], files["coverage.json"], names=(name, "coverage.json"), indexed=self.evidence)
        # without --format json the native report still comes along
        self.assertEqual(self.run_report("--format", "lcov", "--format", "term", "--output", "c")[0], 0)
        self.assertEqual(sorted(os.listdir(self.cwd / "c")), ["coverage.json", "coverage.txt", "lcov.info", "lcov.manifest.json"])

    def test_every_companion_name_is_checked_before_anything_is_read(self) -> None:
        self.project()
        (self.cwd / "out").mkdir()
        for taken in ("out/l.info", "out/l.info.sv0cov.json", "out/l.info.manifest.json"):
            with self.subTest(taken=taken):
                (self.cwd / taken).write_bytes(b"mine")
                before = self.tree()
                code, out, err = self.run_report("--format", "lcov", "--output", "out/l.info")
                self.assertEqual((code, out, records(err)[0]["code"]), (6, "", "COV4010"))
                self.assertEqual(self.tree(), before)
                (self.cwd / taken).unlink()

    def test_repeated_exports_are_byte_identical(self) -> None:
        self.project()
        for d in ("one", "two"):
            (self.cwd / d).mkdir()
            self.assertEqual(self.run_report("--format", "cobertura", "--output", f"{d}/c.xml")[0], 0)
        for name in ("c.xml", "c.xml.sv0cov.json", "c.xml.manifest.json"):
            self.assertEqual((self.cwd / "one" / name).read_bytes(), (self.cwd / "two" / name).read_bytes(), name)
        self.assertNotIn(str(self.cwd).encode(), (self.cwd / "one/c.xml.manifest.json").read_bytes())

    def test_saturated_evidence_publishes_nothing(self) -> None:
        maps, profiles, selection = rich_inputs()
        self.project(evidence=encode(build_indexed(maps, profiles, run_selection=selection, tool_version=V)))
        before = self.tree()
        for fmt in ("lcov", "cobertura"):
            code, out, err = self.run_report("--format", fmt, "--format", "json", "--allow-source-mismatch")
            self.assertEqual((code, out, [r["code"] for r in records(err)][-1:]), (6, "", ["COV4020"]))
        self.assertEqual(self.tree(), before)

    def test_an_extended_profile_is_refused_before_anything_is_read(self) -> None:
        """AC-053."""
        self.project()
        before = self.tree()
        for value in ("lcov-extended", "cobertura-gitlab", "LCOV2"):
            with self.subTest(value=value):
                code, out, err = self.run_report("--format", value)
                (r,) = records(err)
                detail = dict((f["name"], f["value"]) for f in r["facts"])["detail"]
                self.assertEqual((code, out, r["code"]), (2, "", "COV0001"))
                self.assertIn("use native JSON", detail)
        code, _, err = self.run_report("--format", "xml")
        self.assertNotIn("native JSON", err)
        from sv0cov.config import ConfigError, check_value, REPORTS
        with self.assertRaises(ConfigError) as ctx:
            check_value(REPORTS, ["term", "cobertura-v2"], "tool.sv0cov.reports")
        self.assertIn("propose an extended profile after R1", str(ctx.exception))
        self.assertEqual(self.tree(), before)

    def test_the_native_companion_is_the_json_report(self) -> None:
        """AC-052: the native report keeps everything the export loses."""
        self.project("functions")
        self.assertEqual(self.run_report("--format", "lcov")[0], 0)
        native = json.loads((self.cwd / REPORTS / "lcov.info.sv0cov.json").read_bytes())
        self.assertEqual(native["regions"], json.loads(self.expected()[1])["regions"])
        m = decode_manifest((self.cwd / REPORTS / "lcov.info.manifest.json").read_bytes())
        self.assertIn("region_coverage", m["omissions"])
        self.assertIn("partial_line_state", m["omissions"])


if __name__ == "__main__":
    unittest.main()
