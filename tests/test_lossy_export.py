# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Saturated standard exports (CV-420; SPEC 14.2.1, 16.6, 21.3.8;
COV-POL-011).

The lossy-export matrix: the flag on or off, exact or saturated evidence,
LCOV and Cobertura, every layout. Without the flag saturated evidence
publishes nothing (``COV4020``); with it the export is written with each
inexact count as hit count ``1``, a ``COV4021`` warning, a
``lossy_hit_only`` manifest and a ``diagnostic_only`` native report. With
the flag but exact evidence nothing changes. A manifest whose disposition
does not match its native report is ``COV4402``.
"""

from __future__ import annotations

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_cmd_report import ReportBase  # noqa: E402
from test_indexed_reader import fixture_inputs  # noqa: E402
from test_saturation_policy import evidence  # noqa: E402

from sv0cov.expr import U64_MAX  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.export_manifest import ManifestError, decode_manifest, verify_export  # noqa: E402
from sv0cov.formats.lcov import has_inexact, parse_lcov  # noqa: E402
from sv0cov.model.report import read_report  # noqa: E402

LOSSY = "--allow-lossy-saturated-export"
REPORTS = ".sv0cov/reports"
PRIMARY = {"lcov": "lcov.info", "cobertura": "cobertura.xml"}


def saturated_entry() -> str:
    _, m, _ = fixture_inputs("f0")
    return next(p["point_id"] for p in m["points"] if p["kind"] == "function_entry")


class MatrixTest(ReportBase):
    def setUp(self) -> None:
        super().setUp()
        self.exact = evidence("f0", "fail")[0]
        self.saturated = evidence("f0", "fail", {saturated_entry(): U64_MAX})[0]

    def published(self) -> dict[str, bytes]:
        root = self.cwd / ".sv0cov"
        return {str(p.relative_to(self.cwd)): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()} if root.exists() else {}

    def run_layout(self, layout: str, fmt: str, *flags: str) -> tuple[int, str, str, dict]:
        """Run one export; return its code, stdout, stderr and (manifest, primary, native, names)."""
        if layout == "file":
            code, out, err = self.run_report("--format", fmt, *flags)
            p = f"{REPORTS}/{PRIMARY[fmt]}"
            paths = (p + ".manifest.json", p, p + ".sv0cov.json")
            names = (PRIMARY[fmt], PRIMARY[fmt] + ".sv0cov.json")
        elif layout == "bundle":
            code, out, err = self.run_report("--format", fmt, "--format", "json", *flags)
            paths = (f"{REPORTS}/{fmt}.manifest.json", f"{REPORTS}/{PRIMARY[fmt]}", f"{REPORTS}/coverage.json")
            names = (PRIMARY[fmt], "coverage.json")
        else:
            code, out, err = self.run_report("--format", fmt, "--output", "-", *flags)
            d = f"{REPORTS}/{fmt}-stdout-support"
            paths = (f"{d}/{fmt}.manifest.json", None, f"{d}/coverage.json")
            names = (None, "coverage.json")
        files = {}
        if code == 0:
            files = {"manifest": (self.cwd / paths[0]).read_bytes(),
                     "primary": out.encode() if paths[1] is None else (self.cwd / paths[1]).read_bytes(),
                     "native": (self.cwd / paths[2]).read_bytes(), "names": names}
        return code, out, err, files

    def test_the_matrix(self) -> None:
        for layout in ("file", "bundle", "stdout"):
            for fmt in ("lcov", "cobertura"):
                for saturated in (False, True):
                    for flag in (False, True):
                        with self.subTest(layout=layout, fmt=fmt, saturated=saturated, flag=flag):
                            self.setUp()
                            self.project(evidence=self.saturated if saturated else self.exact)
                            flags = (LOSSY,) if flag else ()
                            code, out, err, files = self.run_layout(layout, fmt, *flags)
                            codes = [r["code"] for r in records(err)]
                            if saturated and not flag:
                                self.assertEqual((code, out, codes), (6, "", ["COV4020"]))
                                self.assertEqual(self.published(), {})
                                continue
                            self.assertEqual(code, 0, err)
                            m = verify_export(files["manifest"], files["primary"], files["native"], names=files["names"],
                                              indexed=self.evidence)
                            native = read_report(files["native"])
                            if saturated:
                                self.assertEqual(codes, ["COV4021"])
                                self.assertEqual(m["saturation_disposition"], "lossy_hit_only")
                                self.assertEqual(native["evidence_eligibility"], "diagnostic_only")
                                self.assertTrue(native["resolved_configuration"]["report"]["allow_lossy_saturated_export"]["value"])
                                self.assertTrue(has_inexact(native))
                            else:
                                self.assertEqual((codes, m["saturation_disposition"]), ([], "exact"))
                                self.assertNotEqual(native["evidence_eligibility"], "diagnostic_only")

    def test_a_saturated_count_is_written_as_one(self) -> None:
        self.project(evidence=self.saturated)
        code, out, err, files = self.run_layout("file", "lcov", LOSSY)
        self.assertEqual(code, 0, err)
        native = read_report(files["native"])
        sat = next(p for p in native["points"] if p["count"]["saturated"] and p["kind"] == "function_entry")
        name = next(e["qualified_name"] for e in native["entities"] if e["entity_index"] == sat["entity_index"])
        self.assertIn(f"FNDA:1,{name}\n".encode(), files["primary"])
        self.assertNotIn(str(U64_MAX).encode(), files["primary"])
        totals = parse_lcov(files["primary"])
        self.assertEqual(sum(r["function"][0] for r in totals), native["summary"]["function"]["covered"])

    def test_the_disposition_must_match_the_native_report(self) -> None:
        self.project(evidence=self.saturated)
        _, _, _, lossy = self.run_layout("bundle", "lcov", LOSSY)
        relabelled = json.loads(lossy["manifest"])
        relabelled["saturation_disposition"] = "exact"
        with self.assertRaises(ManifestError):
            verify_export(encode(relabelled), lossy["primary"], lossy["native"])
        self.setUp()
        self.project(evidence=self.exact)
        _, _, _, exact = self.run_layout("bundle", "lcov")
        relabelled = json.loads(exact["manifest"])
        relabelled["saturation_disposition"] = "lossy_hit_only"
        with self.assertRaises(ManifestError):
            verify_export(encode(relabelled), exact["primary"], exact["native"])
        self.setUp()
        self.project(evidence=self.exact)
        _, _, _, flagged = self.run_layout("bundle", "lcov", LOSSY)  # the flag without saturation is exact
        relabelled = json.loads(flagged["manifest"])
        relabelled["saturation_disposition"] = "lossy_hit_only"
        with self.assertRaises(ManifestError):
            verify_export(encode(relabelled), flagged["primary"], flagged["native"])
        self.assertEqual(decode_manifest(flagged["manifest"])["saturation_disposition"], "exact")

    def test_a_lossy_export_and_an_exact_one_cannot_share_a_bundle_with_other_meaning(self) -> None:
        """Both exports of one invocation share one native report and one disposition."""
        self.project(evidence=self.saturated)
        code, _, err = self.run_report("--format", "lcov", "--format", "cobertura", LOSSY)
        self.assertEqual((code, [r["code"] for r in records(err)]), (0, ["COV4021", "COV4021"]))
        names = sorted(os.listdir(self.cwd / REPORTS))
        self.assertEqual(names, ["cobertura.manifest.json", "cobertura.xml", "coverage.json", "lcov.info", "lcov.manifest.json"])
        for fmt in ("lcov", "cobertura"):
            m = decode_manifest((self.cwd / REPORTS / f"{fmt}.manifest.json").read_bytes())
            self.assertEqual(m["saturation_disposition"], "lossy_hit_only")


if __name__ == "__main__":
    unittest.main()
