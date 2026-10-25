# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The LCOV consumer-conformance tool (CV-418; COV-REP-009, AC-050).

The real LCOV 1.16 and 2.5 runs happen in CI (the ``lcov-consumers`` job),
or here when ``SV0COV_LCOV_TARBALLS`` names a directory holding the two
pinned tarballs. Without them this checks the tool itself: the pins, the
digest refusal before extraction, and the summary parser on both versions'
output.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import lcov_conformance as lc  # noqa: E402

from sv0cov.formats.export_manifest import FORMATS  # noqa: E402

SUMMARY_116 = """Reading tracefile f0.info
Summary coverage rate:
  lines......: 93.8% (15 of 16 lines)
  functions..: 100.0% (3 of 3 functions)
  branches...: 66.7% (4 of 6 branches)
"""
SUMMARY_25 = """Reading tracefile f0.info.
Summary coverage rate:
  source files: 1
  lines.......: 93.8% (15 of 16 lines)
  functions...: 100.0% (3 of 3 functions)
  branches....: 66.7% (4 of 6 branches)
Message summary:
  no messages were reported
"""


class ToolTest(unittest.TestCase):
    def test_the_pins_are_the_profiles_compatibility_reference(self) -> None:
        pins = lc.pins()
        self.assertEqual(sorted(pins["distributions"]), ["1.16", "2.5"])
        self.assertEqual(FORMATS["lcov"]["compatibility_reference"], "lcov:1.16+2.5")
        for version, d in pins["distributions"].items():
            self.assertRegex(d["sha256"], r"\A[0-9a-f]{64}\Z")
            self.assertEqual(d["url"], f"https://github.com/linux-test-project/lcov/releases/download/v{version}/lcov-{version}.tar.gz")

    def test_a_tarball_that_is_not_the_pinned_one_is_refused_before_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            fake = Path(td) / "lcov-1.16.tar.gz"
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w:gz") as tf:
                info = tarfile.TarInfo("lcov-1.16/bin/lcov")
                info.size = 0
                tf.addfile(info, io.BytesIO())
            fake.write_bytes(buf.getvalue())
            with self.assertRaises(SystemExit) as ctx:
                lc.unpack("1.16", fake, Path(td) / "out")
            self.assertIn("not the pinned distribution", str(ctx.exception))
            self.assertFalse((Path(td) / "out").exists())

    def test_both_summary_formats_parse(self) -> None:
        want = {"line": (15, 16), "function": (3, 3), "branch": (4, 6)}
        self.assertEqual(lc.totals(SUMMARY_116), want)
        self.assertEqual(lc.totals(SUMMARY_25), want)

    def test_fetch_prints_https_only_commands(self) -> None:
        p = subprocess.run([sys.executable, str(ROOT / "tools" / "lcov_conformance.py"), "--fetch-into", "/x"], capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        lines = p.stdout.splitlines()
        self.assertEqual(len(lines), 2)
        for line in lines:
            self.assertTrue(line.startswith("curl -sSfL --proto '=https' -o /x/lcov-"), line)


@unittest.skipUnless(os.environ.get("SV0COV_LCOV_TARBALLS"), "SV0COV_LCOV_TARBALLS names no directory with the pinned LCOV tarballs")
class ConsumerTest(unittest.TestCase):
    def test_every_golden_through_both_lcov_versions(self) -> None:
        d = Path(os.environ["SV0COV_LCOV_TARBALLS"])
        args = [a for v in json.loads(lc.PINS.read_text())["distributions"] for a in ("--tarball", f"{v}={d / f'lcov-{v}.tar.gz'}")]
        self.assertEqual(lc.main(args), 0)


if __name__ == "__main__":
    unittest.main()
