# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The recorded 64-bit atomics probe (CV-422; SPEC 14.2; COV-INS-010).

``tools/atomics_probe.py`` writes this host's record; it has exactly the
documented members, its build-time and run-time answers agree, the storage
is aligned, and the probe table in ``docs/generated-c-protocol.md`` carries
this host class with the same answers (CI runs this on all four).
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import atomics_probe  # noqa: E402

DOC = ROOT / "docs" / "generated-c-protocol.md"
ROW = re.compile(r"^\| (macOS|Linux) (arm64|x86-64) \| [^|]+ \| (\d) \([a-z]+\) \| (\d) \| (\d+) \|$", re.M)


def host_class() -> tuple[str, str] | None:
    system = {"Darwin": "macOS", "Linux": "Linux"}.get(platform.system())
    machine = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "x86-64", "AMD64": "x86-64"}.get(platform.machine())
    return (system, machine) if system and machine else None


class AtomicsProbeTest(unittest.TestCase):
    record: dict

    @classmethod
    def setUpClass(cls) -> None:
        if atomics_probe.compiler() is None:
            raise unittest.SkipTest("no C compiler on this host")
        with tempfile.TemporaryDirectory() as t:
            out = Path(t, "probe.json")
            subprocess.run([sys.executable, str(ROOT / "tools" / "atomics_probe.py"), "--out", str(out)], check=True)
            cls.record = json.loads(out.read_text(encoding="utf-8"))

    def test_record_shape(self) -> None:
        r = self.record
        self.assertEqual(sorted(r), ["compiler", "counter_size", "host", "lock_free_build", "lock_free_runtime",
                                     "record", "runtime_sha256", "storage_aligned", "version"])
        self.assertEqual((r["record"], r["version"]), ("sv0cov-atomics-probe", 1))
        self.assertEqual(r["host"], {"system": platform.system(), "machine": platform.machine()})
        self.assertRegex(r["runtime_sha256"], r"^[0-9a-f]{64}$")
        self.assertTrue(r["compiler"]["command"] and r["compiler"]["version"])

    def test_answers_agree_and_storage_is_aligned(self) -> None:
        r = self.record
        self.assertIn(r["lock_free_build"], (0, 1, 2))
        self.assertIn(r["lock_free_runtime"], (0, 1))
        if r["lock_free_build"] == 2:
            self.assertEqual(r["lock_free_runtime"], 1)
        if r["lock_free_build"] == 0:
            self.assertEqual(r["lock_free_runtime"], 0)
        self.assertIs(r["storage_aligned"], True)
        self.assertGreaterEqual(r["counter_size"], 8)

    def test_documented_table_matches_this_host(self) -> None:
        rows = {(m[0], m[1]): tuple(map(int, m[2:])) for m in ROW.findall(DOC.read_text(encoding="utf-8"))}
        self.assertEqual(sorted(rows), [("Linux", "arm64"), ("Linux", "x86-64"), ("macOS", "arm64"),
                                        ("macOS", "x86-64")])
        here = host_class()
        if here is None:
            self.skipTest(f"{platform.system()} {platform.machine()} is not an R1 host class")
        r = self.record
        self.assertEqual(rows[here], (r["lock_free_build"], r["lock_free_runtime"], r["counter_size"]))


if __name__ == "__main__":
    unittest.main()
