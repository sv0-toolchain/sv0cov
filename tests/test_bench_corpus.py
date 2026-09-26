# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Hybrid benchmark corpus manifest and generators (CV-036; SPEC 24.3, COV-PERF-011..014/019)."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))

import corpus as C  # noqa: E402

MANIFEST = json.loads((ROOT / "bench" / "corpus" / "manifest.json").read_bytes())


class CorpusTest(unittest.TestCase):
    def test_manifest_is_current(self) -> None:
        r = subprocess.run([sys.executable, str(ROOT / "bench" / "corpus.py"), "check"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_manifest_shape(self) -> None:
        C.check_manifest_object(MANIFEST)
        self.assertEqual(MANIFEST["categories"], list(C.CATEGORIES))
        by_cat = {c: [f for f in MANIFEST["fixtures"] if f["category"] == c] for c in C.CATEGORIES}
        self.assertEqual(len(by_cat["native-contention"]), 8)
        self.assertTrue(all(f["backends"] == ["vm-v1", "vm-v2"] for f in by_cat["vm-dispatch"]))
        for f in MANIFEST["fixtures"]:
            with self.subTest(fixture=f["id"]):
                self.assertTrue(f["status"] == "runnable-baseline" or f["status"].startswith("pending: "))
                self.assertTrue(f["applicable_budgets"])
                self.assertTrue(f["timed_boundary"])
                if f["source"]["kind"] == "generated":
                    self.assertEqual(f["source"]["generator"], C.GENERATOR)
                    self.assertIsInstance(f["source"]["seed"], int)

    def test_invalid_manifests_are_rejected(self) -> None:
        for name, change in {
            "missing-category": lambda m: m.update(fixtures=[f for f in m["fixtures"] if f["category"] != "contracts"]),
            "duplicate-id": lambda m: m["fixtures"].append(dict(m["fixtures"][0])),
            "weighting": lambda m: m["fixtures"][0].update(weight="double"),
            "runnable-without-expectation": lambda m: m["fixtures"][0].pop("expected"),
        }.items():
            with self.subTest(case=name), self.assertRaises(ValueError):
                m = json.loads(json.dumps(MANIFEST))
                change(m)
                C.check_manifest_object(m)

    def test_prng_is_pinned(self) -> None:
        r = C.SplitMix64(0)
        self.assertEqual([r.next() for _ in range(3)], [0xE220A8397B1DCDAF, 0x6E789E6AA1B965F4, 0x06C45D188009454F])

    def test_generator_replay_is_byte_identical(self) -> None:
        recorded = {f["id"]: f for f in MANIFEST["fixtures"]}
        for f in C.fixtures():
            if f.category == "merge-report-scale":
                continue
            with self.subTest(fixture=f.id):
                a, _ = C.materialize_one(f)
                b, _ = C.materialize_one(f)
                self.assertEqual(a, b)
                if a:
                    self.assertEqual(C.tree_digest(a), recorded[f.id]["tree_sha256"])

    def test_small_scale_artifacts_replay_and_ingest(self) -> None:
        a = C.gen_scale(3000, 2, 801)
        C._scale_map.cache_clear()
        b = C.gen_scale(3000, 2, 801)
        self.assertEqual(C.tree_digest(a), C.tree_digest(b))
        with tempfile.TemporaryDirectory() as tmp:
            C.write_tree(a, Path(tmp))
            r = subprocess.run([os.path.realpath(sys.executable), "-I", "-B", str(ROOT / "bench" / "ingest.py"), tmp], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)

    def test_full_scale_digests_are_recorded(self) -> None:
        for f in MANIFEST["fixtures"]:
            if f["category"] == "merge-report-scale":
                with self.subTest(fixture=f["id"]):
                    self.assertRegex(f.get("tree_sha256", ""), r"^[0-9a-f]{64}$")

    def test_snapshots_are_content_addressed(self) -> None:
        for name, snap in MANIFEST["snapshots"].items():
            self.assertRegex(snap["revision"], r"^[0-9a-f]{40}$")
            self.assertEqual(snap["license"], "MIT OR Apache-2.0")
            for path, digest in snap["files"].items():
                with self.subTest(snapshot=name, path=path):
                    self.assertEqual(hashlib.sha256((ROOT / "bench" / "corpus" / "real" / name / path).read_bytes()).hexdigest(), digest)
        review = (ROOT / "bench" / "corpus" / "REDISTRIBUTION.md").read_text()
        for snap in MANIFEST["snapshots"].values():
            self.assertIn(snap["revision"], review)

    def test_generated_programs_state_their_result(self) -> None:
        prog = C.gen_straight(3, 4, 7)
        self.assertEqual(prog.exit_code, 0)
        self.assertIn(b"return acc - ", prog.files["main.sv0"])
        self.assertEqual(C.gen_contracts("failing", 3, 9).exit_code, 1)
        self.assertEqual(C.gen_modules("same-basename", 3, 5).files.keys(), {"m0/util.sv0", "m1/util.sv0", "m2/util.sv0", "main.sv0"})


if __name__ == "__main__":
    unittest.main()
