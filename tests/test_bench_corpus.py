# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Hybrid benchmark corpus manifest and generators (CV-036; SPEC 24.3, COV-PERF-011..014/019),
complete since CV-427 (COV-PERF-015/016/018: semantic validation before timing, the
native contention harness, the scale merge and report commands)."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
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
                self.assertEqual(f["status"], "runnable-baseline")  # CV-427: none pending; v2 dispatch is a backend, not a status
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



@unittest.skipIf(shutil.which(os.environ.get("CC", "cc")) is None, "no C compiler")
class SemanticValidationTest(unittest.TestCase):
    """COV-PERF-015/016: the contention harness's result is known in closed form, and a
    run that skips work or miscounts is refused before anything is timed."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        cls.dir = Path(cls.tmp.name)
        cc = [os.environ.get("CC", "cc"), "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic", "-pthread"]
        cls.off, cls.on = cls.dir / "off", cls.dir / "on"
        subprocess.run([*cc, "-o", str(cls.off), str(C.CONTENTION_C)], check=True)
        subprocess.run([*cc, "-DSV0COV_ON", "-I", str(ROOT / "runtime" / "c"), "-o", str(cls.on), str(C.CONTENTION_C),
                        str(ROOT / "runtime" / "c" / "sv0cov_rt.c")], check=True)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def arms(self, threads: int, sharing: str, hits: int, seed: int, stdout: bytes | None = None) -> tuple[dict, C.Program]:
        prog = C.gen_contention(threads, sharing, hits, seed)
        profiles = self.dir / "profiles"
        profiles.mkdir(exist_ok=True)
        expect = {"exit_code": 0, "stdout_sha256": C._sha(prog.stdout if stdout is None else stdout)}
        run = [str(threads), sharing, str(hits), str(seed)]
        return {"off": {"argv": [str(self.off), *run], "expect": expect},
                "on": {"argv": [str(self.on), *run], "env": {"SV0COV_RUN_ID": C.BENCH_RUN_ID, "SV0COV_PROFILE_DIR": str(profiles)}, "expect": expect}}, prog

    def test_the_closed_form_is_the_iteration(self) -> None:
        for t, hits, seed in ((1, 0, 3), (3, 17, 604), (8, 1000, 608)):
            x = 0
            for i in range(t):
                a, b, v = 2 + (seed * 31 + i) % 900, (seed * 17 + i * 7) % C.MOD, i + 1
                for _ in range(hits):
                    v = (v * a + b) % C.MOD
                x += v
            self.assertEqual(C.contention_sum(t, hits, seed), x)

    def test_both_arms_give_the_expected_sum_and_exact_counts(self) -> None:
        for threads, sharing in ((1, "shared"), (4, "shared"), (4, "disjoint"), (8, "disjoint")):
            with self.subTest(threads=threads, sharing=sharing):
                arms, prog = self.arms(threads, sharing, 20000, 600 + threads)
                done = C.validate("t", arms, self.dir, C._profile_checker(Path(C.CONTENTION_MAP_ID), prog.facts["counter_hits"]))
                self.assertRegex(done["off"].stderr.decode(), r"^affinity: (pinned|advisory)\n$")
                self.assertEqual(list((self.dir / "profiles").iterdir()), [])  # removed before timing

    def test_a_fast_wrong_run_is_refused_before_timing(self) -> None:
        arms, prog = self.arms(2, "shared", 1000, 602, stdout=b"0\n")  # what a run that skipped its work would print
        with self.assertRaisesRegex(SystemExit, "nothing is timed"):
            C.validate("t", arms, self.dir)
        arms, prog = self.arms(2, "shared", 1000, 602)
        with self.assertRaisesRegex(SystemExit, "profile is not the expected result"):
            C.validate("t", arms, self.dir, C._profile_checker(Path(C.CONTENTION_MAP_ID), {"0": 1999}))
        for raw in (self.dir / "profiles").iterdir():
            raw.unlink()

    def test_scale_merge_and_reports_are_checked_against_the_raw_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp)
            C.write_tree(C.gen_scale(3000, 2, 801), src)
            C._scale_map.cache_clear()
            argv, evidence = C._scale_evidence("t", src, 2)
            self.assertIn("merge", argv)
            data = src / "e.json"
            data.write_bytes(evidence)
            for fmt in ("term", "html"):
                r = subprocess.run([os.path.realpath(sys.executable), "-I", "-B", str(C.SV0COV_CMD), "report", "--format", fmt, "--output", "-", str(data)],
                                   cwd=src, capture_output=True)
                self.assertEqual(r.returncode, 0, r.stderr)
                self.assertTrue(r.stdout)
            (src / "profile-1.sv0profraw").unlink()  # one run missing: incomplete evidence
            with self.assertRaisesRegex(SystemExit, "not the expected result"):
                C._scale_evidence("t", src, 2)


if __name__ == "__main__":
    unittest.main()
