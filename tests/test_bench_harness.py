# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Benchmark harness and frozen measurement protocol (CV-035; SPEC 24.1-24.2)."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "bench"))
sys.path.insert(0, str(ROOT / "src"))

import harness as H  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402

PY = sys.executable
OK_OUT = hashlib.sha256(b"ok\n").hexdigest()


def fixture(off: list[str], on: list[str] | None = None, exit_code: int = 0, stdout: str | None = OK_OUT) -> dict:
    arm = lambda argv: {"argv": argv, "expect": {"exit_code": exit_code, "stdout_sha256": stdout}}  # noqa: E731
    return {"arms": {"off": arm(off), "on": arm(on) if on else None}, "category": "startup-small", "cwd": str(ROOT), "id": "t"}


def small_protocol(**kw) -> dict:
    p = copy.deepcopy(H.load_protocol())
    p["samples"] = {"measured_slots": 4, "warmup_slots": 1}
    p.update(kw)
    return p


class ProtocolTest(unittest.TestCase):
    def test_protocol_is_hash_frozen(self) -> None:
        data = (ROOT / "bench" / "protocol.json").read_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), H.PROTOCOL_SHA256)
        p = H.load_protocol()
        self.assertEqual((p["samples"]["warmup_slots"], p["samples"]["measured_slots"]), (3, 30))
        self.assertEqual(p["ordering"]["method"], "counterbalanced-abba")
        self.assertEqual(p["outliers"]["policy"], "retain-all")

    def test_changed_protocol_is_refused(self) -> None:
        p = H.load_protocol()
        p["samples"]["measured_slots"] = 5
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "protocol.json"
            path.write_bytes(encode(p))
            with self.assertRaises(H.HarnessError):
                H.load_protocol(path)

    def test_abba_ordering(self) -> None:
        self.assertEqual([H.slot_order(k, ["off", "on"]) for k in range(4)], [["off", "on"], ["on", "off"], ["off", "on"], ["on", "off"]])
        self.assertEqual(H.slot_order(1, ["off"]), ["off"])

    def test_statistics(self) -> None:
        self.assertEqual(H.nearest_rank(list(range(1, 21)), 95, 100), 19)
        self.assertEqual(H.nearest_rank([5], 95, 100), 5)
        runs = [{"rss_bytes": 1, "wall_ns": v} for v in (10, 20, 30, 40, 1000)]
        s = H.statistics(runs)["wall_ns"]
        self.assertEqual((s["median"], s["p95"], s["min"], s["max"], s["count"]), (30, 1000, 10, 1000, 5))
        self.assertEqual(s["outliers"], 1)
        self.assertEqual(s["variance"], 0)  # 190250 ns^2 reported in us^2 (floor)
        big = H.statistics([{"rss_bytes": 1, "wall_ns": v} for v in (10**9, 40 * 10**9, 90 * 10**9)])["wall_ns"]
        self.assertEqual(big["variance_unit"], "us^2")
        self.assertEqual(big["variance"], 1_990_333_333_333_333)  # 1990.33 s^2 in us^2 (raw ns^2 would be 2e21)

    def test_statistics_stay_in_canonical_range_for_macos_rss_and_noisy_wall(self) -> None:
        # macOS reports ru_maxrss in bytes (Linux: KiB); wide spreads must still encode.
        for mac in (True, False):
            with mock.patch.object(H.sys, "platform", "darwin" if mac else "linux"):
                rss = [H._maxrss_bytes(k * 1_000_000_000 // (1 if mac else 1024)) for k in (1, 8, 20, 30)]
            runs = [{"rss_bytes": r, "wall_ns": w} for r, w in zip(rss, (2 * 10**9, 30 * 10**9, 70 * 10**9, 120 * 10**9))]
            data = encode({"statistics": H.statistics(runs)})  # raises CanonicalJsonError on overflow
            self.assertIn(b"variance_unit", data)


class ExecutionTest(unittest.TestCase):
    def test_paired_fixture(self) -> None:
        f = fixture([PY, "-c", "print('ok')"], [PY, "-c", "print('ok')"])
        r = H.run_fixture(f, small_protocol())
        self.assertTrue(r["valid"])
        self.assertEqual(len(r["slots"]), 5)
        self.assertTrue(r["slots"][0]["warmup"])
        self.assertEqual(r["slots"][1]["attempts"][0]["order"], ["on", "off"])
        self.assertEqual(r["statistics"]["off"]["wall_ns"]["count"], 4)
        self.assertGreater(r["statistics"]["off"]["rss_bytes"]["max"], 1_000_000)
        self.assertIn("overhead_p95_ratio_ppm", r)

    def test_baseline_only_fixture(self) -> None:
        r = H.run_fixture(fixture([PY, "-c", "print('ok')"]), small_protocol())
        self.assertEqual(r["arms"], ["off"])
        self.assertNotIn("overhead_p95_ratio_ppm", r)

    def test_invalid_runs_are_retried_and_retained(self) -> None:
        r = H.run_fixture(fixture([PY, "-c", "raise SystemExit(3)"], stdout=None), small_protocol())
        self.assertFalse(r["valid"])
        self.assertEqual(r["invalid"], "invalid-slots-over-budget")
        self.assertEqual(len(r["slots"][2]["attempts"]), 3)
        self.assertEqual(r["slots"][2]["attempts"][0]["runs"]["off"]["invalid"], "nonzero-or-unexpected-exit")

    def test_output_validation(self) -> None:
        r = H.run_fixture(fixture([PY, "-c", "print('wrong')"]), small_protocol())
        self.assertEqual(r["slots"][1]["attempts"][0]["runs"]["off"]["invalid"], "output-validation-failure")

    def test_timeout(self) -> None:
        p = small_protocol(timeout_seconds=1)
        p["samples"] = {"measured_slots": 1, "warmup_slots": 0}
        p["retry"] = {"max_attempts_per_slot": 1, "max_invalid_slots_basis_points": 0}
        r = H.run_fixture(fixture([PY, "-c", "import time; time.sleep(30)"], stdout=None), p)
        self.assertEqual(r["slots"][0]["attempts"][0]["runs"]["off"], {"invalid": "timeout"})

    def test_spawn_failure(self) -> None:
        r = H.run_once(["/nonexistent/binary"], str(ROOT), {"exit_code": 0, "stdout_sha256": None}, 5)
        self.assertEqual(r["invalid"], "spawn-failure")


class BundleTest(unittest.TestCase):
    def test_bundle_is_labelled_and_repeatable(self) -> None:
        plan = {"corpus": {"version": "test"}, "fixtures": [fixture([PY, "-c", "print('ok')"])]}
        a = json.loads(H.run_plan(plan, "managed-ci-provisional"))
        b = json.loads(H.run_plan(plan, "managed-ci-provisional"))
        self.assertFalse(a["conformance"])
        self.assertIn("not performance conformance", a["label"])
        self.assertEqual(len(a["fixtures"][0]["slots"]), 33)

        def shape(bundle: dict) -> dict:
            out = copy.deepcopy(bundle)
            for f in out["fixtures"]:
                f.pop("statistics")
                for s in f["slots"]:
                    for att in s["attempts"]:
                        for run in att["runs"].values():
                            run.pop("wall_ns", None)
                            run.pop("rss_bytes", None)
            return out

        self.assertEqual(shape(a), shape(b))

    def test_bundle_validation(self) -> None:
        host = H.host_descriptor("managed-ci-provisional")
        good = {"conformance": False, "corpus": {}, "fixtures": [], "host": host, "label": H.LABELS["managed-ci-provisional"], "protocol_sha256": H.PROTOCOL_SHA256,
                "schema": "sv0cov.benchmark-results", "series": H.series_key(host), "version": "1.0"}
        H.validate_bundle(encode(good))
        for name, change in {
            "claims-conformance": {"conformance": True},
            "other-protocol": {"protocol_sha256": "0" * 64},
            "series": {"series": "x"},
            "extra": {"extra": 1},
            "another stage's label": {"label": H.LABELS["managed-ci-recorded"]},
        }.items():
            with self.subTest(case=name), self.assertRaises(H.HarnessError):
                H.validate_bundle(encode({**good, **change}))

    def test_descriptor_is_closed_and_private(self) -> None:
        d = H.host_descriptor("local-development")
        H.check_descriptor(d)
        for change in ({"extra": "x"}, {"cpu_model": ""}, {"stage": "prod"}, {"os_build": "/Users/someone/x"}):
            with self.subTest(change=change), self.assertRaises(H.HarnessError):
                H.check_descriptor({**d, **change})
        self.assertNotIn(os.path.realpath(sys.executable), json.dumps(d))


class ProbeTest(unittest.TestCase):
    def test_cpuinfo_x86(self) -> None:
        self.assertEqual(H._cpuinfo_model("processor\t: 0\nmodel name\t: AMD EPYC 7763 64-Core Processor\n"), "AMD EPYC 7763 64-Core Processor")

    def test_cpuinfo_arm(self) -> None:
        arm = "processor\t: 0\nCPU implementer\t: 0x41\nCPU architecture: 8\nCPU part\t: 0xd4f\n\nprocessor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd4f\n"
        self.assertEqual(H._cpuinfo_model(arm), "Arm Neoverse-V2")
        self.assertEqual(H._cpuinfo_model("CPU implementer\t: 0x41\nCPU part\t: 0xdead\n"), "arm implementer 0x41 part 0xdead")
        self.assertEqual(H._cpuinfo_model("CPU implementer\t: 0xc0\nCPU part\t: 0xac3\n"), "Ampere-1")

    def test_cpuinfo_unobservable(self) -> None:
        self.assertEqual(H._cpuinfo_model(""), H.UNKNOWN)
        self.assertEqual(H._cpuinfo_model("processor : 0\nBogoMIPS : 50\n"), H.UNKNOWN)

    def test_mountinfo_longest_prefix(self) -> None:
        text = (
            "22 1 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
            "30 22 0:27 / /tmp rw - tmpfs tmpfs rw\n"
            "31 22 0:28 / /tmpx rw - xfs /dev/sdb rw\n"
            "32 22 0:29 / /mnt/with\\040space rw - btrfs /dev/sdc rw\n"
        )
        self.assertEqual(H._mountinfo_fstype(text, "/tmp/bench"), "tmpfs")
        self.assertEqual(H._mountinfo_fstype(text, "/tmp"), "tmpfs")
        self.assertEqual(H._mountinfo_fstype(text, "/tmpx/a"), "xfs")
        self.assertEqual(H._mountinfo_fstype(text, "/home/runner/work"), "ext4")
        self.assertEqual(H._mountinfo_fstype(text, "/mnt/with space/x"), "btrfs")
        self.assertEqual(H._mountinfo_fstype("garbage\n", "/tmp"), H.UNKNOWN)

    def test_mount_output(self) -> None:
        text = "/dev/disk3s1s1 on / (apfs, sealed, local, read-only)\n/dev/disk3s5 on /System/Volumes/Data (apfs, local)\nmap auto_home on /System/Volumes/Data/home (autofs, automounted)\n"
        self.assertEqual(H._mount_output_fstype(text, "/System/Volumes/Data/Users/a"), "apfs")
        self.assertEqual(H._mount_output_fstype(text, "/System/Volumes/Data/home/u"), "autofs")
        self.assertEqual(H._mount_output_fstype(text, "/private/tmp"), "apfs")
        self.assertEqual(H._mount_output_fstype("", "/x"), H.UNKNOWN)

    def test_descriptor_deterministic(self) -> None:
        self.assertEqual(H.host_descriptor("local-development", "abc"), H.host_descriptor("local-development", "abc"))
        self.assertTrue(H.host_descriptor("local-development")["filesystem"])


if __name__ == "__main__":
    unittest.main()
