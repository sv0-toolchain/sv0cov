# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""F0 backend parity comparator (CV-171, F0-G4, AC-001, AC-002).

Equal maps and counts pass; a count or saturation difference, a point only
one map has, and different semantic metadata each fail and are listed;
metadata is compared through what map indexes name, not the indexes;
profiles from the wrong backend are refused. The sv0c root suite
(run_vm_profile.py) runs the comparator on real generated-C and sv0vm
outputs for every semantic fixture.
"""

from __future__ import annotations

import copy
import io
import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import decode_canonical  # noqa: E402
from sv0cov.formats.rawprofile import U64_MAX, RawProfile, encode  # noqa: E402
from sv0cov.parity import compare, main, point_semantics  # noqa: E402
from sv0cov.resolve import ResolveError  # noqa: E402

SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
RUN = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")


def load(name: str) -> tuple[bytes, dict]:
    data = (SEMANTIC / name / "expected-map.json").read_bytes()
    return data, json.loads(data)


def prof(m: dict, counts: dict[int, int], k: int, backend: str) -> bytes:
    return encode(RawProfile(bytes.fromhex(m["map_id"]), RUN, bytes([k]) * 16, backend, None,
                             tuple(sorted((i, c) for i, c in counts.items() if c))), m["program_counter_count"])


class ParityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.data, self.m = load("f0")
        self.counts = {i: i + 1 for i in range(self.m["program_counter_count"])}

    def test_equal_backends_pass(self) -> None:
        r = compare("f0", self.data, [prof(self.m, self.counts, 1, "native")],
                    self.data, [prof(self.m, self.counts, 2, "vm-v1")])
        self.assertEqual(r["status"], "pass")
        self.assertEqual((r["points"], r["counted_points"]), (len(self.m["points"]), self.m["program_counter_count"]))
        self.assertEqual(r["identity"], {"only_generated_c": [], "only_vm_v1": []})
        self.assertEqual((r["metadata_mismatches"], r["count_mismatches"]), ([], []))
        self.assertEqual(r["schema"], "sv0cov.f0-parity")

    def test_count_and_saturation_mismatches_fail(self) -> None:
        vm_counts = dict(self.counts)
        vm_counts[3] += 1
        r = compare("f0", self.data, [prof(self.m, self.counts, 1, "native")],
                    self.data, [prof(self.m, vm_counts, 2, "vm-v1")])
        self.assertEqual(r["status"], "fail")
        self.assertEqual(len(r["count_mismatches"]), 1)
        mm = r["count_mismatches"][0]
        self.assertEqual((mm["generated_c"]["value"], mm["vm_v1"]["value"]), (4, 5))
        # Same value, one side saturated: still a mismatch. The C side holds
        # one count at the maximum (a lower bound); the VM side reaches the
        # same value exactly, (2^64 - 2) + 1.
        c = {**self.counts, 0: U64_MAX}
        v1 = {**self.counts, 0: U64_MAX - 1}
        r = compare("f0", self.data, [prof(self.m, c, 1, "native")],
                    self.data, [prof(self.m, v1, 2, "vm-v1"), prof(self.m, {0: 1}, 3, "vm-v1")])
        self.assertEqual(r["status"], "fail")
        diffs = {d["point_id"]: d for d in r["count_mismatches"]}
        first = next(d for d in diffs.values() if d["generated_c"]["value"] == U64_MAX)
        self.assertEqual(first["generated_c"], {"saturated": True, "value": U64_MAX})
        self.assertEqual(first["vm_v1"], {"saturated": False, "value": U64_MAX})

    def test_identity_mismatch_fails(self) -> None:
        other, om = load("loops")
        r = compare("mixed", self.data, [prof(self.m, self.counts, 1, "native")],
                    other, [prof(om, {0: 1}, 2, "vm-v1")])
        self.assertEqual(r["status"], "fail")
        self.assertEqual(len(r["identity"]["only_generated_c"]), len(self.m["points"]))
        self.assertEqual(len(r["identity"]["only_vm_v1"]), len(om["points"]))

    def test_metadata_compares_what_indexes_name(self) -> None:
        m2 = copy.deepcopy(self.m)
        m2["entities"].reverse()
        n = len(m2["entities"])
        for p in m2["points"]:
            p["entity_index"] = n - 1 - p["entity_index"]
        for p, q in zip(self.m["points"], m2["points"]):
            self.assertEqual(point_semantics(self.m, p), point_semantics(m2, q))
        m3 = copy.deepcopy(self.m)
        m3["entities"][0]["qualified_name"] = "renamed"
        p0 = next(p for p in self.m["points"] if p["entity_index"] == 0)
        self.assertNotEqual(point_semantics(self.m, p0), point_semantics(m3, p0))
        m4 = copy.deepcopy(self.m)
        m4["points"][0]["counter_index"] = None
        self.assertNotEqual(point_semantics(self.m, self.m["points"][0]), point_semantics(m4, m4["points"][0]))

    def test_wrong_backend_is_refused(self) -> None:
        with self.assertRaises(ResolveError):
            compare("f0", self.data, [prof(self.m, self.counts, 1, "vm-v1")],
                    self.data, [prof(self.m, self.counts, 2, "vm-v1")])
        with self.assertRaises(ResolveError):
            compare("f0", self.data, [prof(self.m, self.counts, 1, "native")],
                    self.data, [prof(self.m, self.counts, 2, "vm-v2")])

    def test_module_cli(self) -> None:
        with TemporaryDirectory() as td:
            t = Path(td)
            (t / "m.json").write_bytes(self.data)
            (t / "c.raw").write_bytes(prof(self.m, self.counts, 1, "native"))
            (t / "v.raw").write_bytes(prof(self.m, self.counts, 2, "vm-v1"))
            (t / "bad.raw").write_bytes(prof(self.m, {0: 9}, 3, "vm-v1"))
            for vm, rc, status in (("v.raw", 0, "pass"), ("bad.raw", 1, "fail")):
                out = io.BytesIO()
                w = io.TextIOWrapper(out, encoding="utf-8")
                with redirect_stdout(w), redirect_stderr(io.StringIO()):
                    self.assertEqual(main(["--fixture", "f0", "--c-map", str(t / "m.json"), "--c-profile",
                                           str(t / "c.raw"), "--vm-map", str(t / "m.json"), "--vm-profile",
                                           str(t / vm)]), rc)
                    w.flush()
                self.assertEqual(decode_canonical(out.getvalue())["status"], status)


if __name__ == "__main__":
    unittest.main()
