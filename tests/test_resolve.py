# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Minimal map + raw profile reader (CV-170, BL-012).

The seven semantic fixtures' hand-reviewed expected counts round-trip
through a raw profile and the reader; profiles add with u64 saturation;
identical copies count once and reused profile IDs fail (COV2112); wrong
maps, corrupt profiles, invalid maps, and no profiles are rejected with
their codes. The sv0c root suite (run_vm_profile.py) runs this reader on
real native (CV-115) and VM (CV-121) profiles.
"""

from __future__ import annotations

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
from sv0cov.resolve import ResolveError, main, resolve  # noqa: E402

SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
RUN = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")


def pid(k: int) -> bytes:
    return bytes([0xA0, k]) + bytes(13) + b"\x01"


def fixture(name: str) -> tuple[bytes, dict, dict]:
    d = SEMANTIC / name
    data = (d / "expected-map.json").read_bytes()
    return data, json.loads(data), json.loads((d / "expected-counts.json").read_bytes())


def profile(m: dict, counts: dict[int, int], k: int = 1, backend: str = "native", context: str | None = None) -> bytes:
    return encode(
        RawProfile(bytes.fromhex(m["map_id"]), RUN, pid(k), backend, context,
                   tuple(sorted((i, c) for i, c in counts.items() if c))),
        m["program_counter_count"],
    )


def by_counter(m: dict, by_point: dict[str, int]) -> dict[int, int]:
    index = {p["point_id"]: p["counter_index"] for p in m["points"] if p.get("counter_index") is not None}
    return {index[p]: c for p, c in by_point.items()}


class ResolveTest(unittest.TestCase):
    def test_fixture_counts_round_trip(self) -> None:
        names = sorted(p.name for p in SEMANTIC.iterdir() if (p / "expected-counts.json").is_file())
        self.assertEqual(len(names), 7)
        for name in names:
            with self.subTest(name):
                data, m, exp = fixture(name)
                want = {e["point_id"]: e["count"] for e in exp["counts"]}
                r = resolve(data, [profile(m, by_counter(m, want))])
                self.assertEqual(r.counts(), want)
                self.assertEqual(r.map_id, m["map_id"])
                self.assertEqual([p.counter_index for p in r.points], list(range(m["program_counter_count"])))
                self.assertFalse(any(p.saturated for p in r.points))
                labels = {e["point_id"]: e["label"] for e in exp["counts"]}
                for p in r.points:
                    # The label's function is the point's owning entity.
                    self.assertTrue(labels[p.point_id].startswith(p.entity + "."), (p, labels[p.point_id]))

    def test_profiles_add_across_backends(self) -> None:
        data, m, exp = fixture("f0")
        want = {e["point_id"]: e["count"] for e in exp["counts"]}
        counts = by_counter(m, want)
        r = resolve(data, [profile(m, counts, 1, "native"), profile(m, counts, 2, "vm-v1", "shard")])
        self.assertEqual(r.counts(), {p: 2 * c for p, c in want.items()})
        self.assertEqual(r.backends, ("native", "vm-v1"))
        self.assertEqual(r.contexts, (None, "shard"))
        self.assertEqual(r.profile_ids, (pid(1).hex(), pid(2).hex()))
        self.assertEqual(r.run_ids, (RUN.hex(),))

    def test_identical_copy_counts_once(self) -> None:
        data, m, _ = fixture("f0")
        p = profile(m, {0: 3})
        self.assertEqual(resolve(data, [p, p]).points[0].value, 3)

    def test_reused_profile_id_is_a_collision(self) -> None:
        data, m, _ = fixture("f0")
        with self.assertRaises(ResolveError) as cm:
            resolve(data, [profile(m, {0: 3}, 1), profile(m, {0: 4}, 1)])
        self.assertEqual(cm.exception.code, "COV2112")

    def test_saturation(self) -> None:
        data, m, _ = fixture("f0")
        r = resolve(data, [profile(m, {0: U64_MAX, 1: U64_MAX - 1}, 1), profile(m, {0: 1, 1: 5, 2: 2}, 2)])
        p0, p1, p2 = r.points[0], r.points[1], r.points[2]
        self.assertEqual((p0.value, p0.saturated), (U64_MAX, True))  # already a lower bound
        self.assertEqual((p1.value, p1.saturated), (U64_MAX, True))  # the sum overflowed
        self.assertEqual((p2.value, p2.saturated), (2, False))

    def test_rejections(self) -> None:
        data, m, _ = fixture("f0")
        other_data, other, _ = fixture("loops")
        good = profile(m, {0: 1})
        corrupt = bytearray(good)
        corrupt[92] ^= 0x01  # the first pair's count (header 84 + context length + pair count + index)
        truncated = good[:-12]  # no completion marker or CRC32C
        cases = {
            "COV2111": [profile(other, {0: 1})],  # another map's profile
            "COV2012": [bytes(corrupt)],  # CRC32C no longer matches
            "COV2011": [truncated],  # incomplete: a run that never finished writing
            "COV3001": [],
        }
        for code, profs in cases.items():
            with self.subTest(code):
                with self.assertRaises(ResolveError) as cm:
                    resolve(data, profs)
                self.assertEqual(cm.exception.code, code)
        with self.assertRaises(ResolveError) as cm:
            resolve(data.replace(b'"schema":"sv0cov.map"', b'"schema":"sv0cov.mop"'), [good])
        self.assertEqual(cm.exception.code, "COV1010")
        # Too few counters in the bound map for the profile's pairs.
        with self.assertRaises(ResolveError) as cm:
            resolve(other_data, [profile(m, {m["program_counter_count"] - 1: 1})])
        self.assertIn(cm.exception.code, ("COV2111", "COV2110"))

    def test_module_cli(self) -> None:
        data, m, exp = fixture("f0")
        want = {e["point_id"]: e["count"] for e in exp["counts"]}
        with TemporaryDirectory() as td:
            mp, pp = Path(td) / "m.json", Path(td) / "p.sv0profraw"
            mp.write_bytes(data)
            pp.write_bytes(profile(m, by_counter(m, want)))
            out, err = io.BytesIO(), io.StringIO()

            wrapper = io.TextIOWrapper(out, encoding="utf-8")
            with redirect_stdout(wrapper), redirect_stderr(err):
                self.assertEqual(main([str(mp), str(pp)]), 0)
                wrapper.flush()
            doc = decode_canonical(out.getvalue())
            self.assertEqual({p["point_id"]: p["value"] for p in doc["points"]}, want)
            self.assertEqual(doc["schema"], "sv0cov.f0-resolution")
            with redirect_stderr(err):
                self.assertEqual(main([str(mp), str(Path(td) / "absent")]), 1)
                self.assertEqual(main([str(mp)]), 2)
            self.assertIn("error[COV2010]", err.getvalue())


if __name__ == "__main__":
    unittest.main()
