# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""CRC32C and raw profile 1.0 (CV-023, CV-024, CV-025; SPEC 16.4).

COV-FMT-004/005/007/008/010/015/016/018/021/022/025..029/032/034,
AC-031, AC-034, AC-054..057, AC-061, AC-090.
"""

from __future__ import annotations

import json
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.crc32c import crc32c, crc32c_update  # noqa: E402
from sv0cov.formats.rawprofile import (  # noqa: E402
    U64_MAX,
    RawProfile,
    RawProfileError,
    Tier,
    decode,
    encode,
)

FIXTURES = ROOT / "tests" / "fixtures"
CRC_VECTORS = json.loads((FIXTURES / "crc32c" / "vectors.json").read_text(encoding="utf-8"))["vectors"]
GOLDENS = json.loads((FIXTURES / "rawprofile" / "goldens.json").read_text(encoding="utf-8"))["goldens"]


def golden(name: str) -> tuple[dict, bytes]:
    g = next(g for g in GOLDENS if g["file"] == f"{name}.sv0profraw")
    return g, (FIXTURES / "rawprofile" / g["file"]).read_bytes()


def profile_of(g: dict) -> RawProfile:
    return RawProfile(
        map_id=bytes.fromhex(g["map_id"]),
        run_id=bytes.fromhex(g["run_id"]),
        profile_id=bytes.fromhex(g["profile_id"]),
        backend=g["backend"],
        context=g["context"],
        counts=tuple((i, c) for i, c in g["counts"]),
    )


def recrc(data: bytes) -> bytes:
    return data[:-4] + struct.pack("<I", crc32c(data[:-4]))


def code(data: bytes, **kw) -> str | None:
    try:
        decode(data, **kw)
    except RawProfileError as exc:
        return exc.code
    return None


class Crc32cTest(unittest.TestCase):
    def test_published_vectors(self) -> None:
        for v in CRC_VECTORS:
            with self.subTest(vector=v["name"]):
                self.assertEqual(f"{crc32c(bytes.fromhex(v['hex'])):08x}", v["crc32c"])

    def test_incremental_equals_one_shot(self) -> None:
        data = bytes(range(256)) * 3
        state = 0xFFFFFFFF
        for k in range(0, len(data), 37):
            state = crc32c_update(state, data[k : k + 37])
        self.assertEqual(state ^ 0xFFFFFFFF, crc32c(data))

    def test_single_bit_changes_detected(self) -> None:
        data = bytearray(b"sv0cov raw profile")
        base = crc32c(data)
        for bit in range(len(data) * 8):
            flipped = bytearray(data)
            flipped[bit // 8] ^= 1 << (bit % 8)
            self.assertNotEqual(crc32c(flipped), base)


class GoldenTest(unittest.TestCase):
    def test_goldens_regenerate_exactly(self) -> None:
        before = {p.name: p.read_bytes() for p in (FIXTURES / "rawprofile").iterdir() if p.suffix in (".json", ".sv0profraw")}
        subprocess.run([sys.executable, str(FIXTURES / "rawprofile" / "generate_goldens.py")], check=True)
        after = {p.name: p.read_bytes() for p in (FIXTURES / "rawprofile").iterdir() if p.suffix in (".json", ".sv0profraw")}
        self.assertEqual(before, after)

    def test_writer_matches_every_golden(self) -> None:
        for g in GOLDENS:
            with self.subTest(golden=g["file"]):
                data = (FIXTURES / "rawprofile" / g["file"]).read_bytes()
                self.assertEqual(encode(profile_of(g), g["map_counter_count"]), data)

    def test_reader_decodes_every_golden(self) -> None:
        for g in GOLDENS:
            with self.subTest(golden=g["file"]):
                data = (FIXTURES / "rawprofile" / g["file"]).read_bytes()
                self.assertEqual(decode(data, map_counter_count=g["map_counter_count"]), profile_of(g))

    def test_header_bytes_by_hand(self) -> None:
        _, data = golden("native-basic")
        self.assertEqual(data[:16], b"SV0PRF\x00\x00\x01\x00\x00\x00\x04\x00\x00\x00")
        self.assertEqual(data[-12:-4], b"SV0DONE!")
        self.assertEqual(struct.unpack("<Q", data[-12:-4])[0], 0x21454E4F44305653)

    def test_context_four_states(self) -> None:
        g, data = golden("vm-v1-empty-context")
        self.assertEqual(decode(data).context, "")
        g2, data2 = golden("native-basic")
        self.assertIsNone(decode(data2).context)
        g3, data3 = golden("vm-v2-context-saturated")
        self.assertEqual(decode(data3).context, "ctx/é")
        self.assertEqual(decode(data3).saturated(), [64])

    def test_zero_counter_profile_is_complete(self) -> None:
        g, data = golden("native-zero-counter")
        p = decode(data, map_counter_count=0)
        self.assertEqual(p.counts, ())


class NegativeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.basic = golden("native-basic")[1]
        self.sat = golden("vm-v2-context-saturated")[1]

    def mutate(self, data: bytes, at: int, new: bytes, fix_crc: bool = True) -> bytes:
        out = data[:at] + new + data[at + len(new) :]
        return recrc(out) if fix_crc else out

    def test_version_rejected_before_anything_else(self) -> None:
        for version in (b"\x01\x00\x01\x00", b"\x02\x00\x00\x00", b"\x00\x00\x00\x00", b"\xff\xff\xff\xff"):
            with self.subTest(version=version.hex()):
                bad = self.mutate(self.basic, 8, version + b"\xff\xff\xff\xff", fix_crc=False)
                self.assertEqual(code(bad), "COV2103")

    def test_structural_rejections(self) -> None:
        b, s = self.basic, self.sat
        pairs_at = 84 + 4
        cases = {
            "bad magic": (self.mutate(b, 0, b"SV0PRG"), "COV2110"),
            "unknown flag bit": (self.mutate(b, 12, struct.pack("<I", 0x04 | 0x20)), "COV2110"),
            "no backend": (self.mutate(b, 12, struct.pack("<I", 0)), "COV2110"),
            "two backends": (self.mutate(b, 12, struct.pack("<I", 0x04 | 0x08)), "COV2110"),
            "zero run id": (self.mutate(b, 48, bytes(16)), "COV2110"),
            "zero profile id": (self.mutate(b, 64, bytes(16)), "COV2110"),
            "context without flag": (self.mutate(golden("vm-v2-context-saturated")[1], 12, struct.pack("<I", 0x10 | 0x02)), "COV2110"),
            "unsorted pairs": (self.mutate(b, pairs_at, struct.pack("<IQ", 2, 7) + struct.pack("<IQ", 0, 1)), "COV2110"),
            "duplicate index": (self.mutate(b, pairs_at + 12, struct.pack("<I", 0)), "COV2110"),
            "zero count": (self.mutate(b, pairs_at + 4, struct.pack("<Q", 0)), "COV2110"),
            "saturated without bit": (self.mutate(b, pairs_at + 16, struct.pack("<Q", U64_MAX)), "COV2110"),
            "overflow flag, empty bitmap": (self.mutate(s, len(s) - 12 - 8, struct.pack("<Q", 0)), "COV2110"),
            "bit without saturation": (self.mutate(s, len(s) - 12 - 16, struct.pack("<Q", 1)), "COV2110"),
            "trailing byte": (recrc(b[:-4] + b"\x00" + b[-4:]), "COV2110"),
        }
        for name, (data, expected) in cases.items():
            with self.subTest(case=name):
                self.assertEqual(code(data, map_counter_count=None if "saturat" in name or "bit" in name else 4), expected)

    def test_map_bound_checks(self) -> None:
        b = self.basic
        self.assertEqual(code(b, map_counter_count=2), "COV2110")  # index 2 outside a 2-counter map
        self.assertEqual(code(b, map_counter_count=1), "COV2110")  # pair_count above the map
        self.assertEqual(code(b, expected_map_id=b"\x00" * 32), "COV2111")
        self.assertEqual(code(self.sat, map_counter_count=64 + 64 + 1), "COV2110")  # wrong word count
        g, zero = golden("native-zero-counter")
        self.assertEqual(code(golden("native-no-hits")[1], map_counter_count=0), None)
        self.assertEqual(code(b, map_counter_count=0), "COV2110")

    def test_incomplete_and_corrupt(self) -> None:
        b = self.basic
        for cut in (0, 11, 40, 84, 90, len(b) - 12, len(b) - 5, len(b) - 1):
            with self.subTest(truncated_to=cut):
                self.assertIn(code(b[:cut]), ("COV2011",))
        swapped = self.mutate(b, len(b) - 12, b"!ENOD0VS", fix_crc=True)
        self.assertEqual(code(swapped), "COV2011")
        partial = self.mutate(b, len(b) - 12, b"SV0DON\x00\x00", fix_crc=True)
        self.assertEqual(code(partial), "COV2011")
        corrupt = self.mutate(b, 100, b"\x09", fix_crc=False)
        self.assertEqual(code(corrupt), "COV2012")

    def test_invalid_utf8_context(self) -> None:
        data = self.mutate(self.sat, 84, b"\xff")
        self.assertEqual(code(data), "COV2110")

    def test_limits_apply_before_anything_else(self) -> None:
        tight = Tier.custom(max_counters=1, max_bytes=10_000)
        self.assertEqual(code(self.basic, tier=tight), "COV6001")  # pair_count 2 > 1
        tiny = Tier.custom(max_counters=100, max_bytes=100)
        self.assertEqual(code(self.basic, tier=tiny), "COV6001")  # 128 bytes > 100
        # A hostile header declaring a huge pair count cannot raise the reader's ceiling
        # or trigger allocation: it is rejected from the fixed fields alone.
        hostile = self.mutate(self.basic, 84, struct.pack("<I", 0xFFFFFFFF), fix_crc=False)  # pair_count
        self.assertEqual(code(hostile), "COV6001")
        hostile_ctx = self.mutate(self.basic, 80, struct.pack("<I", 0xFFFFFFFF), fix_crc=False)
        self.assertEqual(code(hostile_ctx), "COV2110")


class TierTest(unittest.TestCase):
    def test_builtin_tiers(self) -> None:
        self.assertEqual((Tier.standard().max_counters, Tier.standard().max_bytes), (4194304, 67108864))
        self.assertEqual((Tier.large().max_counters, Tier.large().max_bytes), (16777216, 268435456))

    def test_custom_bounds(self) -> None:
        Tier.custom(4294967295, 68719476736)
        for mc, mb in ((0, 1), (1, 0), (4294967296, 1), (1, 68719476737), (True, 1), (1.0, 1)):
            with self.subTest(mc=mc, mb=mb):
                with self.assertRaises(ValueError):
                    Tier.custom(mc, mb)

    def test_producer_refuses_over_tier(self) -> None:
        g, _ = golden("native-basic")
        p = profile_of(g)
        with self.assertRaises(RawProfileError) as ctx:
            encode(p, 4194305)
        self.assertEqual(ctx.exception.code, "COV6001")
        encode(p, 4194304)
        with self.assertRaises(RawProfileError):
            encode(p, 4, Tier.custom(10, 100))

    def test_producer_rejects_bad_counts(self) -> None:
        g, _ = golden("native-basic")
        base = profile_of(g)
        for counts in (((1, 1), (0, 1)), ((0, 0),), ((4, 1),), ((0, U64_MAX + 1),)):
            with self.subTest(counts=counts):
                with self.assertRaises(RawProfileError):
                    encode(RawProfile(base.map_id, base.run_id, base.profile_id, "native", None, counts), 4)


if __name__ == "__main__":
    unittest.main()
