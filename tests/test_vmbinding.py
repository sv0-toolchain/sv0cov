# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""VM binding 1.0, COVR 1.0, and the shared projection (CV-026).

SPEC 15.3, 15.4, 16.8; COV-VM-013/021/023/024, COV-VM-027 (v2 bytes frozen
as language-neutral goldens), AC-028, AC-092, AC-093, AC-094.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sv0cov.formats.vmbinding import (  # noqa: E402
    Binding,
    BindingError,
    decode_covr,
    decode_v1,
    encode_covr,
    encode_v1,
    verify_container,
)

MAP_ID = "ab" * 32
IDENT = "sv0c@" + "0123456789abcdef0123456789abcdef012"  # 40 bytes
BINDING = Binding(MAP_ID, 3, IDENT)
BYTECODE = b"SV0B\x01\x00" + bytes(range(40))

# Written by hand from the SPEC 15.3 example (keys sorted, no whitespace, final LF).
V1_GOLDEN = (
    '{"bytecode_length":46,"bytecode_sha256":"' + hashlib.sha256(BYTECODE).hexdigest() + '",'
    '"capabilities":["sv0cov.coverage.v1"],"compiler_identity":"' + IDENT + '",'
    '"map_id":"' + MAP_ID + '","plan_capability":"sv0cov.plan.v1","profile":"sv0vm-v1-coverage",'
    '"program_counter_count":3,"raw_profile_version":"1.0","schema":"sv0cov.vm-binding","version":"1.0"}\n'
).encode()

# Written by hand from the SPEC 15.4 offset table.
COVR_GOLDEN_ZERO_DIGEST = (
    b"\x01\x00\x00\x00"  # schema 1.0
    + b"\x01\x00\x00\x00"  # raw profile 1.0
    + b"\x01\x00\x00\x00"  # required_flags = COVER_HIT_REQUIRED
    + b"\x03\x00\x00\x00"  # program_counter_count
    + bytes.fromhex(MAP_ID)
    + b"\x12\x00" + b"sv0cov.coverage.v1"
    + b"\x0e\x00" + b"sv0cov.plan.v1"
    + b"\x28\x00" + IDENT.encode()
    + bytes(32)
)


class V1Test(unittest.TestCase):
    def test_golden_bytes(self) -> None:
        self.assertEqual(encode_v1(BINDING, BYTECODE), V1_GOLDEN)
        self.assertEqual(decode_v1(V1_GOLDEN, BYTECODE), BINDING)

    def test_binding_to_bytecode(self) -> None:
        for other in (BYTECODE + b"\x00", BYTECODE[:-1], BYTECODE[:-1] + b"\xff"):
            with self.subTest(len=len(other)):
                with self.assertRaises(BindingError) as ctx:
                    decode_v1(V1_GOLDEN, other)
                self.assertEqual(ctx.exception.code, "COV2202")

    def test_closed_schema(self) -> None:
        g = V1_GOLDEN
        bad = {
            "unknown key": g.replace(b'"version"', b'"x":1,"version"'),
            "missing key": g.replace(b'"raw_profile_version":"1.0",', b""),
            "wrong profile": g.replace(b"sv0vm-v1-coverage", b"sv0vm-v2-typed"),
            "case variant capability": g.replace(b"sv0cov.coverage.v1", b"sv0cov.Coverage.v1"),
            "two capabilities": g.replace(b'["sv0cov.coverage.v1"]', b'["sv0cov.coverage.v1","sv0cov.coverage.v1"]'),
            "uppercase digest": g.replace(MAP_ID.encode(), MAP_ID.upper().encode()),
            "zero length": g.replace(b'"bytecode_length":46', b'"bytecode_length":0'),
            "negative count": g.replace(b'"program_counter_count":3', b'"program_counter_count":-1'),
            "float count": g.replace(b'"program_counter_count":3', b'"program_counter_count":3.0'),
            "null count": g.replace(b'"program_counter_count":3', b'"program_counter_count":null'),
            "space in identity": g.replace(IDENT.encode(), b"sv0c @x"),
            "version 1.1": g.replace(b'"version":"1.0"', b'"version":"1.1"'),
            "whitespace": g.replace(b",", b", ", 1),
            "bom": b"\xef\xbb\xbf" + g,
            "no LF": g[:-1],
            "trailing": g + b"\n",
            "duplicate key": g.replace(b'"version":"1.0"}', b'"version":"1.0","version":"1.0"}'),
        }
        for name, data in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(BindingError) as ctx:
                    decode_v1(data)
                self.assertEqual(ctx.exception.code, "COV2201")


class CovrTest(unittest.TestCase):
    def test_golden_bytes_and_length(self) -> None:
        payload = encode_covr(BINDING)
        self.assertEqual(payload, COVR_GOLDEN_ZERO_DIGEST)
        self.assertEqual(len(payload), 158)  # AC-093: 118 + 40
        self.assertEqual(decode_covr(payload).binding, BINDING)

    def test_layout_violations(self) -> None:
        g = COVR_GOLDEN_ZERO_DIGEST

        def at(off: int, new: bytes) -> bytes:
            return g[:off] + new + g[off + len(new) :]

        bad = {
            "schema 1.1": at(0, b"\x01\x00\x01\x00"),
            "schema 2.0": at(0, b"\x02\x00"),
            "raw 2.0": at(4, b"\x02\x00"),
            "flag clear": at(8, b"\x00\x00\x00\x00"),
            "reserved flag": at(8, b"\x03\x00\x00\x00"),
            "capability length": at(48, b"\x13\x00"),
            "capability case": at(50, b"SV0COV"),
            "plan length": at(68, b"\x0d\x00"),
            "plan text": at(70, b"sv0cov.plan.v2"),
            "identity length long": at(84, b"\x29\x00"),
            "identity length short": at(84, b"\x27\x00"),
            "identity space": at(86, b" "),
            "identity control": at(86, b"\x01"),
            "trailing byte": g + b"\x00",
            "truncated": g[:-1],
            "padding": g[:86] + b"\x00" + g[86:],
        }
        for name, data in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(BindingError):
                    decode_covr(data)

    def test_whole_container_digest(self) -> None:
        # A stand-in container: header, a COVR section, and code bytes.
        payload = encode_covr(BINDING)
        prefix = b"SV0B\x02\x00" + b"COVR" + struct.pack("<I", len(payload))
        container = prefix + payload + b"\x70\x00\x00\x00\x00code"
        slot = len(prefix) + len(payload) - 32
        digest = hashlib.sha256(container).digest()  # slot is still zero-filled
        sealed = container[:slot] + digest + container[slot + 32 :]
        verify_container(sealed, slot)
        self.assertEqual(decode_covr(sealed[len(prefix) : len(prefix) + len(payload)]).bytecode_sha256, digest)
        for pos in (0, 7, len(prefix) + 3, len(sealed) - 1, slot):
            with self.subTest(mutated_byte=pos):
                bad = bytearray(sealed)
                bad[pos] ^= 0x01
                with self.assertRaises(BindingError):
                    verify_container(bytes(bad), slot)
        transplanted = b"SV0B\x02\x00" + sealed[6:-4] + b"othr"
        with self.assertRaises(BindingError):
            verify_container(transplanted, slot)


class ProjectionTest(unittest.TestCase):
    def test_v1_and_v2_project_identically(self) -> None:
        v1 = decode_v1(encode_v1(BINDING, BYTECODE), BYTECODE)
        v2 = decode_covr(encode_covr(BINDING, b"\x55" * 32)).binding
        self.assertEqual(v1.semantic_projection(), v2.semantic_projection())
        self.assertNotIn(b"sv0vm-v1", v1.semantic_projection())
        self.assertNotIn(hashlib.sha256(BYTECODE).hexdigest().encode(), v1.semantic_projection())

    def test_projection_distinguishes_plans(self) -> None:
        self.assertNotEqual(BINDING.semantic_projection(), Binding(MAP_ID, 4, IDENT).semantic_projection())


if __name__ == "__main__":
    unittest.main()
