#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Regenerate ``vectors.json``: golden point-identity preimages (SPEC 10.3).

This is a second, deliberately separate encoding of SPEC 10.3. It does not
import sv0cov, so the expected bytes do not come from the implementation
under test (SPEC 28.3). Each field is written as its own hex segment with its
byte offset, so a reviewer can check every field against the SPEC table.

Run from the repository root:

    python3 tests/fixtures/point-id/generate_vectors.py > tests/fixtures/point-id/vectors.json
"""

from __future__ import annotations

import hashlib
import json
import struct
import sys

D1 = "00" * 32
D2 = "ff" * 32
D3 = "0123456789abcdef" * 4

KIND_NUMBER = {"function_entry": 1, "region": 2, "branch_outcome": 3, "contract_true": 4, "contract_false": 5}
ENTITY_NUMBER = {"none": 0, "function": 1, "contract": 2}

CASES = [
    # name, path, digest, entity kind, entity name, point kind, start, end, ordinal, discriminator
    ("function-entry", "src/main.sv0", D3, "function", "main", "function_entry", 0, 42, None, "entry"),
    ("region-owned", "src/main.sv0", D3, "function", "main", "region", 16, 30, None, "initializer"),
    ("region-unowned", "lib/consts.sv0", D1, "none", "", "region", 5, 5, None, "expression"),
    ("branch-if-true", "src/main.sv0", D3, "function", "positive", "branch_outcome", 40, 80, 0, "if"),
    ("branch-if-false", "src/main.sv0", D3, "function", "positive", "branch_outcome", 40, 80, 1, "if"),
    ("branch-max-ordinal", "a.sv0", D2, "function", "f", "branch_outcome", 0, 1, 0xFFFFFFFE, "match"),
    ("contract-true", "src/math.sv0", D3, "contract", "math::div#requires0", "contract_true", 100, 118, None, "requires"),
    ("contract-false", "src/math.sv0", D3, "contract", "math::div#requires0", "contract_false", 100, 118, None, "requires"),
    ("max-offsets", "big.sv0", D2, "function", "f", "region", 2**64 - 1, 2**64 - 1, None, "return"),
    ("unicode", "tests/données/測試/😀.sv0", D1, "function", "π::√2", "region", 3, 9, None, "call→é"),
    ("longest-fields", "d/" + "p" * 4092, D2, "function", "n" * 4096, "region", 0, 0, None, "x" * 256),
    ("one-byte-fields", "a", D1, "function", "b", "function_entry", 0, 0, None, "c"),
]


def segments(case: tuple) -> list[tuple[str, bytes]]:
    _, path, digest, ekind, ename, pkind, start, end, ordinal, disc = case
    path_b = path.encode("utf-8")
    name_b = ename.encode("utf-8")
    disc_b = disc.encode("utf-8")
    if ordinal is None:
        ordinal = 0xFFFFFFFF
    return [
        ("domain", b"sv0cov.point.v1\x00"),
        ("identity_major", struct.pack("<H", 1)),
        ("identity_minor", struct.pack("<H", 0)),
        ("path_length", struct.pack("<I", len(path_b))),
        ("path", path_b),
        ("source_digest", bytes.fromhex(digest)),
        ("entity_kind", bytes([ENTITY_NUMBER[ekind]])),
        ("entity_name_length", struct.pack("<I", len(name_b))),
        ("entity_name", name_b),
        ("point_kind", bytes([KIND_NUMBER[pkind]])),
        ("start_byte", struct.pack("<Q", start)),
        ("end_byte", struct.pack("<Q", end)),
        ("outcome_ordinal", struct.pack("<I", ordinal)),
        ("discriminator_length", struct.pack("<I", len(disc_b))),
        ("discriminator", disc_b),
    ]


def main() -> int:
    vectors = []
    for case in CASES:
        name, path, digest, ekind, ename, pkind, start, end, ordinal, disc = case
        segs = segments(case)
        offset = 0
        seg_records = []
        for field, data in segs:
            seg_records.append({"field": field, "hex": data.hex(), "offset": offset})
            offset += len(data)
        whole = b"".join(d for _, d in segs)
        vectors.append(
            {
                "discriminator": disc,
                "end_byte": end,
                "entity_kind": ekind,
                "entity_name": ename,
                "name": name,
                "outcome_ordinal": ordinal,
                "point_id": hashlib.sha256(whole).hexdigest(),
                "point_kind": pkind,
                "preimage_length": len(whole),
                "segments": seg_records,
                "source_digest": digest,
                "source_path": path,
                "start_byte": start,
            }
        )
    doc = {"point_identity_version": "1.0", "vectors": vectors}
    sys.stdout.write(json.dumps(doc, ensure_ascii=False, indent=1, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
