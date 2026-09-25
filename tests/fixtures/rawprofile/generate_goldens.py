#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Regenerate the raw-profile 1.0 golden files (SPEC 16.4).

A second, deliberately separate encoding of the byte layout: it does not
import sv0cov, and it computes CRC32C bit by bit rather than by table. Run
from the repository root:

    python3 tests/fixtures/rawprofile/generate_goldens.py
"""

from __future__ import annotations

import hashlib
import json
import struct
from pathlib import Path

HERE = Path(__file__).resolve().parent
U64_MAX = 2**64 - 1


def crc32c_bitwise(data: bytes) -> int:
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
    return crc ^ 0xFFFFFFFF


CASES = [
    # name, backend flag, map counters, context (None = absent), counts
    ("native-basic", 0x04, 4, None, [(0, 1), (2, 7)]),
    ("vm-v1-empty-context", 0x08, 3, "", [(1, 1)]),
    ("vm-v2-context-saturated", 0x10, 65, "ctx/é", [(0, 5), (64, U64_MAX)]),
    ("native-zero-counter", 0x04, 0, None, []),
    ("native-no-hits", 0x04, 3, None, []),
]
BACKENDS = {0x04: "native", 0x08: "vm-v1", 0x10: "vm-v2"}


def build(n: int, backend: int, counters: int, context: str | None, counts: list) -> bytes:
    map_id = bytes([0x10 + n]) * 32
    run_id = bytes(range(1, 17))
    profile_id = bytes(range(0xA0, 0xB0))
    flags = backend
    ctx = b""
    if context is not None:
        flags |= 0x01
        ctx = context.encode("utf-8")
    saturated = [i for i, c in counts if c == U64_MAX]
    words = []
    if saturated:
        flags |= 0x02
        words = [0] * ((counters + 63) // 64)
        for i in saturated:
            words[i // 64] |= 1 << (i % 64)
    body = b"SV0PRF\x00\x00"
    body += struct.pack("<H", 1) + struct.pack("<H", 0) + struct.pack("<I", flags)
    body += map_id + run_id + profile_id
    body += struct.pack("<I", len(ctx)) + ctx
    body += struct.pack("<I", len(counts))
    for index, count in counts:
        body += struct.pack("<I", index) + struct.pack("<Q", count)
    body += struct.pack("<I", len(words))
    for w in words:
        body += struct.pack("<Q", w)
    body += b"SV0DONE!"
    return body + struct.pack("<I", crc32c_bitwise(body))


def main() -> None:
    index = []
    for n, (name, backend, counters, context, counts) in enumerate(CASES):
        data = build(n, backend, counters, context, counts)
        (HERE / f"{name}.sv0profraw").write_bytes(data)
        index.append(
            {
                "backend": BACKENDS[backend],
                "context": context,
                "counts": [[i, c] for i, c in counts],
                "file": f"{name}.sv0profraw",
                "map_counter_count": counters,
                "map_id": (bytes([0x10 + n]) * 32).hex(),
                "profile_id": bytes(range(0xA0, 0xB0)).hex(),
                "run_id": bytes(range(1, 17)).hex(),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    text = json.dumps({"goldens": index}, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    (HERE / "goldens.json").write_text(text, encoding="utf-8")


if __name__ == "__main__":
    main()
