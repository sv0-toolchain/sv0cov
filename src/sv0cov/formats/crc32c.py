# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""CRC32C (Castagnoli), exactly as SPEC 16.4 fixes it.

Width 32; polynomial 0x1edc6f41 (reflected 0x82f63b78); initial value
0xffffffff; reflected input and output; final XOR 0xffffffff. The check
value for ASCII ``123456789`` is 0xe3069283. Raw profiles store the value
little-endian.

Portable table-driven implementation (standard library only). CRC32C
detects accidental corruption; it is not an authenticity mechanism.
"""

from __future__ import annotations

POLY_REFLECTED = 0x82F63B78


def _table() -> tuple[int, ...]:
    table = []
    for n in range(256):
        c = n
        for _ in range(8):
            c = (c >> 1) ^ POLY_REFLECTED if c & 1 else c >> 1
        table.append(c)
    return tuple(table)


_TABLE = _table()


def crc32c_update(state: int, data: bytes | bytearray | memoryview) -> int:
    """Advance a raw (pre-final-XOR) CRC state over ``data``."""
    table = _TABLE
    crc = state
    for b in bytes(data):
        crc = table[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc


def crc32c(data: bytes | bytearray | memoryview) -> int:
    """CRC32C of ``data`` as an unsigned 32-bit integer."""
    return crc32c_update(0xFFFFFFFF, data) ^ 0xFFFFFFFF
