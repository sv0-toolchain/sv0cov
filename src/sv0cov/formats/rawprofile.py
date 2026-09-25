# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Raw profile 1.0 codec (SPEC 16.4).

Little-endian layout::

    magic[8] = "SV0PRF\\0\\0"
    u16 major = 1, u16 minor = 0
    u32 flags                      bit0 CONTEXT_PRESENT, bit1 OVERFLOW_PRESENT,
                                   bit2 BACKEND_NATIVE, bit3 BACKEND_VM_V1,
                                   bit4 BACKEND_VM_V2; bits 5..31 zero
    u8  map_id[32], run_id[16], profile_id[16]
    u32 context_length, u8 context[context_length]
    u32 pair_count, repeat: (u32 local_counter_index, u64 count)
    u32 overflow_word_count, u64 overflow_words[...]
    u64 completion_marker = "SV0DONE!"
    u32 crc32c                     over every preceding byte

The reader enforces its configured resource tier before anything else,
rejects any version other than 1.0 before reading flags or lengths, checks
every length with exact arithmetic before touching variable-length data,
checks the completion marker before computing CRC32C, and checks CRC32C
before decoding counts. A raw file can never raise the reader's ceilings.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

from sv0cov.formats.crc32c import crc32c

MAGIC = b"SV0PRF\x00\x00"
VERSION = (1, 0)
COMPLETION = b"SV0DONE!"
COMPLETION_VALUE = 0x21454E4F44305653
U64_MAX = 2**64 - 1

CONTEXT_PRESENT = 0x01
OVERFLOW_PRESENT = 0x02
BACKEND_FLAGS = {"native": 0x04, "vm-v1": 0x08, "vm-v2": 0x10}
KNOWN_FLAGS = 0x1F

HEADER = 84  # magic .. context_length
MAX_CONTEXT = 256
PROTOCOL_MAX_COUNTERS = 4294967295
PROTOCOL_MAX_BYTES = 68719476736


class RawProfileError(ValueError):
    """``code`` is the registry code: COV2011 incomplete, COV2012 checksum,
    COV2103 version, COV2110 structure, COV2111 map mismatch, COV6001 limits."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Tier:
    """Effective raw-profile resource ceilings (SPEC 16.4, 18.2.2)."""

    name: str
    max_counters: int
    max_bytes: int

    @classmethod
    def standard(cls) -> Tier:
        return cls("standard", 4194304, 67108864)

    @classmethod
    def large(cls) -> Tier:
        return cls("large", 16777216, 268435456)

    @classmethod
    def custom(cls, max_counters: int, max_bytes: int) -> Tier:
        for name, v, top in (("max_counters", max_counters, PROTOCOL_MAX_COUNTERS), ("max_bytes", max_bytes, PROTOCOL_MAX_BYTES)):
            if isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= top:
                raise ValueError(f"custom {name} must be an integer in 1..{top}")
        return cls("custom", max_counters, max_bytes)


@dataclass(frozen=True)
class RawProfile:
    map_id: bytes  # 32 raw bytes
    run_id: bytes  # 16 raw bytes, nonzero
    profile_id: bytes  # 16 raw bytes, nonzero
    backend: str  # "native" | "vm-v1" | "vm-v2"
    context: str | None  # None = absent; "" = explicitly empty
    counts: tuple[tuple[int, int], ...]  # sorted (local_counter_index, count), counts > 0

    def saturated(self) -> list[int]:
        return [i for i, c in self.counts if c == U64_MAX]


def _words(n_counters: int) -> int:
    return (n_counters + 63) // 64


def encoded_length(context_bytes: int, pairs: int, overflow_words: int) -> int:
    return HEADER + context_bytes + 4 + 12 * pairs + 4 + 8 * overflow_words + 8 + 4


# ── writer ──────────────────────────────────────────────────────────────────


def encode(p: RawProfile, map_counter_count: int, tier: Tier | None = None) -> bytes:
    """Serialize a complete profile bound to a map with ``map_counter_count`` counters."""
    tier = tier or Tier.standard()
    if map_counter_count > tier.max_counters:
        raise RawProfileError("COV6001", f"map has {map_counter_count} counters; tier {tier.name} allows {tier.max_counters}")
    if len(p.map_id) != 32 or len(p.run_id) != 16 or len(p.profile_id) != 16:
        raise RawProfileError("COV2110", "map_id is 32 bytes; run_id and profile_id are 16 bytes")
    if p.run_id == bytes(16) or p.profile_id == bytes(16):
        raise RawProfileError("COV2110", "run_id and profile_id must be nonzero")
    if p.backend not in BACKEND_FLAGS:
        raise RawProfileError("COV2110", f"unknown backend {p.backend!r}")
    flags = BACKEND_FLAGS[p.backend]
    ctx = b""
    if p.context is not None:
        ctx = p.context.encode("utf-8")
        if len(ctx) > MAX_CONTEXT:
            raise RawProfileError("COV2110", "context exceeds 256 bytes")
        flags |= CONTEXT_PRESENT
    previous = -1
    for index, count in p.counts:
        if not previous < index < map_counter_count:
            raise RawProfileError("COV2110", "counts must be strictly increasing indexes below the map counter count")
        if not 0 < count <= U64_MAX:
            raise RawProfileError("COV2110", "sparse counts must be nonzero u64 values")
        previous = index
    saturated = p.saturated()
    words = [0] * _words(map_counter_count) if saturated else []
    for i in saturated:
        words[i // 64] |= 1 << (i % 64)
    if saturated:
        flags |= OVERFLOW_PRESENT
    total = encoded_length(len(ctx), len(p.counts), len(words))
    if total > tier.max_bytes:
        raise RawProfileError("COV6001", f"profile would be {total} bytes; tier {tier.name} allows {tier.max_bytes}")
    out = bytearray()
    out += MAGIC + struct.pack("<HHI", *VERSION, flags)
    out += p.map_id + p.run_id + p.profile_id
    out += struct.pack("<I", len(ctx)) + ctx
    out += struct.pack("<I", len(p.counts))
    for index, count in p.counts:
        out += struct.pack("<IQ", index, count)
    out += struct.pack("<I", len(words))
    for w in words:
        out += struct.pack("<Q", w)
    out += COMPLETION
    out += struct.pack("<I", crc32c(out))
    assert len(out) == total
    return bytes(out)


# ── reader ──────────────────────────────────────────────────────────────────


def _u32(data: bytes, at: int) -> int:
    return struct.unpack_from("<I", data, at)[0]


def decode(
    data: bytes,
    *,
    map_counter_count: int | None = None,
    expected_map_id: bytes | None = None,
    tier: Tier | None = None,
) -> RawProfile:
    """Validate and decode one complete raw profile.

    ``map_counter_count`` (when the bound map is known) enables the counter
    bound and exact bitmap-length checks; ``expected_map_id`` rejects a
    profile bound to another map.
    """
    tier = tier or Tier.standard()
    n = len(data)
    if n > tier.max_bytes:
        raise RawProfileError("COV6001", f"{n} bytes exceeds tier {tier.name} ({tier.max_bytes})")
    if n < 12:
        raise RawProfileError("COV2011", "truncated before the version")
    if data[:8] != MAGIC:
        raise RawProfileError("COV2110", "bad magic")
    if struct.unpack_from("<HH", data, 8) != VERSION:
        raise RawProfileError("COV2103", f"unsupported raw-profile version {struct.unpack_from('<HH', data, 8)}")
    if n < HEADER:
        raise RawProfileError("COV2011", "truncated inside the fixed header")
    flags = _u32(data, 12)
    if flags & ~KNOWN_FLAGS:
        raise RawProfileError("COV2110", f"unknown flag bits {flags & ~KNOWN_FLAGS:#x}")
    backends = [name for name, bit in BACKEND_FLAGS.items() if flags & bit]
    if len(backends) != 1:
        raise RawProfileError("COV2110", "exactly one backend flag must be set")
    map_id, run_id, profile_id = data[16:48], data[48:64], data[64:80]
    if run_id == bytes(16) or profile_id == bytes(16):
        raise RawProfileError("COV2110", "run_id and profile_id must be nonzero")
    ctx_len = _u32(data, 80)
    if ctx_len > MAX_CONTEXT:
        raise RawProfileError("COV2110", "context longer than 256 bytes")
    if not flags & CONTEXT_PRESENT and ctx_len:
        raise RawProfileError("COV2110", "context bytes without CONTEXT_PRESENT")
    at = HEADER + ctx_len
    if n < at + 4:
        raise RawProfileError("COV2011", "truncated before pair_count")
    pair_count = _u32(data, at)
    limit = tier.max_counters if map_counter_count is None else min(tier.max_counters, map_counter_count)
    if pair_count > limit:
        raise RawProfileError("COV6001" if pair_count > tier.max_counters else "COV2110", f"pair_count {pair_count} exceeds {limit}")
    words_at = at + 4 + 12 * pair_count
    if n < words_at + 4:
        raise RawProfileError("COV2011", "truncated inside the counter pairs")
    words = _u32(data, words_at)
    if words > _words(tier.max_counters):
        raise RawProfileError("COV6001", "overflow_word_count exceeds the tier")
    expected_total = encoded_length(ctx_len, pair_count, words)
    if expected_total > tier.max_bytes:
        raise RawProfileError("COV6001", "declared lengths exceed the tier")
    if n < expected_total:
        raise RawProfileError("COV2011", "truncated before the completion marker")
    if n > expected_total:
        raise RawProfileError("COV2110", "trailing bytes after the checksum")
    if data[expected_total - 12 : expected_total - 4] != COMPLETION:
        raise RawProfileError("COV2011", "missing or corrupt completion marker")
    if crc32c(memoryview(data)[: expected_total - 4]) != _u32(data, expected_total - 4):
        raise RawProfileError("COV2012", "CRC32C mismatch")

    if expected_map_id is not None and map_id != expected_map_id:
        raise RawProfileError("COV2111", "profile is bound to a different map")
    try:
        context = data[HEADER:at].decode("utf-8") if flags & CONTEXT_PRESENT else None
    except UnicodeDecodeError as exc:
        raise RawProfileError("COV2110", "context is not valid UTF-8") from exc
    counts = []
    previous = -1
    for k in range(pair_count):
        index, count = struct.unpack_from("<IQ", data, at + 4 + 12 * k)
        if index <= previous:
            raise RawProfileError("COV2110", "counter pairs must be strictly increasing by index")
        if count == 0:
            raise RawProfileError("COV2110", "sparse pairs must be nonzero")
        if map_counter_count is not None and index >= map_counter_count:
            raise RawProfileError("COV2110", f"counter index {index} is outside the map")
        counts.append((index, count))
        previous = index
    bitmap = [struct.unpack_from("<Q", data, words_at + 4 + 8 * k)[0] for k in range(words)]
    saturated = {i for i, c in counts if c == U64_MAX}
    if flags & OVERFLOW_PRESENT:
        if map_counter_count is not None and words != _words(map_counter_count):
            raise RawProfileError("COV2110", "overflow_word_count must be ceil(counters / 64)")
        bits = {w * 64 + b for w, word in enumerate(bitmap) for b in range(64) if word >> b & 1}
        if not bits:
            raise RawProfileError("COV2110", "OVERFLOW_PRESENT with an empty bitmap")
        if map_counter_count is not None and any(i >= map_counter_count for i in bits):
            raise RawProfileError("COV2110", "overflow bit set beyond the map counter count")
        if bits != saturated:
            raise RawProfileError("COV2110", "overflow bits must equal the saturated (u64 max) pairs")
    else:
        if words:
            raise RawProfileError("COV2110", "overflow words without OVERFLOW_PRESENT")
        if saturated:
            raise RawProfileError("COV2110", "a u64-max count requires its overflow bit")
    if map_counter_count == 0 and (pair_count or words):
        raise RawProfileError("COV2110", "a zero-counter map admits no pairs or overflow words")
    return RawProfile(map_id, run_id, profile_id, backends[0], context, tuple(counts))
