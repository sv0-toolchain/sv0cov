# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""VM coverage bindings (SPEC 15.3, 15.4, 16.8).

- ``sv0cov.vm-binding`` 1.0: the closed canonical JSON companion that binds
  ``sv0vm-v1-coverage`` bytecode (length + SHA-256) to a program map.
- ``COVR`` 1.0: the packed little-endian inline section payload of coverage-
  capable ``sv0vm-v2-typed`` bytecode. Its final 32 bytes hold the SHA-256 of
  the complete container with that slot zero-filled.
- The shared semantic projection: both physical forms reduce to identical
  canonical bytes for the same program and plan; container-specific physical
  provenance (v1 length and digest, v2 bytecode digest) is excluded.

Interpretation recorded here: the projection holds the coverage capability,
not the bytecode profile name, because the profile names differ between v1
and v2 while SPEC 16.8 requires byte-identical projections.
"""

from __future__ import annotations

import hashlib
import re
import struct
from dataclasses import dataclass

from sv0cov._generated.validators import sv0cov_vm_binding_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError

COVERAGE_CAPABILITY = "sv0cov.coverage.v1"
PLAN_CAPABILITY = "sv0cov.plan.v1"
V1_PROFILE = "sv0vm-v1-coverage"
COVR_TAG = b"COVR"
RE_DIGEST = re.compile(r"[0-9a-f]{64}")
COVR_FIXED = 118  # payload length without the compiler identity


class BindingError(ValueError):
    """``code``: COV2201 invalid binding, COV2202 bytecode binding mismatch."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _check_identity(identity: str) -> bytes:
    data = identity.encode("utf-8") if isinstance(identity, str) else b""
    if not 1 <= len(data) <= 128 or any(not 0x21 <= b <= 0x7E for b in data):
        raise BindingError("COV2201", "compiler identity must be 1..128 printable ASCII bytes without whitespace")
    return data


@dataclass(frozen=True)
class Binding:
    """The coverage facts both VM profiles carry."""

    map_id: str
    program_counter_count: int
    compiler_identity: str

    def semantic_projection(self) -> bytes:
        """Canonical bytes shared by the v1 companion and the v2 COVR payload."""
        return encode(
            {
                "capabilities": [COVERAGE_CAPABILITY],
                "compiler_identity": self.compiler_identity,
                "map_id": self.map_id,
                "plan_capability": PLAN_CAPABILITY,
                "program_counter_count": self.program_counter_count,
                "raw_profile_version": "1.0",
                "schema": "sv0cov.vm-binding-semantic",
                "version": "1.0",
            }
        )


# ── v1 companion ────────────────────────────────────────────────────────────


def encode_v1(binding: Binding, bytecode: bytes) -> bytes:
    _check_identity(binding.compiler_identity)
    if not RE_DIGEST.fullmatch(binding.map_id) or not 0 <= binding.program_counter_count <= 0xFFFFFFFF or not bytecode:
        raise BindingError("COV2201", "invalid map ID, counter count, or empty bytecode")
    return encode(
        {
            "bytecode_length": len(bytecode),
            "bytecode_sha256": hashlib.sha256(bytecode).hexdigest(),
            "capabilities": [COVERAGE_CAPABILITY],
            "compiler_identity": binding.compiler_identity,
            "map_id": binding.map_id,
            "plan_capability": PLAN_CAPABILITY,
            "profile": V1_PROFILE,
            "program_counter_count": binding.program_counter_count,
            "raw_profile_version": "1.0",
            "schema": "sv0cov.vm-binding",
            "version": "1.0",
        }
    )


def decode_v1(data: bytes, bytecode: bytes | None = None) -> Binding:
    """Validate companion bytes, and (when given) bind them to the exact bytecode."""
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise BindingError("COV2201", str(exc)) from exc
    for key in ("bytecode_sha256", "map_id"):
        if not RE_DIGEST.fullmatch(obj[key]):
            raise BindingError("COV2201", f"{key} must be lowercase hexadecimal")
    _check_identity(obj["compiler_identity"])
    if bytecode is not None:
        if len(bytecode) != obj["bytecode_length"] or hashlib.sha256(bytecode).hexdigest() != obj["bytecode_sha256"]:
            raise BindingError("COV2202", "binding does not match the supplied bytecode")
    return Binding(obj["map_id"], obj["program_counter_count"], obj["compiler_identity"])


# ── v2 COVR payload ─────────────────────────────────────────────────────────


def encode_covr(binding: Binding, bytecode_sha256: bytes = bytes(32)) -> bytes:
    """Packed COVR 1.0 payload. Pass the zero digest when building the preimage."""
    ident = _check_identity(binding.compiler_identity)
    if not RE_DIGEST.fullmatch(binding.map_id) or not 0 <= binding.program_counter_count <= 0xFFFFFFFF:
        raise BindingError("COV2201", "invalid map ID or counter count")
    if len(bytecode_sha256) != 32:
        raise BindingError("COV2201", "bytecode digest is 32 bytes")
    return b"".join(
        (
            struct.pack("<HHHHII", 1, 0, 1, 0, 0x00000001, binding.program_counter_count),
            bytes.fromhex(binding.map_id),
            struct.pack("<H", 18),
            COVERAGE_CAPABILITY.encode(),
            struct.pack("<H", 14),
            PLAN_CAPABILITY.encode(),
            struct.pack("<H", len(ident)),
            ident,
            bytecode_sha256,
        )
    )


@dataclass(frozen=True)
class Covr:
    binding: Binding
    bytecode_sha256: bytes


def decode_covr(payload: bytes) -> Covr:
    """Validate a COVR 1.0 payload's exact layout (not yet its digest)."""
    if len(payload) < COVR_FIXED + 1:
        raise BindingError("COV2201", "COVR payload too short")
    schema_major, schema_minor, raw_major, raw_minor, flags, count = struct.unpack_from("<HHHHII", payload, 0)
    if (schema_major, schema_minor) != (1, 0):
        raise BindingError("COV2201", f"unsupported COVR schema {schema_major}.{schema_minor}")
    if (raw_major, raw_minor) != (1, 0):
        raise BindingError("COV2201", "unsupported raw-profile version")
    if flags != 0x00000001:
        raise BindingError("COV2201", "required_flags must be exactly COVER_HIT_REQUIRED")
    map_id = payload[16:48]
    if struct.unpack_from("<H", payload, 48)[0] != 18 or payload[50:68] != COVERAGE_CAPABILITY.encode():
        raise BindingError("COV2201", "coverage capability must be exactly sv0cov.coverage.v1")
    if struct.unpack_from("<H", payload, 68)[0] != 14 or payload[70:84] != PLAN_CAPABILITY.encode():
        raise BindingError("COV2201", "plan capability must be exactly sv0cov.plan.v1")
    n = struct.unpack_from("<H", payload, 84)[0]
    if len(payload) != COVR_FIXED + n:
        raise BindingError("COV2201", "COVR length must be exactly 118 + compiler identity length")
    try:
        ident = payload[86 : 86 + n].decode("ascii")
    except UnicodeDecodeError as exc:
        raise BindingError("COV2201", "compiler identity is not ASCII") from exc
    _check_identity(ident)
    return Covr(Binding(map_id.hex(), count, ident), payload[86 + n :])


def container_digest(container: bytes, slot_offset: int) -> bytes:
    """SHA-256 of ``container`` with its 32-byte digest slot zero-filled (SPEC 15.4)."""
    if not 0 <= slot_offset <= len(container) - 32:
        raise BindingError("COV2202", "digest slot outside the container")
    return hashlib.sha256(container[:slot_offset] + bytes(32) + container[slot_offset + 32 :]).digest()


def verify_container(container: bytes, slot_offset: int) -> None:
    """Reject v2 bytecode whose stored COVR digest does not match its bytes."""
    stored = container[slot_offset : slot_offset + 32]
    if container_digest(container, slot_offset) != stored:
        raise BindingError("COV2202", "COVR bytecode_sha256 does not match the container")
