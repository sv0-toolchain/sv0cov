# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Global point identity, version 1.0 (SPEC 10.3).

A point ID is the lowercase hexadecimal SHA-256 of a dedicated binary
preimage. The preimage fields, in order:

======================  =====================================================
domain separator        16 bytes ``sv0cov.point.v1\\0``
identity major, minor   ``u16le`` 1, ``u16le`` 0
logical source path     ``u32le`` length (1..4096), UTF-8 bytes
source digest           32 raw SHA-256 bytes
entity kind             ``u8``: 0 none, 1 function, 2 contract
entity qualified name   ``u32le`` length (0 iff kind 0, else 1..4096), UTF-8
point kind              ``u8``: 1 function entry, 2 region, 3 branch outcome,
                        4 contract true, 5 contract false
start byte, end byte    ``u64le`` each, start <= end
outcome ordinal         ``u32le``: 0..0xfffffffe for a branch outcome,
                        exactly 0xffffffff otherwise
semantic discriminator  ``u32le`` length (1..256), UTF-8 bytes
======================  =====================================================

No padding, alignment, BOM, terminator, or Unicode normalization.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass
from enum import IntEnum

from sv0cov.model.logical import (
    LogicalValueError,
    check_digest,
    check_logical_path,
    check_logical_string,
)

DOMAIN = b"sv0cov.point.v1\x00"
IDENTITY_VERSION = (1, 0)
POINT_IDENTITY_VERSION = "1.0"
NO_ORDINAL = 0xFFFFFFFF
MAX_ORDINAL = 0xFFFFFFFE
U64_MAX = 2**64 - 1


class EntityKind(IntEnum):
    NONE = 0
    FUNCTION = 1
    CONTRACT = 2


class PointKind(IntEnum):
    FUNCTION_ENTRY = 1
    REGION = 2
    BRANCH_OUTCOME = 3
    CONTRACT_TRUE = 4
    CONTRACT_FALSE = 5


# Map vocabulary (SPEC 16.3.4) for each point kind.
POINT_KIND_NAMES = {
    PointKind.FUNCTION_ENTRY: "function_entry",
    PointKind.REGION: "region",
    PointKind.BRANCH_OUTCOME: "branch_outcome",
    PointKind.CONTRACT_TRUE: "contract_true",
    PointKind.CONTRACT_FALSE: "contract_false",
}

# Entity kinds each point kind may reference. A function entry belongs to a
# function; contract outcomes belong to their contract entity; regions and
# branch outcomes belong to their nearest enclosing function or to no entity.
ALLOWED_ENTITY_KINDS = {
    PointKind.FUNCTION_ENTRY: {EntityKind.FUNCTION},
    PointKind.REGION: {EntityKind.NONE, EntityKind.FUNCTION},
    PointKind.BRANCH_OUTCOME: {EntityKind.NONE, EntityKind.FUNCTION},
    PointKind.CONTRACT_TRUE: {EntityKind.CONTRACT},
    PointKind.CONTRACT_FALSE: {EntityKind.CONTRACT},
}


@dataclass(frozen=True)
class PointIdentity:
    """Every input to a point ID and nothing else (SPEC 10.3)."""

    source_path: str
    source_digest: str
    entity_kind: EntityKind
    entity_name: str
    point_kind: PointKind
    start_byte: int
    end_byte: int
    outcome_ordinal: int
    discriminator: str


def _u32_len(data: bytes) -> bytes:
    return struct.pack("<I", len(data))


def preimage(p: PointIdentity) -> bytes:
    """Validate ``p`` and return its exact point-identity preimage bytes."""
    try:
        entity_kind = EntityKind(p.entity_kind)
    except ValueError:
        raise LogicalValueError("entity_kind", f"invalid value {p.entity_kind!r}") from None
    try:
        point_kind = PointKind(p.point_kind)
    except ValueError:
        raise LogicalValueError("point_kind", f"invalid value {p.point_kind!r}") from None
    if entity_kind not in ALLOWED_ENTITY_KINDS[point_kind]:
        raise LogicalValueError(
            "entity_kind", f"{entity_kind.name.lower()} cannot own a {POINT_KIND_NAMES[point_kind]} point"
        )

    path = check_logical_path(p.source_path, "source_path")
    digest = check_digest(p.source_digest, "source_digest")
    if entity_kind is EntityKind.NONE:
        if p.entity_name != "":
            raise LogicalValueError("entity_name", "must be empty when there is no entity")
        name = b""
    else:
        name = check_logical_string(p.entity_name, "entity_name", min_bytes=1)

    for field, value in (("start_byte", p.start_byte), ("end_byte", p.end_byte)):
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U64_MAX:
            raise LogicalValueError(field, "must be an integer in 0..2^64-1")
    if p.end_byte < p.start_byte:
        raise LogicalValueError("end_byte", "is before start_byte")

    ordinal = p.outcome_ordinal
    if isinstance(ordinal, bool) or not isinstance(ordinal, int):
        raise LogicalValueError("outcome_ordinal", "must be an integer")
    if point_kind is PointKind.BRANCH_OUTCOME:
        if not 0 <= ordinal <= MAX_ORDINAL:
            raise LogicalValueError("outcome_ordinal", "must be 0..4294967294 for a branch outcome")
    elif ordinal != NO_ORDINAL:
        raise LogicalValueError("outcome_ordinal", "must be 4294967295 for a non-branch point")

    disc = check_logical_string(p.discriminator, "discriminator", min_bytes=1, max_bytes=256)

    return b"".join(
        (
            DOMAIN,
            struct.pack("<HH", *IDENTITY_VERSION),
            _u32_len(path),
            path,
            digest,
            struct.pack("<B", entity_kind),
            _u32_len(name),
            name,
            struct.pack("<B", point_kind),
            struct.pack("<QQ", p.start_byte, p.end_byte),
            struct.pack("<I", ordinal),
            _u32_len(disc),
            disc,
        )
    )


def point_id(p: PointIdentity) -> str:
    """The lowercase hexadecimal point ID of ``p``."""
    return hashlib.sha256(preimage(p)).hexdigest()
