# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Run identity and the run-set manifest 1.0 (SPEC 14.3, 17.2).

A run ID is 16 nonzero bytes spelled as exactly 32 lowercase hexadecimal
characters. ``new_run_id`` draws them from the operating system's
cryptographically secure source; there is no fallback.
"""

from __future__ import annotations

import os
import re

from sv0cov._generated.validators import sv0cov_run_set_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError

RE_RUN_ID = re.compile(r"[0-9a-f]{32}")
ZERO_RUN_ID = "0" * 32


class RunIdError(ValueError):
    """Invalid run ID or run-set manifest (SPEC code COV3003 or COV2001 by context)."""


def parse_run_id(text: str) -> bytes:
    """Strictly decode a run ID spelling; returns the 16 raw bytes."""
    if not isinstance(text, str) or not RE_RUN_ID.fullmatch(text):
        raise RunIdError("a run ID is exactly 32 lowercase hexadecimal characters")
    if text == ZERO_RUN_ID:
        raise RunIdError("the all-zero run ID is forbidden")
    return bytes.fromhex(text)


def new_run_id(entropy=os.urandom) -> str:
    """A fresh run ID from the OS CSPRNG. An all-zero draw is an error, not retried silently."""
    data = entropy(16)
    if len(data) != 16:
        raise RunIdError("entropy source returned the wrong number of bytes")
    if data == bytes(16):
        raise RunIdError("entropy source returned all zero bytes")
    return data.hex()


def encode_run_set(run_ids: list[str]) -> bytes:
    """Canonical manifest bytes for a set of run IDs (validated, then sorted)."""
    for r in run_ids:
        parse_run_id(r)
    if len(set(run_ids)) != len(run_ids):
        raise RunIdError("duplicate run ID")
    if not run_ids:
        raise RunIdError("a run set needs at least one run ID")
    return encode({"run_ids": sorted(run_ids), "schema": "sv0cov.run-set", "version": "1.0"})


def decode_run_set(data: bytes) -> list[str]:
    """Validate manifest bytes; returns the run IDs in their (strictly increasing) order."""
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise RunIdError(f"invalid run-set manifest: {exc}") from exc
    ids = obj["run_ids"]
    for r in ids:
        parse_run_id(r)
    if any(not a < b for a, b in zip(ids, ids[1:])):
        raise RunIdError("run_ids must be unique and strictly increasing")
    return ids
