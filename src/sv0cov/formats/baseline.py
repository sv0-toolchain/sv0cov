# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ratchet baseline, ``sv0cov.baseline`` 1.0 (CV-313; SPEC 22.4;
COV-POL-005, BL-051).

A baseline is the digest-pinned summary a ratchet compares a report with:

- for each of the five metrics, the covered and total units and the units
  exclusions removed from the denominator;
- the number of exclusion records;
- the compiled sources, each with its digest;
- the saturation policy and the metric schema the counts were made under;
- the producer and the Git commit it was made at (``null`` outside Git).

``baseline_sha256`` pins it: the SHA-256 of the canonical bytes of the
object without that member. A file whose pin does not match was changed by
hand or damaged, and is refused like any other invalid baseline.

:func:`encode_baseline` adds the pin and returns canonical bytes;
:func:`decode_baseline` checks bytes (canonical JSON within the reader's
size, the closed schema, lexical forms, order, ``covered <= total`` and the
pin) and raises :class:`BaselineError` otherwise.
"""

from __future__ import annotations

import hashlib
import re

from sv0cov._generated.validators import sv0cov_baseline_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.map import map_limits
from sv0cov.formats.structural import StructuralError
from sv0cov.model.logical import LogicalValueError, check_logical_path

METRICS = ("branch", "contract", "function", "line", "region")
#: The metric schema this build counts under: a baseline made under another is incompatible.
METRIC_SCHEMA = "sv0cov.report 1.0"
RE_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
RE_DIGEST = re.compile(r"[0-9a-f]{64}")
PIN = "baseline_sha256"


class BaselineError(ValueError):
    """A baseline that cannot be used: unreadable, invalid, or not matching its pin."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _printable(text: str, low: int) -> bool:
    return text.isascii() and all(low <= ord(ch) <= 0x7E for ch in text)


def pin(body: dict) -> str:
    """The SHA-256 a baseline without its pin is pinned by."""
    return hashlib.sha256(encode({k: v for k, v in body.items() if k != PIN})).hexdigest()


def _check(obj: dict) -> None:
    if obj["commit"] is not None and not RE_COMMIT.fullmatch(obj["commit"]):
        raise BaselineError("commit: a Git object name is 40 or 64 lowercase hex digits")
    if not RE_DIGEST.fullmatch(obj[PIN]):
        raise BaselineError(f"{PIN}: not a SHA-256 digest")
    if not _printable(obj["metric_schema"], 0x20):
        raise BaselineError("metric_schema: printable ASCII")
    if not _printable(obj["tool"]["version"], 0x21):
        raise BaselineError("tool/version: each byte is ASCII 0x21 through 0x7e")
    for m in METRICS:
        c = obj["metrics"][m]
        if c["covered"] > c["total"]:
            raise BaselineError(f"metrics/{m}: covered is more than total")
    paths = []
    for n, s in enumerate(obj["sources"]):
        try:
            paths.append(check_logical_path(s["path"], f"sources/{n}/path"))
        except LogicalValueError as exc:
            raise BaselineError(exc.detail) from None
        if not RE_DIGEST.fullmatch(s["digest"]):
            raise BaselineError(f"sources/{n}/digest: not a SHA-256 digest")
    if any(not a < b for a, b in zip(paths, paths[1:])):
        raise BaselineError("sources: not strictly ordered by path, or a path is repeated")
    if pin(obj) != obj[PIN]:
        raise BaselineError("the baseline does not match its own SHA-256 pin: it was changed after it was written")


def check_baseline(obj: object) -> dict:
    """The schema and every rule of a decoded baseline."""
    try:
        _schema.validate(obj)
    except StructuralError as exc:
        raise BaselineError(str(exc)) from None
    assert isinstance(obj, dict)
    _check(obj)
    return obj


def decode_baseline(data: bytes, *, tier: str = "standard") -> dict:
    """Baseline bytes -> the validated object."""
    try:
        obj = decode_canonical(data, map_limits(tier))
    except CanonicalJsonError as exc:
        raise BaselineError(f"not a canonical JSON baseline within the {tier} tier ({exc})") from None
    return check_baseline(obj)


def encode_baseline(body: dict) -> bytes:
    """Canonical bytes of ``body`` (every member but the pin) with its pin."""
    obj = {**{k: v for k, v in body.items() if k != PIN}, PIN: "0" * 64}
    obj[PIN] = pin(obj)
    check_baseline(obj)
    return encode(obj)


__all__ = ["BaselineError", "METRIC_SCHEMA", "check_baseline", "decode_baseline", "encode_baseline", "pin"]
