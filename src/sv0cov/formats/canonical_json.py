# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Canonical JSON (SPEC 16.2).

Every sv0cov JSON artifact uses one byte encoding:

- UTF-8 without BOM, valid Unicode scalar values only;
- object keys sorted by UTF-8 byte order, duplicates rejected;
- no insignificant whitespace;
- integers only (no fraction, exponent, NaN, or infinity);
- exactly one final LF and nothing after it.

String escaping is the minimal form: ``"`` and ``\\`` are escaped, the control
characters U+0008, U+0009, U+000A, U+000C, U+000D use their short escapes,
every other control character below U+0020 uses a lowercase ``\\u00xx``
escape, and every other character, including U+007F and non-ASCII, is written
as raw UTF-8.

:func:`decode` accepts any JSON text that satisfies the semantic rules above
(and the resource limits), whether or not its bytes are canonical.
:func:`decode_canonical` additionally requires the input bytes to equal
:func:`encode` of the decoded value. Readers of closed artifacts use
:func:`decode_canonical`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

JsonValue = None | bool | int | str | list["JsonValue"] | dict[str, "JsonValue"]

# Integers are bounded by the widest range any R1 schema uses:
# i64 minimum through u64 maximum (SPEC 25.2.3).
INT_MIN = -(2**63)
INT_MAX = 2**64 - 1


@dataclass(frozen=True)
class Limits:
    """Resource bounds enforced before and during decoding (SPEC 23.2)."""

    max_bytes: int = 64 * 1024 * 1024
    max_depth: int = 64
    max_string_bytes: int = 16 * 1024 * 1024
    max_container_items: int = 16 * 1024 * 1024


DEFAULT_LIMITS = Limits()


class CanonicalJsonError(ValueError):
    """Rejected input. ``reason`` is a stable machine-readable token."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ── decoding ────────────────────────────────────────────────────────────────


def _scan_depth(text: str, limit: int) -> None:
    """Reject nesting deeper than ``limit`` before invoking the parser."""
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > limit:
                raise CanonicalJsonError("depth_limit", f"nesting exceeds {limit}")
        elif ch in "]}":
            depth -= 1


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise CanonicalJsonError("duplicate_key", repr(key))
        obj[key] = value
    return obj


def _parse_int(token: str) -> int:
    digits = token.lstrip("-")
    if len(digits) > 20:
        raise CanonicalJsonError("integer_range", token[:32])
    value = int(token)
    if not INT_MIN <= value <= INT_MAX:
        raise CanonicalJsonError("integer_range", token)
    return value


def _reject_float(token: str) -> Any:
    raise CanonicalJsonError("non_integer_number", token[:32])


def _reject_constant(token: str) -> Any:
    raise CanonicalJsonError("non_integer_number", token)


def _check_values(value: Any, limits: Limits) -> None:
    stack = [value]
    while stack:
        v = stack.pop()
        if isinstance(v, str):
            _check_string(v, limits)
        elif isinstance(v, list):
            if len(v) > limits.max_container_items:
                raise CanonicalJsonError("container_limit", f"array of {len(v)} items")
            stack.extend(v)
        elif isinstance(v, dict):
            if len(v) > limits.max_container_items:
                raise CanonicalJsonError("container_limit", f"object of {len(v)} members")
            for k, item in v.items():
                _check_string(k, limits)
                stack.append(item)


def _check_string(s: str, limits: Limits) -> None:
    try:
        encoded = s.encode("utf-8")
    except UnicodeEncodeError as exc:  # lone surrogate from a \\u escape
        raise CanonicalJsonError("invalid_unicode", "unpaired surrogate") from exc
    if len(encoded) > limits.max_string_bytes:
        raise CanonicalJsonError("string_limit", f"{len(encoded)} bytes")


def decode(data: bytes, limits: Limits = DEFAULT_LIMITS) -> JsonValue:
    """Decode JSON bytes under the SPEC 16.2 semantic rules and ``limits``.

    Requires exactly one final LF. Does not require canonical bytes.
    """
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("decode expects bytes")
    if len(data) > limits.max_bytes:
        raise CanonicalJsonError("size_limit", f"{len(data)} bytes")
    if data.startswith(b"\xef\xbb\xbf"):
        raise CanonicalJsonError("bom")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        raise CanonicalJsonError("final_newline", "exactly one final LF is required")
    try:
        text = bytes(data).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanonicalJsonError("invalid_utf8", str(exc)) from exc
    _scan_depth(text, limits.max_depth)
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJsonError:
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        raise CanonicalJsonError("syntax", str(exc)) from exc
    _check_values(value, limits)
    return value


def decode_canonical(data: bytes, limits: Limits = DEFAULT_LIMITS) -> JsonValue:
    """Decode and require that ``data`` is exactly the canonical encoding."""
    value = decode(data, limits)
    if encode(value) != bytes(data):
        raise CanonicalJsonError("noncanonical", "bytes differ from the canonical encoding")
    return value


# ── encoding ────────────────────────────────────────────────────────────────

_SHORT_ESCAPES = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}


def _encode_string(s: str, out: list[str]) -> None:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalJsonError("invalid_unicode", "unpaired surrogate") from exc
    out.append('"')
    for ch in s:
        esc = _SHORT_ESCAPES.get(ch)
        if esc is not None:
            out.append(esc)
        elif ch < " ":
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')


def _utf8_key(item: tuple[str, Any]) -> bytes:
    return item[0].encode("utf-8")


def _encode_value(value: Any, out: list[str], depth: int) -> None:
    if depth > DEFAULT_LIMITS.max_depth:
        raise CanonicalJsonError("depth_limit", f"nesting exceeds {DEFAULT_LIMITS.max_depth}")
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if not INT_MIN <= value <= INT_MAX:
            raise CanonicalJsonError("integer_range", str(value))
        out.append(str(int(value)))
    elif isinstance(value, str):
        _encode_string(value, out)
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for i, item in enumerate(value):
            if i:
                out.append(",")
            _encode_value(item, out, depth + 1)
        out.append("]")
    elif isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise CanonicalJsonError("non_string_key", repr(key))
        out.append("{")
        for i, (key, item) in enumerate(sorted(value.items(), key=_utf8_key)):
            if i:
                out.append(",")
            _encode_string(key, out)
            out.append(":")
            _encode_value(item, out, depth + 1)
        out.append("}")
    elif isinstance(value, float):
        raise CanonicalJsonError("non_integer_number", repr(value))
    else:
        raise CanonicalJsonError("unsupported_type", type(value).__name__)


def encode(value: JsonValue) -> bytes:
    """Return the canonical UTF-8 bytes of ``value``, including the final LF."""
    out: list[str] = []
    _encode_value(value, out, 1)
    out.append("\n")
    return "".join(out).encode("utf-8")
