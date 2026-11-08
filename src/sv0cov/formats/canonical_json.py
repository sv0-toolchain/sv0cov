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
import re
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
    if value.__class__ is str:
        _check_string(value, limits)
    if value.__class__ not in (list, dict):
        return
    if limits.max_depth < 1:
        raise CanonicalJsonError("depth_limit", f"nesting exceeds {limits.max_depth}")
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        if len(v) > limits.max_container_items:
            raise CanonicalJsonError("container_limit", f"{'array' if v.__class__ is list else 'object'} of {len(v)} {'items' if v.__class__ is list else 'members'}")
        if v.__class__ is dict:
            for k in v:
                _check_string(k, limits)
            v = v.values()
        for item in v:
            cls = item.__class__
            if cls is str:
                _check_string(item, limits)
            elif cls is list or cls is dict:
                if depth >= limits.max_depth:
                    raise CanonicalJsonError("depth_limit", f"nesting exceeds {limits.max_depth}")
                stack.append((item, depth + 1))


def _check_string(s: str, limits: Limits) -> None:
    if s.isascii() and len(s) <= limits.max_string_bytes:
        return
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
    # The bracket scan is a per-character Python loop, so it runs only when parsing fails
    # (a depth violation must still win over any other finding); a parsed value's own
    # nesting is its bracket depth, which _check_values measures.
    try:
        value = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJsonError:
        _scan_depth(text, limits.max_depth)
        raise
    except (json.JSONDecodeError, RecursionError) as exc:
        _scan_depth(text, limits.max_depth)
        raise CanonicalJsonError("syntax", str(exc)) from exc
    _check_values(value, limits)
    return value


def _fast_canonical(data: bytes, limits: Limits) -> tuple[JsonValue] | None:
    """``(value,)`` when ``data`` is certainly canonical JSON within ``limits``, else ``None``.

    Parses without the per-pair and per-integer hooks of :func:`decode`, then lets the
    canonical re-encoding stand in for them: a duplicate key would shorten it and a
    noncanonical integer would print differently. A lone surrogate (only reachable through a
    ``\\u`` escape, which canonical bytes use for control characters alone) fails the UTF-8
    encode. What remains is checked by one walk: depth, container sizes, string sizes, and
    integer range (only when a 19-digit run makes a range violation possible)."""
    if (not isinstance(data, (bytes, bytearray)) or len(data) > limits.max_bytes or data.startswith(b"\xef\xbb\xbf")
            or not data.endswith(b"\n") or data.endswith(b"\n\n") or limits.max_depth > DEFAULT_LIMITS.max_depth):
        return None
    try:
        value = json.loads(bytes(data).decode("utf-8"), parse_float=_reject_float, parse_constant=_reject_constant)
        if not _fits(value, limits, _LONG_DIGITS.search(data) is not None):
            return None
        canonical = _dumps(value).encode("utf-8")
        if len(canonical) + 1 != len(data) or not data.startswith(canonical):
            return None
    except (ValueError, RecursionError):  # CanonicalJsonError, JSONDecodeError, UnicodeError
        return None
    return (value,)


_LONG_DIGITS = re.compile(rb"[0-9]{19}")


def _fits(value: Any, limits: Limits, check_ints: bool) -> bool:
    """Depth, container and string limits, and (when asked) the integer range, of a parsed value."""
    if value.__class__ is str:
        return len(value.encode("utf-8")) <= limits.max_string_bytes
    if value.__class__ is int:
        return not check_ints or INT_MIN <= value <= INT_MAX
    if value.__class__ not in (list, dict):
        return True
    chars = limits.max_string_bytes // 4  # a string of at most this many characters fits in any encoding
    level, depth = [value], 1
    while level:
        if depth > limits.max_depth:
            return False
        nxt: list = []
        for c in level:
            if len(c) > limits.max_container_items:
                return False
            if c.__class__ is dict:
                if c and max(map(len, c)) > chars and any(len(k.encode("utf-8")) > limits.max_string_bytes for k in c):
                    return False
                c = c.values()
            for x in c:
                cls = x.__class__
                if cls is str:
                    if len(x) > chars and len(x.encode("utf-8")) > limits.max_string_bytes:
                        return False
                elif cls is list or cls is dict:
                    nxt.append(x)
                elif check_ints and cls is int and not INT_MIN <= x <= INT_MAX:
                    return False
        level, depth = nxt, depth + 1
    return True


def decode_canonical(data: bytes, limits: Limits = DEFAULT_LIMITS) -> JsonValue:
    """Decode and require that ``data`` is exactly the canonical encoding."""
    fast = _fast_canonical(data, limits)
    if fast is not None:
        return fast[0]
    # Anything the fast path could not vouch for gets the full checks, and their findings.
    value = decode(data, limits)
    # decode has proven every property encode checks (types, ranges, keys, scalar values),
    # except depth when the caller allows deeper nesting than encode does.
    canonical = _dumps(value).encode("utf-8") + b"\n" if limits.max_depth <= DEFAULT_LIMITS.max_depth else encode(value)
    if canonical != bytes(data):
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


# The stdlib C encoder writes exactly the canonical form (Python orders str keys by code
# point, which is UTF-8 byte order for scalar values; control characters get the short or
# lowercase \\u00xx escapes) but rejects none of what SPEC 16.2 forbids, so encode checks first.
_encoder = json.JSONEncoder(ensure_ascii=False, separators=(",", ":"), sort_keys=True, allow_nan=False, check_circular=False)
_c_encoder = getattr(json.encoder, "c_make_encoder", None)
if _c_encoder is not None:  # built once: JSONEncoder.encode rebuilds it on every call, which dominates small values
    _c_encoder = _c_encoder(None, _encoder.default, json.encoder.encode_basestring, None, ":", ",", True, False, False)

    def _dumps(value: Any) -> str:
        return "".join(_c_encoder(value, 0))
else:
    _dumps = _encoder.encode
_SCALARS = (str, bool, type(None))


def _check_encodable(value: Any) -> None:
    """Raise what :func:`_encode_value` would for ``value``, without encoding it. Exact
    builtin types take the fast path; anything else is handed to ``_encode_value``."""
    limit = DEFAULT_LIMITS.max_depth
    stack = [(value, 1)]
    while stack:
        v, depth = stack.pop()
        cls = v.__class__
        if cls is dict:
            for key in v:
                if key.__class__ is not str:
                    _encode_value(v, [], depth)  # raises for the bad key
            items = v.values()
        elif cls is list or cls is tuple:
            items = v
        else:
            _encode_value(v, [], depth)
            continue
        if not v:
            continue
        if depth >= limit:
            raise CanonicalJsonError("depth_limit", f"nesting exceeds {limit}")
        for item in items:
            cls = item.__class__
            if cls in _SCALARS:
                continue
            if cls is int:
                if not INT_MIN <= item <= INT_MAX:
                    raise CanonicalJsonError("integer_range", str(item))
                continue
            stack.append((item, depth + 1))


def encode(value: JsonValue) -> bytes:
    """Return the canonical UTF-8 bytes of ``value``, including the final LF."""
    if value.__class__ not in (dict, list, tuple):
        out: list[str] = []
        _encode_value(value, out, 1)
        out.append("\n")
        return "".join(out).encode("utf-8")
    _check_encodable(value)
    try:
        return _dumps(value).encode("utf-8") + b"\n"
    except UnicodeEncodeError as exc:
        raise CanonicalJsonError("invalid_unicode", "unpaired surrogate") from exc
