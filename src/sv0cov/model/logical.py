# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Shared scalar types (SPEC 10.1, 21.3.1).

These are validators for values that are already in canonical form. They
never normalize: a caller that holds an unnormalized path must normalize it
first, and these functions then confirm the result.
"""

from __future__ import annotations

import re

RE_DIGEST = re.compile(r"[0-9a-f]{64}")
RE_DRIVE = re.compile(r"[A-Za-z]:")
DEFAULT_MAX_BYTES = 4096


class LogicalValueError(ValueError):
    """A value violates a SPEC scalar rule. ``field`` names the offending input."""

    def __init__(self, field: str, detail: str) -> None:
        super().__init__(f"{field}: {detail}")
        self.field = field
        self.detail = detail


def utf8_bytes(value: str, field: str) -> bytes:
    if not isinstance(value, str):
        raise LogicalValueError(field, "must be a string")
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError:
        raise LogicalValueError(field, "is not valid Unicode (unpaired surrogate)") from None


def check_logical_string(value: str, field: str, *, min_bytes: int = 0, max_bytes: int = DEFAULT_MAX_BYTES) -> bytes:
    """Valid UTF-8, no NUL/CR/LF, byte length within bounds. Returns the bytes."""
    data = utf8_bytes(value, field)
    if any(c in value for c in "\x00\r\n"):
        raise LogicalValueError(field, "contains NUL, CR, or LF")
    if not min_bytes <= len(data) <= max_bytes:
        raise LogicalValueError(field, f"byte length {len(data)} outside {min_bytes}..{max_bytes}")
    return data


def check_logical_path(value: str, field: str = "path") -> bytes:
    """A normalized project-relative logical path (SPEC 10.1). Returns the bytes."""
    data = check_logical_string(value, field, min_bytes=1)
    if value.startswith("/"):
        raise LogicalValueError(field, "is absolute")
    if RE_DRIVE.match(value):
        raise LogicalValueError(field, "begins with a drive designator")
    if "\\" in value:
        raise LogicalValueError(field, "contains a backslash; the only separator is '/'")
    for segment in value.split("/"):
        if segment in ("", ".", ".."):
            raise LogicalValueError(field, f"has an empty, '.', or '..' component: {value!r}")
    return data


def check_digest(value: str, field: str = "digest") -> bytes:
    """A lowercase hexadecimal SHA-256 digest. Returns the 32 raw bytes."""
    if not isinstance(value, str) or not RE_DIGEST.fullmatch(value):
        raise LogicalValueError(field, "must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)
