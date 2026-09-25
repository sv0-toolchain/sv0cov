# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Primitives shared by the generated structural validators (SPEC 25.2.2).

Generated modules under ``sv0cov._generated.validators`` call only these
functions and the standard library. They never interpret schema text at run
time.

The type and equality rules follow JSON Schema Draft 2020-12: ``true`` is not
the number 1, an integer is any number with a zero fractional part, and
string lengths count Unicode code points.
"""

from __future__ import annotations

import math


class StructuralError(ValueError):
    """First structural failure: a JSON pointer, the failing keyword, and a detail."""

    def __init__(self, pointer: str, keyword: str, detail: str) -> None:
        super().__init__(f"{pointer or '/'}: {keyword}: {detail}")
        self.pointer = pointer
        self.keyword = keyword
        self.detail = detail


def fail(pointer: str, keyword: str, detail: str) -> None:
    raise StructuralError(pointer, keyword, detail)


def child(pointer: str, token: str | int) -> str:
    """Append one JSON pointer reference token."""
    t = str(token).replace("~", "~0").replace("/", "~1")
    return f"{pointer}/{t}"


def is_number(v: object) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def is_integer(v: object) -> bool:
    if isinstance(v, bool):
        return False
    if isinstance(v, int):
        return True
    return isinstance(v, float) and math.isfinite(v) and v.is_integer()


def is_type(v: object, name: str) -> bool:
    if name == "null":
        return v is None
    if name == "boolean":
        return isinstance(v, bool)
    if name == "object":
        return isinstance(v, dict)
    if name == "array":
        return isinstance(v, list)
    if name == "string":
        return isinstance(v, str)
    if name == "integer":
        return is_integer(v)
    if name == "number":
        return is_number(v)
    raise ValueError(f"unknown type {name!r}")


def json_equal(a: object, b: object) -> bool:
    """JSON instance equality (Draft 2020-12 section 4.2.2)."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if is_number(a) and is_number(b):
        return a == b
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, str) and isinstance(b, str):
        return a == b
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(json_equal(a[k], b[k]) for k in a)
    return False
