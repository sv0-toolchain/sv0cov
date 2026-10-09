# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Normalized linear counter expressions (CV-204; SPEC 11.1, COV-MAP-016,
COV-MET-017, AC-109).

A region's count is ``E = sum(coefficient_i * count(point_id_i))`` over
runtime-counted points. sv0c establishes from structured flow that ``E`` is
nonnegative for every valid execution; this module checks the encoding and
evaluates it:

- :func:`check_expression` enforces the normalized form: terms strictly
  ordered by bytewise point ID (so unique), integer coefficients that are
  nonzero and within signed 32 bits, and references only to counted points.
  The empty array is the only constant zero. A violation is COV1010.
- :func:`evaluate` evaluates one context with unbounded Python integers
  (no host overflow, no evaluation-order dependence). Exact inputs give an
  exact result; a negative exact result is corrupt or incompatible evidence
  (COV3002); a result above ``UINT64_MAX`` becomes the lower bound
  ``UINT64_MAX``. A saturated point is the interval ``[UINT64_MAX, +inf)``:
  if any negatively weighted point is saturated the result is the
  lower-bound zero (nonnegativity is all that is known); otherwise it is
  the lower bound ``max(0, sum of coefficient * lower endpoint)``, capped.
- :func:`evaluate_contexts` evaluates every context independently and
  aggregates by saturating sum (never re-evaluating aggregated point
  counts); exact zeros are omitted from ``by_context``, inexact zeros kept.

An inexact count carries ``saturated`` and ``lower_bound`` together (SPEC
16.6.3): it proves at least ``value`` executions, so a lower-bound zero is
"not proven executed" and classifies as uncovered.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Mapping

U64_MAX = 2**64 - 1
I32_MIN, I32_MAX = -(2**31), 2**31 - 1


class ExprError(ValueError):
    """``code`` is the registry code: COV1010 (encoding) or COV3002 (evidence)."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Count:
    """A count; ``inexact`` is the equal ``saturated`` / ``lower_bound`` pair."""

    value: int
    inexact: bool = False

    @staticmethod
    def physical(value: int) -> "Count":
        """A raw point count: exactly ``UINT64_MAX`` means saturated."""
        return Count(value, value == U64_MAX)


@dataclass(frozen=True)
class CountRecord:
    """SPEC 16.6.3 count record: per-context counts and their aggregate."""

    by_context: tuple[tuple[int, Count], ...]
    value: int
    inexact: bool

    def to_json(self) -> dict:
        return {
            "by_context": [{"context_index": i, "lower_bound": c.inexact, "saturated": c.inexact, "value": c.value}
                           for i, c in self.by_context],
            "lower_bound": self.inexact,
            "saturated": self.inexact,
            "value": self.value,
        }


def check_expression(expr: object, counted: Iterable[str] | None = None) -> list[tuple[int, str]]:
    """The ``(coefficient, point_id)`` terms of a normalized expression, or
    COV1010. ``counted`` (when given) is the set of runtime-counted point IDs."""
    if not isinstance(expr, dict) or set(expr) != {"terms"} or not isinstance(expr["terms"], list):
        raise ExprError("COV1010", "a counter expression is an object with exactly `terms` (an array)")
    allowed = None if counted is None else set(counted)
    out: list[tuple[int, str]] = []
    prev: bytes | None = None
    for t in expr["terms"]:
        if not isinstance(t, dict) or set(t) != {"coefficient", "point_id"}:
            raise ExprError("COV1010", "a term has exactly `coefficient` and `point_id`")
        c, p = t["coefficient"], t["point_id"]
        if type(c) is not int:
            raise ExprError("COV1010", f"coefficient {c!r} is not an integer")
        if c == 0:
            raise ExprError("COV1010", "zero coefficient")
        if not I32_MIN <= c <= I32_MAX:
            raise ExprError("COV1010", f"coefficient {c} is outside the signed 32-bit range")
        if not isinstance(p, str):
            raise ExprError("COV1010", "point_id is not a string")
        key = p.encode("utf-8")
        if prev is not None and key <= prev:
            raise ExprError("COV1010", f"terms are not strictly ordered by point ID at {p}"
                            + (" (duplicate point)" if key == prev else ""))
        if allowed is not None and p not in allowed:
            raise ExprError("COV1010", f"term references {p}, which is not a runtime-counted point")
        prev = key
        out.append((c, p))
    return out


def evaluate(terms: list[tuple[int, str]], counts: Mapping[str, Count]) -> Count:
    """One context's region count (SPEC 11.1). ``counts`` maps each referenced
    point ID to its count in that context."""
    total = 0
    saturated = False
    for c, p in terms:
        n = counts[p]
        if n.inexact:
            if c < 0:
                return Count(0, True)
            saturated = True
        total += c * n.value  # an inexact point contributes its lower endpoint
    if saturated:
        return Count(min(max(total, 0), U64_MAX), True)
    if total < 0:
        raise ExprError("COV3002", f"the region expression evaluates to {total} on exact counts "
                        "(nonnegative by construction): corrupt or incompatible evidence")
    if total > U64_MAX:
        return Count(U64_MAX, True)
    return Count(total, False)


def evaluate_contexts(terms: list[tuple[int, str]], contexts: Mapping[int, Mapping[str, Count]]) -> CountRecord:
    """Evaluate each context independently, then aggregate by saturating sum."""
    by_context = []
    value = 0
    inexact = False
    for index in sorted(contexts):
        r = evaluate(terms, contexts[index])
        if r.value != 0 or r.inexact:
            by_context.append((index, r))
        value += r.value
        inexact = inexact or r.inexact
    if value > U64_MAX:
        value, inexact = U64_MAX, True
    return CountRecord(tuple(by_context), value, inexact)


def executed(count: Count | CountRecord) -> bool:
    """Proven executed at least once: a lower-bound zero is not."""
    return count.value > 0
