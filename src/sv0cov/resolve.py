# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Minimal map + raw profile reader (CV-170, BL-012).

Resolves raw profiles through their program map: counter index -> counted
point -> count. This is the F0 reader the parity comparator (CV-171) builds
on; R0 merge, contexts, policy, and reports come later (SPEC 16.5, 17).

- The map is validated with :func:`sv0cov.formats.map.validate_map`.
- Each profile is decoded against the map's ID and counter count
  (:func:`sv0cov.formats.rawprofile.decode`: structure, completion marker,
  CRC32C, counter bounds, overflow bitmap).
- A profile supplied twice (same profile ID, same bytes) contributes once;
  the same profile ID with different bytes is COV2112 (SPEC 16.5 identity
  rules). No profile at all is COV3001.
- Counts add per counter with unsigned 64-bit saturation. A count is
  ``saturated`` (and so only a lower bound) when any contributing count was
  saturated or the sum exceeded ``2**64 - 1``.

Point counts add into one aggregate across every accepted profile; they are
also kept per context (profiles with the same context add together), so
derived region counts can be evaluated per context and then aggregated
(:meth:`Resolution.context_counts`, SPEC 11.1; CV-204).

    python -m sv0cov.resolve MAP PROFILE [PROFILE ...]

prints the resolution as canonical JSON (an internal F0 tool, not a public
``sv0cov`` command).
"""

from __future__ import annotations

import hashlib
import sys
from dataclasses import dataclass
from typing import Iterable, Mapping

from sv0cov.expr import Count
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.map import MapError, validate_map
from sv0cov.formats.rawprofile import U64_MAX, RawProfile, RawProfileError, Tier, decode


class ResolveError(ValueError):
    """``code`` is the registry code of the first problem found."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PointCount:
    point_id: str
    kind: str  # "function_entry" | "branch_outcome" | ...
    entity: str | None  # the owning entity's qualified name
    counter_index: int
    value: int
    saturated: bool  # also lower_bound: the true count is at least ``value``


@dataclass(frozen=True)
class Resolution:
    map_id: str
    run_ids: tuple[str, ...]  # sorted, distinct
    profile_ids: tuple[str, ...]  # accepted, sorted, distinct
    backends: tuple[str, ...]  # sorted, distinct
    contexts: tuple[str | None, ...]  # sorted (None first), distinct
    points: tuple[PointCount, ...]  # every counted point, in counter order
    # Per context (in ``contexts`` order): (value, saturated) per point, in
    # ``points`` order.
    per_context: tuple[tuple[tuple[int, bool], ...], ...] = ()

    def counts(self) -> dict[str, int]:
        """point ID -> count."""
        return {p.point_id: p.value for p in self.points}

    def context_counts(self) -> dict[int, dict[str, Count]]:
        """context index (into ``contexts``) -> point ID -> that context's count."""
        return {i: {p.point_id: Count(v, sat) for p, (v, sat) in zip(self.points, row)}
                for i, row in enumerate(self.per_context)}

    def to_json(self) -> dict:
        return {
            "backends": list(self.backends),
            "contexts": list(self.contexts),
            "map_id": self.map_id,
            "points": [
                {
                    "counter_index": p.counter_index,
                    "entity": p.entity,
                    "kind": p.kind,
                    "point_id": p.point_id,
                    "saturated": p.saturated,
                    "value": p.value,
                }
                for p in self.points
            ],
            "profile_ids": list(self.profile_ids),
            "run_ids": list(self.run_ids),
            "schema": "sv0cov.f0-resolution",
            "version": "1.0",
        }


def resolve(
    map_bytes: bytes,
    profiles: Iterable[bytes],
    *,
    sources: Mapping[str, bytes] | None = None,
    tier: Tier | None = None,
) -> Resolution:
    try:
        m = validate_map(map_bytes, sources=sources)
    except MapError as exc:
        raise ResolveError(exc.code, f"map: {exc.detail}") from exc
    n = m["program_counter_count"]
    map_id = bytes.fromhex(m["map_id"])

    accepted: dict[bytes, tuple[str, RawProfile]] = {}  # profile ID -> (SHA-256 of bytes, profile)
    for k, data in enumerate(profiles):
        digest = hashlib.sha256(data).hexdigest()
        try:
            prof = decode(data, map_counter_count=n, expected_map_id=map_id, tier=tier)
        except RawProfileError as exc:
            raise ResolveError(exc.code, f"profile {k}: {exc.detail}") from exc
        seen = accepted.get(prof.profile_id)
        if seen is not None:
            if seen[0] != digest:
                raise ResolveError("COV2112", f"profile {k}: profile ID {prof.profile_id.hex()} is reused with different bytes")
            continue  # an identical copy contributes once
        accepted[prof.profile_id] = (digest, prof)
    if not accepted:
        raise ResolveError("COV3001", "no raw profile was supplied")

    total = [0] * n
    saturated = [False] * n
    ctx_key = lambda c: (c is not None, c or "")  # noqa: E731
    contexts = sorted({p.context for _, p in accepted.values()}, key=ctx_key)
    ctx_total = {c: [0] * n for c in contexts}
    ctx_sat = {c: [False] * n for c in contexts}
    for _, prof in accepted.values():
        for index, count in prof.counts:
            for tot, sat in ((total, saturated), (ctx_total[prof.context], ctx_sat[prof.context])):
                s = tot[index] + count
                if count == U64_MAX or s > U64_MAX:
                    sat[index] = True
                tot[index] = min(s, U64_MAX)

    entities = m["entities"]
    points = sorted(
        (
            PointCount(
                point_id=p["point_id"],
                kind=p["kind"],
                entity=None if p["entity_index"] is None else entities[p["entity_index"]]["qualified_name"],
                counter_index=p["counter_index"],
                value=total[p["counter_index"]],
                saturated=saturated[p["counter_index"]],
            )
            for p in m["points"]
            if p.get("counter_index") is not None
        ),
        key=lambda p: p.counter_index,
    )
    profs = [p for _, p in accepted.values()]
    return Resolution(
        map_id=m["map_id"],
        run_ids=tuple(sorted({p.run_id.hex() for p in profs})),
        profile_ids=tuple(sorted(pid.hex() for pid in accepted)),
        backends=tuple(sorted({p.backend for p in profs})),
        contexts=tuple(contexts),
        points=tuple(points),
        per_context=tuple(tuple((ctx_total[c][p.counter_index], ctx_sat[c][p.counter_index]) for p in points)
                          for c in contexts),
    )


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) < 2:
        print("usage: python -m sv0cov.resolve MAP PROFILE [PROFILE ...]", file=sys.stderr)
        return 2
    try:
        with open(args[0], "rb") as f:
            map_bytes = f.read()
        datas = []
        for path in args[1:]:
            with open(path, "rb") as f:
                datas.append(f.read())
        r = resolve(map_bytes, datas)
    except OSError as exc:
        print(f"error[COV2010]: {exc.strerror}: {exc.filename}", file=sys.stderr)
        return 1
    except ResolveError as exc:
        print(f"error[{exc.code}]: {exc.detail}", file=sys.stderr)
        return 1
    sys.stdout.buffer.write(encode(r.to_json()))
    return 0


if __name__ == "__main__":
    sys.exit(main())
