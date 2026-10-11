# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The merge engine (CV-223; SPEC 17.1-17.3, 17.5; COV-MRG-001..010,
AC-011, AC-013, AC-089, AC-097).

:func:`merge` takes the bytes of every supplied map and raw profile and
returns indexed evidence (:mod:`sv0cov.model.indexed`). It works in this
order, and nothing is combined before every input has been classified:

1. **Inventory.** Every input gets a record, whatever happens to it.
2. **Maps.** A map is accepted when :func:`sv0cov.formats.map.validate_map`
   accepts its bytes and its definitions agree with every other accepted
   map. Two maps that define one source, entity, point, region, line,
   branch, contract or exclusion differently are both rejected.
3. **Profiles.** A profile is decoded on its own, then against its map. It
   is ``incomplete`` when it is truncated or lacks its completion marker,
   ``rejected`` for any other failure, an unknown or rejected map, a
   profile-ID collision, or exact counts that make one of its map's regions
   negative (no run of the mapped program produces those).
4. **Copies and collisions.** Inputs with the same profile ID and the same
   bytes are one profile and count once. One profile ID with different
   bytes is a collision: every such input is rejected. Different profile
   IDs stay distinct however equal their contents are. Names decide
   nothing.
5. **Run selection** and **combination** are done by
   :func:`sv0cov.model.indexed.build_indexed`: counts add by point ID and
   context with 64-bit saturation.

The result does not depend on the order of the inputs. It is ``complete``
only under SPEC 16.5.7. ``publishable`` says whether a merge command may
write it: always when complete, and otherwise only as visibly incomplete
diagnostic evidence under ``allow_rejected_inputs`` (which itself makes the
evidence incomplete).

:func:`select_runs` turns the two command-line forms into a run selection
and refuses every malformed request with ``COV3003``; no evidence is
produced for a request that names no valid run set.

Reading files, size-limited streaming, and publication belong to the
``merge`` command (CV-226, CV-227).
"""

from __future__ import annotations

import hashlib
import itertools
from dataclasses import dataclass
from typing import Iterable, Sequence

from sv0cov.expr import Count, ExprError, check_expression, evaluate
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.map import MapError, map_limits, validate_map
from sv0cov.formats.rawprofile import Header, RawProfile, RawProfileError, Tier, decode, peek_header
from sv0cov.formats.runset import RunIdError, decode_run_set, parse_run_id
from sv0cov.model.indexed import MapInput, ProfileInput, RunSelection, build_indexed, read_indexed
from sv0cov.model.semantic import ModelError, build_semantic

GLOBAL_DETAIL = {
    "COV3001": "no raw profile was accepted",
    "COV3002": "a map or raw-profile input was rejected or incomplete",
    "COV3003": "the accepted profiles' run IDs are not the selected run set",
    "COV3004": "one source path appears with two different digests",
}


class MergeError(ValueError):
    """No evidence can be produced. ``code`` is ``COV3003`` for a malformed
    run-selection request and ``COV3002`` for inputs the engine cannot
    classify."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Artifact:
    """One supplied input: its basename and its bytes (``None`` when the
    bytes could not be read). ``fault`` is a finding the caller made before
    the engine saw the input, as ``(code, detail)``: a file over the size
    tier, an uncommitted temporary. Such an input is inventoried and not
    decoded."""

    name: str
    data: bytes | None
    fault: tuple[str, str] | None = None


@dataclass(frozen=True)
class Finding:
    """Why an input was not accepted (``kind`` ``map`` or ``profile``), or a
    finding about the whole merge (``kind`` ``merge``, no name)."""

    code: str
    kind: str
    name: str | None
    detail: str


@dataclass(frozen=True)
class Duplicate:
    """An accepted artifact that was supplied more than once. ``name`` is
    the inventoried name; ``copies`` counts the extra inputs."""

    kind: str
    name: str
    artifact_sha256: str
    copies: int


@dataclass(frozen=True)
class MergeResult:
    indexed: dict
    data: bytes
    complete: bool
    publishable: bool
    findings: tuple[Finding, ...]
    duplicates: tuple[Duplicate, ...]


def select_runs(expect_runs: Sequence[str] | None = None, manifest: bytes | None = None) -> RunSelection:
    """The run selection for ``--expect-run`` values or ``--run-manifest``
    bytes (SPEC 17.2). Neither gives the implicit single-run rule. Raises
    :class:`MergeError` ``COV3003`` when both are given, the list is empty
    or repeats a value, an ID is invalid, or the manifest is invalid."""
    if expect_runs is not None and manifest is not None:
        raise MergeError("COV3003", "--expect-run and --run-manifest cannot be combined")
    try:
        if manifest is not None:
            return RunSelection("manifest", tuple(decode_run_set(manifest)), hashlib.sha256(manifest).hexdigest())
        if expect_runs is None:
            return RunSelection()
        for r in expect_runs:
            parse_run_id(r)
    except RunIdError as exc:
        raise MergeError("COV3003", str(exc)) from exc
    if not expect_runs:
        raise MergeError("COV3003", "at least one expected run ID is required")
    if len(set(expect_runs)) != len(expect_runs):
        raise MergeError("COV3003", "an expected run ID is repeated")
    return RunSelection("explicit-list", tuple(sorted(expect_runs)))


def _compatible(maps: Sequence[dict]) -> bool:
    try:
        build_semantic(maps, [])
    except ModelError:
        return False
    return True


def _conflicting(maps: dict[str, dict]) -> set[str]:
    """Map IDs whose definitions disagree with another map's, or with
    themselves. Every disagreement is between two records, so pairs find
    them all."""
    if _compatible(list(maps.values())):
        return set()
    bad = {mid for mid, m in maps.items() if not _compatible([m])}
    for a, b in itertools.combinations(sorted(set(maps) - bad), 2):
        if not _compatible([maps[a], maps[b]]):
            bad |= {a, b}
    return bad


class _Zero(dict):
    def __missing__(self, key: str) -> Count:
        return Count(0, False)


class _Regions:
    """One accepted map's region expressions, to test a profile's counts
    against. Exact counts that make a region negative cannot come from a
    run of the mapped program (SPEC 11.1)."""

    def __init__(self, m: dict) -> None:
        self.slots = {p["counter_index"]: p["point_id"] for p in m["points"] if p["counter_index"] is not None}
        self.terms = [(r["region_index"], check_expression(r["counter_expression"])) for r in m["regions"]]

    def impossible(self, p: RawProfile) -> str | None:
        counts = _Zero({self.slots[i]: Count.physical(v) for i, v in p.counts})
        for n, terms in self.terms:
            try:
                evaluate(terms, counts)
            except ExprError as exc:
                return f"region {n} of its map: {exc.detail}"
        return None


def merge(
    maps: Iterable[Artifact],
    profiles: Iterable[Artifact],
    *,
    run_selection: RunSelection = RunSelection(),
    allow_rejected_inputs: bool = False,
    tier: Tier | None = None,
    execution: dict | None = None,
    tool_version: str | None = None,
    saturation_policy: str = "fail",
) -> MergeResult:
    """Classify every input, then combine the accepted ones."""
    tier = tier or Tier.standard()
    map_arts, profile_arts = list(maps), list(profiles)
    # A finding belongs to the artifact, not to its name: two files may share a basename.
    found: dict[tuple[str, Artifact], dict[str, str]] = {}

    def reject(kind: str, a: Artifact, code: str, detail: str) -> None:
        found.setdefault((kind, a), {}).setdefault(code, detail)

    # Maps: validate each, then require the valid ones to agree.
    decoded: dict[Artifact, dict] = {}
    for a in set(map_arts):
        if a.fault is not None:
            reject("map", a, *a.fault)
            continue
        if a.data is None:
            reject("map", a, "COV1010", "the map could not be read")
            continue
        try:
            decoded[a] = validate_map(a.data, limits=map_limits(tier.name))
        except MapError as exc:
            reject("map", a, exc.code, exc.detail)
    conflicting = _conflicting({m["map_id"]: m for m in decoded.values()})
    accepted_maps: dict[str, dict] = {}
    for a, m in decoded.items():
        if m["map_id"] in conflicting:
            reject("map", a, "COV3002", "its definitions disagree with another supplied map")
        else:
            accepted_maps[m["map_id"]] = m

    # Profiles: decode alone first, so identity is known before any map is consulted.
    alone: dict[Artifact, RawProfile] = {}
    incomplete: set[Artifact] = set()
    for a in set(profile_arts):
        if a.fault is not None:
            reject("profile", a, *a.fault)
            if a.fault[0] == "COV2011":
                incomplete.add(a)
            continue
        if a.data is None:
            reject("profile", a, "COV2010", "the profile could not be read")
            continue
        try:
            alone[a] = decode(a.data, tier=tier)
        except RawProfileError as exc:
            reject("profile", a, exc.code, exc.detail)
            if exc.code == "COV2011":
                incomplete.add(a)
    versions: dict[bytes, set[bytes]] = {}
    for a, p in alone.items():
        versions.setdefault(p.profile_id, set()).add(a.data)
    accepted: dict[Artifact, RawProfile] = {}
    regions: dict[str, _Regions] = {}
    for a, p in alone.items():
        mid = p.map_id.hex()
        if len(versions[p.profile_id]) > 1:
            reject("profile", a, "COV2112", f"profile ID {p.profile_id.hex()} is used by different bytes")
        if mid not in accepted_maps:
            why = "was rejected" if mid in conflicting else "was not supplied or is invalid"
            reject("profile", a, "COV2111", f"its map {mid} {why}")
            continue
        try:
            bound = decode(a.data, map_counter_count=accepted_maps[mid]["program_counter_count"], expected_map_id=p.map_id, tier=tier)
        except RawProfileError as exc:
            reject("profile", a, exc.code, exc.detail)
            continue
        if mid not in regions:
            regions[mid] = _Regions(accepted_maps[mid])
        why = regions[mid].impossible(bound)
        if why is not None:
            reject("profile", a, "COV3002", why)
        if ("profile", a) not in found:
            accepted[a] = bound

    def codes(kind: str, a: Artifact) -> tuple[str, ...]:
        return tuple(sorted(found.get((kind, a), ())))

    map_inputs = [MapInput(a.name, a.data, None if ("map", a) in found else decoded[a], codes("map", a)) for a in set(map_arts)]
    profile_inputs = []
    for a in set(profile_arts):
        if a in accepted:
            profile_inputs.append(ProfileInput(a.name, a.data, accepted[a]))
            continue
        head = alone.get(a) or (None if a.data is None else peek_header(a.data))
        fields = {} if head is None else dict(
            backend=head.backend, has_context=not isinstance(head, Header) or head.has_context, context=head.context,
            map_id=head.map_id.hex(), profile_id=head.profile_id.hex(), run_id=head.run_id.hex())
        profile_inputs.append(ProfileInput(a.name, a.data, None, "incomplete" if a in incomplete else "rejected",
                                           codes("profile", a), **fields))

    try:
        obj = build_indexed(map_inputs, profile_inputs, run_selection=run_selection, execution=execution,
                            allow_rejected_inputs=allow_rejected_inputs, tier=tier, tool_version=tool_version,
                            saturation_policy=saturation_policy)
        data = encode(obj)
        read_indexed(data, tier=tier.name)
    except (ModelError, IndexedError) as exc:
        raise MergeError("COV3002", f"the classified inputs do not form valid evidence: {exc}") from exc

    findings = [Finding(code, kind, a.name, detail) for (kind, a), by_code in found.items() for code, detail in by_code.items()]
    findings += [Finding(code, "merge", None, GLOBAL_DETAIL[code]) for code in obj["diagnostics"]]
    duplicates = []
    for kind, arts in (("map", map_arts), ("profile", profile_arts)):
        names: dict[str, list[str]] = {}
        for a in arts:
            if (kind, a) not in found:
                names.setdefault(hashlib.sha256(a.data).hexdigest(), []).append(a.name)
        duplicates += [Duplicate(kind, min(ns, key=lambda n: n.encode("utf-8")), sha, len(ns) - 1)
                       for sha, ns in names.items() if len(ns) > 1]
    complete = obj["semantic"]["complete"]
    return MergeResult(
        indexed=obj, data=data, complete=complete, publishable=complete or allow_rejected_inputs,
        findings=tuple(sorted(set(findings), key=lambda f: (f.kind, (f.name or "").encode("utf-8"), f.code, f.detail))),
        duplicates=tuple(sorted(duplicates, key=lambda d: (d.kind, d.artifact_sha256))))
