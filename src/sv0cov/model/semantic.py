# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Build the indexed semantic model (CV-221; SPEC 16.5.5, 11.1, 11.4, 11.5,
12, 21.3.4, 21.3.8; BL-023, COV-MET-017, COV-FMT-041).

:func:`build_semantic` turns validated program maps and decoded, accepted raw
profiles into one ``sv0cov.indexed-semantic`` 1.0 object: the source-level
meaning of a run, with nothing about how its counts were transported.

- **Union.** Sources, entities, points, regions, branches, contracts and
  exclusions of every map are merged and reindexed in the canonical orders.
  Equal definitions deduplicate. Two definitions that disagree for one
  identity (a point ID, an entity, a source's ownership, ...) are
  incompatible maps and fail with COV3002. One path with two digests is a
  source-version conflict: both sources stay, COV3004 is recorded, and the
  model is incomplete.
- **Contexts.** Every distinct profile context (absent first, then bytewise
  UTF-8), plus any the caller adds for inventoried but rejected profiles.
- **Points.** A profile's counts reach points through its own map's counter
  bindings and add per context with unsigned 64-bit saturation. A count is
  inexact (``saturated`` = ``lower_bound``) when a contribution was
  ``UINT64_MAX`` or a sum passed it. An uncounted point is the exact zero.
- **Regions.** Each region's expression is evaluated per context with
  interval lower bounds and the context results are aggregated
  (:mod:`sv0cov.expr`); an inexact zero is kept.
- **Lines.** Membership is inverted from the regions' ``line_numbers``
  alone; no source file is opened. A line is present when any region lists
  it. ``region_indices`` are its ``line_contributing`` regions. Status comes
  from the contributing ``user`` regions: all executed is ``covered``, some
  ``partial``, none ``uncovered`` (a lower-bound zero is not executed).
  With no such region the line is ``excluded`` when an excluded region
  lists it, else ``non_executable``.
- **Branches and contracts.** An outcome's count is its point's count; an
  eligible outcome is ``covered`` when that count is positive. A
  runtime-checked clause reports ``mixed``, ``evaluated_true``,
  ``evaluated_false`` or ``not_evaluated`` from its two counts.
- **Saturation.** The inexact physical points and the inexact regions. The
  policy is the caller's (``fail`` until R1's ``allow-ordinary``);
  ``ineligible_uses`` is left empty here because which uses exist is a
  report-time fact.

``complete`` is the caller's transport verdict (inputs, run selection)
unless the model itself recorded a diagnostic. The output is independent of
the order of ``maps`` and ``profiles``.
"""

from __future__ import annotations

from typing import Iterable, Sequence

from sv0cov.expr import U64_MAX, Count, CountRecord, ExprError, check_expression, evaluate_contexts
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.rawprofile import RawProfile

CAPABILITIES = ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "line-membership",
                "normalized-linear-expressions", "saturation-lower-bounds", "semantic-function-ownership", "source-digests"]
ELIGIBLE_METRICS = ["branch", "function", "line", "region"]
ZERO = Count(0, False)


class ModelError(ValueError):
    """``code``: COV3002 incompatible or corrupt inputs, COV2111 a profile
    whose map is not among the maps, COV2112 a profile ID used twice."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class _Counts(dict):
    """point ID -> Count for one context; a point never hit is the exact zero."""

    def __missing__(self, key: str) -> Count:
        return ZERO


def context_key(value: str | None) -> tuple[bool, bytes]:
    """Ordering of context values: absent first, then bytewise UTF-8 (SPEC 21.3.3)."""
    return (value is not None, (value or "").encode("utf-8"))


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _span_key(r: dict) -> tuple[int, int]:
    return (r["span"]["start_byte"], r["span"]["end_byte"])


class _Union:
    """Records keyed by identity; a second definition must equal the first."""

    def __init__(self, what: str) -> None:
        self.what = what
        self.records: dict[tuple, dict] = {}

    def add(self, key: tuple, record: dict) -> None:
        seen = self.records.setdefault(key, record)
        if seen is not record and seen != record:
            raise ModelError("COV3002", f"two maps define the same {self.what} differently")

    def ordered(self) -> list[tuple[tuple, dict]]:
        return sorted(self.records.items(), key=lambda kv: kv[0])


def build_semantic(
    maps: Sequence[dict],
    profiles: Iterable[RawProfile],
    *,
    extra_contexts: Iterable[str | None] = (),
    complete: bool = True,
    diagnostics: Iterable[str] = (),
    saturation_policy: str = "fail",
) -> dict:
    """The semantic object for validated ``maps`` and accepted ``profiles``.

    ``maps`` are objects returned by :func:`sv0cov.formats.map.validate_map`;
    ``profiles`` were decoded against their map. ``extra_contexts`` are
    contexts of inventoried profiles that contribute no count.
    ``complete`` and ``diagnostics`` carry the caller's transport findings.
    """
    if saturation_policy not in ("allow-ordinary", "fail"):
        raise ValueError(f"unknown saturation policy {saturation_policy!r}")
    by_id: dict[str, dict] = {}
    for m in maps:
        seen = by_id.setdefault(m["map_id"], m)
        if seen is not m and seen != m:
            raise ModelError("COV3002", f"two different maps carry the map ID {m['map_id']}")
    ordered_maps = [by_id[k] for k in sorted(by_id)]
    found = set(diagnostics)

    # Sources: (path, digest) -> ownership and package.
    src_union = _Union("source")
    for m in ordered_maps:
        for s in m["sources"]:
            src_union.add((_b(s["path"]), s["digest"]), {"ownership": s["ownership"], "package": s["package"], "path": s["path"],
                                                         "digest": s["digest"]})
    src_index = {key: n for n, (key, _) in enumerate(src_union.ordered())}
    sources = [{"digest": r["digest"], "ownership": r["ownership"], "package": r["package"], "path": r["path"], "source_index": n}
               for n, (_, r) in enumerate(src_union.ordered())]
    paths = [s["path"] for s in sources]
    if len(set(paths)) != len(paths):
        found.add("COV3004")

    def src_of(m: dict, i: int) -> int:
        s = m["sources"][i]
        return src_index[(_b(s["path"]), s["digest"])]

    # Entities.
    ent_union = _Union("entity")
    ent_keys: dict[tuple[str, int], tuple] = {}
    for m in ordered_maps:
        for e in m["entities"]:
            key = (src_of(m, e["source_index"]), *_span_key(e), _b(e["kind"]), _b(e["qualified_name"]))
            ent_keys[(m["map_id"], e["entity_index"])] = key
            ent_union.add(key, {"kind": e["kind"], "qualified_name": e["qualified_name"], "source_index": key[0], "span": e["span"]})
    ent_index = {key: n for n, (key, _) in enumerate(ent_union.ordered())}
    entities = [{"entity_index": n, **r} for n, (_, r) in enumerate(ent_union.ordered())]

    def ent_of(m: dict, i: int | None) -> int | None:
        return None if i is None else ent_index[ent_keys[(m["map_id"], i)]]

    # Points, and each map's counter -> point binding.
    pt_union = _Union("point")
    counted: set[str] = set()
    binding: dict[str, list[str | None]] = {}
    for m in ordered_maps:
        slots: list[str | None] = [None] * m["program_counter_count"]
        for p in m["points"]:
            is_counted = p["counter_index"] is not None
            pt_union.add((p["point_id"],), {
                "classification": p["classification"], "entity_index": ent_of(m, p["entity_index"]), "kind": p["kind"],
                "outcome_ordinal": p["outcome_ordinal"], "point_id": p["point_id"],
                "semantic_discriminator": p["semantic_discriminator"], "source_index": src_of(m, p["source_index"]), "span": p["span"],
                "_counted": is_counted})
            if is_counted:
                counted.add(p["point_id"])
                slots[p["counter_index"]] = p["point_id"]
        binding[m["map_id"]] = slots

    # Contexts and per-context point counts.
    profiles = list(profiles)
    values = sorted({p.context for p in profiles} | set(extra_contexts), key=context_key)
    ctx_index = {v: n for n, v in enumerate(values)}
    per_context: dict[int, _Counts] = {n: _Counts() for n in range(len(values))}
    seen_profiles: set[bytes] = set()
    for prof in profiles:
        if prof.profile_id in seen_profiles:
            raise ModelError("COV2112", f"profile ID {prof.profile_id.hex()} is supplied twice")
        seen_profiles.add(prof.profile_id)
        slots = binding.get(prof.map_id.hex())
        if slots is None:
            raise ModelError("COV2111", f"profile {prof.profile_id.hex()} names a map that was not supplied")
        counts = per_context[ctx_index[prof.context]]
        for counter, value in prof.counts:
            if not 0 <= counter < len(slots) or slots[counter] is None:
                raise ModelError("COV2111", f"profile {prof.profile_id.hex()} counts counter {counter}, which its map does not bind")
            pid = slots[counter]
            old = counts[pid]
            total = old.value + value
            # A sum that lands exactly on UINT64_MAX is saturated too: a physical count of that value is never exact.
            counts[pid] = Count(min(total, U64_MAX), old.inexact or total >= U64_MAX)

    def point_count(pid: str) -> CountRecord:
        # A raw profile lists only nonzero counts, so every entry here is positive.
        by_context = tuple((n, c[pid]) for n, c in sorted(per_context.items()) if pid in c)
        total = sum(c.value for _, c in by_context)
        inexact = any(c.inexact for _, c in by_context) or total > U64_MAX
        return CountRecord(by_context, min(total, U64_MAX), inexact)

    point_counts = {key[0]: point_count(key[0]) for key in pt_union.records}
    points = []
    for (pid,), r in pt_union.ordered():
        rec = {k: v for k, v in r.items() if k != "_counted"}
        rec["count"] = point_counts[pid].to_json()
        points.append(rec)

    # Regions.
    rg_union = _Union("region")
    rg_keys: dict[tuple[str, int], tuple] = {}
    for m in ordered_maps:
        for r in m["regions"]:
            key = (src_of(m, r["source_index"]), *_span_key(r), _b(r["kind"]), encode(r["counter_expression"]))
            rg_keys[(m["map_id"], r["region_index"])] = key
            rg_union.add(key, {"classification": r["classification"], "counter_expression": r["counter_expression"],
                               "entity_index": ent_of(m, r["entity_index"]), "kind": r["kind"],
                               "line_contributing": r["line_contributing"], "line_numbers": r["line_numbers"],
                               "source_index": key[0], "span": r["span"]})
    rg_index = {key: n for n, (key, _) in enumerate(rg_union.ordered())}
    regions = []
    region_counts: list[CountRecord] = []
    for n, (_, r) in enumerate(rg_union.ordered()):
        try:
            cnt = evaluate_contexts(check_expression(r["counter_expression"], counted), per_context)
        except ExprError as exc:
            raise ModelError("COV3002", f"region {n}: {exc.detail}") from exc
        region_counts.append(cnt)
        regions.append({**r, "count": cnt.to_json(), "region_index": n})

    # Lines: membership inverted from line_numbers.
    members: dict[tuple[int, int], list[int]] = {}
    for n, r in enumerate(regions):
        for line in r["line_numbers"]:
            members.setdefault((r["source_index"], line), []).append(n)
    lines = []
    for (source, line), listed in sorted(members.items()):
        contributing = [n for n in listed if regions[n]["line_contributing"]]
        ran = [region_counts[n].value > 0 for n in contributing if regions[n]["classification"] == "user"]
        if ran:
            status = "covered" if all(ran) else "partial" if any(ran) else "uncovered"
        elif any(regions[n]["classification"] == "excluded" for n in listed):
            status = "excluded"
        else:
            status = "non_executable"
        lines.append({"line": line, "line_index": len(lines), "region_indices": contributing, "source_index": source, "status": status})

    # Branches.
    br_union = _Union("branch")
    br_keys: dict[tuple[str, int], tuple] = {}
    for m in ordered_maps:
        for b in m["branches"]:
            key = (src_of(m, b["source_index"]), *_span_key(b), _b(b["kind"]), b["outcomes"][0]["point_id"])
            br_keys[(m["map_id"], b["branch_index"])] = key
            br_union.add(key, {"entity_index": ent_of(m, b["entity_index"]), "kind": b["kind"],
                               "outcomes": [dict(o) for o in b["outcomes"]], "source_index": key[0], "span": b["span"]})
    br_index = {key: n for n, (key, _) in enumerate(br_union.ordered())}
    branches = []
    for n, (_, b) in enumerate(br_union.ordered()):
        outcomes = []
        for o in b["outcomes"]:
            cnt = point_counts[o["point_id"]]
            status = o["classification"] if o["classification"] != "eligible" else "covered" if cnt.value > 0 else "uncovered"
            outcomes.append({"count": cnt.to_json(), "evidence_identity": o["evidence_identity"], "name": o["name"],
                             "ordinal": o["ordinal"], "point_id": o["point_id"], "status": status})
        branches.append({"branch_index": n, "entity_index": b["entity_index"], "kind": b["kind"], "outcomes": outcomes,
                         "source_index": b["source_index"], "span": b["span"]})

    # Contracts.
    ct_union = _Union("contract")
    ct_keys: dict[tuple[str, int], tuple] = {}
    for m in ordered_maps:
        for c in m["contracts"]:
            key = (src_of(m, c["source_index"]), *_span_key(c), _b(c["kind"]), ent_of(m, c["entity_index"]))
            ct_keys[(m["map_id"], c["clause_index"])] = key
            ct_union.add(key, {"enforcement": c["enforcement"], "entity_index": key[4], "evidence_identity": c["evidence_identity"],
                               "false_point_id": c["false_point_id"], "function_entity_index": ent_of(m, c["function_entity_index"]),
                               "kind": c["kind"], "source_index": key[0], "span": c["span"], "true_point_id": c["true_point_id"]})
    ct_index = {key: n for n, (key, _) in enumerate(ct_union.ordered())}
    contracts = []
    for n, (_, c) in enumerate(ct_union.ordered()):
        if c["enforcement"] == "runtime_checked":
            t, f = point_counts[c["true_point_id"]], point_counts[c["false_point_id"]]
            result = "mixed" if t.value and f.value else "evaluated_true" if t.value else "evaluated_false" if f.value else "not_evaluated"
            count_true, count_false = t.to_json(), f.to_json()
        else:
            result, count_true, count_false = "not_applicable", None, None
        contracts.append({"clause_index": n, "count_false": count_false, "count_true": count_true, "enforcement": c["enforcement"],
                          "entity_index": c["entity_index"], "evidence_identity": c["evidence_identity"],
                          "function_entity_index": c["function_entity_index"], "kind": c["kind"], "runtime_result": result,
                          "source_index": c["source_index"], "span": c["span"]})

    # Exclusions, with their affected sets reindexed.
    ex_union = _Union("exclusion")
    for m in ordered_maps:
        mid = m["map_id"]
        for x in m["exclusions"]:
            a = x["affected"]
            key = (src_of(m, x["source_index"]), *_span_key(x), _b(x["mode"]), _b(x["reason"]))
            ex_union.add(key, {
                "affected": {"branch_indices": sorted(br_index[br_keys[(mid, i)]] for i in a["branch_indices"]),
                             "clause_indices": sorted(ct_index[ct_keys[(mid, i)]] for i in a["clause_indices"]),
                             "entity_indices": sorted(ent_index[ent_keys[(mid, i)]] for i in a["entity_indices"]),
                             "point_ids": sorted(a["point_ids"]),
                             "region_indices": sorted(rg_index[rg_keys[(mid, i)]] for i in a["region_indices"])},
                "mode": x["mode"], "origin": x["origin"], "reason": x["reason"], "source_index": key[0], "span": x["span"]})
    exclusions = [{"affected": x["affected"], "exclusion_index": n, "mode": x["mode"], "origin": x["origin"], "reason": x["reason"],
                   "source_index": x["source_index"], "span": x["span"]} for n, (_, x) in enumerate(ex_union.ordered())]

    # Saturation.
    hot_points = sorted(pid for pid, c in point_counts.items() if c.inexact)
    hot_regions = [n for n, c in enumerate(region_counts) if c.inexact]
    any_hot = bool(hot_points or hot_regions)
    saturation = {"affected_point_ids": hot_points, "affected_region_indices": hot_regions, "any": any_hot,
                  "eligible_metrics": list(ELIGIBLE_METRICS) if any_hot and saturation_policy == "allow-ordinary" else [],
                  "ineligible_uses": [], "policy": saturation_policy}

    return {
        "branches": branches, "capabilities": list(CAPABILITIES), "complete": bool(complete) and not found,
        "contexts": [{"context_index": n, "value": v} for n, v in enumerate(values)], "contracts": contracts,
        "diagnostics": sorted(found, key=_b), "entities": entities, "exclusions": exclusions, "lines": lines,
        "map_ids": sorted(by_id), "map_version": "1.0", "point_identity_version": "1.0", "points": points, "regions": regions,
        "saturation": saturation, "schema": "sv0cov.indexed-semantic", "sources": sources, "version": "1.0",
    }
