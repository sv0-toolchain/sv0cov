# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The full indexed object and its cross-validating reader (CV-222; SPEC
16.5, 17.2, 17.3; COV-FMT-040, COV-MRG-011, AC-112).

:func:`build_indexed` assembles ``sv0cov.indexed`` 1.0 from inputs a merge
has already classified (CV-223 does the classifying): the input inventory,
each accepted map's counter-to-point binding, the run selection, the
execution and merge records, the semantic object
(:func:`sv0cov.model.semantic.build_semantic`), completeness, and the
projection digest. Its bytes do not depend on input order.

:func:`read_indexed` is the reader every consumer starts from. After the
structure layer (:mod:`sv0cov.formats.indexed`) it re-derives every fact the
artifact retains and rejects any disagreement, so ``report`` and ``check``
need no map or raw profile:

- canonical order and index positions of every record array;
- every reference (source, entity, context, point, region, branch, clause);
- each point ID, recomputed from its definition (SPEC 10.3);
- bindings: each accepted map binds exactly its counters to distinct
  runtime-counted points; a point no map binds has the exact zero count;
- point counts are physical (an inexact context is ``UINT64_MAX``) and
  aggregate by saturating sum; region counts recompute from expressions per
  context; line membership exactly inverts ``line_numbers`` and statuses
  recompute; outcome and contract results equal their points; exclusions
  equal classifications; the saturation inventory equals the count flags;
- the inventory names the bindings, the run selection matches the accepted
  profiles, every context is used, every stored code is in the diagnostic
  registry the artifact names, and ``complete`` is exactly SPEC 16.5.7.

What the reader cannot do is recheck the omitted bytes: that the counts are
the sum of the raw profiles, or that a binding is the map's. The artifact
digests record what the producer validated (SPEC 16.5.7).

Failures raise :class:`sv0cov.formats.indexed.IndexedError`: ``COV3010``
invalid evidence, ``COV3011`` projection mismatch, ``COV3012`` binding
mismatch.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Iterable, Sequence

from sv0cov import capabilities, diagnostics
from sv0cov.expr import U64_MAX, Count, ExprError, check_expression, evaluate_contexts
from sv0cov.formats.indexed import IndexedError, decode_indexed_structure, projection_sha256
from sv0cov.formats.map import OUTCOME_NAMES
from sv0cov.formats.rawprofile import RawProfile, Tier
from sv0cov.model.identity import NO_ORDINAL, EntityKind, PointIdentity, PointKind, point_id
from sv0cov.model.semantic import ModelError, build_semantic, context_key

POINT_KINDS = {"function_entry": PointKind.FUNCTION_ENTRY, "region": PointKind.REGION, "branch_outcome": PointKind.BRANCH_OUTCOME,
               "contract_true": PointKind.CONTRACT_TRUE, "contract_false": PointKind.CONTRACT_FALSE}
ENTITY_KINDS = {"function": EntityKind.FUNCTION, "contract": EntityKind.CONTRACT}
UNCOUNTED = ("excluded", "statically_unreachable")
NOT_APPLICABLE = {"exit_code": None, "signal": None, "status": "not_applicable"}


# ── producer ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MapInput:
    """One inventoried map artifact. ``map`` is the validated object of an
    accepted input; a rejected input has ``diagnostics`` and no ``map``.
    ``data`` is ``None`` only when the bytes could not be read."""

    name: str
    data: bytes | None
    map: dict | None = None
    diagnostics: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProfileInput:
    """One inventoried raw profile. ``profile`` is the decoded profile of an
    accepted input. For an ``incomplete`` or ``rejected`` input, whatever
    the header gave may be passed in ``backend``, ``context`` (with
    ``has_context``), ``map_id``, ``profile_id`` and ``run_id``."""

    name: str
    data: bytes | None
    profile: RawProfile | None = None
    status: str = "accepted"
    diagnostics: tuple[str, ...] = ()
    backend: str | None = None
    has_context: bool = False
    context: str | None = None
    map_id: str | None = None
    profile_id: str | None = None
    run_id: str | None = None


@dataclass(frozen=True)
class RunSelection:
    """How the run set was chosen (SPEC 17.2). ``requested`` is empty for
    ``implicit-single`` and ``none``."""

    mode: str = "implicit-single"
    requested: tuple[str, ...] = ()
    manifest_sha256: str | None = None


def _sha(data: bytes | None) -> str | None:
    return None if data is None else hashlib.sha256(data).hexdigest()


def _input_key(r: dict) -> tuple:
    return (r["status"].encode(), r["artifact_sha256"] is not None, r["artifact_sha256"] or "", r["name"].encode("utf-8"))


def selection_satisfied(mode: str, requested: Sequence[str], selected: Sequence[str]) -> bool:
    """SPEC 16.5.4: one run when implicit; the declared set exactly otherwise."""
    if mode == "implicit-single":
        return len(selected) == 1
    if mode in ("explicit-list", "manifest"):
        return list(selected) == list(requested)
    return False


def build_indexed(
    map_inputs: Iterable[MapInput],
    profile_inputs: Iterable[ProfileInput],
    *,
    run_selection: RunSelection = RunSelection(),
    execution: dict | None = None,
    allow_rejected_inputs: bool = False,
    tier: Tier | None = None,
    tool_version: str | None = None,
    saturation_policy: str = "fail",
) -> dict:
    """The ``sv0cov.indexed`` 1.0 object for classified inputs.

    Exact copies of an accepted artifact (same bytes) are inventoried once,
    under the bytewise-smallest name. Raises
    :class:`sv0cov.model.semantic.ModelError` when the accepted inputs are
    incompatible with each other.
    """
    tier = tier or Tier.standard()
    registry = diagnostics.load_registry()

    maps: dict[str, dict] = {}
    map_records: dict[tuple, dict] = {}
    for mi in map_inputs:
        accepted = mi.map is not None and not mi.diagnostics
        if accepted and mi.data is None:
            raise ValueError(f"accepted map input {mi.name!r} has no bytes")
        if not accepted and not mi.diagnostics:
            raise ValueError(f"rejected map input {mi.name!r} has no diagnostic")
        rec = {"artifact_sha256": _sha(mi.data), "byte_length": 0 if mi.data is None else len(mi.data),
               "diagnostics": sorted(set(mi.diagnostics)), "map_id": mi.map["map_id"] if accepted else None, "name": mi.name,
               "status": "accepted" if accepted else "rejected"}
        key = (rec["status"], rec["artifact_sha256"]) if accepted else (rec["status"], rec["artifact_sha256"], rec["name"],
                                                                         tuple(rec["diagnostics"]))
        if key not in map_records or rec["name"].encode("utf-8") < map_records[key]["name"].encode("utf-8"):
            map_records[key] = rec
        if accepted:
            maps[mi.map["map_id"]] = mi.map

    accepted_profiles: dict[str, RawProfile] = {}
    profile_records: dict[tuple, dict] = {}
    pending: list[tuple[dict, bool, str | None]] = []
    for pi in profile_inputs:
        if pi.status not in ("accepted", "incomplete", "rejected"):
            raise ValueError(f"unknown profile status {pi.status!r}")
        accepted = pi.status == "accepted"
        if accepted and (pi.profile is None or pi.data is None or pi.diagnostics):
            raise ValueError(f"accepted profile input {pi.name!r} needs its bytes and decoded profile, and no diagnostic")
        if not accepted and not pi.diagnostics:
            raise ValueError(f"{pi.status} profile input {pi.name!r} has no diagnostic")
        if accepted:
            p = pi.profile
            rec = {"backend": p.backend, "map_id": p.map_id.hex(), "profile_id": p.profile_id.hex(), "run_id": p.run_id.hex()}
            has_context, context = True, p.context
        else:
            rec = {"backend": pi.backend, "map_id": pi.map_id if pi.map_id in maps else None, "profile_id": pi.profile_id,
                   "run_id": pi.run_id}
            has_context, context = pi.has_context, pi.context
        rec.update(artifact_sha256=_sha(pi.data), byte_length=0 if pi.data is None else len(pi.data),
                   diagnostics=sorted(set(pi.diagnostics)), name=pi.name, status=pi.status, context_index=None)
        key = (rec["status"], rec["artifact_sha256"]) if accepted else (rec["status"], rec["artifact_sha256"], rec["name"],
                                                                         tuple(rec["diagnostics"]))
        if key not in profile_records or rec["name"].encode("utf-8") < profile_records[key]["name"].encode("utf-8"):
            profile_records[key] = rec
            if accepted:
                accepted_profiles[rec["artifact_sha256"]] = pi.profile
        pending.append((rec, has_context, context))

    selected = sorted({p.run_id.hex() for p in accepted_profiles.values()})
    requested = sorted(run_selection.requested)
    all_accepted = all(r["status"] == "accepted" for r in list(map_records.values()) + list(profile_records.values()))
    found: set[str] = set()
    if not accepted_profiles:
        found.add("COV3001")
    if not all_accepted:
        found.add("COV3002")
    if not selection_satisfied(run_selection.mode, requested, selected):
        found.add("COV3003")

    extra = [ctx for rec, has, ctx in pending if has and rec["status"] != "accepted"]
    semantic = build_semantic(list(maps.values()), list(accepted_profiles.values()), extra_contexts=extra,
                              complete=not found and not allow_rejected_inputs, saturation_policy=saturation_policy)
    context_index = {c["value"]: c["context_index"] for c in semantic["contexts"]}
    for rec, has, ctx in pending:
        if has:
            rec["context_index"] = context_index[ctx]
    found |= {c for c in semantic["diagnostics"]}

    src_index = {(s["path"], s["digest"]): s["source_index"] for s in semantic["sources"]}
    bindings = []
    for mid in sorted(maps):
        m = maps[mid]
        slots = sorted((p["counter_index"], p["point_id"]) for p in m["points"] if p["counter_index"] is not None)
        bindings.append({
            "bindings": [{"counter_index": i, "point_id": pid} for i, pid in slots],
            "compiler_identity": m["compiler"]["identity"], "map_id": mid, "program_counter_count": m["program_counter_count"],
            "source_indices": sorted(src_index[(s["path"], s["digest"])] for s in m["sources"]), "target": dict(m["target"])})

    obj = {
        "diagnostics": sorted(found),
        "execution": dict(execution or NOT_APPLICABLE),
        "map_inputs": sorted(map_records.values(), key=_input_key),
        "maps": bindings,
        "merge": {"allow_rejected_inputs": bool(allow_rejected_inputs),
                  "limits": {"max_bytes": tier.max_bytes, "max_counters": tier.max_counters, "tier": tier.name},
                  "tool": {"diagnostic_registry_revision": registry.revision, "diagnostic_registry_sha256": registry.sha256,
                           "name": "sv0cov", "version": tool_version or capabilities.tool_version()}},
        "profile_inputs": sorted(profile_records.values(), key=_input_key),
        "run_selection": {"manifest_sha256": run_selection.manifest_sha256, "mode": run_selection.mode,
                          "requested_run_ids": requested, "selected_run_ids": selected},
        "schema": "sv0cov.indexed",
        "semantic": semantic,
        "semantic_projection_sha256": projection_sha256(semantic),
        "version": "1.0",
    }
    return obj


# ── reader ──────────────────────────────────────────────────────────────────


def _fail(where: str, detail: str, code: str = "COV3010") -> None:
    raise IndexedError(code, f"{where}: {detail}")


def _positions(items: list[dict], field: str, what: str) -> None:
    for n, r in enumerate(items):
        if r[field] != n:
            _fail(f"{what}[{n}]", f"{field} must equal its position")


def _ordered(items: list, key, what: str) -> None:
    keys = [key(x) for x in items]
    if any(not a < b for a, b in zip(keys, keys[1:])):
        _fail(what, "records are not in canonical order, or one is duplicated")


def _b(s: str) -> bytes:
    return s.encode("utf-8")


def _span_key(r: dict) -> tuple[int, int]:
    return (r["span"]["start_byte"], r["span"]["end_byte"])


def _within(inner: dict, outer: dict) -> bool:
    return outer["start_byte"] <= inner["start_byte"] and inner["end_byte"] <= outer["end_byte"]


def _ref(index: int | None, items: list, where: str, what: str) -> None:
    if index is not None and index >= len(items):
        _fail(where, f"dangling {what} reference")


class _Counts(dict):
    def __missing__(self, key: str) -> Count:
        return Count(0, False)


def _check_semantic(s: dict, bound: set[str]) -> None:
    """Cross-validate a structurally valid semantic object. ``bound`` is the
    set of point IDs some accepted map binds to a counter."""
    sources, entities, contexts, points, regions = s["sources"], s["entities"], s["contexts"], s["points"], s["regions"]
    nctx = len(contexts)

    _positions(sources, "source_index", "sources")
    _ordered(sources, lambda r: (_b(r["path"]), r["digest"]), "sources")
    for r in sources:
        if r["ownership"] == "dependency" and r["package"] is None:
            _fail(f"sources[{r['source_index']}]", "a dependency source names its package")
    paths = [r["path"] for r in sources]
    if ("COV3004" in s["diagnostics"]) != (len(set(paths)) != len(paths)):
        _fail("diagnostics", "COV3004 is recorded exactly when one path has two source versions")

    _positions(entities, "entity_index", "entities")
    for n, e in enumerate(entities):
        _ref(e["source_index"], sources, f"entities[{n}]", "source")
    _ordered(entities, lambda e: (e["source_index"], *_span_key(e), _b(e["kind"]), _b(e["qualified_name"])), "entities")

    _positions(contexts, "context_index", "contexts")
    _ordered(contexts, lambda c: context_key(c["value"]), "contexts")

    def check_count(rec: dict, where: str) -> None:
        for c in rec["by_context"]:
            if c["context_index"] >= nctx:
                _fail(where, "dangling context reference")

    def owner(index: int | None, source: int, span: dict, where: str) -> None:
        if index is None:
            return
        _ref(index, entities, where, "entity")
        e = entities[index]
        if e["kind"] != "function" or e["source_index"] != source or not _within(span, e["span"]):
            _fail(where, "the owner must be a function entity of the same source that encloses the span")

    # Points.
    _ordered(points, lambda p: p["point_id"], "points")
    by_id = {p["point_id"]: p for p in points}
    for p in points:
        where = f"point {p['point_id']}"
        _ref(p["source_index"], sources, where, "source")
        _ref(p["entity_index"], entities, where, "entity")
        e = None if p["entity_index"] is None else entities[p["entity_index"]]
        if e is not None and e["source_index"] != p["source_index"]:
            _fail(where, "the entity is in another source")
        if p["kind"] == "function_entry" and e["kind"] != "function":
            _fail(where, "a function_entry point names a function entity")
        if p["kind"] in ("contract_true", "contract_false"):
            if e["kind"] != "contract" or p["classification"] != "contract":
                _fail(where, "a contract point names a contract entity and is classified contract")
        elif p["classification"] == "contract":
            _fail(where, "only contract points are classified contract")
        src = sources[p["source_index"]]
        want = point_id(PointIdentity(
            src["path"], src["digest"], EntityKind.NONE if e is None else ENTITY_KINDS[e["kind"]],
            "" if e is None else e["qualified_name"], POINT_KINDS[p["kind"]], p["span"]["start_byte"], p["span"]["end_byte"],
            NO_ORDINAL if p["outcome_ordinal"] is None else p["outcome_ordinal"], p["semantic_discriminator"]))
        if want != p["point_id"]:
            _fail(where, f"the point ID recomputes to {want}")
        cnt = p["count"]
        check_count(cnt, where)
        is_bound = p["point_id"] in bound
        if is_bound and p["classification"] in UNCOUNTED:
            _fail(where, f"a {p['classification']} point is bound to a counter", "COV3012")
        if not is_bound and (cnt["value"] or cnt["by_context"] or cnt["lower_bound"]):
            _fail(where, "a point no map binds has the exact zero count", "COV3012")
        if any(c["lower_bound"] and c["value"] != U64_MAX for c in cnt["by_context"]):
            _fail(where, "a saturated physical count is UINT64_MAX")
        if any(c["value"] == U64_MAX and not c["lower_bound"] for c in cnt["by_context"]):
            _fail(where, "a physical count of UINT64_MAX is saturated")
        total = sum(c["value"] for c in cnt["by_context"])
        if cnt["value"] != min(total, U64_MAX) or cnt["lower_bound"] != (total > U64_MAX or any(c["lower_bound"] for c in cnt["by_context"])):
            _fail(where, "the aggregate is not the saturating sum of the context counts")

    per_context: dict[int, _Counts] = {n: _Counts() for n in range(nctx)}
    for p in points:
        for c in p["count"]["by_context"]:
            per_context[c["context_index"]][p["point_id"]] = Count(c["value"], c["lower_bound"])

    # Regions.
    _positions(regions, "region_index", "regions")
    for n, r in enumerate(regions):
        where = f"regions[{n}]"
        _ref(r["source_index"], sources, where, "source")
        owner(r["entity_index"], r["source_index"], r["span"], where)
        check_count(r["count"], where)
        terms = r["counter_expression"]["terms"]
        for t in terms:
            p = by_id.get(t["point_id"])
            if p is None or t["point_id"] not in bound:
                _fail(where, "a term must reference a runtime-counted point")
            if p["source_index"] != r["source_index"] or p["entity_index"] != r["entity_index"]:
                _fail(where, "expression points share the region's source and entity")
        if r["classification"] == "user" and not terms:
            _fail(where, "a user region needs a nonempty counter expression")
        if r["classification"] in UNCOUNTED and terms:
            _fail(where, f"a {r['classification']} region uses the empty expression")
        try:
            want = evaluate_contexts(check_expression(r["counter_expression"]), per_context).to_json()
        except ExprError as exc:
            _fail(where, exc.detail)
        if r["count"] != want:
            _fail(where, "the count is not its expression evaluated over the point counts")
    _ordered(regions, lambda r: (r["source_index"], *_span_key(r), _b(r["kind"]),
                                 _canonical(r["counter_expression"])), "regions")

    # Lines: exactly the inversion of line_numbers, with recomputed statuses.
    listed: dict[tuple[int, int], list[int]] = {}
    for n, r in enumerate(regions):
        for line in r["line_numbers"]:
            listed.setdefault((r["source_index"], line), []).append(n)
    lines = s["lines"]
    _positions(lines, "line_index", "lines")
    if [(ln["source_index"], ln["line"]) for ln in lines] != sorted(listed):
        _fail("lines", "the lines are not exactly those the regions' line_numbers name, in order")
    for ln in lines:
        where = f"lines[{ln['line_index']}]"
        members = listed[(ln["source_index"], ln["line"])]
        if ln["region_indices"] != [n for n in members if regions[n]["line_contributing"]]:
            _fail(where, "region_indices are not the line-contributing regions on the line")
        ran = [regions[n]["count"]["value"] > 0 for n in ln["region_indices"] if regions[n]["classification"] == "user"]
        if ran:
            want = "covered" if all(ran) else "partial" if any(ran) else "uncovered"
        elif any(regions[n]["classification"] == "excluded" for n in members):
            want = "excluded"
        else:
            want = "non_executable"
        if ln["status"] != want:
            _fail(where, f"the status recomputes to {want}")

    # Branches.
    branches = s["branches"]
    _positions(branches, "branch_index", "branches")
    used: set[str] = set()
    for n, b in enumerate(branches):
        where = f"branches[{n}]"
        _ref(b["source_index"], sources, where, "source")
        owner(b["entity_index"], b["source_index"], b["span"], where)
        names = tuple(o["name"] for o in b["outcomes"])
        if names != (OUTCOME_NAMES.get(b["kind"]) or tuple(f"arm:{k}" for k in range(len(names)))):
            _fail(where, f"a {b['kind']} branch has other outcome names")
        for k, o in enumerate(b["outcomes"]):
            p = by_id.get(o["point_id"])
            if p is None or p["kind"] != "branch_outcome":
                _fail(where, "an outcome must reference a branch_outcome point")
            if o["point_id"] in used:
                _fail(where, "a branch_outcome point is referenced twice")
            used.add(o["point_id"])
            if (p["source_index"], p["entity_index"], p["outcome_ordinal"]) != (b["source_index"], b["entity_index"], k) \
                    or p["span"] != b["span"]:
                _fail(where, "an outcome point does not match the branch's source, owner, span, or ordinal")
            if o["count"] != p["count"]:
                _fail(where, "an outcome's count is its point's count")
            cls = p["classification"]
            want = cls if cls in UNCOUNTED else "covered" if p["count"]["value"] > 0 else "uncovered"
            if cls not in ("user", *UNCOUNTED) or o["status"] != want:
                _fail(where, f"outcome {k} must be {want} for its point")
    stray = [p["point_id"] for p in points if p["kind"] == "branch_outcome" and p["point_id"] not in used]
    if stray:
        _fail("branches", f"branch_outcome point {stray[0]} belongs to no branch")
    _ordered(branches, lambda b: (b["source_index"], *_span_key(b), _b(b["kind"]), b["outcomes"][0]["point_id"]), "branches")

    # Contracts: each contract entity once, results equal to its two points.
    contracts = s["contracts"]
    _positions(contracts, "clause_index", "contracts")
    clause_points: dict[int, dict[str, dict]] = {}
    for p in points:
        if p["kind"] in ("contract_true", "contract_false"):
            slot = clause_points.setdefault(p["entity_index"], {})
            if p["kind"] in slot:
                _fail(f"point {p['point_id']}", "a contract entity has two points of one kind")
            slot[p["kind"]] = p
    seen: set[int] = set()
    for n, c in enumerate(contracts):
        where = f"contracts[{n}]"
        _ref(c["source_index"], sources, where, "source")
        _ref(c["entity_index"], entities, where, "entity")
        e = entities[c["entity_index"]]
        if e["kind"] != "contract" or e["source_index"] != c["source_index"] or e["span"] != c["span"]:
            _fail(where, "the entity must be the clause's own contract entity")
        if c["entity_index"] in seen:
            _fail(where, "a contract entity is used by two clauses")
        seen.add(c["entity_index"])
        owner(c["function_entity_index"], c["source_index"], c["span"], where)
        mine = clause_points.get(c["entity_index"], {})
        if c["enforcement"] == "runtime_checked":
            t, f = mine.get("contract_true"), mine.get("contract_false")
            if t is None or f is None or t["point_id"] not in bound or f["point_id"] not in bound:
                _fail(where, "a runtime_checked clause has a counted true point and a counted false point")
            if c["count_true"] != t["count"] or c["count_false"] != f["count"]:
                _fail(where, "the clause's counts are its two points' counts")
        elif mine:
            _fail(where, f"a {c['enforcement']} clause has no outcome point")
    if seen != {e["entity_index"] for e in entities if e["kind"] == "contract"}:
        _fail("contracts", "every contract entity appears in exactly one contract record")
    _ordered(contracts, lambda c: (c["source_index"], *_span_key(c), _b(c["kind"]), c["entity_index"]), "contracts")

    # Exclusions equal classifications (the map rules, SPEC 16.3.7).
    exclusions = s["exclusions"]
    _positions(exclusions, "exclusion_index", "exclusions")
    sizes = {"branch_indices": len(branches), "clause_indices": len(contracts), "entity_indices": len(entities),
             "region_indices": len(regions)}
    claimed: dict[str, set] = {k: set() for k in (*sizes, "point_ids")}
    for n, x in enumerate(exclusions):
        where = f"exclusions[{n}]"
        _ref(x["source_index"], sources, where, "source")
        a = x["affected"]
        for key, values in a.items():
            if key in sizes and any(v >= sizes[key] for v in values):
                _fail(where, f"affected.{key} has a dangling index")
            if key == "point_ids" and any(v not in by_id for v in values):
                _fail(where, "affected.point_ids names an unknown point")
            if claimed[key] & set(values):
                _fail(where, "a construct is excluded twice")
            claimed[key].update(values)
        if not any(a.values()):
            _fail(where, "the exclusion affects nothing")
        affected_points = [by_id[p] for p in a["point_ids"]]
        if x["mode"] == "contract_off":
            clause_entities = {contracts[i]["entity_index"] for i in a["clause_indices"]}
            if a["branch_indices"] or a["region_indices"] or not a["clause_indices"] or not set(a["entity_indices"]) <= clause_entities \
                    or any(p["entity_index"] not in clause_entities for p in affected_points):
                _fail(where, "contract_off affects only its contract clauses, their entities and their points")
            continue
        if a["clause_indices"]:
            _fail(where, f"{x['mode']} cannot exclude contract clauses")
        if any(p["classification"] != "excluded" for p in affected_points) \
                or any(regions[i]["classification"] != "excluded" for i in a["region_indices"]):
            _fail(where, "affected points and regions are classified excluded")
        outcome_ids = {o["point_id"] for i in a["branch_indices"] for o in branches[i]["outcomes"]}
        if not outcome_ids <= set(a["point_ids"]):
            _fail(where, "an excluded branch lists all its outcome points")
        if x["mode"] == "branch_off" and (a["region_indices"] or a["entity_indices"] or not a["branch_indices"]
                                         or set(a["point_ids"]) != outcome_ids):
            _fail(where, "branch_off affects exactly its branches' outcomes")
        if any(entities[i]["kind"] != "function" for i in a["entity_indices"]):
            _fail(where, "off excludes only function entities")
    for p in points:
        if p["classification"] == "excluded" and p["point_id"] not in claimed["point_ids"]:
            _fail(f"point {p['point_id']}", "classified excluded without an exclusion record")
    for n, r in enumerate(regions):
        if r["classification"] == "excluded" and n not in claimed["region_indices"]:
            _fail(f"regions[{n}]", "classified excluded without an exclusion record")
    _ordered(exclusions, lambda x: (x["source_index"], *_span_key(x), _b(x["mode"]), _b(x["reason"])), "exclusions")

    # Saturation equals the count flags.
    sat = s["saturation"]
    if sat["affected_point_ids"] != [p["point_id"] for p in points if p["count"]["lower_bound"]]:
        _fail("saturation", "affected_point_ids are not exactly the inexact points")
    if sat["affected_region_indices"] != [n for n, r in enumerate(regions) if r["count"]["lower_bound"]]:
        _fail("saturation", "affected_region_indices are not exactly the inexact regions")


def _canonical(value: object) -> bytes:
    from sv0cov.formats.canonical_json import encode

    return encode(value)


def _check_full(o: dict, registry: diagnostics.Registry | None) -> None:
    s = o["semantic"]
    by_id = {p["point_id"]: p for p in s["points"]}
    nsrc, nctx = len(s["sources"]), len(s["contexts"])

    # Stored codes belong to the registry the artifact names.
    tool = o["merge"]["tool"]
    registry = registry or diagnostics.load_registry()
    if (tool["diagnostic_registry_revision"], tool["diagnostic_registry_sha256"]) != (registry.revision, registry.sha256):
        _fail("merge/tool", f"the artifact names diagnostic registry revision {tool['diagnostic_registry_revision']}, "
                            f"which this reader does not have (it has revision {registry.revision})")
    stored = set(o["diagnostics"]) | set(s["diagnostics"])
    for r in o["map_inputs"] + o["profile_inputs"]:
        stored |= set(r["diagnostics"])
    unknown = sorted(c for c in stored if c not in registry.entries)
    if unknown:
        _fail("diagnostics", f"{unknown[0]} is not in the diagnostic registry")

    # Bindings.
    maps = o["maps"]
    _ordered(maps, lambda b: b["map_id"], "maps")
    if [b["map_id"] for b in maps] != s["map_ids"]:
        _fail("maps", "the binding records are not exactly the semantic map_ids", "COV3012")
    for b in maps:
        where = f"map {b['map_id']}"
        if any(i >= nsrc for i in b["source_indices"]):
            _fail(where, "dangling source reference", "COV3012")
        ids = [x["point_id"] for x in b["bindings"]]
        if len(set(ids)) != len(ids):
            _fail(where, "two counters bind one point", "COV3012")
        for pid in ids:
            p = by_id.get(pid)
            if p is None:
                _fail(where, f"a counter binds {pid}, which is not a semantic point", "COV3012")
            if p["source_index"] not in b["source_indices"]:
                _fail(where, "a bound point's source is not one of the map's sources", "COV3012")
    listed = {i for b in maps for i in b["source_indices"]}
    if listed != set(range(nsrc)):
        _fail("maps", "every semantic source belongs to at least one accepted map", "COV3012")
    bound = {x["point_id"] for b in maps for x in b["bindings"]}

    _check_semantic(s, bound)

    # Inventory.
    map_ids = {b["map_id"] for b in maps}
    _ordered(o["map_inputs"], _input_key, "map_inputs")
    _ordered(o["profile_inputs"], _input_key, "profile_inputs")
    accepted_maps = {r["map_id"] for r in o["map_inputs"] if r["status"] == "accepted"}
    if accepted_maps != map_ids:
        _fail("map_inputs", "the accepted map inputs and the binding records name different maps", "COV3012")
    if any(r["map_id"] is not None for r in o["map_inputs"] if r["status"] != "accepted"):
        _fail("map_inputs", "a rejected map input names no map")
    accepted = [r for r in o["profile_inputs"] if r["status"] == "accepted"]
    used_contexts: set[int] = set()
    counting_contexts: set[int] = set()
    for n, r in enumerate(o["profile_inputs"]):
        where = f"profile_inputs[{n}]"
        if r["context_index"] is not None:
            if r["context_index"] >= nctx:
                _fail(where, "dangling context reference")
            used_contexts.add(r["context_index"])
        if r["map_id"] is not None and r["map_id"] not in map_ids:
            _fail(where, "the profile names a map that was not accepted", "COV3012")
        if r["status"] == "accepted":
            counting_contexts.add(r["context_index"])
    profile_ids = [r["profile_id"] for r in accepted]
    if len(set(profile_ids)) != len(profile_ids):
        _fail("profile_inputs", "two accepted profiles carry one profile ID")
    if used_contexts != set(range(nctx)):
        _fail("semantic/contexts", "a context is listed that no inventoried profile decoded")
    for p in s["points"]:
        if any(c["context_index"] not in counting_contexts for c in p["count"]["by_context"]):
            _fail(f"point {p['point_id']}", "a count is attributed to a context no accepted profile has")

    # Run selection and completeness (SPEC 16.5.4, 16.5.7).
    rs = o["run_selection"]
    if rs["selected_run_ids"] != sorted({r["run_id"] for r in accepted}):
        _fail("run_selection", "selected_run_ids are not exactly the accepted profiles' run IDs")
    everything_accepted = all(r["status"] == "accepted" for r in o["map_inputs"] + o["profile_inputs"])
    want = bool(accepted) and everything_accepted and not o["merge"]["allow_rejected_inputs"] \
        and selection_satisfied(rs["mode"], rs["requested_run_ids"], rs["selected_run_ids"]) \
        and not o["diagnostics"] and not s["diagnostics"]
    if s["complete"] != want:
        _fail("semantic/complete", f"completeness recomputes to {str(want).lower()} (SPEC 16.5.7)")
    for code, present in (("COV3001", not accepted), ("COV3002", not everything_accepted),
                          ("COV3003", not selection_satisfied(rs["mode"], rs["requested_run_ids"], rs["selected_run_ids"])),
                          ("COV3004", "COV3004" in s["diagnostics"])):
        if (code in o["diagnostics"]) != present:
            _fail("diagnostics", f"{code} is recorded exactly when its condition holds")


def read_indexed(data: bytes, *, registry: diagnostics.Registry | None = None) -> dict:
    """Canonical ``sv0cov.indexed`` 1.0 bytes -> the validated object.

    Runs the structure layer, then cross-validates every retained fact (see
    the module docstring). Nothing outside ``data`` is read."""
    obj = decode_indexed_structure(data)
    _check_full(obj, registry)
    return obj


__all__ = ["MapInput", "ModelError", "ProfileInput", "RunSelection", "build_indexed", "read_indexed", "selection_satisfied"]
