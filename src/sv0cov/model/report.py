# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The native report producer and its cross-validating reader (CV-229; SPEC
11.2-11.6, 21.3, 22.1, 22.2.1; COV-REP-003, COV-REP-018..021, AC-105).

:func:`build_report` turns validated indexed evidence, a resolved
configuration and the current source bytes into ``sv0cov.report`` 1.0. It
reads the evidence through :func:`sv0cov.model.indexed.read_indexed`, so a
report is never made from evidence that does not cross-validate.

- Detail records are the indexed semantic records, unchanged; a region
  gains ``point_ids`` and an exclusion gains ``line_indices``.
- Summaries are counted from the detail (SPEC 11, 22.2.1): eligible units
  are ``user`` regions, branch outcomes that are ``covered`` or
  ``uncovered``, lines that are ``covered``, ``partial`` or ``uncovered``,
  functions whose entry point is ``user``, and non-excluded
  ``runtime_checked`` clauses. A function entity counts only what it owns,
  with its lines recomputed from its own regions.
- Policy holds the integrity evaluation and one evaluation per configured
  project threshold, decided by integer cross multiplication. A zero
  denominator follows the ``empty`` policy.
- Sources are compared with the bytes the caller supplies. A mismatch or a
  missing file is an error unless ``--allow-source-mismatch`` is resolved,
  and then the report can only be ``diagnostic_only``.

:func:`read_report` is what every consumer starts from. After the structure
layer (:mod:`sv0cov.formats.report`) it re-derives each redundant fact and
rejects any disagreement: record order, index positions and references;
point IDs; counts, region expressions, line membership and statuses, branch
and contract results, exclusions, the saturation inventory; every summary;
provenance against inputs and maps; the project evaluations and the
integrity evaluation; ``passed``; and the eligibility precedence.

What this build cannot do yet, and refuses rather than guess (``COV5001``):
scope, entity, diff, ratchet and exclusion assertions (R0.1), and an
execution record that failed or was signalled, for which the diagnostic
registry has no code. The reader accepts evaluations of those kinds when
they are internally consistent, because it cannot re-select their members.

What a reader cannot recheck is what a report does not retain: the indexed
evidence's own diagnostics beyond their union in the integrity evaluation,
and the current source bytes behind ``observed_digest``.

Failures raise :class:`sv0cov.formats.report.ReportError`: ``COV4001``
structure, ``COV4002`` a redundant fact that disagrees, ``COV1004`` a source
that is not current, ``COV0013`` a configuration that conflicts with the
evidence, ``COV5001`` something this build cannot evaluate.
"""

from __future__ import annotations

import hashlib
from typing import Mapping

from sv0cov import capabilities, diagnostics
from sv0cov.config_resolve import Resolved
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.report import METRICS, ReportError, decode_report_structure, ratio
from sv0cov.model import indexed as _ix

CAPABILITIES = ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "policy-assertions", "saturation-lower-bounds",
                "source-integrity"]
UNCOUNTED = ("excluded", "statically_unreachable")
EXECUTABLE = ("covered", "partial", "uncovered")
NO_MEMBERS = {"branch_indices": [], "clause_indices": [], "entity_indices": [], "line_indices": [], "region_indices": [],
              "source_indices": []}
MEMBER_KEY = {"branch": "branch_indices", "contract": "clause_indices", "function": "entity_indices", "line": "line_indices",
              "region": "region_indices"}
UNSUPPORTED_ASSERTIONS = ("scopes", "entities")
STALE, SATURATED, LOSSY, OVERRIDE = "COV1004", "COV4020", "COV4021", "COV3002"
REPORT_TIME = (STALE, SATURATED, LOSSY)


def _mismatch(where: str, detail: str) -> None:
    raise ReportError("COV4002", f"{where}: {detail}")


# ── metrics from detail ─────────────────────────────────────────────────────


class _Detail:
    """The units of a report (or of a report in the making) that metrics count."""

    def __init__(self, r: dict) -> None:
        self.r = r
        points = {p["point_id"]: p for p in r["points"]}
        self.entry = {p["entity_index"]: p for p in r["points"] if p["kind"] == "function_entry"}
        self.functions = [e["entity_index"] for e in r["entities"]
                          if e["kind"] == "function" and self.entry.get(e["entity_index"], {}).get("classification") == "user"]
        self.regions = [x["region_index"] for x in r["regions"] if x["classification"] == "user"]
        self.lines = [x["line_index"] for x in r["lines"] if x["status"] in EXECUTABLE]
        self.outcomes = [(b["branch_index"], o) for b in r["branches"] for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
        excluded = {i for x in r["exclusions"] for i in x["affected"]["clause_indices"]}
        self.clauses = [c["clause_index"] for c in r["contracts"] if c["enforcement"] == "runtime_checked" and c["clause_index"] not in excluded]
        self.points = points

    def _metric(self, covered: int, total: int, partial: int | None = None) -> dict:
        return {"covered": covered, "partial": partial, "ratio": ratio(covered, total), "total": total}

    def _regions(self, keep) -> dict:
        mine = [self.r["regions"][i] for i in self.regions if keep(self.r["regions"][i])]
        return self._metric(sum(x["count"]["value"] > 0 for x in mine), len(mine))

    def _branches(self, keep) -> dict:
        mine = [o for b, o in self.outcomes if keep(self.r["branches"][b])]
        return self._metric(sum(o["status"] == "covered" for o in mine), len(mine))

    def _functions(self, keep) -> dict:
        mine = [i for i in self.functions if keep(self.r["entities"][i])]
        return self._metric(sum(self.entry[i]["count"]["value"] > 0 for i in mine), len(mine))

    def _contracts(self, keep) -> dict:
        mine = [self.r["contracts"][i] for i in self.clauses if keep(self.r["contracts"][i])]
        return self._metric(sum(c["count_true"]["value"] + c["count_false"]["value"] > 0 for c in mine), len(mine))

    def _lines(self, keep) -> dict:
        mine = [self.r["lines"][i] for i in self.lines if keep(self.r["lines"][i])]
        return self._metric(sum(x["status"] == "covered" for x in mine), len(mine), sum(x["status"] == "partial" for x in mine))

    def group(self, keep=lambda rec: True) -> dict:
        """The five metrics over the units ``keep`` selects (by source, or all)."""
        return {"branch": self._branches(keep), "contract": self._contracts(keep), "function": self._functions(keep),
                "line": self._lines(keep), "region": self._regions(keep)}

    def entity(self, e: dict) -> dict:
        """SPEC 22.2.1: only what the entity owns."""
        n, r = e["entity_index"], self.r
        if e["kind"] == "contract":
            own = [c for c in r["contracts"] if c["entity_index"] == n and c["clause_index"] in self.clauses]
            covered = sum(c["count_true"]["value"] + c["count_false"]["value"] > 0 for c in own)
            return {"branch": None, "contract": self._metric(covered, len(own)), "function": None, "line": None, "region": None}
        owned = {i for i in self.regions if r["regions"][i]["entity_index"] == n}
        covered = partial = total = 0
        for line in r["lines"]:
            ran = [r["regions"][i]["count"]["value"] > 0 for i in line["region_indices"] if i in owned]
            if ran:
                total += 1
                covered += all(ran)
                partial += any(ran) and not all(ran)
        mine = lambda rec: rec["entity_index"] == n  # noqa: E731
        return {"branch": self._branches(mine),
                "contract": self._contracts(lambda c: c["function_entity_index"] == n),
                "function": self._metric(int(n in self.functions and self.entry[n]["count"]["value"] > 0), int(n in self.functions)),
                "line": self._metric(covered, total, partial),
                "region": self._regions(mine)}

    def members(self, metric: str) -> list[int]:
        if metric == "branch":
            return sorted({b for b, _ in self.outcomes})
        return {"contract": self.clauses, "function": self.functions, "line": self.lines, "region": self.regions}[metric]


def _line_indices(r: dict, affected: dict) -> list[int]:
    """The lines an exclusion touches: those naming one of its regions, or
    lying within one of its branches or clauses."""
    spots = {(r["regions"][i]["source_index"], n) for i in affected["region_indices"] for n in r["regions"][i]["line_numbers"]}
    for key, records in (("branch_indices", r["branches"]), ("clause_indices", r["contracts"])):
        for i in affected[key]:
            rec = records[i]
            spots |= {(rec["source_index"], n) for n in range(rec["span"]["start_line"], rec["span"]["end_line"] + 1)}
    return [x["line_index"] for x in r["lines"] if (x["source_index"], x["line"]) in spots]


# ── policy ──────────────────────────────────────────────────────────────────


def _evaluation(kind: str, name: str, metric: str, comparison: str, result: str, *, actual=None, limit=None, source=None,
                codes=(), members=None) -> dict:
    return {"actual": actual, "assertion_kind": kind, "assertion_name": name, "comparison": comparison, "diagnostics": sorted(codes),
            "limit": limit, "members": {**NO_MEMBERS, **(members or {})}, "metric": metric, "result": result, "threshold_source": source}


def _project_evaluations(r: dict, detail: _Detail) -> list[dict]:
    """One evaluation per configured project threshold (SPEC 22.1, 11.6)."""
    cov = r["resolved_configuration"]["coverage"]
    sat, out = r["saturation"], []
    contract_points = {p["point_id"] for p in r["points"] if p["kind"] in ("contract_true", "contract_false")}
    for metric in METRICS:
        threshold = cov["thresholds"][metric]["value"]
        if threshold is None:
            continue
        m = r["summary"][metric]
        limit = {"denominator": 10000, "numerator": threshold}
        base = dict(limit=limit, source="project", members={MEMBER_KEY[metric]: detail.members(metric)})
        blocked = sat["any"] and (sat["policy"] == "fail" or (metric == "contract" and contract_points & set(sat["affected_point_ids"])))
        if blocked:
            out.append(_evaluation("project", "project", metric, "at_least", "ineligible", codes=[SATURATED], **base))
        elif m["total"] == 0:
            passes = cov["empty"]["value"] == "pass"
            out.append(_evaluation("project", "project", metric, "at_least", "pass" if passes else "fail",
                                   codes=[] if passes else ["COV4102"], **base))
        else:
            passes = m["covered"] * 10000 >= m["total"] * threshold
            out.append(_evaluation("project", "project", metric, "at_least", "pass" if passes else "fail",
                                   actual={"denominator": m["total"], "numerator": m["covered"]}, codes=[] if passes else ["COV4101"], **base))
    return out


def _lossy(r: dict) -> bool:
    return r["resolved_configuration"]["report"]["allow_lossy_saturated_export"]["value"] and r["saturation"]["any"] \
        and "standard_exports" in r["saturation"]["ineligible_uses"]


def _report_time_codes(r: dict) -> set[str]:
    codes = set()
    if any(s["source_state"] != "current" for s in r["sources"]):
        codes.add(STALE)
    if r["saturation"]["any"] and (r["saturation"]["policy"] == "fail" or r["saturation"]["ineligible_uses"]):
        codes.add(SATURATED)
    if _lossy(r):
        codes.add(LOSSY)
    return codes


def _integrity(r: dict, evidence_codes: set[str]) -> dict:
    now = _report_time_codes(r)
    result = "fail" if evidence_codes - now else "ineligible" if now else "pass"
    return _evaluation("integrity", "integrity", "evidence", "none", result, codes=evidence_codes | now)


def _eligibility(r: dict) -> str:
    if not r["complete"]:
        return "incomplete"
    if r["provenance"]["source_accuracy"] == "mismatch_allowed" or _lossy(r) or r["saturation"]["ineligible_uses"]:
        return "diagnostic_only"
    return "passing" if r["policy"]["passed"] else "policy_failed"


def _ineligible_uses(r: dict, standard_export: bool) -> list[str]:
    """The exact-count uses present in a report whose evidence saturated (SPEC 21.3.8)."""
    sat = r["saturation"]
    if not sat["any"]:
        return []
    kinds = {p["kind"] for p in r["points"] if p["point_id"] in set(sat["affected_point_ids"])}
    uses = set()
    if kinds & {"contract_true", "contract_false"}:
        uses.add("contract_counts")
    if any(c["value"] is not None for c in r["contexts"]):
        uses.add("context_exact_counts")
    if standard_export:
        uses.add("standard_exports")
    return sorted(uses)


# ── producer ────────────────────────────────────────────────────────────────


def build_report(indexed: bytes, config: Resolved, sources: Mapping[str, bytes | None], *, standard_export: bool = False,
                 tool_version: str | None = None) -> dict:
    """The ``sv0cov.report`` 1.0 object for canonical indexed bytes.

    ``sources`` gives the current bytes of each source path of the evidence
    (``None`` or a missing key: the file is unavailable). ``standard_export``
    says the report accompanies an LCOV or Cobertura export. Raises
    :class:`ReportError`, or ``IndexedError`` for invalid evidence."""
    tier = config.tier().name
    ix = _ix.read_indexed(indexed, tier=tier)
    sem = ix["semantic"]
    cov = config.coverage
    for table in UNSUPPORTED_ASSERTIONS:
        if cov[table]:
            raise ReportError("COV5001", f"this build of sv0cov cannot evaluate [[tool.sv0cov.{table}]] assertions yet")
    for table in ("diff", "ratchet"):
        if cov[table] is not None:
            raise ReportError("COV5001", f"this build of sv0cov cannot evaluate a [tool.sv0cov.{table}] assertion yet")
    if any(leaf.value not in (None, []) for leaf in cov["exclusions"].values()):
        raise ReportError("COV5001", "this build of sv0cov cannot evaluate [tool.sv0cov.exclusions] caps yet")
    if ix["execution"]["status"] in ("failed", "signaled"):
        raise ReportError("COV5001", "this build of sv0cov cannot report evidence whose test command failed: the diagnostic "
                                     "registry has no code for it yet")
    policy = config.value("integrity.saturation")
    if sem["saturation"]["policy"] != policy:
        raise ReportError("COV0013", f"the evidence was merged under saturation policy {sem['saturation']['policy']}, "
                                     f"the report is configured for {policy}")

    allow_stale = config.report["allow_source_mismatch"].value
    report_sources = []
    for s in sem["sources"]:
        data = sources.get(s["path"])
        observed = None if data is None else hashlib.sha256(data).hexdigest()
        state = "unavailable" if observed is None else "current" if observed == s["digest"] else "mismatch"
        if state != "current" and not allow_stale:
            raise ReportError(STALE, f"source {s['path']} is {state}: coverage was collected from other bytes")
        report_sources.append({**s, "observed_digest": observed, "source_state": state})

    registry = diagnostics.load_registry()
    accepted = [x for x in ix["profile_inputs"] if x["status"] == "accepted"]
    r: dict = {
        "branches": sem["branches"],
        "capabilities": list(CAPABILITIES),
        "complete": sem["complete"],
        "contexts": sem["contexts"],
        "contracts": sem["contracts"],
        "entities": sem["entities"],
        "inputs": ix["profile_inputs"],
        "lines": sem["lines"],
        "maps": [{k: v for k, v in m.items() if k != "bindings"} for m in ix["maps"]],
        "points": sem["points"],
        "provenance": {
            "backends": sorted({x["backend"] for x in accepted}),
            "execution_exit_code": ix["execution"]["exit_code"],
            "execution_signal": ix["execution"]["signal"],
            "execution_status": ix["execution"]["status"],
            "indexed_diagnostic_registry_revision": ix["merge"]["tool"]["diagnostic_registry_revision"],
            "indexed_diagnostic_registry_sha256": ix["merge"]["tool"]["diagnostic_registry_sha256"],
            "indexed_input_sha256": hashlib.sha256(indexed).hexdigest(),
            "map_ids": sem["map_ids"],
            "run_ids": ix["run_selection"]["selected_run_ids"],
            "run_manifest_sha256": ix["run_selection"]["manifest_sha256"],
            "run_selection": ix["run_selection"]["mode"],
            "semantic_projection_sha256": ix["semantic_projection_sha256"],
            "source_accuracy": "current" if all(s["source_state"] == "current" for s in report_sources) else "mismatch_allowed",
        },
        "regions": [{**x, "point_ids": sorted({t["point_id"] for t in x["counter_expression"]["terms"]})} for x in sem["regions"]],
        "resolved_configuration": config.document(),
        "saturation": dict(sem["saturation"]),
        "schema": "sv0cov.report",
        "sources": report_sources,
        "tool": {"diagnostic_registry_revision": registry.revision, "diagnostic_registry_sha256": registry.sha256, "name": "sv0cov",
                 "version": tool_version or capabilities.tool_version()},
        "version": "1.0",
    }
    r["exclusions"] = [{**x, "affected": {**x["affected"], "line_indices": _line_indices(r, x["affected"])}} for x in sem["exclusions"]]
    r["saturation"]["ineligible_uses"] = _ineligible_uses(r, standard_export)
    keys = [_region_key(x) for x in r["regions"]]
    if any(not a < b for a, b in zip(keys, keys[1:])):
        raise ReportError("COV5001", "two regions share a source, span, kind and point set; this build cannot order them for a report")

    detail = _Detail(r)
    r["summary"] = detail.group()
    r["sources"] = [{**s, "summary": detail.group(lambda rec, n=s["source_index"]: rec["source_index"] == n)} for s in report_sources]
    r["entities"] = [{**e, "summary": detail.entity(e)} for e in sem["entities"]]

    evidence = set(ix["diagnostics"]) | set(sem["diagnostics"])
    if not sem["complete"] and not evidence:
        evidence.add(OVERRIDE)  # incomplete only because rejected inputs were allowed: the reason must still be named
    evaluations = sorted([_integrity(r, evidence), *_project_evaluations(r, detail)], key=_evaluation_key)
    r["policy"] = {"evaluations": evaluations, "passed": all(e["result"] in ("pass", "not_applicable") for e in evaluations)}
    r["evidence_eligibility"] = _eligibility(r)
    return dict(sorted(r.items()))


# ── reader ──────────────────────────────────────────────────────────────────


def _region_key(x: dict) -> tuple:
    return (x["source_index"], x["span"]["start_byte"], x["span"]["end_byte"], x["kind"].encode(), x["point_ids"])


def _evaluation_key(e: dict) -> tuple:
    return (e["assertion_kind"].encode(), e["assertion_name"].encode(), e["metric"].encode(), e["comparison"].encode())


def _holds(comparison: str, actual: dict, limit: dict) -> bool:
    left, right = actual["numerator"] * limit["denominator"], limit["numerator"] * actual["denominator"]
    return left >= right if comparison == "at_least" else left <= right if comparison == "at_most" else left == right


def _cross_validate(r: dict, registry: diagnostics.Registry | None) -> None:
    registry = registry or diagnostics.load_registry()
    tool = r["tool"]
    if (tool["diagnostic_registry_revision"], tool["diagnostic_registry_sha256"]) != (registry.revision, registry.sha256):
        raise ReportError("COV4001", f"the report names diagnostic registry revision {tool['diagnostic_registry_revision']}, "
                                     f"which this reader does not have (it has revision {registry.revision})")
    prov = r["provenance"]
    if (prov["indexed_diagnostic_registry_revision"] == registry.revision) != (prov["indexed_diagnostic_registry_sha256"] == registry.sha256):
        _mismatch("provenance", "the indexed registry revision and digest name different registries")
    stored = {c for x in r["inputs"] for c in x["diagnostics"]} | {c for e in r["policy"]["evaluations"] for c in e["diagnostics"]}
    unknown = sorted(c for c in stored if c not in registry.entries)
    if unknown:
        raise ReportError("COV4001", f"{unknown[0]} is not in the diagnostic registry")

    evaluations = r["policy"]["evaluations"]
    integrity = next(e for e in evaluations if e["assertion_kind"] == "integrity")

    # Everything the semantic records must satisfy among themselves (the indexed reader's rules).
    counted = {p["point_id"] for p in r["points"] if p["classification"] not in UNCOUNTED}
    view = {**r, "diagnostics": integrity["diagnostics"],
            "exclusions": [{**x, "affected": {k: v for k, v in x["affected"].items() if k != "line_indices"}} for x in r["exclusions"]]}
    try:
        _ix._check_semantic(view, counted)
    except IndexedError as exc:
        raise ReportError("COV4002", exc.detail) from None
    keys = [_region_key(x) for x in r["regions"]]
    if any(not a < b for a, b in zip(keys, keys[1:])):
        _mismatch("regions", "not ordered by source, span, kind and point set")
    for x in r["exclusions"]:
        if x["affected"]["line_indices"] != _line_indices(r, x["affected"]):
            _mismatch(f"exclusions[{x['exclusion_index']}]", "line_indices are not the lines its constructs touch")

    # Maps, inputs and provenance.
    nsrc, nctx = len(r["sources"]), len(r["contexts"])
    maps = r["maps"]
    map_ids = [m["map_id"] for m in maps]
    if map_ids != sorted(set(map_ids)):
        _mismatch("maps", "not strictly ordered by map ID")
    if any(i >= nsrc for m in maps for i in m["source_indices"]) or {i for m in maps for i in m["source_indices"]} != set(range(nsrc)):
        _mismatch("maps", "every source belongs to a map, and every map source exists")
    in_keys = [(x["status"].encode(), x["artifact_sha256"] is not None, x["artifact_sha256"] or "", x["name"].encode()) for x in r["inputs"]]
    if any(not a < b for a, b in zip(in_keys, in_keys[1:])):
        _mismatch("inputs", "not in canonical order, or one is repeated")
    accepted = [x for x in r["inputs"] if x["status"] == "accepted"]
    used: set[int] = set()
    for n, x in enumerate(r["inputs"]):
        if x["context_index"] is not None:
            if x["context_index"] >= nctx:
                _mismatch(f"inputs[{n}]", "dangling context reference")
            used.add(x["context_index"])
        if x["map_id"] is not None and x["map_id"] not in map_ids:
            _mismatch(f"inputs[{n}]", "names a map the report does not have")
    if used != set(range(nctx)):
        _mismatch("contexts", "a context is listed that no input decoded")
    counting = {x["context_index"] for x in accepted}
    if any(c["context_index"] not in counting for p in r["points"] for c in p["count"]["by_context"]):
        _mismatch("points", "a count is attributed to a context no accepted input has")
    ids = [x["profile_id"] for x in accepted]
    if len(set(ids)) != len(ids):
        _mismatch("inputs", "two accepted inputs carry one profile ID")
    for key, want in (("backends", sorted({x["backend"] for x in accepted})), ("run_ids", sorted({x["run_id"] for x in accepted})),
                      ("map_ids", map_ids)):
        if prov[key] != want:
            _mismatch(f"provenance/{key}", "does not equal what the inputs and maps give")
    if not accepted and r["complete"]:
        _mismatch("complete", "evidence with no accepted input is not complete")

    # Summaries.
    detail = _Detail(r)
    if r["summary"] != detail.group():
        _mismatch("summary", "does not equal the metrics counted from the detail records")
    for s in r["sources"]:
        if s["summary"] != detail.group(lambda rec, n=s["source_index"]: rec["source_index"] == n):
            _mismatch(f"sources[{s['source_index']}]/summary", "does not equal the metrics of that source's records")
    for e in r["entities"]:
        if e["summary"] != detail.entity(e):
            _mismatch(f"entities[{e['entity_index']}]/summary", "does not equal the metrics of what the entity owns")

    # Saturation uses, policy, eligibility.
    uses = r["saturation"]["ineligible_uses"]
    if [u for u in uses if u != "standard_exports"] != _ineligible_uses(r, False):
        _mismatch("saturation/ineligible_uses", "are not the exact-count uses present in the report")
    keys = [_evaluation_key(e) for e in evaluations]
    if any(not a < b for a, b in zip(keys, keys[1:])):
        _mismatch("policy/evaluations", "not in canonical order, or one is repeated")
    sizes = {"branch_indices": len(r["branches"]), "clause_indices": len(r["contracts"]), "entity_indices": len(r["entities"]),
             "line_indices": len(r["lines"]), "region_indices": len(r["regions"]), "source_indices": nsrc}
    for n, e in enumerate(evaluations):
        if any(v >= sizes[key] for key, values in e["members"].items() for v in values):
            _mismatch(f"policy/evaluations[{n}]", "a member index is dangling")
        if e["actual"] is not None and e["limit"] is not None and e["result"] in ("pass", "fail") \
                and _holds(e["comparison"], e["actual"], e["limit"]) != (e["result"] == "pass"):
            _mismatch(f"policy/evaluations[{n}]", "the result does not follow from the two fractions")
    if [e for e in evaluations if e["assertion_kind"] == "project"] != _project_evaluations(r, detail):
        _mismatch("policy/evaluations", "the project evaluations are not what the configured thresholds and the summary give")
    now = _report_time_codes(r)
    evidence = set(integrity["diagnostics"]) - now
    if not now <= set(integrity["diagnostics"]) or integrity != _integrity(r, evidence):
        _mismatch("policy/evaluations", "the integrity evaluation does not carry the report-time findings, or its result is wrong")
    if bool(evidence) != (not r["complete"]):
        _mismatch("complete", "evidence is incomplete exactly when the integrity evaluation names an evidence finding")
    if r["policy"]["passed"] != all(e["result"] in ("pass", "not_applicable") for e in evaluations):
        _mismatch("policy/passed", "true exactly when every evaluation passed or did not apply")
    if r["evidence_eligibility"] != _eligibility(r):
        _mismatch("evidence_eligibility", f"must be {_eligibility(r)} by the precedence of SPEC 21.3.8")


def read_report(data: bytes, *, registry: diagnostics.Registry | None = None, tier: str = "standard") -> dict:
    """Canonical ``sv0cov.report`` 1.0 bytes -> the validated object.

    Runs the structure layer, then cross-validates every redundant fact (see
    the module docstring). Nothing outside ``data`` is read."""
    obj = decode_report_structure(data, tier=tier)
    _cross_validate(obj, registry)
    return obj


__all__ = ["build_report", "read_report"]
