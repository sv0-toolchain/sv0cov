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

Changed-region coverage (CV-312; SPEC 22.3): with a diff policy the caller
passes the Git capture of the user sources (:mod:`sv0cov.gitdiff`); it is
kept as ``changes`` and bound to the evidence by source digest, and any
source that is not the compiled bytes is ``COV4305`` with no result. One
``diff`` evaluation per line, region and branch counts what meets a changed
current-side line. The reader re-derives them from ``changes``.

Ratchets (CV-313; SPEC 22.4): with a ratchet policy the caller passes the
baseline file's bytes (or none) and the Git facts that decide staleness. The
report keeps what it compared as ``ratchet``: the baseline's counts, its
state (``ok``, ``missing``, ``invalid``, ``incompatible``, ``stale``), the
per-metric outcomes and the source-set change. The ratchet evaluations are
re-derived from it.

What this build cannot do yet, and refuses rather than guess (``COV5001``):
exclusion-cap assertions (R0.1). The reader accepts evaluations
of those kinds when they are internally consistent, because it cannot
re-select their members.

A lifecycle command that failed or was ended by a signal makes the integrity
evaluation fail with ``COV2130``, whatever the coverage says (SPEC 21.3.5,
22.5).

What a reader cannot recheck is what a report does not retain: the indexed
evidence's own diagnostics beyond their union in the integrity evaluation,
and the current source bytes behind ``observed_digest``.

Failures raise :class:`sv0cov.formats.report.ReportError`: ``COV4001``
structure, ``COV4002`` a redundant fact that disagrees, ``COV1004`` a source
that is not current, ``COV0013`` a configuration that conflicts with the
evidence (including a scope package or source, or an entity, the evidence
does not have), ``COV5001`` something this build cannot evaluate.
"""

from __future__ import annotations

import hashlib
from bisect import bisect_left
from math import gcd
from typing import Mapping

from sv0cov import capabilities, diagnostics
from sv0cov.config_resolve import Resolved
from sv0cov.formats.baseline import METRIC_SCHEMA, BaselineError, decode_baseline
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.report import METRICS, ReportError, decode_report_structure, ratio
from sv0cov.gitignore import Matcher
from sv0cov.model import indexed as _ix

CAPABILITIES = ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "policy-assertions", "saturation-lower-bounds",
                "source-integrity"]
UNCOUNTED = ("excluded", "statically_unreachable")
EXECUTABLE = ("covered", "partial", "uncovered")
NO_MEMBERS = {"branch_indices": [], "clause_indices": [], "entity_indices": [], "line_indices": [], "region_indices": [],
              "source_indices": []}
MEMBER_KEY = {"branch": "branch_indices", "contract": "clause_indices", "function": "entity_indices", "line": "line_indices",
              "region": "region_indices"}
APPLICABLE = {"function": METRICS, "contract": ("contract",)}
STALE, SATURATED, LOSSY, OVERRIDE = "COV1004", "COV4020", "COV4021", "COV3002"
#: A compiled source changed between the changed-region capture and publication (SPEC 22.3).
CHANGED = "COV4305"
DIFF_METRICS = ("branch", "line", "region")
#: A ratchet comparison failed or could not be made (SPEC 22.4).
RATCHET_FAILED = "COV4201"
#: What a ratchet can find about one metric besides its verdict (SPEC 22.4).
OUTCOMES = ("denominator_growth", "exclusion_growth", "numerator_regression")
#: The lifecycle command failed or was ended by a signal (registry revision 2; SPEC 21.3.5).
COMMAND_FAILED = "COV2130"
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

    def members(self, metric: str, keep=lambda rec: True) -> list[int]:
        """The denominator membership of ``metric`` over the units ``keep`` selects."""
        r = self.r
        if metric == "branch":
            return sorted({b for b, _ in self.outcomes if keep(r["branches"][b])})
        if metric == "contract":
            return [i for i in self.clauses if keep(r["contracts"][i])]
        if metric == "function":
            return [i for i in self.functions if keep(r["entities"][i])]
        if metric == "line":
            return [i for i in self.lines if keep(r["lines"][i])]
        return [i for i in self.regions if keep(r["regions"][i])]

    def entity_members(self, e: dict, metric: str) -> list[int]:
        """SPEC 22.2.1: the denominator membership of ``metric`` for the entity."""
        n, r = e["entity_index"], self.r
        if metric == "function":
            return [n]
        if metric == "contract":
            field = "entity_index" if e["kind"] == "contract" else "function_entity_index"
            return [i for i in self.clauses if r["contracts"][i][field] == n]
        if metric == "region":
            return [i for i in self.regions if r["regions"][i]["entity_index"] == n]
        if metric == "branch":
            return sorted({b for b, _ in self.outcomes if r["branches"][b]["entity_index"] == n})
        owned = {i for i in self.regions if r["regions"][i]["entity_index"] == n}
        return [x["line_index"] for x in r["lines"] if any(i in owned for i in x["region_indices"])]


def _line_indices(r: dict, affected: dict) -> list[int]:
    """The lines an exclusion touches: those naming one of its regions, or
    lying within one of its branches or clauses."""
    spots = {(r["regions"][i]["source_index"], n) for i in affected["region_indices"] for n in r["regions"][i]["line_numbers"]}
    # A span is compared with the line records rather than enumerated: its line range comes
    # from the input and can be four billion lines long.
    spans: dict[int, list[tuple[int, int]]] = {}
    for key, records in (("branch_indices", r["branches"]), ("clause_indices", r["contracts"])):
        for i in affected[key]:
            rec = records[i]
            spans.setdefault(rec["source_index"], []).append((rec["span"]["start_line"], rec["span"]["end_line"]))
    return [x["line_index"] for x in r["lines"]
            if (x["source_index"], x["line"]) in spots or any(a <= x["line"] <= b for a, b in spans.get(x["source_index"], ()))]


# ── policy ──────────────────────────────────────────────────────────────────


def _evaluation(kind: str, name: str, metric: str, comparison: str, result: str, *, actual=None, limit=None, source=None,
                codes=(), members=None) -> dict:
    return {"actual": actual, "assertion_kind": kind, "assertion_name": name, "comparison": comparison, "diagnostics": sorted(codes),
            "limit": limit, "members": {**NO_MEMBERS, **(members or {})}, "metric": metric, "result": result, "threshold_source": source}


def _threshold_evaluation(r: dict, kind: str, name: str, metric: str, m: dict, limit_value: int | None, source: str | None,
                          members: dict) -> dict:
    """One assertion's evaluation of one metric (SPEC 22.1, 22.2, 11.6,
    14.2.1): no threshold reports the fraction and checks nothing."""
    cov, sat = r["resolved_configuration"]["coverage"], r["saturation"]
    actual = None if m["total"] == 0 else {"denominator": m["total"], "numerator": m["covered"]}
    if limit_value is None:
        return _evaluation(kind, name, metric, "none", "not_applicable", actual=actual, members=members)
    limit = {"denominator": 10000, "numerator": limit_value}
    base = dict(limit=limit, source=source, members=members)
    contract_points = {p["point_id"] for p in r["points"] if p["kind"] in ("contract_true", "contract_false")}
    if sat["any"] and (sat["policy"] == "fail" or (metric == "contract" and contract_points & set(sat["affected_point_ids"]))):
        return _evaluation(kind, name, metric, "at_least", "ineligible", codes=[SATURATED], **base)
    if m["total"] == 0:
        passes = cov["empty"]["value"] == "pass"
        return _evaluation(kind, name, metric, "at_least", "pass" if passes else "fail", codes=[] if passes else ["COV4102"], **base)
    passes = m["covered"] * 10000 >= m["total"] * limit_value
    return _evaluation(kind, name, metric, "at_least", "pass" if passes else "fail", actual=actual,
                       codes=[] if passes else ["COV4101"], **base)


def _inherit(assertion: dict, project: dict, metric: str) -> tuple[int | None, str | None]:
    """SPEC 22.2: an explicit value is the assertion's own; an omitted one
    inherits the project threshold for that metric only; no cascade."""
    own = assertion[metric]["value"]
    if own is not None:
        return own, "assertion"
    if project[metric] is not None:
        return project[metric], "project"
    return None, None


def scope_sources(r: dict, scope: dict) -> list[int]:
    """The sources a scope selects (SPEC 18.2.2, 18.3, 22.2): the union of
    its ``include`` patterns, ``packages`` and ``sources``, each source once.
    A configured package or source path the evidence does not have is
    ``COV0013``; patterns that select nothing make an empty scope."""
    name = scope["name"]["value"]
    chosen: set[int] = set()
    patterns = scope["include"]["value"]
    if patterns is not None:
        m = Matcher(patterns)
        chosen |= {s["source_index"] for s in r["sources"] if m.selects(s["path"])}
    packages = {s["package"] for s in r["sources"] if s["package"] is not None}
    for pkg in scope["packages"]["value"] or []:
        if pkg not in packages:
            raise ReportError("COV0013", f"scope {name}: no compiled source belongs to the package {pkg!r}")
        chosen |= {s["source_index"] for s in r["sources"] if s["package"] == pkg}
    paths = {s["path"] for s in r["sources"]}
    for path in scope["sources"]["value"] or []:
        if path not in paths:
            raise ReportError("COV0013", f"scope {name}: the source {path!r} was not compiled into this evidence")
        chosen |= {s["source_index"] for s in r["sources"] if s["path"] == path}
    return sorted(chosen)


def resolve_entity(r: dict, entity: dict) -> dict:
    """The one entity of the evidence an entity assertion names (SPEC
    18.2.2): source path, qualified name and kind; none or several is
    ``COV0013``."""
    name, want = entity["name"]["value"], (entity["source"]["value"], entity["qualified_name"]["value"], entity["kind"]["value"])
    path = {s["source_index"]: s["path"] for s in r["sources"]}
    found = [e for e in r["entities"] if (path[e["source_index"]], e["qualified_name"], e["kind"]) == want]
    if len(found) != 1:
        what = "no entity" if not found else f"{len(found)} entities"
        raise ReportError("COV0013", f"entity {name}: {what} of kind {want[2]} named {want[1]!r} in {want[0]!r}")
    return found[0]


def _assertion_evaluations(r: dict, detail: _Detail) -> list[dict]:
    """Every named scope and entity assertion, each metric on its own
    (SPEC 22.2, 22.2.1; COV-SCP-005/006, COV-POL-002/022/023/026,
    COV-CFG-008). Assertions are independent: none overrides another."""
    cov = r["resolved_configuration"]["coverage"]
    project = {m: cov["thresholds"][m]["value"] for m in METRICS}
    out = []
    for scope in cov["scopes"]:
        chosen = frozenset(scope_sources(r, scope))
        keep = lambda rec, c=chosen: rec["source_index"] in c  # noqa: E731
        summary = detail.group(keep)
        for metric in METRICS:
            limit, source = _inherit(scope, project, metric)
            members = {"source_indices": sorted(chosen), MEMBER_KEY[metric]: detail.members(metric, keep)}
            out.append(_threshold_evaluation(r, "scope", scope["name"]["value"], metric, summary[metric], limit, source, members))
    for entity in cov["entities"]:
        e = resolve_entity(r, entity)
        summary = detail.entity(e)
        for metric in APPLICABLE[e["kind"]]:
            limit, source = _inherit(entity, project, metric)
            members = {"entity_indices": [e["entity_index"]], MEMBER_KEY[metric]: detail.entity_members(e, metric)}
            out.append(_threshold_evaluation(r, "entity", entity["name"]["value"], metric, summary[metric], limit, source, members))
    return out


def change_record(sources: list[dict], capture: dict) -> dict:
    """The report's ``changes`` member from a capture record
    (:meth:`sv0cov.gitdiff.Capture.record`) of exactly the user sources.
    A source whose captured bytes are not the ones compiled is ``COV4305``."""
    users = {s["path"]: s for s in sources if s["ownership"] == "user"}
    held = {c["path"]: c for c in capture["sources"]}
    if set(held) != set(users):
        raise ValueError("the changed-region capture must hold exactly the user sources of the evidence")
    out = []
    for path, c in held.items():
        if c["sha256"] != users[path]["digest"]:
            raise ReportError(CHANGED, f"source {path} is not what was compiled: it changed between the changed-region capture "
                                       "and the build")
        out.append({"changed_lines": c["changed_lines"], "old_path": c["old_path"], "repo_path": c["repo_path"], "sha256": c["sha256"],
                    "source_index": users[path]["source_index"], "staged": c["staged"], "state": c["state"], "unstaged": c["unstaged"]})
    return {"base": dict(capture["base"]), "clean": capture["clean"], "diff_options": list(capture["diff_options"]),
            "diff_sha256": capture["diff_sha256"], "git": dict(capture["git"]), "sources": sorted(out, key=lambda c: c["source_index"])}


def _diff_evaluations(r: dict, detail: _Detail) -> list[dict]:
    """The changed-region assertion (SPEC 22.3): a region or a branch is
    changed when its span meets a changed current-side line, a line when it
    is one. Deleted lines have no current line and never count. Each metric
    is its own evaluation; one without a diff threshold reports its fraction
    and checks nothing. No project threshold is inherited."""
    if r["changes"] is None:
        return []
    diff = r["resolved_configuration"]["coverage"]["diff"]
    changed = {c["source_index"]: c["changed_lines"] for c in r["changes"]["sources"] if c["changed_lines"]}
    sets = {i: set(v) for i, v in changed.items()}

    def meets(rec: dict) -> bool:
        lines = changed.get(rec["source_index"])
        if not lines:
            return False
        i = bisect_left(lines, rec["span"]["start_line"])
        return i < len(lines) and lines[i] <= rec["span"]["end_line"]

    def on(rec: dict) -> bool:
        return rec["line"] in sets.get(rec["source_index"], ())

    keep = {"branch": meets, "line": on, "region": meets}
    measured = {"branch": detail._branches(meets), "line": detail._lines(on), "region": detail._regions(meets)}
    out = []
    for metric in DIFF_METRICS:
        limit = diff[metric]["value"]
        members = {"source_indices": sorted(changed), MEMBER_KEY[metric]: detail.members(metric, keep[metric])}
        out.append(_threshold_evaluation(r, "diff", "diff", metric, measured[metric], limit, None if limit is None else "diff", members))
    return out


# ── ratchets (CV-313; SPEC 22.4) ────────────────────────────────────────────


def excluded_members(r: dict, metric: str) -> list[int]:
    """The records of ``metric`` that an exclusion removed from its
    denominator: excluded regions, lines, functions and runtime-checked
    clauses, and branches with an excluded outcome."""
    if metric == "region":
        return [x["region_index"] for x in r["regions"] if x["classification"] == "excluded"]
    if metric == "line":
        return [x["line_index"] for x in r["lines"] if x["status"] == "excluded"]
    if metric == "branch":
        return [b["branch_index"] for b in r["branches"] if any(o["status"] == "excluded" for o in b["outcomes"])]
    if metric == "function":
        entry = {p["entity_index"]: p for p in r["points"] if p["kind"] == "function_entry"}
        return [e["entity_index"] for e in r["entities"]
                if e["kind"] == "function" and entry.get(e["entity_index"], {}).get("classification") == "excluded"]
    off = {i for x in r["exclusions"] for i in x["affected"]["clause_indices"]}
    return [c["clause_index"] for c in r["contracts"] if c["enforcement"] == "runtime_checked" and c["clause_index"] in off]


def excluded_units(r: dict, metric: str) -> int:
    """How many units of ``metric`` exclusions removed (a branch counts its excluded outcomes)."""
    if metric == "branch":
        return sum(o["status"] == "excluded" for b in r["branches"] for o in b["outcomes"])
    return len(excluded_members(r, metric))


def baseline_body(r: dict, *, commit: str | None) -> dict:
    """The ``sv0cov.baseline`` 1.0 content of a report, without its pin
    (:func:`sv0cov.formats.baseline.encode_baseline` adds it)."""
    return {
        "commit": commit,
        "exclusion_records": len(r["exclusions"]),
        "metric_schema": METRIC_SCHEMA,
        "metrics": {m: {"covered": r["summary"][m]["covered"], "excluded": excluded_units(r, m), "total": r["summary"][m]["total"]}
                    for m in METRICS},
        "saturation_policy": r["saturation"]["policy"],
        "schema": "sv0cov.baseline",
        "sources": sorted(({"digest": s["digest"], "path": s["path"]} for s in r["sources"]), key=lambda s: s["path"].encode()),
        "tool": {"name": "sv0cov", "version": r["tool"]["version"]},
        "version": "1.0",
    }


def _ratchet_derived(r: dict, rec: dict) -> dict:
    """The comparisons and the source-set difference a ratchet record holds
    when its baseline is usable, and nothing otherwise."""
    if rec["state"] != "ok":
        return {"comparisons": [], "sources_added": [], "sources_removed": []}
    b = rec["baseline"]
    now = {s["path"] for s in r["sources"]}
    comparisons = []
    for m in METRICS:
        old, cur = b["metrics"][m], r["summary"][m]
        found = []
        if cur["total"] > old["total"]:
            found.append("denominator_growth")
        if excluded_units(r, m) > old["excluded"]:
            found.append("exclusion_growth")
        if cur["covered"] < old["covered"]:
            found.append("numerator_regression")
        comparisons.append({"metric": m, "outcomes": found})
    key = lambda p: p.encode()  # noqa: E731
    return {"comparisons": comparisons, "sources_added": sorted(now - set(b["sources"]), key=key),
            "sources_removed": sorted(set(b["sources"]) - now, key=key)}


def ratchet_state(r: dict, baseline: dict | None, ancestor: bool | None) -> str:
    """``incompatible`` for another metric schema or saturation policy,
    ``stale`` for a baseline made at a commit that is not ``HEAD`` or one
    of its ancestors, else ``ok`` (SPEC 14.2.1, 22.4)."""
    if baseline["metric_schema"] != METRIC_SCHEMA or baseline["saturation_policy"] != r["saturation"]["policy"]:
        return "incompatible"
    if baseline["commit"] is not None and not ancestor:
        return "stale"
    return "ok"


def ratchet_record(r: dict, data: bytes | None, *, head: str | None, ancestor: bool | None, tier: str = "standard") -> dict:
    """The report's ``ratchet`` member from the baseline file's bytes
    (``None``: there is none), ``HEAD`` now, and whether the baseline's
    commit is ``HEAD`` or an ancestor of it."""
    rec = {"baseline": None, "baseline_sha256": None if data is None else hashlib.sha256(data).hexdigest(), "head": head,
           "state": "missing" if data is None else "invalid"}
    if data is not None:
        try:
            b = decode_baseline(data, tier=tier)
        except BaselineError:
            b = None
        if b is not None:
            rec["baseline"] = {"commit": b["commit"], "exclusion_records": b["exclusion_records"], "metric_schema": b["metric_schema"],
                               "metrics": b["metrics"], "saturation_policy": b["saturation_policy"],
                               "sources": [s["path"] for s in b["sources"]], "tool_version": b["tool"]["version"]}
            rec["state"] = ratchet_state(r, rec["baseline"], ancestor)
    return {**rec, **_ratchet_derived(r, rec)}


def _fraction(numerator: int, denominator: int) -> dict:
    g = gcd(numerator, denominator) or 1
    return {"denominator": denominator // g, "numerator": numerator // g}


def ratchet_limit(old: dict, tolerance: int) -> dict:
    """The least ratio that does not regress: the baseline's less the
    tolerance in basis points, never below zero (an empty baseline: 0/1)."""
    if old["total"] == 0:
        return {"denominator": 1, "numerator": 0}
    return _fraction(max(0, old["covered"] * 10000 - tolerance * old["total"]), old["total"] * 10000)


def _ratchet_evaluations(r: dict, detail: _Detail) -> list[dict]:
    """Per configured metric, the ratio (``at_least`` the baseline's less
    the tolerance) and the excluded units (``at_most`` the baseline's), and
    the exclusion-record count (``at_most``). A changed source set makes the
    ratios ineligible; a missing, invalid, incompatible or stale baseline
    makes every comparison ineligible (SPEC 22.4)."""
    rec = r["ratchet"]
    if rec is None:
        return []
    cfg = r["resolved_configuration"]["coverage"]["ratchet"]
    metrics, tolerance = cfg["metrics"]["value"], cfg["tolerance_basis_points"]["value"]
    sat, empty = r["saturation"], r["resolved_configuration"]["coverage"]["empty"]["value"]
    contract_points = {p["point_id"] for p in r["points"] if p["kind"] in ("contract_true", "contract_false")}
    out = []
    for m in metrics:
        cur = r["summary"][m]
        actual = None if cur["total"] == 0 else {"denominator": cur["total"], "numerator": cur["covered"]}
        members = {MEMBER_KEY[m]: detail.members(m)}
        excluded = {MEMBER_KEY[m]: excluded_members(r, m)}
        if rec["state"] != "ok":
            out.append(_evaluation("ratchet", "ratchet", m, "none", "ineligible", actual=actual, codes=[RATCHET_FAILED], members=members))
            continue
        old = rec["baseline"]["metrics"][m]
        base = dict(limit=ratchet_limit(old, tolerance), source="ratchet", members=members)
        if sat["any"] and (sat["policy"] == "fail" or (m == "contract" and contract_points & set(sat["affected_point_ids"]))):
            out.append(_evaluation("ratchet", "ratchet", m, "at_least", "ineligible", codes=[SATURATED], **base))
        elif rec["sources_added"] or rec["sources_removed"]:
            out.append(_evaluation("ratchet", "ratchet", m, "at_least", "ineligible", actual=actual, codes=[RATCHET_FAILED], **base))
        elif actual is None:
            passes = empty == "pass"
            out.append(_evaluation("ratchet", "ratchet", m, "at_least", "pass" if passes else "fail",
                                   codes=[] if passes else ["COV4102"], **base))
        else:
            passes = _holds("at_least", actual, base["limit"])
            out.append(_evaluation("ratchet", "ratchet", m, "at_least", "pass" if passes else "fail", actual=actual,
                                   codes=[] if passes else [RATCHET_FAILED], **base))
        units = excluded_units(r, m)
        grew = units > old["excluded"]
        out.append(_evaluation("ratchet", "ratchet", m, "at_most", "fail" if grew else "pass", actual={"denominator": 1, "numerator": units},
                               limit={"denominator": 1, "numerator": old["excluded"]}, source="ratchet",
                               codes=[RATCHET_FAILED] if grew else [], members=excluded))
    records = len(r["exclusions"])
    if rec["state"] != "ok":
        out.append(_evaluation("ratchet", "ratchet", "exclusion_records", "none", "ineligible",
                               actual={"denominator": 1, "numerator": records}, codes=[RATCHET_FAILED]))
    else:
        old = rec["baseline"]["exclusion_records"]
        grew = records > old
        out.append(_evaluation("ratchet", "ratchet", "exclusion_records", "at_most", "fail" if grew else "pass",
                               actual={"denominator": 1, "numerator": records}, limit={"denominator": 1, "numerator": old},
                               source="ratchet", codes=[RATCHET_FAILED] if grew else []))
    return out


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
    command = {COMMAND_FAILED} if r["provenance"]["execution_status"] in ("failed", "signaled") else set()
    result = "fail" if (evidence_codes - now) or command else "ineligible" if now else "pass"
    return _evaluation("integrity", "integrity", "evidence", "none", result, codes=evidence_codes | now | command)


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
                 tool_version: str | None = None, changes: dict | None = None, ratchet: dict | None = None) -> dict:
    """The ``sv0cov.report`` 1.0 object for canonical indexed bytes.

    ``sources`` gives the current bytes of each source path of the evidence
    (``None`` or a missing key: the file is unavailable). ``standard_export``
    says the report accompanies an LCOV or Cobertura export. ``changes``
    is the changed-region capture of the user sources
    (:meth:`sv0cov.gitdiff.Capture.record`), required exactly when a diff
    policy is configured. ``ratchet`` is what a ratchet policy compares
    with: ``{"data": <baseline bytes or None>, "head": <commit or None>,
    "ancestor": <bool or None>}``, required exactly when one is configured.
    Raises
    :class:`ReportError`, or ``IndexedError`` for invalid evidence."""
    tier = config.tier().name
    ix = _ix.read_indexed(indexed, tier=tier)
    sem = ix["semantic"]
    cov = config.coverage
    if (cov["ratchet"] is None) != (ratchet is None):
        raise ValueError("a ratchet input is given exactly when a ratchet policy is configured")
    if (cov["diff"] is None) != (changes is None):
        raise ValueError("a changed-region capture is given exactly when a diff policy is configured")
    if any(leaf.value not in (None, []) for leaf in cov["exclusions"].values()):
        raise ReportError("COV5001", "this build of sv0cov cannot evaluate [tool.sv0cov.exclusions] caps yet")
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
        if state != "current" and cov["diff"] is not None:
            # No changed-region result for bytes that are not the ones compiled (SPEC 22.3, AC-049).
            raise ReportError(CHANGED, f"source {s['path']} changed after it was compiled; no changed-region result is published")
        if state != "current" and not allow_stale:
            what = "is missing or unreadable" if state == "unavailable" else "has changed since coverage was collected"
            raise ReportError(STALE, f"source {s['path']} {what}")
        report_sources.append({**s, "observed_digest": observed, "source_state": state})

    registry = diagnostics.load_registry()
    accepted = [x for x in ix["profile_inputs"] if x["status"] == "accepted"]
    r: dict = {
        "branches": sem["branches"],
        "capabilities": list(CAPABILITIES),
        "changes": None if changes is None else change_record(report_sources, changes),
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
    r["ratchet"] = None if ratchet is None else ratchet_record(r, ratchet["data"], head=ratchet["head"], ancestor=ratchet["ancestor"],
                                                                tier=tier)

    evidence = set(ix["diagnostics"]) | set(sem["diagnostics"])
    if not sem["complete"] and not evidence:
        evidence.add(OVERRIDE)  # incomplete only because rejected inputs were allowed: the reason must still be named
    evaluations = sorted([_integrity(r, evidence), *_project_evaluations(r, detail), *_assertion_evaluations(r, detail),
                          *_diff_evaluations(r, detail), *_ratchet_evaluations(r, detail)],
                         key=_evaluation_key)
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
    try:
        derived = sorted(_assertion_evaluations(r, detail), key=_evaluation_key)
    except ReportError as exc:
        _mismatch("policy/evaluations", f"the configured assertions do not resolve against the report: {exc.detail}")
    if [e for e in evaluations if e["assertion_kind"] in ("entity", "scope")] != derived:
        _mismatch("policy/evaluations", "the scope and entity evaluations are not what their configuration and the detail give")
    if r["changes"] is not None:
        if prov["source_accuracy"] != "current":
            _mismatch("changes", "a changed-region result is made only from current sources")
        users = {s["source_index"]: s for s in r["sources"] if s["ownership"] == "user"}
        if [c["source_index"] for c in r["changes"]["sources"]] != sorted(users) or \
                any(c["sha256"] != users[c["source_index"]]["digest"] for c in r["changes"]["sources"]):
            _mismatch("changes/sources", "the capture holds each user source once, with the digest it was compiled from")
    rt = r["ratchet"]
    if (rt is None) != (r["resolved_configuration"]["coverage"]["ratchet"] is None):
        _mismatch("ratchet", "a ratchet record is present exactly when a ratchet policy is configured")
    if rt is not None:
        if (rt["baseline"] is None) != (rt["state"] in ("missing", "invalid")) or (rt["baseline_sha256"] is None) != (rt["state"] == "missing"):
            _mismatch("ratchet/state", "missing has no file, invalid no usable baseline, and every other state a decoded baseline")
        if rt["baseline"] is not None:
            want = ratchet_state(r, rt["baseline"], rt["state"] == "ok")
            if want == "incompatible" or rt["state"] == "incompatible":
                if want != rt["state"]:
                    _mismatch("ratchet/state", "incompatible exactly for another metric schema or saturation policy")
            elif rt["state"] == "stale" and rt["baseline"]["commit"] is None:
                _mismatch("ratchet/state", "only a baseline made at a commit can be stale")
        if {k: rt[k] for k in ("comparisons", "sources_added", "sources_removed")} != _ratchet_derived(r, rt):
            _mismatch("ratchet", "the comparisons and source changes are not what the baseline and the report give")
    if [e for e in evaluations if e["assertion_kind"] == "ratchet"] != sorted(_ratchet_evaluations(r, detail), key=_evaluation_key):
        _mismatch("policy/evaluations", "the ratchet evaluations are not what the baseline, its configuration and the detail give")
    if [e for e in evaluations if e["assertion_kind"] == "diff"] != _diff_evaluations(r, detail):
        _mismatch("policy/evaluations", "the changed-region evaluations are not what the capture, its thresholds and the detail give")
    now = _report_time_codes(r)
    evidence = set(integrity["diagnostics"]) - now - {COMMAND_FAILED}
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
