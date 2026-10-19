# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Context filtering of a native report (CV-308; SPEC 17.4, 21.2,
COV-CTX-001, COV-CTX-004, AC-024).

A report carries the aggregate count of every point, region, branch outcome
and contract clause, and each context's own count in ``by_context`` (absent
there: that context's exact zero). :func:`context_view` is the read-only
filter a report renderer offers next to the aggregate: the same report units
with every count replaced by one context's count, and everything derived
from counts worked out again from those counts with the report's own rules
(line status from the contributing user regions, outcome status, a clause's
runtime result, and the five metrics of the whole report, of each source and
of each entity).

The view is a new object. The report passed in is never modified, so
filtering cannot change the aggregate (COV-CTX-004), and the aggregate stays
available whether or not any context was collected (COV-CTX-001). Policy,
provenance, inputs and exclusions are not part of a view: thresholds read
aggregate counts (SPEC 17.4) and a view is not a report.
"""

from __future__ import annotations

import copy

from sv0cov.model.report import _Detail

ZERO = {"lower_bound": False, "saturated": False, "value": 0}


class ContextError(ValueError):
    """The context index names no context of the report."""


def _pick(count: dict | None, index: int) -> dict | None:
    """The count record ``count`` reduced to context ``index``."""
    if count is None:
        return None
    mine = next((c for c in count["by_context"] if c["context_index"] == index), None)
    one = ZERO if mine is None else {k: mine[k] for k in ("lower_bound", "saturated", "value")}
    by_context = [] if mine is None else [dict(mine)]
    return {"by_context": by_context, **one}


def context_view(report: dict, context_index: int) -> dict:
    """The units of ``report`` counted by context ``context_index`` alone.

    Returns ``context`` (the context record), and ``branches``,
    ``contracts``, ``entities``, ``lines``, ``points``, ``regions``,
    ``sources`` and ``summary`` shaped as in the report. Raises
    :class:`ContextError` for an unknown index."""
    ctx = next((c for c in report["contexts"] if c["context_index"] == context_index), None)
    if ctx is None:
        raise ContextError(f"the report has no context {context_index}")
    r = copy.deepcopy({k: report[k] for k in ("branches", "contracts", "entities", "exclusions", "lines", "points", "regions",
                                              "sources")})
    for p in r["points"]:
        p["count"] = _pick(p["count"], context_index)
    for x in r["regions"]:
        x["count"] = _pick(x["count"], context_index)
    for line in r["lines"]:
        if line["status"] in ("covered", "partial", "uncovered"):
            ran = [r["regions"][i]["count"]["value"] > 0 for i in line["region_indices"]
                   if r["regions"][i]["classification"] == "user"]
            line["status"] = "covered" if all(ran) else "partial" if any(ran) else "uncovered"
    for b in r["branches"]:
        for o in b["outcomes"]:
            o["count"] = _pick(o["count"], context_index)
            if o["status"] in ("covered", "uncovered"):
                o["status"] = "covered" if o["count"]["value"] > 0 else "uncovered"
    for c in r["contracts"]:
        if c["enforcement"] == "runtime_checked":
            c["count_true"] = _pick(c["count_true"], context_index)
            c["count_false"] = _pick(c["count_false"], context_index)
            t, f = c["count_true"]["value"], c["count_false"]["value"]
            c["runtime_result"] = "mixed" if t and f else "evaluated_true" if t else "evaluated_false" if f else "not_evaluated"
    detail = _Detail(r)
    view = {
        "branches": r["branches"],
        "context": dict(ctx),
        "contracts": r["contracts"],
        "entities": [{**e, "summary": detail.entity(e)} for e in r["entities"]],
        "lines": r["lines"],
        "points": r["points"],
        "regions": r["regions"],
        "sources": [{**s, "summary": detail.group(lambda rec, n=s["source_index"]: rec["source_index"] == n)} for s in r["sources"]],
        "summary": detail.group(),
    }
    return view
