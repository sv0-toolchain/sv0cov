# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``baseline`` command (CV-313; SPEC 22.4; COV-POL-005, BL-051)::

    sv0cov baseline [options] <indexed-profile>

The explicit update of a ratchet baseline. It builds the native report of
the evidence under the resolved configuration, exactly as ``check`` and
``report`` do (so the old baseline is compared too), prints the old and new
metrics, exclusion counts and source changes, and then writes the
``sv0cov.baseline`` 1.0 file named by ``[tool.sv0cov.ratchet].baseline``
(or ``--ratchet-baseline``) in one atomic step that replaces the old file.
It is the only sv0cov operation that replaces an artifact.

The new baseline records the commit ``HEAD`` names (``null`` outside Git), so
a later ratchet can tell when it describes another history.

A baseline is made only from evidence a policy could pass on: complete,
from current sources, with no exact-count use made ineligible by
saturation. Anything else is refused and nothing is written.

==== ==========================================================
exit meaning
==== ==========================================================
0    The baseline was written.
2    Usage or configuration: no ratchet policy names a baseline.
5    The evidence cannot be relied on, or cannot make a baseline.
6    The baseline could not be written.
7    The operand is a native report.
==== ==========================================================

This command is not advertised (``version``) and is not part of the root
``coverage`` namespace until its gate review (CV-316).
"""

from __future__ import annotations

import hashlib

from sv0cov import cli, gitdiff
from sv0cov.diagnostics import Diagnostic
from sv0cov.evidence import Stop, load_report
from sv0cov.formats.baseline import METRICS, decode_baseline, encode_baseline
from sv0cov.model.report import baseline_body
from sv0cov.publish import PublishError, replace_file


def _signed(n: int) -> str:
    return f"+{n}" if n > 0 else str(n)


def delta_lines(old: dict | None, new: dict) -> list[str]:
    """The old and new counts of each metric and of the exclusion records,
    and the sources added and removed (SPEC 22.4)."""
    rows = [["metric", "old covered/total", "old excluded", "new covered/total", "new excluded", "change"]]
    for m in METRICS:
        n = new["metrics"][m]
        if old is None:
            rows.append([m, "-", "-", f"{n['covered']}/{n['total']}", str(n["excluded"]), "new"])
            continue
        o = old["metrics"][m]
        change = (f"covered {_signed(n['covered'] - o['covered'])}, total {_signed(n['total'] - o['total'])}, "
                  f"excluded {_signed(n['excluded'] - o['excluded'])}")
        rows.append([m, f"{o['covered']}/{o['total']}", str(o["excluded"]), f"{n['covered']}/{n['total']}", str(n["excluded"]), change])
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]) - 1)]
    out = ["  ".join(c.ljust(w) for c, w in zip(r, widths)) + "  " + r[-1] for r in rows]
    old_records = "-" if old is None else str(old["exclusion_records"])
    out.append(f"exclusion records: {old_records} -> {new['exclusion_records']}")
    if old is not None:
        before = set(old["sources"])
        after = {s["path"] for s in new["sources"]}
        added, removed = sorted(after - before, key=str.encode), sorted(before - after, key=str.encode)
        out.append(f"sources: {len(added)} added, {len(removed)} removed")
        out += [f"  + {p}" for p in added] + [f"  - {p}" for p in removed]
    return out


@cli.command("baseline")
def cmd_baseline(ctx: cli.Context) -> int:
    console, config = ctx.console, ctx.config
    table = config.coverage["ratchet"]
    if table is None:
        console.report(Diagnostic("COV0001", "invocation", facts=(
            ("detail", "baseline writes the file a ratchet policy names: configure [tool.sv0cov.ratchet] or pass "
                       "--ratchet-baseline and --ratchet-metric"), ("subject", "baseline"))))
        return cli.EXIT_USAGE
    rel = table["baseline"].value
    try:
        report, _ = load_report(ctx)
    except Stop as stop:
        console.report(stop.diagnostic)
        return stop.status
    if not report["complete"] or report["evidence_eligibility"] == "diagnostic_only":
        console.report(Diagnostic("COV4201", "policy", facts=(
            ("detail", "a baseline is made only from complete evidence of current sources with no exact-count use made "
                       f"ineligible; this evidence is {report['evidence_eligibility'].replace('_', ' ')}"),)))
        return cli.EXIT_EVIDENCE
    body = baseline_body(report, commit=gitdiff.head_commit(ctx.cwd))
    data = encode_baseline(body)
    new = decode_baseline(data)
    old = report["ratchet"]
    state = old["state"]
    was = "none" if state == "missing" else f"{state}, sha256 {old['baseline_sha256'][:12]}"
    commit = "no commit" if body["commit"] is None else f"commit {body['commit'][:12]}"
    console.say(f"baseline {rel}: was {was}; now sha256 {hashlib.sha256(data).hexdigest()[:12]} at {commit}")
    console.say("\n".join(delta_lines(old["baseline"], new)))
    tier = config.tier().name
    try:
        replace_file(rel, data, anchor=str(ctx.cwd), validate=lambda b: decode_baseline(b, tier=tier))
    except PublishError as exc:
        console.report(Diagnostic(exc.code, "publication", facts=(("artifact", "baseline"), ("detail", cli.fact_text(exc.detail)))))
        return cli.EXIT_REPORT
    console.say(f"wrote {rel}")
    return cli.EXIT_OK
