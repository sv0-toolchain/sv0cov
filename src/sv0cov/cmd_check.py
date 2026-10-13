# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``check`` command (CV-231; SPEC 11.6, 20.1, 20.3, 22.1, 22.5;
COV-CLI-002, COV-POL-001, COV-MET-012, AC-014, AC-015)::

    sv0cov check [options] <indexed-profile>

It reads one indexed profile, compares the current source files with the
ones the evidence was collected from, and evaluates the resolved policy:
the integrity of the evidence and every configured project threshold. It
writes nothing to disk.

The evaluation itself is the native report's (:mod:`sv0cov.evidence`), so
``check`` and a report of the same evidence under the same configuration
can never disagree. The report is built, encoded and read back through the
cross-validating reader before any result is given.

**Sources.** Each source path of the evidence is read below the working
directory, which is the project root. A missing or changed file is a
source-integrity failure: ``check`` has no way to allow it.

**Result.**

==== ==========================================================
exit meaning
==== ==========================================================
0    The evidence is complete and current and every assertion passed.
1    The evidence is sound and an assertion did not pass: a threshold
     failed, a selected metric was empty, or saturation made a check
     ineligible.
2    The configuration conflicts with the evidence (its saturation policy).
5    The evidence cannot be relied on: it cannot be read, is invalid, is
     incomplete, or a source file is missing or changed.
7    The policy needs something this build cannot evaluate, or the operand
     is a native report.
==== ==========================================================

Every assertion that did not pass is a diagnostic on stderr with its exact
fractions. The summary on stdout is incidental and ``--quiet`` removes it.
"""

from __future__ import annotations

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.evidence import Stop, load_report
from sv0cov.formats.terminal import render_check

COMPARISON = {"at_least": ">=", "at_most": "<=", "equal": "=="}


def _fraction(f: dict) -> str:
    return f"{f['numerator']}/{f['denominator']}"


def evaluation_diagnostics(report: dict) -> list[Diagnostic]:
    """One diagnostic for each code of each assertion that did not pass."""
    out = []
    for e in report["policy"]["evaluations"]:
        if e["result"] in ("pass", "not_applicable"):
            continue
        facts = [("assertion", f"{e['assertion_kind']}:{e['assertion_name']}"), ("metric", e["metric"]), ("result", e["result"])]
        if e["actual"] is not None:
            facts.append(("actual", _fraction(e["actual"])))
        if e["limit"] is not None:
            facts.append(("required", f"{COMPARISON[e['comparison']]} {_fraction(e['limit'])}"))
        out += [Diagnostic(code, "policy", facts=tuple(facts)) for code in e["diagnostics"]]
    return out


def exit_status(report: dict) -> int:
    """SPEC 20.3: unreliable evidence is 5, a policy that did not pass is 1."""
    (integrity,) = [e for e in report["policy"]["evaluations"] if e["assertion_kind"] == "integrity"]
    if not report["complete"] or integrity["result"] == "fail":
        return cli.EXIT_EVIDENCE
    if not report["policy"]["passed"] or report["evidence_eligibility"] != "passing":
        return cli.EXIT_POLICY
    return cli.EXIT_OK


@cli.command("check")
def cmd_check(ctx: cli.Context) -> int:
    console = ctx.console
    try:
        report, _ = load_report(ctx)
    except Stop as stop:
        console.report(stop.diagnostic)
        return stop.status
    for diagnostic in evaluation_diagnostics(report):
        console.report(diagnostic)
    console.say(render_check(report, color=console.colored(console.stdout)).rstrip("\n"))
    return exit_status(report)
