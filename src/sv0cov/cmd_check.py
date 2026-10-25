# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``check`` command (CV-231; SPEC 11.6, 20.1, 20.3, 22.1, 22.5;
COV-CLI-002, COV-POL-001, COV-MET-012, AC-014, AC-015)::

    sv0cov check [options] <indexed-profile-or-native-report>

It reads one indexed profile, or a native report (CV-416, D-10), compares the current source files with the
ones the evidence was collected from, and evaluates the resolved policy:
the integrity of the evidence, every configured threshold, scope and entity
assertion and, with a diff policy, changed-region coverage against a Git base
(:mod:`sv0cov.gitdiff`, captured now and bound to the evidence by source
digest). It writes nothing to disk.

A native-report operand is read through the cross-validating reader and its
detail re-evaluated under the current configuration and against the current
sources, exactly as the indexed profile it came from would be: the verdict
it recorded is never reused.

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
2    The configuration conflicts with the evidence (its saturation policy),
     or the changed-region base is missing, cannot be resolved or is
     ambiguous (COV4301..COV4303).
5    The evidence cannot be relied on: it cannot be read, is invalid, is
     incomplete, or a source file is missing or changed; or, with a diff
     policy, a compiled source is not tracked by Git (COV4304) or is not
     the bytes compiled (COV4305).
7    The policy needs something this build cannot evaluate.
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


def ratchet_facts(t: dict, metric: str) -> list[tuple[str, str]]:
    """Why a ratchet evaluation did not pass: the baseline's state, the
    source-set change and what changed in this metric (SPEC 22.4)."""
    facts = [("baseline", t["state"])]
    if t["sources_added"] or t["sources_removed"]:
        def some(paths: list[str], verb: str) -> str:
            shown = ", ".join(paths[:5]) + (", ..." if len(paths) > 5 else "")
            return f"{len(paths)} {verb}" + (f" ({shown})" if paths else "")
        facts.append(("sources", cli.fact_text(f"{some(t['sources_added'], 'added')}, {some(t['sources_removed'], 'removed')}")))
    found = [o for c in t["comparisons"] if c["metric"] == metric for o in c["outcomes"]]
    if found:
        facts.append(("outcomes", ", ".join(found)))
    return facts


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
        if e["assertion_kind"] == "ratchet" and report["ratchet"] is not None:
            facts += ratchet_facts(report["ratchet"], e["metric"])
        facts.sort(key=lambda f: f[0].encode())
        out += [Diagnostic(code, "policy", facts=tuple(facts)) for code in e["diagnostics"]]
    return out


def coverage_failed(report: dict) -> bool:
    """Whether an assertion did not pass for a reason other than the test
    command itself having failed (``COV2130`` on the integrity evaluation)."""
    for e in report["policy"]["evaluations"]:
        if e["result"] in ("pass", "not_applicable"):
            continue
        if e["assertion_kind"] == "integrity" and e["diagnostics"] == ["COV2130"]:
            continue
        return True
    return False


def exit_status(report: dict) -> int:
    """SPEC 20.3: incomplete evidence is 5, a policy that did not pass is 1.
    (A reader-validated report names an evidence finding exactly when it is
    incomplete; a failed test command alone is a policy failure here.)"""
    if not report["complete"]:
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
