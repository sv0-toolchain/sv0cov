# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``check`` command (CV-231; SPEC 11.6, 20.1, 20.3, 22.1, 22.5;
COV-CLI-002, COV-POL-001, COV-MET-012, AC-014, AC-015)::

    sv0cov check [options] <indexed-profile>

It reads one indexed profile, compares the current source files with the
ones the evidence was collected from, and evaluates the resolved policy:
the integrity of the evidence and every configured project threshold. It
writes nothing to disk.

The evaluation itself is the native report's (:func:`build_report`), so
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
from sv0cov.cmd_merge import _read
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.map import map_limits
from sv0cov.formats.report import ReportError
from sv0cov.formats.terminal import render_check
from sv0cov.model.indexed import read_indexed
from sv0cov.model.report import build_report, read_report

COMPARISON = {"at_least": ">=", "at_most": "<=", "equal": "=="}
#: What a refusal to evaluate means for the exit status.
REFUSAL_EXIT = {"COV0013": cli.EXIT_USAGE, "COV5001": cli.EXIT_UNSUPPORTED}
REFUSAL_PHASE = {"COV0013": "configuration", "COV5001": "policy"}
NATIVE_REPORT = b'"schema":"sv0cov.report"'


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
    console, config = ctx.console, ctx.config
    tier = config.tier().name
    limit = map_limits(tier).max_bytes
    (operand,) = ctx.invocation.operands

    def stop(code: str, phase: str, detail: str, status: int) -> int:
        console.report(Diagnostic(code, phase, facts=(("detail", cli.fact_text(detail)),)))
        return status

    data, fault = _read(ctx.cwd / operand, limit, follow=True)
    if data is None:
        code, why = fault or ("COV3010", "cannot be read")
        return stop(code, "collection", f"the indexed profile {why}", cli.EXIT_EVIDENCE)
    try:
        indexed = read_indexed(data, tier=tier)
    except IndexedError as exc:
        if NATIVE_REPORT in data:  # canonical JSON: these bytes can only be the top-level member
            return stop("COV5001", "invocation", "this build of sv0cov checks an indexed profile, not a native report",
                        cli.EXIT_UNSUPPORTED)
        return stop(exc.code, "collection", exc.detail, cli.EXIT_EVIDENCE)

    sources = {}
    for s in indexed["semantic"]["sources"]:
        sources[s["path"]], _ = _read(ctx.cwd / s["path"], limit, follow=True)
    try:
        report = build_report(data, config, sources)
        report = read_report(encode(report), tier=tier)
    except ReportError as exc:
        if exc.code in REFUSAL_EXIT:
            return stop(exc.code, REFUSAL_PHASE[exc.code], exc.detail, REFUSAL_EXIT[exc.code])
        if exc.code in ("COV4001", "COV4002"):
            raise  # the producer and the reader disagree: an internal failure
        return stop(exc.code, "report", exc.detail, cli.EXIT_EVIDENCE)

    for diagnostic in evaluation_diagnostics(report):
        console.report(diagnostic)
    console.say(render_check(report, color=console.colored(console.stdout)).rstrip("\n"))
    return exit_status(report)
