# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""From an indexed-profile operand to a validated native report: the part
``check`` and ``report`` share (CV-231, CV-232; SPEC 16.5, 20.3).

:func:`load_report` reads the operand (bounded before it is read), reads
every source path of the evidence below the working directory, builds the
native report under the command's resolved configuration, encodes it, and
reads it back through the cross-validating reader. A caller therefore only
ever sees a report the reader accepts.

What cannot go on is raised as :class:`Stop` with the diagnostic and the
exit status of SPEC 20.3:

- 5: the evidence cannot be read or is invalid, or a source file is missing
  or changed and the command does not allow that;
- 2: the configured saturation policy is not the one the evidence was
  merged under;
- 7: the policy needs an assertion this build cannot evaluate, or the
  operand is a native report.

A report the reader rejects is not a :class:`Stop`: it propagates and ends
as an internal failure.
"""

from __future__ import annotations

from sv0cov import cli
from sv0cov.cmd_merge import _read
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.map import map_limits
from sv0cov.formats.report import ReportError
from sv0cov.model.indexed import read_indexed
from sv0cov.model.report import build_report, read_report

#: What a refusal to evaluate means for the exit status.
REFUSAL_EXIT = {"COV0013": cli.EXIT_USAGE, "COV5001": cli.EXIT_UNSUPPORTED}
REFUSAL_PHASE = {"COV0013": "configuration", "COV5001": "policy"}
NATIVE_REPORT = b'"schema":"sv0cov.report"'


class Stop(Exception):
    """The command cannot go on: ``diagnostic`` says why, ``status`` is its exit status."""

    def __init__(self, code: str, phase: str, detail: str, status: int) -> None:
        super().__init__(code)
        self.diagnostic = Diagnostic(code, phase, facts=(("detail", cli.fact_text(detail)),))
        self.status = status


def load_report(ctx: cli.Context, *, standard_export: bool = False) -> tuple[dict, bytes]:
    """The native report of the command's one operand, and its canonical bytes."""
    tier = ctx.config.tier().name
    (operand,) = ctx.invocation.operands
    data, fault = _read(ctx.cwd / operand, map_limits(tier).max_bytes, follow=True)
    if data is None:
        code, why = fault or ("COV3010", "cannot be read")
        raise Stop(code, "collection", f"the indexed profile {why}", cli.EXIT_EVIDENCE)
    return report_of(ctx, data, standard_export=standard_export)


def report_of(ctx: cli.Context, data: bytes, *, standard_export: bool = False) -> tuple[dict, bytes]:
    """The native report of indexed-profile bytes under the command's
    configuration, read back through the reader, and its canonical bytes."""
    config = ctx.config
    tier = config.tier().name
    limit = map_limits(tier).max_bytes
    try:
        indexed = read_indexed(data, tier=tier)
    except IndexedError as exc:
        if NATIVE_REPORT in data:  # canonical JSON: these bytes can only be the top-level member
            raise Stop("COV5001", "invocation", f"this build of sv0cov takes an indexed profile for {ctx.invocation.command}, "
                                                "not a native report", cli.EXIT_UNSUPPORTED) from None
        raise Stop(exc.code, "collection", exc.detail, cli.EXIT_EVIDENCE) from None

    sources = {}
    for s in indexed["semantic"]["sources"]:
        sources[s["path"]], _ = _read(ctx.cwd / s["path"], limit, follow=True)
    try:
        encoded = encode(build_report(data, config, sources, standard_export=standard_export))
        return read_report(encoded, tier=tier), encoded
    except ReportError as exc:
        if exc.code in REFUSAL_EXIT:
            raise Stop(exc.code, REFUSAL_PHASE[exc.code], exc.detail, REFUSAL_EXIT[exc.code]) from None
        if exc.code in ("COV4001", "COV4002"):
            raise  # the producer and the reader disagree: an internal failure
        raise Stop(exc.code, "report", exc.detail, cli.EXIT_EVIDENCE) from None
