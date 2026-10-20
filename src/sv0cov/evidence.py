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

With a ratchet policy the configured baseline is read (a missing one is
not an error here: the ratchet reports it) and Git is asked for ``HEAD``
and whether the baseline's commit is an ancestor (:func:`ratchet_input`).

With a diff policy (``[tool.sv0cov.diff]`` or ``--diff-base``) the Git side
of changed-region coverage comes first (:mod:`sv0cov.gitdiff`, SPEC 22.3):
the base is resolved and the user sources of the evidence are captured,
unless the caller (``run``) captured them before the build. A base that is
missing, cannot be resolved or is ambiguous (``COV4301``..``COV4303``) is a
configuration error, 2. A compiled source that is untracked or ignored
(``COV4304``), or that is not the bytes compiled (``COV4305``), is a
source-integrity failure, 5. None of them produces a changed-region number.

A report the reader rejects is not a :class:`Stop`: it propagates and ends
as an internal failure.
"""

from __future__ import annotations

from sv0cov import cli, gitdiff
from sv0cov.cmd_merge import _read
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.baseline import BaselineError, decode_baseline
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.map import map_limits
from sv0cov.formats.report import ReportError
from sv0cov.model.indexed import read_indexed
from sv0cov.model.report import build_report, read_report

#: What a refusal to evaluate means for the exit status.
REFUSAL_EXIT = {"COV0013": cli.EXIT_USAGE, "COV5001": cli.EXIT_UNSUPPORTED}
REFUSAL_PHASE = {"COV0013": "configuration", "COV5001": "policy"}
#: Exit status of a changed-region failure (SPEC 20.3, 22.3).
GIT_EXIT = {gitdiff.MISSING: cli.EXIT_USAGE, gitdiff.UNRESOLVED: cli.EXIT_USAGE, gitdiff.AMBIGUOUS: cli.EXIT_USAGE,
            gitdiff.UNTRACKED: cli.EXIT_EVIDENCE, gitdiff.STALE: cli.EXIT_EVIDENCE}
NATIVE_REPORT = b'"schema":"sv0cov.report"'


class Stop(Exception):
    """The command cannot go on: ``diagnostic`` says why, ``status`` is its exit status."""

    def __init__(self, code: str, phase: str, detail: str, status: int) -> None:
        super().__init__(code)
        self.diagnostic = Diagnostic(code, phase, facts=(("detail", cli.fact_text(detail)),))
        self.status = status


def load_report(ctx: cli.Context, *, standard_export: bool = False,
                sources_out: dict[str, bytes | None] | None = None) -> tuple[dict, bytes]:
    """The native report of the command's one operand, and its canonical bytes.
    ``sources_out``, when given, receives the source bytes that were read."""
    tier = ctx.config.tier().name
    (operand,) = ctx.invocation.operands
    data, fault = _read(ctx.cwd / operand, map_limits(tier).max_bytes, follow=True)
    if data is None:
        code, why = fault or ("COV3010", "cannot be read")
        raise Stop(code, "collection", f"the indexed profile {why}", cli.EXIT_EVIDENCE)
    return report_of(ctx, data, standard_export=standard_export, sources_out=sources_out)


def git_stop(exc: gitdiff.GitDiffError) -> Stop:
    """The :class:`Stop` of a changed-region failure."""
    return Stop(exc.code, "policy", exc.detail, GIT_EXIT[exc.code])


def diff_base(ctx: cli.Context) -> gitdiff.Base | None:
    """The resolved changed-region base, or ``None`` without a diff policy."""
    diff = ctx.config.coverage["diff"]
    if diff is None:
        return None
    try:
        return gitdiff.resolve_base(ctx.cwd, diff["base"].value)
    except gitdiff.GitDiffError as exc:
        raise git_stop(exc) from None


def inside(ctx: cli.Context, rel: str) -> bool:
    """Whether ``rel`` really is inside the project: a symlink on the way
    may point elsewhere in it, never out of it (COV-SEC-002)."""
    try:
        return (ctx.cwd / rel).resolve().is_relative_to(ctx.cwd.resolve())
    except (OSError, RuntimeError):  # a symlink loop
        return False


def ratchet_input(ctx: cli.Context) -> dict | None:
    """What a ratchet policy compares with (CV-313; SPEC 22.4): the bytes
    of the configured baseline (``None`` when there is no such file), the
    current ``HEAD``, and whether the commit the baseline names is ``HEAD``
    or an ancestor of it. ``None`` without a ratchet policy. A baseline path
    that leads out of the project, is not a regular file, or is over the
    reader's size stops the command (5)."""
    table = ctx.config.coverage["ratchet"]
    if table is None:
        return None
    rel = table["baseline"].value
    if not inside(ctx, rel):
        raise Stop("COV6002", "policy", f"the ratchet baseline {rel} resolves outside the project", cli.EXIT_EVIDENCE)
    data, fault = _read(ctx.cwd / rel, map_limits(ctx.config.tier().name).max_bytes, follow=True)
    if fault is not None:
        raise Stop(fault[0], "policy", f"the ratchet baseline {rel} {fault[1]}", cli.EXIT_EVIDENCE)
    head = gitdiff.head_commit(ctx.cwd)
    ancestor = None
    if data is not None:
        try:
            commit = decode_baseline(data, tier=ctx.config.tier().name)["commit"]
        except BaselineError:
            commit = None
        if commit is not None:
            ancestor = head is not None and gitdiff.is_ancestor(ctx.cwd, commit, head)
    return {"ancestor": ancestor, "data": data, "head": head}


def report_of(ctx: cli.Context, data: bytes, *, standard_export: bool = False,
              sources_out: dict[str, bytes | None] | None = None, capture: gitdiff.Capture | None = None) -> tuple[dict, bytes]:
    """The native report of indexed-profile bytes under the command's
    configuration, read back through the reader, and its canonical bytes.
    ``sources_out``, when given, receives the source bytes that were read
    (``None`` for a file that could not be), for the HTML report.
    ``capture`` is a changed-region snapshot taken before the build; without
    one, a diff policy captures the sources now."""
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
        # A source is read only where it really is inside the project (COV-SEC-002).
        if not inside(ctx, s["path"]):
            raise Stop("COV6002", "report", f"source {s['path']} resolves outside the project", cli.EXIT_EVIDENCE)
        sources[s["path"]], _ = _read(ctx.cwd / s["path"], limit, follow=True)
    if sources_out is not None:
        sources_out.update(sources)
    changes = None
    if config.coverage["diff"] is not None:
        users = [s["path"] for s in indexed["semantic"]["sources"] if s["ownership"] == "user"]
        try:
            if capture is None:
                capture = gitdiff.snapshot(diff_base(ctx), users)
            changes = capture.restrict(users).record()
        except gitdiff.GitDiffError as exc:
            raise git_stop(exc) from None
    try:
        encoded = encode(build_report(data, config, sources, standard_export=standard_export, changes=changes,
                                      ratchet=ratchet_input(ctx)))
        return read_report(encoded, tier=tier), encoded
    except ReportError as exc:
        if exc.code in REFUSAL_EXIT:
            raise Stop(exc.code, REFUSAL_PHASE[exc.code], exc.detail, REFUSAL_EXIT[exc.code]) from None
        if exc.code in ("COV4001", "COV4002"):
            raise  # the producer and the reader disagree: an internal failure
        raise Stop(exc.code, "report", exc.detail, cli.EXIT_EVIDENCE) from None
