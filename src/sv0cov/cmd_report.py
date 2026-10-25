# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``report`` command (CV-232; SPEC 20.2, 21; COV-CLI-002, COV-CLI-008,
COV-REP-016)::

    sv0cov report --format <format> [--format <format>...] [options] <indexed-profile>

It reads one indexed profile, builds the native report (:mod:`sv0cov.evidence`)
and publishes the selected formats without replacing anything
(:mod:`sv0cov.publish`).

**Formats.** Only ``--format`` selects them; ``[tool.sv0cov].reports`` is
for ``run`` and is not read. Request order does not matter: artifacts are
produced in the canonical order ``term``, ``html``, ``json``, ``lcov``,
``cobertura``.

**Standard exports** (CV-403). ``lcov`` and ``cobertura`` are published
with the native JSON report and an export commit manifest
(:mod:`sv0cov.exports`): in a bundle as ``coverage.json`` and
``<format>.manifest.json``; beside a single file ``P`` as
``P.sv0cov.json`` and ``P.manifest.json`` (native first, manifest last);
for stdout in the new directory ``<output_dir>/reports/<format>-stdout-support``,
published only after stdout took the primary. A saturated count refuses the
export (``COV4020``, 6) unless ``--allow-lossy-saturated-export`` asks for
the diagnostic-only lossy export, which is published with a ``COV4021``
warning (CV-420).

**Destination** (SPEC 20.2.2).

=========  ===================  ==========================================
formats    ``--output``         destination
=========  ===================  ==========================================
one        a path               that file; its parent must exist
one        ``-``                stdout, and nothing else on stdout
one        omitted              ``<output_dir>/reports/<canonical name>``
several    a path               a new bundle directory of canonical names
several    ``-``                invalid
several    omitted              the new bundle ``<output_dir>/reports``
=========  ===================  ==========================================

The destination is checked before the evidence is read. A terminal report
written to a file is always colorless; on stdout it follows ``--color``.

**Result.** 0 when the selected formats are published, whatever the policy
says: a report of failing or incomplete evidence is still a report, and
says so. 2 for invalid usage, a saturation-policy conflict or a
changed-region base that cannot be used; 5 when the evidence or a source
cannot be relied on (``--allow-source-mismatch`` lets a stale source
through as diagnostic-only, except under a diff policy, where it is
``COV4305``); 6 when the destination exists
or publication fails; 7 for a format or assertion this build lacks.
"""

from __future__ import annotations

import os

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.evidence import Stop, load_report
from sv0cov.exports import MANIFEST_SUFFIX, NATIVE_SUFFIX, STANDARD, ExportStop, bundle, disposition, lossy_warning, single, support_dir
from sv0cov.formats.html import check_html, render_html
from sv0cov.formats.terminal import render_terminal, terminal_bytes
from sv0cov.model.report import read_report
from sv0cov.publish import PublishError, check_destination, publish_bundle, publish_file, publish_stdout

#: Canonical order and primary filename of every format (SPEC 20.2.1).
FILENAMES = {"term": "coverage.txt", "html": "coverage.html", "json": "coverage.json", "lcov": "lcov.info", "cobertura": "cobertura.xml"}
IMPLEMENTED = tuple(FILENAMES)
REPORTS_DIR = "reports"


def _publish_failure(exc: PublishError) -> Diagnostic:
    return Diagnostic(exc.code, "publication", facts=(("artifact", "report"), ("detail", cli.fact_text(exc.detail))))


def _plain_text(data: bytes) -> None:
    """A terminal report in a file is UTF-8 with no control but the line feed."""
    text = data.decode("utf-8")
    if any((ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F for c in text) or not text.endswith("\n"):
        raise ValueError("the terminal report holds a control character")


@cli.command("report")
def cmd_report(ctx: cli.Context) -> int:
    console, config = ctx.console, ctx.config
    requested = config.controls["--format"]
    formats = [f for f in FILENAMES if f in requested]
    output = config.controls.get("--output")
    to_stdout = output == "-"
    is_bundle = len(formats) > 1
    standard = [f for f in formats if f in STANDARD]
    lone_export = standard[0] if standard and not is_bundle else None

    missing = [f for f in formats if f not in IMPLEMENTED]
    if missing:
        console.report(Diagnostic("COV5001", "invocation", facts=(
            ("detail", "this build of sv0cov does not produce this report format yet"), ("format", missing[0]))))
        return cli.EXIT_UNSUPPORTED
    if is_bundle and to_stdout:
        console.report(Diagnostic("COV0001", "invocation", facts=(
            ("detail", "stdout takes exactly one format; several formats need a bundle directory"), ("subject", "--output"))))
        return cli.EXIT_USAGE

    reports_dir = f"{config.value('output_dir')}/{REPORTS_DIR}"
    if output is None:
        final, anchor = (reports_dir if is_bundle else f"{reports_dir}/{FILENAMES[formats[0]]}"), str(ctx.cwd)
    else:
        final, anchor = str(ctx.cwd / output), None
    support = f"{reports_dir}/{support_dir(lone_export)}" if lone_export and to_stdout else None
    tier = config.tier().name
    timestamp = config.value("reproducible_epoch")

    def native(data: bytes) -> None:
        read_report(data, tier=tier)

    validators = {"coverage.txt": _plain_text, "coverage.json": native, "coverage.html": check_html}
    try:
        try:
            if not to_stdout:
                check_destination(final, anchor=anchor)
                if lone_export:
                    check_destination(final + NATIVE_SUFFIX, anchor=anchor)
                    check_destination(final + MANIFEST_SUFFIX, anchor=anchor)
            elif support is not None:
                check_destination(support, anchor=str(ctx.cwd))
        except PublishError as exc:
            console.report(_publish_failure(exc))
            return cli.EXIT_REPORT
        sources: dict[str, bytes | None] = {}
        report, encoded = load_report(ctx, standard_export=bool(standard), sources_out=sources)
    except Stop as stop:
        console.report(stop.diagnostic)
        return stop.status

    render = {"term": lambda: terminal_bytes(report), "html": lambda: render_html(report, sources), "json": lambda: encoded}
    try:
        files = {FILENAMES[f]: render[f]() for f in formats if f not in STANDARD}
        if is_bundle:
            extra, checks = bundle(formats, report, encoded, timestamp=timestamp, tier=tier)
            files.update(extra)
            validators.update(checks)
        elif lone_export:
            export = single(lone_export, report, encoded, basename=None if to_stdout else os.path.basename(final),
                            timestamp=timestamp, tier=tier)
    except ExportStop as stop:
        console.report(stop.diagnostic)
        return stop.status
    try:
        if lone_export and to_stdout:
            # The support set is complete and valid before stdout is touched; it is committed only after.
            members = {export["native_name"]: export["native"], export["manifest_name"]: export["manifest"]}
            checks = {export["native_name"]: native, export["manifest_name"]: export["check_manifest"]}
            for name, data in members.items():
                try:
                    checks[name](data)
                except Exception as exc:  # noqa: BLE001 - any validator failure means nothing is written
                    raise PublishError("failed", f"validation failed ({type(exc).__name__})") from None
            publish_stdout(console.binary_stdout(), export["primary"], validate=export["check_primary"])
            publish_bundle(support, members, anchor=str(ctx.cwd), validate=checks)
        elif lone_export:
            # Three names, three commits: native, primary, then the manifest that commits the set (SPEC 20.2.3).
            publish_file(final + NATIVE_SUFFIX, export["native"], anchor=anchor, validate=native)
            publish_file(final, export["primary"], anchor=anchor, validate=export["check_primary"])
            publish_file(final + MANIFEST_SUFFIX, export["manifest"], anchor=anchor, validate=export["check_manifest"])
        elif to_stdout:
            first = next(iter(files))
            data = files[first]
            if formats[0] == "term" and console.colored(console.stdout):
                data = render_terminal(report, color=True).encode("utf-8")
            # The colorless bytes are what is validated; color only repeats their status words.
            publish_stdout(console.binary_stdout(), data, validate=lambda _written: validators[first](files[first]))
        elif is_bundle:
            publish_bundle(final, files, anchor=anchor, validate=validators)
        else:
            first = next(iter(files))
            publish_file(final, files[first], anchor=anchor, validate=validators[first])
    except PublishError as exc:
        if to_stdout:
            console.abandon_stdout()
        console.report(_publish_failure(exc))
        return cli.EXIT_REPORT
    if standard and disposition(report) == "lossy_hit_only":
        for fmt in standard:
            console.report(lossy_warning(fmt))
    if not to_stdout:  # stdout carries the one format and nothing else (SPEC 20.2)
        shown = final if output is None else output
        if is_bundle:
            shown += f" ({', '.join(files)})"
        elif lone_export:
            shown += f" (with {os.path.basename(final)}{NATIVE_SUFFIX} and {os.path.basename(final)}{MANIFEST_SUFFIX})"
        console.say(f"wrote {shown}")
    return cli.EXIT_OK
