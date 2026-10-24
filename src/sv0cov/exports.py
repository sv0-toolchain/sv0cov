# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Standard exports as ``report`` and ``run`` publish them (CV-403; SPEC
16.6, 20.2.1-20.2.3, 21.4, 21.5; COV-REP-014, AC-052, AC-104).

An LCOV or Cobertura primary never travels alone: it is published with the
native JSON report it was made from and an ``sv0cov.export-manifest`` 1.0
commit record (:mod:`sv0cov.formats.export_manifest`). Three layouts:

- **Bundle** (several formats, and every ``run``): the primary under its
  canonical name, the shared ``coverage.json`` and ``<format>.manifest.json``,
  all inside the one bundle directory committed by one rename.
- **One file** ``P``: the native report ``P.sv0cov.json``, then ``P``, then
  the manifest ``P.manifest.json``, each committed with no replace, in that
  order; the manifest is last because it is the commit record. All three
  names are checked before anything is read.
- **stdout**: the primary goes to stdout; ``coverage.json`` and the manifest,
  which names the primary ``null`` with destination ``stdout``, become the
  new directory ``<output_dir>/reports/<format>-stdout-support``, published
  only after stdout took every byte.

Every artifact is validated before it is committed: the primary against the
report it was made from, the manifest by :func:`verify_export` against the
very bytes beside it.

A saturated count has no exact value; the export is refused (``COV4020``,
exit 6) before anything is published. ``--allow-lossy-saturated-export``
on saturated evidence is the diagnostic-only lossy export, which this build
does not produce yet (``COV5001``, exit 7; CV-420).
"""

from __future__ import annotations

from collections.abc import Callable

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.cobertura import CoberturaError, check_cobertura, render_cobertura
from sv0cov.formats.export_manifest import FORMATS, build_manifest, verify_export
from sv0cov.formats.lcov import LcovError, check_lcov, render_lcov

STANDARD = ("lcov", "cobertura")
NATIVE = "coverage.json"
NATIVE_SUFFIX, MANIFEST_SUFFIX = ".sv0cov.json", ".manifest.json"


class ExportStop(Exception):
    """An export that cannot be made: its diagnostic and exit status."""

    def __init__(self, diagnostic: Diagnostic, status: int) -> None:
        super().__init__(diagnostic.code)
        self.diagnostic = diagnostic
        self.status = status


def support_dir(fmt: str) -> str:
    """The stdout support directory's name, under ``<output_dir>/reports``."""
    return f"{fmt}-stdout-support"


def render(fmt: str, report: dict, *, timestamp: int) -> bytes:
    """The primary bytes, or :class:`ExportStop`."""
    if report["saturation"]["any"] and report["resolved_configuration"]["report"]["allow_lossy_saturated_export"]["value"]:
        raise ExportStop(Diagnostic("COV5001", "report", facts=(
            ("detail", "the diagnostic-only lossy export of saturated evidence is not implemented yet"), ("format", fmt))),
            cli.EXIT_UNSUPPORTED)
    try:
        return render_lcov(report) if fmt == "lcov" else render_cobertura(report, timestamp=timestamp)
    except (LcovError, CoberturaError) as exc:
        raise ExportStop(Diagnostic(exc.code, "report", facts=(("detail", cli.fact_text(exc.detail)), ("format", fmt))),
                         cli.EXIT_REPORT) from None


def _check_primary(fmt: str, report: dict) -> Callable[[bytes], None]:
    check = check_lcov if fmt == "lcov" else check_cobertura
    return lambda data: check(data, report)


def bundle(formats: list[str], report: dict, native: bytes, *, timestamp: int, tier: str) -> tuple[dict[str, bytes], dict[str, Callable]]:
    """The standard-export members of a bundle and their validators: each
    primary, the shared native report and one manifest per export."""
    files: dict[str, bytes] = {}
    checks: dict[str, Callable] = {}
    for fmt in (f for f in formats if f in STANDARD):
        name, manifest = FORMATS[fmt]["filename"], FORMATS[fmt]["manifest"]
        primary = render(fmt, report, timestamp=timestamp)
        files[name] = primary
        files[NATIVE] = native
        files[manifest] = build_manifest(fmt, report, primary=primary, primary_name=name, native=native, native_name=NATIVE)
        checks[name] = _check_primary(fmt, report)
        checks[manifest] = (lambda p, n: lambda data: verify_export(data, p, native, names=(n, NATIVE), tier=tier))(primary, name)
    return files, checks


def single(fmt: str, report: dict, native: bytes, *, basename: str | None, timestamp: int, tier: str) -> dict:
    """One export set: ``primary``, ``native``, ``manifest`` bytes, the
    names they are committed under (``None`` for a stdout primary) and a
    validator for each."""
    primary = render(fmt, report, timestamp=timestamp)
    native_name = NATIVE if basename is None else basename + NATIVE_SUFFIX
    manifest = build_manifest(fmt, report, primary=primary, primary_name=basename, native=native, native_name=native_name)
    return {
        "primary": primary, "native": native, "manifest": manifest, "native_name": native_name,
        "manifest_name": FORMATS[fmt]["manifest"] if basename is None else basename + MANIFEST_SUFFIX,
        "check_primary": _check_primary(fmt, report),
        "check_manifest": lambda data: verify_export(data, primary, native, names=(basename, native_name), tier=tier),
    }


__all__ = ["ExportStop", "MANIFEST_SUFFIX", "NATIVE", "NATIVE_SUFFIX", "STANDARD", "bundle", "render", "single", "support_dir"]
