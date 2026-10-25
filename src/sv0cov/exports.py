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
asks for the diagnostic-only lossy export instead (CV-420; SPEC 14.2.1,
COV-POL-011): an inexact count is written as the hit count ``1``, the
manifest says ``saturation_disposition: lossy_hit_only``, and the native
report beside it is ``diagnostic_only`` with ``COV4021`` in its integrity
evaluation, so the set is never policy evidence. With the flag but no
inexact exported count the export is simply exact.
"""

from __future__ import annotations

from collections.abc import Callable

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.cobertura import CoberturaError, check_cobertura, render_cobertura
from sv0cov.formats.export_manifest import FORMATS, build_manifest, verify_export
from sv0cov.formats.lcov import LcovError, check_lcov, has_inexact, render_lcov

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


def disposition(report: dict) -> str:
    """``lossy_hit_only`` when an exported count is inexact and the lossy
    export was asked for, else ``exact`` (a refusal comes from :func:`render`)."""
    allowed = report["resolved_configuration"]["report"]["allow_lossy_saturated_export"]["value"]
    return "lossy_hit_only" if allowed and has_inexact(report) else "exact"


def render(fmt: str, report: dict, *, timestamp: int) -> tuple[bytes, str]:
    """The primary bytes and their saturation disposition, or :class:`ExportStop`."""
    lossy = disposition(report) == "lossy_hit_only"
    try:
        data = render_lcov(report, lossy=lossy) if fmt == "lcov" else render_cobertura(report, timestamp=timestamp, lossy=lossy)
    except (LcovError, CoberturaError) as exc:
        raise ExportStop(Diagnostic(exc.code, "report", facts=(("detail", cli.fact_text(exc.detail)), ("format", fmt))),
                         cli.EXIT_REPORT) from None
    return data, ("lossy_hit_only" if lossy else "exact")


def lossy_warning(fmt: str) -> Diagnostic:
    """The ``COV4021`` warning a lossy export is published with."""
    return Diagnostic("COV4021", "report", facts=(
        ("detail", "saturated counts were written as hit count 1; this export and its native report are diagnostic only"),
        ("format", fmt)))


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
        primary, how = render(fmt, report, timestamp=timestamp)
        files[name] = primary
        files[NATIVE] = native
        files[manifest] = build_manifest(fmt, report, primary=primary, primary_name=name, native=native, native_name=NATIVE,
                                         saturation_disposition=how)
        checks[name] = _check_primary(fmt, report)
        checks[manifest] = (lambda p, n: lambda data: verify_export(data, p, native, names=(n, NATIVE), tier=tier))(primary, name)
    return files, checks


def single(fmt: str, report: dict, native: bytes, *, basename: str | None, timestamp: int, tier: str) -> dict:
    """One export set: ``primary``, ``native``, ``manifest`` bytes, the
    names they are committed under (``None`` for a stdout primary) and a
    validator for each."""
    primary, how = render(fmt, report, timestamp=timestamp)
    native_name = NATIVE if basename is None else basename + NATIVE_SUFFIX
    manifest = build_manifest(fmt, report, primary=primary, primary_name=basename, native=native, native_name=native_name,
                              saturation_disposition=how)
    return {
        "primary": primary, "native": native, "manifest": manifest, "native_name": native_name,
        "manifest_name": FORMATS[fmt]["manifest"] if basename is None else basename + MANIFEST_SUFFIX,
        "check_primary": _check_primary(fmt, report),
        "check_manifest": lambda data: verify_export(data, primary, native, names=(basename, native_name), tier=tier),
    }


__all__ = ["ExportStop", "MANIFEST_SUFFIX", "NATIVE", "NATIVE_SUFFIX", "STANDARD", "bundle", "disposition", "lossy_warning", "render", "single",
           "support_dir"]
