# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The export commit manifest, ``sv0cov.export-manifest`` 1.0 (CV-403; SPEC
16.6, 20.2.2, 20.2.3; COV-FMT-037, COV-REP-014, BL-035, BL-080).

A manifest is the closed commit record of exactly one LCOV or Cobertura
primary and its associated native JSON report. It binds:

- both artifacts, primary first and native second, by name (or ``null``
  for a primary written to stdout), destination, media type, byte length
  and SHA-256;
- the indexed input the report was made from and the report's
  ``resolved_configuration`` (the SHA-256 of that object serialized alone);
- the exact profile, compatibility reference and the fixed loss semantics
  of the format (omissions, placeholders, projections);
- the context projection (always ``aggregate``), the saturation
  disposition and the producer.

It provides integrity and completion, not authenticity, and never lists or
hashes itself.

:func:`build_manifest` makes the canonical bytes; :func:`decode_manifest`
checks bytes (canonical JSON, the closed schema, every constant, the exact
format-specific arrays in order, name rules); :func:`verify_export` checks a
whole export set: the manifest, both artifacts against their digests and
lengths, the native report (read and cross-validated), the configuration
digest, the indexed input when it is available, and the primary against
the report. Anything else is ``COV4402``.

``saturation_disposition`` is ``exact`` in this build: a saturated export is
refused before any manifest exists. ``lossy_hit_only`` is valid in a
manifest and is produced only by the explicit lossy export (CV-420).
"""

from __future__ import annotations

import hashlib
import re

from sv0cov._generated.validators import sv0cov_export_manifest_1_0 as _schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.map import map_limits
from sv0cov.formats.structural import StructuralError

INVALID = "COV4402"
SCHEMA, VERSION = "sv0cov.export-manifest", "1.0"
NATIVE_MEDIA = "application/json"
RE_DIGEST = re.compile(r"[0-9a-f]{64}")

#: The fixed R1 core profiles (SPEC 16.6, 21.4, 21.5).
FORMATS = {
    "lcov": {
        "profile": "sv0cov-lcov-r1-core",
        "compatibility_reference": "lcov:1.16+2.5",
        "media_type": "text/plain; charset=utf-8",
        "filename": "lcov.info",
        "manifest": "lcov.manifest.json",
        "omissions": ["contract_coverage", "exclusion_inventory", "named_contexts", "partial_line_state", "provenance_detail",
                      "region_coverage", "saturation_qualifiers"],
        "placeholders": [],
        "projections": ["branch_outcomes_as_brda", "contexts_aggregated", "line_status_binary_covered_only", "zero_denominators_as_zero"],
    },
    "cobertura": {
        "profile": "sv0cov-cobertura-r1-core",
        "compatibility_reference": "cobertura:coverage-04.dtd@e5eea8679ebce047ec6ccdfdbf6cf2c14b376875"
                                   ":sha256:e467cb8252e20feb794fc2dedfbea7b4957921669c758f0282d525df88897917",
        "media_type": "application/xml; charset=utf-8",
        "filename": "cobertura.xml",
        "manifest": "cobertura.manifest.json",
        "omissions": ["contract_coverage", "exact_branch_outcome_counts", "exclusion_inventory", "function_entry_counts", "named_contexts",
                      "partial_line_state", "provenance_detail", "region_coverage", "saturation_qualifiers"],
        "placeholders": ["complexity_unavailable_as_0.0", "java_signature_unavailable_as_empty"],
        "projections": ["branch_outcomes_as_conditions", "condition_percentage_floor_integer", "contexts_aggregated",
                        "line_status_binary_covered_only", "rates_six_fractional_half_even", "source_root_as_dot",
                        "timestamp_from_reproducible_epoch", "zero_denominators_as_zero"],
    },
}


class ManifestError(ValueError):
    """An export manifest, or the export set it commits, that is not valid (``COV4402``)."""

    code = INVALID

    def __init__(self, detail: str) -> None:
        super().__init__(f"{INVALID}: {detail}")
        self.detail = detail


def configuration_sha256(report: dict) -> str:
    """The SHA-256 of the report's ``resolved_configuration`` serialized alone."""
    return hashlib.sha256(encode(report["resolved_configuration"])).hexdigest()


def _artifact(role: str, name: str | None, media_type: str, data: bytes) -> dict:
    return {"byte_length": len(data), "destination": "file" if name is not None else "stdout", "media_type": media_type,
            "name": name, "role": role, "sha256": hashlib.sha256(data).hexdigest()}


def build_manifest(fmt: str, report: dict, *, primary: bytes, primary_name: str | None, native: bytes, native_name: str,
                   saturation_disposition: str = "exact") -> bytes:
    """The canonical manifest of one export set. ``primary_name`` is the
    primary's final basename, or ``None`` when it goes to stdout."""
    f = FORMATS[fmt]
    obj = {
        "artifacts": [_artifact("primary", primary_name, f["media_type"], primary), _artifact("native", native_name, NATIVE_MEDIA, native)],
        "compatibility_reference": f["compatibility_reference"],
        "context_projection": "aggregate",
        "format": fmt,
        "indexed_input_sha256": report["provenance"]["indexed_input_sha256"],
        "omissions": list(f["omissions"]),
        "placeholders": list(f["placeholders"]),
        "producer": {"name": report["tool"]["name"], "version": report["tool"]["version"]},
        "profile": f["profile"],
        "projections": list(f["projections"]),
        "report_configuration_sha256": configuration_sha256(report),
        "saturation_disposition": saturation_disposition,
        "schema": SCHEMA,
        "version": VERSION,
    }
    check_manifest(obj)
    return encode(obj)


def _name_ok(name: str) -> bool:
    raw = name.encode("utf-8", "surrogatepass")
    return 1 <= len(raw) <= 255 and not any(c in name for c in "\0/\\") and name not in (".", "..")


def check_manifest(obj: object) -> dict:
    """The schema and every rule a manifest can be checked against alone."""
    try:
        _schema.validate(obj)
    except StructuralError as exc:
        raise ManifestError(str(exc)) from None
    assert isinstance(obj, dict)
    f = FORMATS[obj["format"]]
    for key in ("profile", "compatibility_reference", "omissions", "placeholders", "projections"):
        if obj[key] != f[key]:
            raise ManifestError(f"{key}: not the exact {obj['format']} value")
    for key in ("indexed_input_sha256", "report_configuration_sha256"):
        if not RE_DIGEST.fullmatch(obj[key]):
            raise ManifestError(f"{key}: not 64 lowercase hexadecimal characters")
    version = obj["producer"]["version"]
    if not version.isascii() or any(not 0x21 <= ord(c) <= 0x7E for c in version):
        raise ManifestError("producer/version: each byte is ASCII 0x21 through 0x7e")
    primary, native = obj["artifacts"]
    for n, (a, role, media) in enumerate(((primary, "primary", f["media_type"]), (native, "native", NATIVE_MEDIA))):
        where = f"artifacts/{n}"
        if a["role"] != role:
            raise ManifestError(f"{where}/role: the artifacts are primary, then native")
        if a["media_type"] != media:
            raise ManifestError(f"{where}/media_type: {role} {obj['format']} is {media!r}")
        if not RE_DIGEST.fullmatch(a["sha256"]):
            raise ManifestError(f"{where}/sha256: not 64 lowercase hexadecimal characters")
        if (a["destination"] == "file") != (a["name"] is not None):
            raise ManifestError(f"{where}/name: a file has a name, stdout has null")
        if a["name"] is not None and not _name_ok(a["name"]):
            raise ManifestError(f"{where}/name: a basename of 1 to 255 bytes with no NUL, '/' or '\\\\'")
    if native["destination"] != "file":
        raise ManifestError("artifacts/1/destination: the native report is always a file")
    if primary["name"] is not None and primary["name"] == native["name"]:
        raise ManifestError("artifacts: the primary and the native report have one name")
    return obj


def decode_manifest(data: bytes, *, tier: str = "standard") -> dict:
    """Manifest bytes -> the validated object (canonical JSON: no BOM,
    duplicate key, noncanonical form or trailing byte)."""
    try:
        obj = decode_canonical(data, map_limits(tier))
    except CanonicalJsonError as exc:
        raise ManifestError(f"not a canonical JSON export manifest within the {tier} tier ({exc})") from None
    return check_manifest(obj)


def verify_export(manifest: bytes, primary: bytes, native: bytes, *, names: tuple[str | None, str] | None = None,
                  indexed: bytes | None = None, tier: str = "standard") -> dict:
    """The validated manifest of a complete export set, or :class:`ManifestError`.

    ``primary`` is the primary's bytes (the captured stdout bytes for a
    stdout primary) and ``native`` the associated report's. ``names``, when
    given, are the basenames the artifacts were found under (``None`` for
    stdout). ``indexed``, when available, is the indexed input."""
    from sv0cov.formats.cobertura import CoberturaError, check_cobertura
    from sv0cov.formats.lcov import LcovError, check_lcov
    from sv0cov.formats.report import ReportError
    from sv0cov.model.report import read_report

    obj = decode_manifest(manifest, tier=tier)
    for a, data in zip(obj["artifacts"], (primary, native)):
        if a["byte_length"] != len(data) or a["sha256"] != hashlib.sha256(data).hexdigest():
            raise ManifestError(f"the {a['role']} artifact does not match its digest and length")
    if names is not None and (obj["artifacts"][0]["name"], obj["artifacts"][1]["name"]) != names:
        raise ManifestError("the artifacts were not found under the names the manifest commits")
    try:
        report = read_report(native, tier=tier)
    except ReportError as exc:
        raise ManifestError(f"the native report is not valid ({exc})") from None
    if configuration_sha256(report) != obj["report_configuration_sha256"]:
        raise ManifestError("report_configuration_sha256 is not the native report's resolved configuration")
    if report["provenance"]["indexed_input_sha256"] != obj["indexed_input_sha256"]:
        raise ManifestError("indexed_input_sha256 is not the native report's indexed input")
    if indexed is not None and hashlib.sha256(indexed).hexdigest() != obj["indexed_input_sha256"]:
        raise ManifestError("indexed_input_sha256 is not the indexed input's")
    if report["tool"]["version"] != obj["producer"]["version"]:
        raise ManifestError("producer/version is not the native report's tool version")
    if obj["saturation_disposition"] == "exact":
        try:
            (check_lcov if obj["format"] == "lcov" else check_cobertura)(primary, report)
        except (LcovError, CoberturaError) as exc:
            raise ManifestError(f"the primary does not match the native report ({exc.detail})") from None
    return obj


__all__ = ["FORMATS", "ManifestError", "build_manifest", "check_manifest", "configuration_sha256", "decode_manifest", "verify_export"]
