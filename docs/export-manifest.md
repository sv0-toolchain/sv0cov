<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Export commit manifest: `sv0cov.export-manifest` 1.0

An LCOV or Cobertura export is never published alone (SPEC 16.6, 20.2.3).
`sv0cov.formats.export_manifest` (CV-403) writes and checks the closed
record that commits one export set: the primary, its native JSON report,
and what they were made from. It gives integrity and completion, not
authenticity, and it never lists or hashes itself.

## What it binds

The fourteen members, all required, serialized as canonical JSON:

- `artifacts`: exactly two, the `primary` then the `native` report, each
  with `byte_length`, `destination` (`file`, or `stdout` for a primary on
  stdout), `media_type`, `name` (the final basename, `null` on stdout) and
  `sha256`. The native report is always a file.
- `indexed_input_sha256`: the indexed input the report was made from.
- `report_configuration_sha256`: the SHA-256 of the native report's
  `resolved_configuration` serialized alone.
- `format`, `profile`, `compatibility_reference`: `lcov`,
  `sv0cov-lcov-r1-core`, `lcov:1.16+2.5`; or `cobertura`,
  `sv0cov-cobertura-r1-core` and the pinned DTD with its digest.
- `omissions`, `placeholders`, `projections`: the fixed loss semantics of
  the profile, the exact arrays of SPEC 16.6 in their order.
- `context_projection` (`aggregate`), `saturation_disposition` (`exact`;
  `lossy_hit_only` only for the explicit lossy export, CV-420), `producer`,
  `schema`, `version`.

## Verification

`decode_manifest` refuses anything but the canonical bytes of a valid
record: unknown or missing members, a BOM, a duplicate key, trailing bytes,
another format's constants or arrays, reordered or case-folded arrays, a
named stdout artifact, a path in a name.

`verify_export(manifest, primary, native, names=, indexed=)` checks a whole
set: both artifacts against their lengths and digests, the names they were
found under, the native report (read and cross-validated), the
configuration digest, the indexed input when it is available, the producer
version, and the primary against the report. Any failure is `COV4402`: the
set is incomplete and is not evidence.

## Publication

| Layout | Primary | Native report | Manifest |
|---|---|---|---|
| bundle (several formats, every `run`) | `lcov.info`, `cobertura.xml` | `coverage.json`, shared | `lcov.manifest.json`, `cobertura.manifest.json` |
| one file `P` | `P` | `P.sv0cov.json` | `P.manifest.json` |
| stdout | stdout | `coverage.json` in `<output_dir>/reports/<format>-stdout-support` | `<format>.manifest.json` beside it |

A bundle is one atomic commit. One file is three no-replace commits in the
order native, primary, manifest: the manifest comes last and is the commit
record. On stdout the support directory is validated first and published
only after stdout took the whole primary; a failed write publishes no
manifest. Every artifact is validated before it is committed, the manifest
by `verify_export` against the bytes beside it.

## Fixtures

`tests/fixtures/export-manifest/`: one manifest per format and layout for
the `f0` fixture, and `mutations.json`, a corpus of single changes, each
marked `valid` or `COV4402`, for every reader of the schema (`build.py`
rebuilds and checks them). Tests: `tests/test_exports.py`.

The `lcov-r1-core` and `cobertura-r1-core` capability features are not
advertised yet: they wait for the consumer checks (CV-418, CV-419) and the
lossy export (CV-420).
