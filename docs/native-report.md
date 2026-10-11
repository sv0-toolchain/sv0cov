<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Native report 1.0

`sv0cov.report` 1.0 is the lossless JSON report: everything a consumer needs
to show or judge coverage, in one canonical document (SPEC §21.3). It embeds
one `sv0cov.resolved-configuration` 1.0 record, the configuration the report
was made under.

This page covers what exists today: the two closed schemas, the record-level
rules, and the frozen structure fixtures (CV-228). Producing a report from
indexed evidence, and the reader that cross-validates one, come next
(CV-229).

## The two schemas

| Schema | File | Top-level properties |
|---|---|---|
| `sv0cov.report` 1.0 | `schemas/sv0cov.report-1.0.schema.json` | 22: `branches`, `capabilities`, `complete`, `contexts`, `contracts`, `entities`, `evidence_eligibility`, `exclusions`, `inputs`, `lines`, `maps`, `points`, `policy`, `provenance`, `regions`, `resolved_configuration`, `saturation`, `schema`, `sources`, `summary`, `tool`, `version` |
| `sv0cov.resolved-configuration` 1.0 | `schemas/sv0cov.resolved-configuration-1.0.schema.json` | 4: `coverage`, `report`, `schema`, `version` |

Both are closed: every object lists its exact properties, with no optional
field, extension, or vendor namespace.

- Point, line, branch, contract, context, saturation and input records are
  the [indexed 1.0](indexed-evidence.md) definitions, referenced from those
  schemas. A record valid in indexed evidence has the same shape here.
- A report adds a `summary` to each source and entity, `observed_digest` and
  `source_state` to each source, `point_ids` to each region, and
  `line_indices` to each exclusion's affected set. A map record keeps the
  map's identity without its counter bindings.
- The resolved-configuration schema is generated from the configuration
  inventory by `tools/configgen.py`, together with its default snapshot
  (`tests/fixtures/config/resolved-defaults.json`). It is not written by
  hand, so it cannot drift from what the [resolver](configuration.md)
  produces.

## What the structure layer checks

`sv0cov.formats.report` is the first validation layer:

1. canonical JSON bytes within the reader's size tier;
2. the generated schema validators;
3. the rules one record can be checked against by itself.

The record-level rules:

- **Lexical forms.** Digests, stable codes, run and profile identities,
  basenames, logical strings and paths, assertion names, the producer
  version (ASCII `0x21`..`0x7e`).
- **Scalar arrays** are strictly ordered and duplicate-free.
- **Shared records** keep every rule they have in indexed evidence.
- **Metrics.** `covered <= total`; `partial` is a count only for lines, and
  `covered + partial <= total`; `ratio` is `null` for a zero total and
  otherwise exactly `covered / total` rounded half to even to six digits,
  written `0.dddddd` or `1.000000`.
- **Metric sets.** A project, a source and a function entity have all five
  metrics. A contract entity has only `contract`.
- **Sources.** `current` means equal digests, `mismatch` unequal ones,
  `unavailable` no observed digest. `source_accuracy` is `mismatch_allowed`
  exactly when some source is not current.
- **Regions.** `point_ids` is exactly the sorted set of points the
  expression names.
- **Policy.** Diagnostics are present exactly for a `fail` or `ineligible`
  result; a limit and a threshold source are present exactly when something
  is compared; singleton assertions use their reserved names; there is
  exactly one integrity evaluation, with its fixed shape; `passed` is false
  when any evaluation failed.
- **Provenance.** The execution status fixes which of the exit code and
  signal are null; a manifest digest is present exactly for manifest
  selection.
- **Eligibility.** `incomplete` exactly when `complete` is false; `passing`
  needs a passed policy and current sources.
- **Resolved configuration.** An absent value is a default (or a
  command-line absence, for `context`); scope, entity and exclusion values
  never come from the command line; sets are in canonical order; scope and
  entity names are valid, sorted and unique; the tier and `diff` relations
  hold; a report control is true exactly when the command line set it; the
  saturation policy equals the report's.

`ratio(covered, total)` is the one arithmetic helper. It uses integers only.

Failures raise `ReportError`: `COV4001` for an invalid report or resolved
configuration, `COV6001` for bytes over the reader's tier.

### What it does not check

Left to the cross-validating reader (CV-229): the order and index positions
of record arrays, references between records, recomputed point IDs, counts
and statuses, summaries against detail, policy fractions against their
members, provenance sets against inputs, the saturation inventory against
count flags, the full eligibility precedence, and the configuration digest
used by export manifests.

## Fixtures

`tests/fixtures/report/`, built and checked by `build.py`:

| File | Purpose |
|---|---|
| `empty.json` | A report of diagnostic evidence with no input. |
| `passing.json` | A small clean report that passes its thresholds. |
| `all-kinds.json` | Every record kind; with the valid mutations, every enumeration value. |
| `bounds.json` | Every integer and length at its largest value. |
| `mutations.json` | Single changes to those documents, each with its outcome: `valid` or `COV4001`. |

The shared records come from the indexed structure fixtures, so both
contracts are exercised on the same data. Digests are made up, and summaries
and policy fractions are not derived from the detail: these fixtures prove
structure only.

`tests/test_report_structure.py` also removes, adds and mistypes every
property of every record in the four documents, rejects noncanonical bytes,
compares `ratio` with exact rational arithmetic, and requires every rule of
the module to be reached by some case.
