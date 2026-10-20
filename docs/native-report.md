<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Native report 1.0

`sv0cov.report` 1.0 is the lossless JSON report: everything a consumer needs
to show or judge coverage, in one canonical document (SPEC §21.3). It embeds
one `sv0cov.resolved-configuration` 1.0 record, the configuration the report
was made under.

This page covers the two closed schemas and their record-level rules
(CV-228), then the producer and the cross-validating reader (CV-229).

## The two schemas

| Schema | File | Top-level properties |
|---|---|---|
| `sv0cov.report` 1.0 | `schemas/sv0cov.report-1.0.schema.json` | 24: `branches`, `capabilities`, `changes`, `complete`, `contexts`, `contracts`, `entities`, `evidence_eligibility`, `exclusions`, `inputs`, `lines`, `maps`, `points`, `policy`, `provenance`, `ratchet`, `regions`, `resolved_configuration`, `saturation`, `schema`, `sources`, `summary`, `tool`, `version` |
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
- **Changes.** Present exactly when a diff policy is configured; commits
  are 40 or 64 lowercase hex digits; sources strictly ordered by index,
  changed lines strictly increasing, an old path exactly for a rename, no
  changed line on an unchanged source, `clean` exactly when nothing is
  staged or unstaged.
- **Ratchet.** Present exactly when a ratchet policy is configured; a
  decoded baseline exactly for `ok`, `stale` and `incompatible`, a file
  digest except for `missing`; comparisons for all five metrics in order
  exactly for `ok`; sorted, logical, disjoint source lists; a stale
  baseline names a commit. Only exclusion and ratchet evaluations count
  `exclusion_records`.
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

The structure layer does not look across records. That is the reader's job,
described below.

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

## Producing a report

`sv0cov.model.report.build_report(indexed_bytes, config, sources)` takes
canonical indexed bytes, a resolved configuration, and the current bytes of
each source file. It reads the evidence through the indexed reader first, so
a report is never made from evidence that does not validate.

### What is counted

| Metric | A unit is | Covered when |
|---|---|---|
| function | a function whose entry point is `user` | its entry count is above zero |
| region | a `user` region | its count is above zero (a lower-bound zero is not) |
| line | a line that is `covered`, `partial` or `uncovered` | every contributing region on it ran; `partial` lines are counted apart and are not covered |
| branch | an outcome that is `covered` or `uncovered` | its count is above zero |
| contract | a `runtime_checked` clause that no exclusion removes | either outcome was observed at least once |

Excluded, statically unreachable and synthetic-support records are outside
every denominator. A zero denominator gives a `null` ratio.

The project and each source get all five metrics. A function entity counts
only what it owns: its own entry, its regions, the outcomes of its branches,
its clauses, and each line once where one of its regions contributes, with
that line's status worked out from its own regions alone. A contract entity
has only the `contract` metric of its one clause.

### Contexts

Every count record holds the aggregate and, in `by_context`, each context's
own count (a context missing there counted exactly zero). The aggregate is
the saturating sum of the contexts and is there whether or not any context
was collected: the same runs with and without labels give the same
aggregate. `contexts` lists every context an input carried, absent (`null`)
first, then the empty string, then the rest bytewise.

`sv0cov.model.context.context_view(report, context_index)` is the context
filter (CV-308): a new object with the report's points, regions, lines,
branches, contracts, entities and sources, every count replaced by that
context's count, and line statuses, outcome statuses, runtime results and
the five metrics (whole report, each source, each entity) worked out again
from those counts. It equals the report built from that context's profiles
alone. The report itself is never changed, so filtering cannot move the
aggregate, and policy is not part of a view: thresholds read the aggregate.
The HTML report (CV-309) offers it as its context filter.
`tests/test_context.py` checks each view against the report of that
context alone (every semantic fixture under four contexts, and the two-map
sample with contracts, an exclusion and a saturated count), that taking
views leaves the report unchanged, and that the aggregate is the sum of the
contexts and does not depend on whether contexts were collected.

### Policy

- **Integrity.** One evaluation carries every finding about the evidence
  itself: the evidence's own codes, plus `COV1004` for a source that is not
  current, `COV4020` for saturation that blocks a use, and `COV4021` for a
  lossy export. It is `fail` for an evidence finding, `ineligible` for a
  report-time one, and `pass` otherwise.
- **Project thresholds.** One evaluation per configured threshold, decided
  by `covered * 10000 >= total * threshold` on integers. The rounded ratio
  is never used. A zero denominator passes only under `empty = "pass"`;
  otherwise it fails with `COV4102`.
- **Scopes and entities** (CV-310, SPEC 22.2). Every `[[scopes]]` entry
  is its own assertion with one evaluation per metric, over the sources it
  selects: the union of its `include` patterns (a virtual root
  `.gitignore`, `sv0cov.gitignore`), `packages` and `sources`, each source
  once. Every `[[entities]]` entry names one entity by source, qualified
  name and kind and has one evaluation per applicable metric (a function:
  all five, with the membership of SPEC 22.2.1; a contract: only
  `contract`). A metric's threshold is the assertion's own value
  (`threshold_source` `assertion`), else the project's (`project`), else
  none: the fraction is still reported, with `comparison` `none` and result
  `not_applicable`. An explicit value never reaches another assertion or
  metric, and no assertion overrides another: the policy passes only when
  every one does. A package, source or entity the evidence does not have is
  `COV0013`. The reader works every scope and entity evaluation out again
  from the resolved configuration in the report.
- **Saturation.** Under the `fail` policy any saturation makes every
  threshold `ineligible`. Under `allow-ordinary`, function, region, line and
  branch are evaluated; a contract threshold is `ineligible` when one of its
  points saturated.

- **Changed regions** (CV-312, SPEC 22.3). With a diff policy the
  report keeps the Git capture as `changes` and has one `diff` evaluation
  per line, region and branch over what meets a changed line; see
  [changed-region coverage](changed-region.md).

- **Ratchets** (CV-313, SPEC 22.4). With a ratchet policy the report keeps
  the baseline comparison as `ratchet` and has ratio, excluded-unit and
  exclusion-record evaluations; see [ratchets](ratchets.md).

### Sources

Each source's digest is compared with the bytes supplied. A file that
differs or is missing is an error (`COV1004`) unless
`--allow-source-mismatch` is resolved. With it, the source is recorded as
`mismatch` or `unavailable` and the report can be at most `diagnostic_only`.

### Eligibility

In order: `incomplete` when the evidence is incomplete; `diagnostic_only`
when a source is not current, a lossy export was used, or an exact-count use
is ineligible; `policy_failed` when the policy did not pass; `passing`
otherwise.

### A failed test command

When the evidence records a test command that exited nonzero or was ended
by a signal, the integrity evaluation fails with `COV2130` (diagnostic
registry revision 2), whatever the coverage says. Collection completeness
is not changed by it, the thresholds are still evaluated, and the report is
`policy_failed`, never `passing`.

### What this build refuses

It reports `COV5001` rather than guess:

- exclusion-cap assertions, which come with the rest of the policy preview;
- two regions with the same source, span, kind and point set, which the
  report's ordering rule cannot tell apart.

## Reading a report

`read_report(bytes)` is what every consumer starts from. It reads nothing
but the report. After the structure layer it recomputes each redundant fact
and rejects any disagreement with `COV4002`:

- the shared records by the indexed reader's rules: order, index positions,
  references, point IDs, counts, region expressions, line membership and
  statuses, branch and contract results, exclusions, the saturation
  inventory;
- region order by the report's key, and each exclusion's lines;
- maps, inputs and contexts against each other, and the provenance sets
  against them;
- every summary: project, source and entity;
- the project evaluations from the configured thresholds, the scope,
  entity and diff evaluations from their configuration (and, for diff, the
  `changes` record, which must hold each user source once with its compiled
  digest and needs current sources), the ratchet record's comparisons,
  source changes and state, and the ratchet evaluations, and the integrity
  evaluation;
- for evaluations of other kinds, that the result follows from the two
  fractions and that every member exists;
- `passed`, `complete` against the integrity findings, and eligibility.

A report must name the diagnostic registry this reader has; every stored
code must be in it.

What a reader cannot recheck is what a report does not retain: source text
(so line and column coordinates), the files behind artifact digests, and the
evidence's own diagnostics beyond their union in the integrity evaluation.
`tests/test_report.py` lists those primary facts and shows that changing any
other single field is rejected.
