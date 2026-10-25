<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Ratchets

A ratchet (SPEC 22.4, CV-313) forbids coverage from getting worse than an
agreed baseline. It is configured with `[tool.sv0cov.ratchet]`:

```toml
[tool.sv0cov.ratchet]
baseline = ".sv0cov-baseline.json"   # project-relative
metrics = ["function", "region", "line", "branch"]
tolerance_basis_points = 0           # the default
```

`run`, `check` and `report` compare with it; `sv0cov baseline` writes it.

## The baseline file

`sv0cov.baseline` 1.0 (`schemas/sv0cov.baseline-1.0.schema.json`) is closed
canonical JSON:

| Member | Meaning |
|---|---|
| `metrics` | For each of the five metrics: `covered`, `total`, and `excluded` (units exclusions removed from the denominator; a branch counts its excluded outcomes). |
| `exclusion_records` | How many exclusion records there were. |
| `sources` | Every compiled source, `path` and `digest`, in path order. |
| `saturation_policy` | The policy the counts were made under. |
| `metric_schema` | The metric schema, `sv0cov.report 1.0`. |
| `commit` | `HEAD` when it was made, or `null` outside Git. |
| `tool` | The producer and its version. |
| `baseline_sha256` | The pin: the SHA-256 of the canonical bytes of everything else. |

A baseline that does not match its pin was changed by hand or damaged, and
is treated as invalid. Every count, path and digest is checked when it is
read (`sv0cov.formats.baseline`).

## The comparison

The report keeps the comparison as its `ratchet` member (null without a
ratchet policy): the baseline's digest and decoded counts, `HEAD` now, the
baseline's state, the sources added and removed, and, for every metric, the
outcomes found.

| State | When | Effect |
|---|---|---|
| `ok` | Usable. | Compared. |
| `missing` | No file at the path. | Every evaluation `ineligible`. |
| `invalid` | Unreadable, not a valid baseline, or its pin does not match. | Every evaluation `ineligible`. |
| `incompatible` | Another metric schema or saturation policy (SPEC 14.2.1). | Every evaluation `ineligible`. |
| `stale` | Made at a commit that is not `HEAD` or one of its ancestors (or `HEAD` is unknown). | Every evaluation `ineligible`. |

Outcomes per metric, for explanation:

- `numerator_regression`: fewer units are covered than in the baseline;
- `denominator_growth`: there are more units than in the baseline;
- `exclusion_growth`: exclusions remove more units than in the baseline.

With an `ok` baseline, each configured metric has two evaluations, and the
exclusion records one:

| Evaluation | Comparison | Fails when |
|---|---|---|
| ratio | `at_least` the baseline's covered/total less the tolerance (`(covered * 10000 - tolerance * total) / (total * 10000)`, never below 0; an empty baseline gives 0/1) | the current ratio is below it (`COV4201`) |
| excluded units | `at_most` the baseline's | exclusions remove more units (`COV4201`) |
| exclusion records | `at_most` the baseline's | there are more records (`COV4201`) |

Fractions are exact integers; nothing is rounded. Denominator growth with
the ratio held passes; it is reported. Exclusion growth fails even when the
percentage improves (AC-017): removing uncovered code by excluding it is
accepted only by an explicit baseline update.

A changed source set (a compiled source added, removed or renamed) makes
every ratio `ineligible` with `COV4201`, so the ratchet fails until the
baseline is updated. A ratchet is an exact-count use: any saturated count,
under either saturation policy, makes every ratio `ineligible` (`COV4020`)
and puts `ratchets` in `saturation.ineligible_uses` (CV-404). An empty current
metric follows the `empty` policy (`COV4102` under `fail`).

`check` names the baseline's state, the source change and the metric's
outcomes as facts of every ratchet diagnostic.

## Updating the baseline

```text
sv0cov baseline [options] <indexed-profile>
```

It builds the native report of the evidence under the resolved
configuration (comparing with the old baseline as usual), prints the old and
new counts of every metric, the exclusion records and the sources added and
removed, and then writes the new baseline. The write is the one replacing
publication sv0cov makes (`sv0cov.publish.replace_file`): written,
synchronized, read back and validated in a sibling temporary, then renamed
over the old file in one step. A symlink or anything but a regular file at
the path is never replaced (`COV6002`, exit 6).

A baseline is made only from complete evidence of current sources with no
exact-count use made ineligible by saturation (`COV4201`, exit 5 otherwise).
Without a ratchet policy the command is a usage error (exit 2). It takes no
`--quiet`: the deltas are always printed.

`baseline` is not advertised by `version` and is not part of the root
`./scripts/sv0 coverage` namespace until its gate review (CV-316).
