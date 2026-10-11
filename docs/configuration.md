<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Configuration

sv0cov reads its configuration from the `[tool.sv0cov]` table of the
project's `sv0.toml` and from command-line options (SPEC §18.2). A root
`[coverage]` table is not sv0cov configuration: the toolchain manifest owns
the root and reserves `[tool.<name>]` for companions.

## Precedence

```text
explicit CLI option > sv0.toml > built-in default
```

There is no environment layer. The modules that load and resolve
configuration read no environment variable, so a variable such as
`SV0COV_THRESHOLD_LINE` has no effect.

## The file

`sv0cov.config` holds the closed inventory: every table, key, type, bound and
default, and the CLI option table. When `[tool.sv0cov]` is present it must
declare `schema = "1.0"`. Unknown keys, subtables, types and schema versions
are errors. Keys outside `tool.sv0cov` are not examined.

A threshold is an integer percentage `0..100` or a string such as `"8500bp"`.
Both resolve to a numerator over 10000, so `85` and `"8500bp"` are the same
value.

## Resolution

`sv0cov.config_resolve.resolve(command, options, toml)` takes the command, the
CLI occurrences in order as `(name, text)` pairs (`None` for a flag), and the
bytes of `sv0.toml` or `None`. It returns the effective configuration, in
which every scalar is a leaf with a value and a source: `cli`, `sv0.toml` or
`default`.

Rules worth knowing:

- A repeated list option (`--report`, `--ratchet-metric`) replaces the file's
  array. `reports` keeps CLI order; a metric set is stored in canonical order.
- `--no-context` replaces a file context with absence, and its source is
  `cli`. It conflicts with `--context`.
- A CLI option can create the `diff` or `ratchet` table when the file has
  none. The table must then be whole: a diff needs a base and a threshold, a
  ratchet needs a baseline and metrics.
- A CLI option cannot remove a file key. `--raw-profile-tier standard` over a
  file that sets custom ceilings is a conflict, not a silent drop.
- Scopes, entities and exclusion rules are file-only.
- File keys are resolved whatever the command, because a report records the
  whole configuration. CLI options are accepted only by the commands they
  apply to.

## What fails

Everything below fails before anything else runs.

| Failure | Code |
|---|---|
| Unknown option, option on the wrong command, repeated scalar or flag, value on a flag, missing value, conflicting pair, missing required option, repeated `--expect-run` or `--format` value | `COV0001` |
| TOML syntax, duplicate key, not UTF-8 | `COV0002` |
| Missing or wrong `schema` | `COV0010` |
| Unknown key or table | `COV0011` |
| Invalid value | `COV0012` |
| Conflicting values, in the file or on the effective configuration | `COV0013` |
| Invalid pattern | `COV0014` |
| Invalid threshold | `COV0015` |

A value error from a CLI option names the option; one from the file names the
dotted key.

## The resolved record

`Resolved.document()` is the `sv0cov.resolved-configuration` 1.0 record that
native reports embed (SPEC §21.3.7):

- `coverage` mirrors the whole inventory. Every scalar is present as
  `{"source": ..., "value": ...}`, with `null` for a defined absence.
- `scopes` and `entities` are sorted by name, with every allowed field
  present.
- `diff` and `ratchet` are `null` when nothing configures them.
- `report` holds the two report-only controls,
  `allow_lossy_saturated_export` and `allow_source_mismatch`.

CLI-only controls such as `--run-id`, `--expect-run`, `--output`, `--quiet`
and `--color` are returned in `Resolved.controls` and never serialized.

Its closed JSON Schema is generated from the same inventory and is described
in [Native report 1.0](native-report.md).
