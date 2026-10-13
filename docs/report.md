<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The report command

```text
sv0cov report --format <format> [--format <format>...] [options] <indexed-profile>
```

`report` reads one indexed profile, builds the native report, and publishes
the selected formats. Run it from the project root: `sv0.toml` and every
source path of the evidence are found below the working directory.

## Formats

Formats come only from `--format`, once per format. `[tool.sv0cov].reports`
belongs to `run` and is not read; `--report` is not an option of `report`.
A repeated value, a comma list and an unknown value are usage errors.

Request order does not matter. Artifacts are produced in the canonical order
and under the canonical names:

| Format | File | This build |
|---|---|---|
| `term` | `coverage.txt` | yes ([terminal-report.md](terminal-report.md)) |
| `html` | `coverage.html` | not yet |
| `json` | `coverage.json` | yes ([native-report.md](native-report.md)) |
| `lcov` | `lcov.info` | not yet |
| `cobertura` | `cobertura.xml` | not yet |

Asking for a format this build lacks is refused with `COV5001` (exit 7)
before anything is read or created.

## Destination

| Formats | `--output` | Destination |
|---|---|---|
| one | a path | That file. Its parent directory must exist. |
| one | `-` | Stdout, and nothing else on stdout. |
| one | omitted | `<output_dir>/reports/<file>` |
| several | a path | A new bundle directory holding the canonical files. |
| several | `-` | Invalid (exit 2). |
| several | omitted | The new bundle directory `<output_dir>/reports`. |

A relative `--output` is resolved from the working directory. Default
destinations are created below the project root with mode `0700`; files are
`0600`.

Nothing is ever replaced ([publication.md](publication.md)). A destination
that exists in any form, including a dangling symlink, is a collision
(`COV4010`, exit 6), and it is found before the evidence is read. Note the
consequence of the two default rows: after a single-format report has
created `<output_dir>/reports`, a multi-format report with no `--output`
collides with that directory. Use `--output`, or `sv0cov clean` first.

A terminal report written to a file is always colorless. On stdout it
follows `--color`, and color only repeats status words.

## Exit status

| Exit | Meaning |
|---:|---|
| 0 | The selected formats were published. |
| 2 | Invalid usage or configuration, including a saturation policy other than the one the evidence was merged under. |
| 5 | The evidence cannot be read or is invalid, or a source file is missing or has changed. |
| 6 | The destination exists, or publication failed. Every artifact is validated before it is committed; one that fails is not published. |
| 7 | A format or a policy assertion this build cannot produce, or a native report operand. |

The policy does not decide the exit status: a report of failing or
incomplete evidence is still published, and says what it is. Use
[`check`](check.md) to gate on policy.

`--allow-source-mismatch` lets a missing or changed source through. The
report then records the mismatch and can be at most diagnostic-only.
