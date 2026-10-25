<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The check command

```text
sv0cov check [options] <indexed-profile-or-native-report>
```

`check` reads one indexed profile or native report, compares the current source files with
the ones the evidence was collected from, and evaluates the resolved
policy. It writes nothing to disk. Run it from the project root: `sv0.toml`
and every source path of the evidence are found below the working
directory.

## What is evaluated

- **Integrity.** The evidence must be complete, its sources must be the
  current bytes, and under the default saturation policy no counter may
  have saturated.
- **Project thresholds.** One assertion for each of `function`, `region`,
  `line`, `branch` and `contract` that has a threshold, from
  `[tool.sv0cov.thresholds]` or `--threshold-<metric>`. With no threshold
  configured, only integrity is checked.

A threshold is decided by integer cross multiplication,
`covered * 10000 >= total * basis_points`. No rounded percentage is ever
compared: 84 of 99 lines fails an 85 percent threshold. A metric with
nothing to count fails with `COV4102` unless `empty = "pass"` (or
`--empty pass`), whatever the threshold.

The evaluation is the native report's own
([native-report.md](native-report.md)). `check` builds that report, encodes
it and reads it back through the cross-validating reader before it gives a
verdict, so `check` and a report of the same evidence under the same
configuration cannot disagree.

Scope, entity, diff, ratchet and exclusion-cap assertions are not evaluated
by this build. A configuration that asks for one is refused (exit 7) rather
than passed without it.

## Exit status

| Exit | Meaning |
|---:|---|
| 0 | The evidence is complete and current and every assertion passed. |
| 1 | The evidence is sound and an assertion did not pass: a threshold failed (`COV4101`), a selected metric was empty (`COV4102`), or saturation made a check ineligible (`COV4020`). |
| 2 | Invalid usage or configuration, including a saturation policy other than the one the evidence was merged under (`COV0013`). |
| 5 | The evidence cannot be relied on: it cannot be read or is invalid (`COV3010`, `COV6001`), it is incomplete, a source file is missing or has changed (`COV1004`), or a source path resolves outside the project through a symlink (`COV6002`). |
| 7 | The policy needs an assertion this build cannot evaluate (`COV5001`). |
| 8 | Internal failure, including a result the reader rejects. |

Unreliable evidence outranks a failed threshold: incomplete evidence exits 5
even when a threshold also failed, and no threshold can rescue it. There is
no `--allow-source-mismatch` for `check`.

## Output

Every assertion that did not pass is one diagnostic on stderr per code, in
the `policy` phase, with the facts `assertion`, `metric`, `result`, and
where they exist `actual` and `required` as exact fractions:

```text
COV4101 error: Coverage threshold failed
  actual: 14/16
  assertion: project:project
  metric: line
  required: >= 8800/10000
  result: fail
```

Stdout carries the header, summary, warnings, policy and saturation
sections of the [terminal report](terminal-report.md), unchanged. That text
is incidental: `--quiet` removes it and never removes a diagnostic.
`--color` follows the usual rule and only repeats status words.

## Native reports

A native report (`coverage.json`, or the `.sv0cov.json` beside an export)
is accepted too (CV-416; owner decision D-10, SPEC 16.5 amendment owed). It
is read through the cross-validating reader, and an invalid one is invalid
evidence (`COV4001`/`COV4002`, exit 5). Its detail is then evaluated again
under the configuration of this invocation and against the current source
files, exactly as the indexed profile it came from would be: thresholds,
scopes, entities, changed regions, ratchets, exclusions and saturation all
give the same evaluations and the same exit status. What the report
recorded (its verdict, configuration and source states) is never reused,
so a report made under a weaker policy cannot pass a stricter one, and a
source edited since is stale (`COV1004`, exit 5).

`report` and `baseline` still take only an indexed profile; a native
report there is refused with `COV5001`, exit 7.
