<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The terminal report

`sv0cov.formats.terminal` turns one validated native report into plain text
(SPEC 21.1). It is a view: it computes no coverage fact of its own. Every
number it prints is a number the native report holds, and the native report
stays the authority (see [native-report.md](native-report.md)).

```python
from sv0cov.formats.terminal import render_terminal, terminal_bytes

text = render_terminal(report)              # no color
text = render_terminal(report, color=True)  # status words colored
data = terminal_bytes(report)               # the bytes of coverage.txt
```

`report` is the dictionary `read_report` returns. The `report` and `run`
commands that choose a destination and decide on color arrive with CV-232
and CV-234.

## What it shows

The sections always appear, in this order. An empty one says `(none)`.

| Section | Content |
|---|---|
| Header | Evidence eligibility in words, completeness, policy result, tool version, backends, test-command status, runs, input counts by status, source accuracy, contexts. |
| Summary | Functions, regions, lines and branches as `covered/total` and a percentage; partial lines. Contracts on a separate row under their own sentence. |
| Files | User sources before dependency sources, then by package, then by path. Under each file, its functions. Each row carries all five metrics. |
| Partial lines, Uncovered lines | Per file, as ranges: `3, 5-7, 9`. A range joins adjacent line numbers only. |
| Uncovered branch outcomes | One row per branch with an outcome that was never taken: location, branch kind, the outcome names. |
| Contracts | One row per clause: location, clause name, enforcement, runtime result, true and false counts. |
| Exclusions | Counts of excluded functions, regions, lines, branches and contracts; statically unreachable outcomes; then every exclusion with its mode, origin and reason. |
| Warnings | Incomplete evidence, every input that was not accepted (with its codes), every source that is stale or missing. |
| Policy | Every assertion in report order: result word, kind and name, metric, required fraction, actual fraction, threshold source, member counts, diagnostic codes. |
| Saturation | The resolved policy, and every count that is not exact. |

## Rules

- **Exact pairs.** A metric is always `covered/total` first. The percentage
  is the report's own six-digit `ratio` with the decimal point moved two
  places (`0.848485` is `84.8485%`), so nothing is rounded twice. Policy
  never reads a percentage, and neither should a reader: 84 of 99 shows
  `84/99` beside a required `8500/10000` and the word `FAIL`.
- **Zero totals.** A metric with nothing to count shows `N/A`, never `0%` or
  `100%` (SPEC 11.6).
- **Lower bounds.** A saturated or lower-bound count is written `>=N`.
- **Status is a word.** `PASS`, `FAIL`, `INELIGIBLE`, `N/A`, `PASSING`,
  `POLICY FAILED`, `INCOMPLETE`, `DIAGNOSTIC ONLY`, `WARNING:`. Color only
  repeats the word: removing the color sequences gives exactly the
  colorless text.
- **Untrusted text is inert.** Paths, names, reasons, context values and
  every other string are escaped: C0 and C1 controls and DEL as `\xNN`, the
  line separators and bidirectional controls as `\uNNNN`. Each finished line
  is escaped once more as a whole, and color is added only after that. A
  quoted field cannot close its own quotes.
- **Deterministic.** The layout does not depend on the terminal width, the
  locale or the clock. The same report gives the same bytes.

## Goldens

`tests/fixtures/terminal` holds one colorless golden per report: the four
hand-built reports of `tests/fixtures/report` and one per semantic fixture.

```sh
python3 tests/fixtures/terminal/build.py           # check
python3 tests/fixtures/terminal/build.py --write   # regenerate
```

sv0c's coverage gate builds the same reports from real native and sv0vm
runs and requires their terminal text to equal these goldens from the
summary on.
