<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# LCOV export: `sv0cov-lcov-r1-core`

`sv0cov.formats.lcov` (CV-401, SPEC 21.4) writes the one LCOV profile R1
defines: the conservative records that LCOV 1.16 and 2.5 both read.

```text
TN:
SF:<logical path>
FN:<first executable line>,<name>     every exported function, then
FNDA:<exact entry count>,<qualified name>
FNF:<functions>   FNH:<functions entered>
DA:<line>,<0 or 1>                    ascending
LF:<executable lines>   LH:<executed lines>
BRDA:<line>,<decision>,<outcome>,<exact count>
BRF:<branch outcomes>   BRH:<outcomes taken>
end_of_record
```

## What is written

- **Sources:** one record per root-project source (`user` ownership), in
  source order, so the LCOV totals equal the native project summary.
  Dependency sources are left out (SPEC 18.1; owner decision); the export
  manifest (CV-403) records the omission.
- **Functions:** every function the native function metric counts, with the
  first executable line of its span and its exact entry count.
- **Lines:** every executable line. `DA` is a binary projection: `1` for a
  line that executed (native status `covered` or `partial`), `0` for
  `uncovered`. The native report keeps partial lines apart.
- **Branches:** every eligible outcome (`covered` or `uncovered`) on the
  first executable line of its branch's span (a `loop` header is not
  executable). Within a line, decisions are numbered
  from zero in canonical branch order and outcomes from zero in ordinal
  order; a decision with no eligible outcome gets no number.
- **Summaries** equal the native per-source function and branch metrics
  and, for lines, the executed lines (covered plus partial); a zero
  denominator is `0`. `TN:` is always empty: all contexts
  are aggregated.

## Why: the pinned consumers (CV-418)

LCOV 2.5 refuses, as a consistency error, a `DA` of `0` on a line holding
a branch that was taken, and it places function and branch data only on
lines that have `DA`. A partial line nearly always holds a taken branch,
and a function's declaration line and a `loop` header are not executable.
So, by owner decision (CV-418; a SPEC 21.4, 16.6 and COV-REP-010 amendment
is owed), `DA` marks every executed line and `FN`/`BRDA` sit on the first
executable line of their unit. The manifest says so:
`line_status_binary_executed` and `unit_lines_as_first_executable_line`.

`tools/lcov_conformance.py` runs every golden through the exact pinned
LCOV 1.16 and 2.5 releases (`tests/conformance/lcov-distributions.json`:
tarball size and SHA-256, verified before extraction), `lcov --summary`
and `genhtml` with branch coverage, on the host `perl`, and requires exit
0, no warning, error or ignored message, and totals equal to the
tracefile's. CI runs it in the `lcov-consumers` job with no network;
locally, `SV0COV_LCOV_TARBALLS=<dir>` makes `tests/test_lcov_conformance.py`
run it.

## What is never written

Regions, contracts, context names, excluded and statically unreachable
units, and every extension: `VER`, line checksums, `FNL`, `FNA`, function
end lines, MC/DC, comments, vendor records. Native JSON stays authoritative.

A saturated or lower-bound count has no exact value; a report holding one in
an exported unit is refused with `COV4020`, unless the diagnostic-only lossy
export is asked for (`lossy=True`, `--allow-lossy-saturated-export`;
[export-manifest.md](export-manifest.md)), which writes it as `1`. `parse_lcov` reads a tracefile under exactly this grammar, checking
order, contiguous decision and outcome indexes and every summary, and
`check_lcov` also requires the totals of every source to equal the report's;
anything else is `COV4401`.

## On the command line

`report --format lcov` and `run --report lcov` publish the tracefile with
its native JSON report and an export commit manifest (CV-403;
[export-manifest.md](export-manifest.md), [report.md](report.md)). The
pinned-consumer checks against LCOV 1.16 and 2.5 are above.

Goldens: `tests/fixtures/lcov/` (one per semantic fixture, rebuilt by its
`build.py`). Tests: `tests/test_lcov.py`.
