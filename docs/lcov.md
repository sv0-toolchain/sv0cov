<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# LCOV export: `sv0cov-lcov-r1-core`

`sv0cov.formats.lcov` (CV-401, SPEC 21.4) writes the one LCOV profile R1
defines: the conservative records that LCOV 1.16 and 2.5 both read.

```text
TN:
SF:<logical path>
FN:<start line>,<qualified name>      every exported function, then
FNDA:<exact entry count>,<qualified name>
FNF:<functions>   FNH:<functions entered>
DA:<line>,<0 or 1>                    ascending
LF:<executable lines>   LH:<covered lines>
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
  first line of its span and its exact entry count.
- **Lines:** every executable line. `DA` is a binary projection: `1` only
  for native status `covered`; `partial` and `uncovered` are `0`.
- **Branches:** every eligible outcome (`covered` or `uncovered`) on the
  first line of its branch's span. Within a line, decisions are numbered
  from zero in canonical branch order and outcomes from zero in ordinal
  order; a decision with no eligible outcome gets no number.
- **Summaries** equal the native per-source function, line and branch
  metrics; a zero denominator is `0`. `TN:` is always empty: all contexts
  are aggregated.

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
pinned-consumer checks against LCOV 1.16 and 2.5 are CV-418.

Goldens: `tests/fixtures/lcov/` (one per semantic fixture, rebuilt by its
`build.py`). Tests: `tests/test_lcov.py`.
