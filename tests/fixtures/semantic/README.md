<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Semantic coverage fixtures

These programs are the source oracle for coverage planning (SPEC §28.3):
their expected maps are decided by hand, never produced by a compiler.
sv0c's planner (CV-107..CV-110) must reproduce each `expected-map.json`
byte for byte.

| Fixture | Exercises (SPEC §28.2 rows) |
|---|---|
| `f0/` | the F0 parity fixture (CV-027): function entries, initializers, assignments, returns, `if` without `else`, `while`, enum `match`, a multibyte string |
| `functions/` | uncalled, once, repeatedly, expression-statement call |
| `branches/` | `if` true-only, false-only, both, `else`, nested, returns after early returns (subtraction expressions) |
| `loops/` | zero, one, many iterations; `break`; `continue` |
| `match/` | enum arms, integer match with `_`, arms never taken (partial lines) |
| `source-text/` | CRLF endings, tabs, no final newline, CJK text, several regions on one line, a partial line |
| `project/` | a two-module project whose files share a basename |

Each fixture directory holds the program, `expected-map.json`, and
`expected-counts.json` (the per-point counts of one run with no input). All
programs exit 0 on the native C backend and on the VM (checked on
2026-09-25 with the toolchain at sv0c `d1a5100`).

## How the expectations are made

- `fixtures.py` records the planning decisions for each program by hand,
  following [`docs/planning-conventions.md`](../../../docs/planning-conventions.md):
  which functions, branches, and regions exist, their kinds, and each
  region's counter expression. It also records the expected counts and the
  status of every source line, both worked out by hand.
- `plan.py` does only the mechanical part: byte offsets, line and column
  coordinates, point IDs, counter numbering in source order, fragment and
  map IDs. It validates every map against its exact source bytes.
- `build.py --write` regenerates the checked-in artifacts after a reviewed
  change; `build.py` (and the test suite) fails when they are stale.
- `tests/test_semantic_fixtures.py` recomputes every line status from the
  map and the counts (SPEC §11.4) and compares it with the hand-derived
  statuses.

## Toolchain findings while writing these fixtures

- A user function named `abs` (a libc name) or `double` (a C keyword) fails
  native compilation because generated C uses sv0 names verbatim; the VM
  runs both. The fixtures use `magnitude` and `doubled` instead; the sv0c
  fix is tracked separately.
