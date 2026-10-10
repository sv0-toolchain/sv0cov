<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Coverage planning conventions (proposed, F0)

SPEC §11 and §16.3 fix what a coverage map must contain but leave several
planning choices to the compiler (`sv0c` owns planning, SPEC §3.1). The
hand-reviewed semantic fixtures in `tests/fixtures/semantic/` (CV-027,
CV-028) need concrete answers, so this page states the conventions they use.
They are the proposed contract for the sv0c planner slices (CV-107..CV-110):
sv0c must reproduce the fixture maps byte for byte, or the conventions and
fixtures change together through review.

## Sources and entities

- A single-file program's logical path is its file name (`main.sv0`); a
  project's paths are relative to the project directory. Ownership is `user`;
  `package` is `null` for the root project.
- One `function` entity per `fn` item that has a body: free functions,
  methods of `impl` blocks, and trait methods with a default body. Its span
  runs from the `fn` keyword through the closing `}` of the body (a leading
  `pub` or attribute is outside the span). The qualified name is the
  function name, prefixed by the `impl` self type or trait name for a method
  (`Type::name`, `Trait::name`) and by the file's `module m;` declaration
  (`m::name`, `m::Type::name`).
- `#[extern_c]` declarations and bodyless trait methods are not entities.
- sv0 has no nested functions yet, so every function owns itself.
- Entities are ordered by source (sources sorted bytewise by logical path),
  then by position in the file.
- Enum, struct, `use`, and `module` items are not entities.

## Points and counters

- Every function has one `function_entry` point: span = the function span,
  discriminator `entry`, counted.
- Every branch outcome is a counted `branch_outcome` point: span = the branch
  span, discriminator = the branch kind (`if`, `loop`, `match`), ordinal =
  outcome position.
- Regions get no points of their own (SPEC AC-108): each region's counter
  expression is written over entry and outcome points.
- Counter indexes follow source order: by point span start, then
  `function_entry` before `branch_outcome`, then outcome ordinal.

## Branches

| Construct | Kind | Span | Outcomes |
|---|---|---|---|
| `if c { … }` (with or without `else`) | `if` | `if` keyword through the last block's `}` (no trailing `;`) | `true`, `false` (implicit `false` without `else`) |
| `while c { … }`, `for x in r { … }` | `loop` | keyword through the body's `}` | `body`, `exit` |
| `match e { … }` | `match` | `match` keyword through the closing `}` | `arm:0`, `arm:1`, … in source order |

A `loop` outcome counts condition evaluations: `body` is a true evaluation
and `exit` a false one (`break` leaves without a condition evaluation, so a
loop left by `break` records `body` but not `exit`).

## Regions

| Source | Kind | Span | `line_contributing` |
|---|---|---|---|
| `let …;` | `initializer` | `let` through `;` | true |
| `x = …;` | `assignment` | target through `;` | true |
| `x += …;` and other compound assignment | `mutation` | target through `;` | true |
| expression statement `f(…);` | `expression_statement` | expression through `;` | true |
| `return …;` | `return` | `return` through `;` | true |
| `break;` / `continue;` | `break` / `continue` | keyword through `;` | true |
| `if` / loop condition | `expression` | the condition expression | true |
| `match` scrutinee | `expression` | the scrutinee expression | true |
| `if` / `else` block | `branch_body` | `{` through `}` | false |
| loop body block | `loop_body` | `{` through `}` | false |
| match arm result | `match_arm` | the arm's result expression | true (false when the result is a block) |

Container regions (`branch_body`, `loop_body`) do not contribute to lines, so
a line holding only `}` stays `non_executable`, as SPEC §27.1 requires. A
multi-line statement region (for example `return match …;`) contributes to
every line it spans that has non-whitespace bytes, so a line holding an
unexecuted arm is `partial` when the enclosing statement ran.

Counter expressions:

- straight-line code in a function body: the function's entry;
- inside an `if` / `else` block: that outcome (`true` / `false`);
- inside a loop body: `body`;
- an `if` condition: the count of the enclosing position;
- a loop condition: `body + exit`;
- code after an `if` or loop that cannot leave the function early: the
  enclosing position's count;
- a match arm result: that arm's outcome.

Calls inside a statement are owned by the statement region; no separate
`call` region is planned for them.

Constructs beyond the F0 fixtures (planned by sv0c since CV-108):

- An `if` nested inside an expression (a `let` initializer, a call argument,
  a `return` value) is a `conditional_expression` branch with outcomes
  `true`, `false`; an `if` in statement or tail position is an `if`. An
  `else if` belongs to its chain's kind, and its condition and bodies count
  from the enclosing `false` outcome (no `branch_body` for the `else if`
  itself).
- A block's tail expression (no `;` before the closing `}`) is an
  `expression` region at the enclosing position.
- `for p in e { … }` is a `loop` branch; `e` is an `expression` region
  counted at the enclosing position (it is evaluated once per loop entry).
- `loop { … }` is a `loop` branch with a `loop_body` and no condition
  region (its `exit` is statically unreachable since CV-203).
- A match arm whose result is a block has a `match_arm` region over the
  block, and the block's statements are planned at the arm's outcome.
- A `while` condition ends before any `loop_invariant(…)` clause.
- A block used as an expression (`let x = { … };`) is planned like any
  block at the enclosing position: its statements get their regions and
  its tail an `expression` region; the block itself has no region of its
  own.

Added in CV-201 (R0):

- Every `match` scrutinee is an `expression` region at the enclosing
  position, in statement, tail, and nested position alike, like an `if`
  or loop condition. A call in a scrutinee is therefore always owned by a
  region (SPEC §11.3).
- `unsafe { … }` is planned as its block: its statements get their
  regions, and the wrapper has no region of its own (same execution
  meaning, §11.3).
- A region whose counter expression is identically zero (it follows an
  unconditional `return`, `break`, or `continue`) is `statically_unreachable`
  with the canonical empty expression. It never enters an ordinary
  denominator (§11.7). Map 1.0 records this provenance as the region's
  `classification`; it has no per-region reason field.
- No `call` region is planned: every call in sv0 sits inside a statement,
  condition, scrutinee, iterable, or tail-expression region.
- Desugared syntax plans only source regions. `for p in e { … }` has its
  iterable and loop body, and `x += …` is one `mutation` region, so
  compiler-generated support code never gets a region (COV-MET-008).
  sv0c therefore emits no `synthetic_support` region yet.
- `?` is refused (exit 9) until CV-213 models it. Its hidden early return
  would otherwise make the code after it count runs that returned early.

Added in CV-202 (R0): line coverage.

- A region contributes to lines (`line_contributing`) exactly when it is a
  `user` region and not a container. Containers are branch bodies, loop
  bodies, and a match arm whose result is a `{ … }` block (owner's choice):
  the statements inside carry the lines, so a brace-only `}` or `},` line,
  and a `Pat => {` line, stay `non_executable`, as with `if` / `else`
  blocks. A non-block arm (`Pat => expr`) still contributes.
- A `statically_unreachable` region does not contribute (owner's choice), so
  a line holding only dead code is `non_executable`, and every contributing
  region enters line status (SPEC 11.4, 11.7).
- `line_numbers` lists every line on which the span has a byte other than
  space, tab, LF, or CR, exactly as SPEC 16.3.5 says. A comment line inside
  a multi-line statement therefore counts with that statement; a blank line
  does not.
- Line status is derived by `sv0cov.lines` (SPEC 11.4): `covered` when every
  contributing region on the line ran, `partial` when some did, `uncovered`
  when none did, `non_executable` when none contributes. A one-line
  `if c { a(); } else { b(); }` or `while c { … }` with an untaken part is
  `partial`; so is a line of a multi-line statement that holds an untaken
  arm or branch value.

Added in CV-203 (R0): loop branches.

- A loop's `exit` outcome is planned only when a false condition evaluation
  is possible (SPEC 11.5). `loop { … }` has no condition, and `while true`
  (the condition is exactly the literal `true`) can never evaluate false,
  so their `exit` is `statically_unreachable` (owner's choice): uncounted
  (`counter_index` and `fragment_index` null), no hit placed, and the
  outcome carries the evidence identity `sv0c:loop:no-condition` or
  `sv0c:loop:condition-literal-true`. The branch keeps both outcomes and
  is covered once its body runs. A `while true` condition region counts
  `body` only.
- `exit` has one meaning for every loop: a false condition evaluation (an
  exhausted iterator for `for`). Leaving by `break` or `return` never
  counts it. (Before CV-203, `loop` counted `exit` after a `break`.)
- `body` counts iterations entered, including one left by `break`,
  `continue`, or `return`.
- Code after a loop counts at the enclosing position minus the `return`s
  inside the loop, so code after a `loop` left only by `return` counts zero
  at run time.

Added in CV-204 (R0): counter expressions.

- Normal form (SPEC 11.1): sv0c merges equal points, drops zero
  coefficients, and orders terms by bytewise point ID; a region whose
  expression normalizes to nothing is `statically_unreachable` with the
  empty array. Only counted points are referenced. Coefficients are small
  integers (each is a count of how often a point was added or subtracted
  while planning one function), far inside signed 32 bits.
- Nonnegativity from structured flow. Every region's expression is the
  count of one control position: a function entry or a branch outcome
  (each a real execution count), minus the outcomes of the early exits
  (`return`, `break`, `continue`) nested inside the constructs that precede
  the region at that position. Each such exit is reached only by passing
  through that position first, and at most once per pass, so its count
  never exceeds the position's count; the difference is the number of
  passes that reached the region. Loop conditions are `body + exit`,
  a sum of counts. Hence every expression is nonnegative on every valid
  execution, and a negative exact result means corrupt or mismatched
  evidence (COV3002).
- Counter reduction is declined (owner's choice). Deriving an outcome as,
  say, `false = condition - true` would leave that outcome uncounted, but
  SPEC 11.1 has branch coverage use direct point counts and a branch
  outcome references its own point. Regions already have no counters of
  their own (AC-108), so every counter is a branch outcome or a function
  entry, and each is needed.
- Evaluation is `sv0cov.expr`: unbounded integers, per-context evaluation
  then a saturating aggregate, saturated terms as lower bounds (a saturated
  subtracted point gives the inexact zero), and a lower-bound zero counts as
  not executed for regions and lines.

Added in CV-205 (R0): fragments and program-map assembly.

- One fragment per source file. Sources, and so fragments, are ordered by
  bytewise logical path; one file has one digest and one fragment, so the
  path alone fixes the order (SPEC 16.3.3). Counters run by source, then
  position, so each fragment owns one contiguous slice.
- A file that plans no counter (only types, enums, `use`, or only
  statically unreachable points) has a zero-length fragment based at the
  next positive slice, or at `program_counter_count` when none follows.
- sv0c compiles a project as one unit, so assembly happens inside one
  compile, but the map is a function of the files alone: it does not
  depend on the order the files are linked in. The test hook
  `SV0_COVERAGE_LINK_ORDER` links a project in any order to prove this
  (all 120 orders of a five-module project, native and VM). Separate
  per-module generated C with one registration per module is DV-5 (R1).

Added in CV-207 (R0): zero-counter programs.

- A source with no function plans no point: its map has
  `program_counter_count` 0, empty semantic arrays, and one empty fragment
  per file (base 0). A VM instrument build of it writes bytecode identical
  to an off build and a binding counting 0.
- Such a source is not an executable: both backends need `main`, and
  `main`'s entry is always counted. So no runnable sv0 program has zero
  counters until exclusions (CV-305) can exclude a whole program. An empty
  file is not an sv0 program.
- Until then the lifecycle is tested with a stand-in for a fully excluded
  build (owner's choice): an ordinary program's uninstrumented C or
  bytecode with the zero-counter registration or binding. It runs like the
  off build and publishes one complete empty profile (no pairs, no
  overflow words, no overflow flag) bound to the zero-counter map. CV-305
  repeats the test with a real fully excluded program.
- sv0vm rejects any disagreement between the binding's count and the
  presence of `COVER_HIT` before user code (COV2201).

Added in CV-209 (R0): ownership and default scope.

- `ownership` and `package` come from the build graph, never from how a
  path is spelled. An sv0 build has one package, the root project: every
  file the project compiles is `user`-owned with a null `package`
  (`cov_src_ownership` / `cov_src_package` in sv0c decide this, and never
  look at the logical path). Dependency packages (COV-SCP-004, R1) will
  set both from build metadata.
- Directory names mean nothing: code under `tests/`, `examples/`,
  `vendor/`, `third_party/`, `generated/`, `build/` or `node_modules/` is
  ordinary root-project code and stays in scope. Scope is the compiled set:
  a file the project does not compile (for example under a dot-directory,
  which the project listing skips) is not a source.
- A `dependency` source names its package (a map with a dependency source
  and a null package is invalid). Root metrics count `user` sources only
  (`sv0cov.lines.user_source_indices`).

