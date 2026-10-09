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
| match arm result | `match_arm` | the arm's result expression | true |

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
  region.
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
