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
- One `function` entity per `fn` item that has a body. Its span runs from the
  `fn` keyword through the closing `}` of the body. The qualified name is the
  function name; a function in module `m` is `m::name`.
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
