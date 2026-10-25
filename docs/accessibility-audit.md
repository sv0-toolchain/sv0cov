<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# HTML report accessibility audit (CV-408)

R1 requires the HTML report to meet WCAG 2.2 Level AA for the tested report
set (SPEC 21.2, R1-G8, COV-REP-007), checked automatically and by a
documented manual keyboard and screen-reader review. This is that record.

## Report set

`tools/accessibility/build_reports.py` renders 14 representative reports:
every semantic fixture with failing thresholds (policy rows, uncovered and
partial lines, untaken outcomes), the context filter (`contexts.html`),
contracts + saturation + exclusions + unavailable sources (`rich.html`),
changed regions, a ratchet, and scopes and entities.

## Automated checks

| Check | Tool | Where |
|---|---|---|
| WCAG 2.0/2.1/2.2 A and AA rules (`wcag2a`, `wcag2aa`, `wcag21a`, `wcag21aa`, `wcag22aa`) on every report, light and dark preference, 1280 and 320 CSS px, and after choosing each context | axe-core 4.14.0 in Playwright 1.64.0 Chromium, lockfile-pinned (`tools/accessibility/`) | CI job `accessibility` |
| Keyboard: shortcuts inert outside a source listing; skip link first and leading into `main`; context select operable by keyboard and announced; `n`/`p` walk exactly the "next uncovered" chain and wrap; focused line outlined; Tab reaches every focusable element in document order with no trap | same | CI job `accessibility` |
| Contrast of every text colour on every background (≥ 4.5:1) and of the focus outline (≥ 3:1), from the style itself; fixed light theme; shortcut guard; 24 px targets | stdlib | `tests/test_accessibility.py` |
| Landmarks, headings, scoped headers, labels, focusable scroll regions, status in words | stdlib | `tests/test_html.py` |

axe leaves `color-contrast` undecided where cell backgrounds overlap (most
at 320 px) and `th-has-data-cells` on the source tables' row headers; the
contrast test computes every pair the style can produce, and the source
tables' row headers are line numbers whose data cells are the status and
the code.

## Manual review, 2026-10-25

Done by Claude in the Claude desktop app's built-in browser (Chromium) and
headless Chromium 156; the screen-reader part is a review of the
accessibility tree (names, roles, states, live regions, reading order), as
the owner accepted, not a session with a running screen reader.

| Criterion | Result |
|---|---|
| 1.3.1 Info and relationships | Landmarks (`header`, `nav`, `main`, `footer`), named regions for every source listing, headings h1-h3 with no skipped level, tables with header cells, the select labelled. |
| 1.3.2 Meaningful sequence | A source row reads number, status word, code; its note row follows with the outcomes. |
| 1.4.1 Use of color | Every status is a word; colour only repeats it. |
| 1.4.3 / 1.4.11 Contrast | Computed: all pairs pass (see test). |
| 1.4.10 Reflow | At 320 px only code scrolls, inside its own focusable region (two-dimensional content). |
| 2.1.1 / 2.1.2 Keyboard, no trap | Everything is reachable with Tab in document order; nothing traps focus. |
| 2.1.4 Character key shortcuts | Fixed: `n`/`p`/`j`/`k` were global; they now act only while focus is in a source listing. |
| 2.4.1 Bypass blocks | "Skip to the report" is the first Tab stop and moves on into `main`. |
| 2.4.3 Focus order | Document order. |
| 2.4.4 Link purpose | "next uncovered" is read in its row's context; file and function links name their target. |
| 2.4.7 / 2.4.11 Focus visible, not obscured | 3 px outline on links, rows and the select; nothing sticky covers it. |
| 2.5.8 Target size | Fixed: line-number links were about 19 px tall in a dense column; now at least 24 by 24 px. |
| 3.1.1 Language | `lang="en"`. |
| 4.1.2 Name, role, value | Native elements only; the select's name is its label. |
| 4.1.3 Status messages | Fixed: choosing a context changed the "showing" text silently; it is now a `role="status"` region. |

## Defects found and fixed

- 2.1.4: global single-key shortcuts.
- 2.5.8: line-number targets under 24 px (axe, all reports).
- 4.1.3: the context change was not announced.
- Functional (CV-309): with one context, the script ended before wiring
  the keys, so `n`/`p` did nothing in most reports; and a line whose
  untaken outcome sits in its note row (a covered `if` with a branch not
  taken, a `loop` header) was not a stop. The keys now walk exactly the
  "next uncovered" chain.

## Running it

```text
cd tools/accessibility && npm ci --ignore-scripts && npx playwright install chromium
python3 tools/accessibility/build_reports.py /tmp/a11y
node tools/accessibility/axe_check.mjs /tmp/a11y
```
