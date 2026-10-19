<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# HTML report

`sv0cov report --format html` (or `html` in `run`'s reports) writes
`coverage.html`: one self-contained UTF-8 document with its style, script,
navigation data and annotated sources inside (SPEC 21.2, 20.2.1). Open it
from disk; it needs no server and no network. It is produced by
`sv0cov.formats.html.render_html` from the native report and the current
bytes of the sources, and computes no coverage fact of its own.

## What it shows

- **Header:** evidence eligibility, completeness, policy result, execution,
  backends, source accuracy and contexts, every status as a word.
- **Summary:** functions, regions, lines (with partial lines) and branch
  outcomes as covered/total and percent; contracts apart.
- **Files:** by ownership and package, each file and function with the five
  metrics, linked to its source.
- **Uncovered:** every uncovered or partial line and every line with an
  outcome not taken, in file and line order.
- **Contracts, Exclusions, Warnings, Policy, Saturation:** as in the
  terminal report, with exclusion reasons and contract dispositions.
- **Provenance:** tool, runs, maps, the indexed input, semantic projection
  and run manifest digests, every input, and each source's evidence and
  observed digest.
- **Sources:** each line with its status; under a line, its branch outcomes
  with counts (each named by column), contract clauses and exclusions. A
  source that is not current is not shown as text: its lines are listed by
  status instead.

## Navigation

A skip link, landmarks (`header`, `nav`, `main`, `footer`), a section index
and headed sections. The uncovered places form one chain: in a source, each
links to the next ("next uncovered"), so the chain works without the script.
With the script, `n` (or `j`) and `p` (or `k`) move focus along the chain of
the context being shown. Long source lines scroll inside a focusable region.

## Contexts

With two or more contexts, a select at the top shows the counts of one
context or of all of them (the aggregate, the default). It changes the
summary, the file and function metrics, line statuses and outcome counts,
using `sv0cov.model.context.context_view`. Policy and thresholds always use
the aggregate. With one context there is no select and no data block.

## Safety

- The Content-Security-Policy is `default-src 'none'` and admits only the
  document's own style and script, pinned by their SHA-256; `connect-src`,
  `img-src`, `font-src`, `form-action` and `base-uri` are `'none'`.
- There are no external URLs, resources, forms or event-handler attributes,
  and every link is a fragment of the document.
- Text from sources, paths, contexts, reasons, names and diagnostics has its
  control and line-reordering characters made visible (tabs in source lines
  stay) and is then escaped for HTML. The navigation data is JSON in a
  `application/json` block with `<`, `>` and `&` escaped. The script only
  changes text and class names.

`sv0cov.formats.html.check_html` checks all of this before the file is
published: UTF-8, a doctype and language, exactly one policy of
`default-src 'none'` whose hashes match every inline style and executable
script, no element or attribute that loads anything, no event handler or
inline style, links only to ids of the document, and unique ids.

## Determinism

No clock, locale or randomness is read: the same report and sources give the
same bytes (AC-025).

## Tests

`tests/test_html.py`: every semantic fixture and the two-map sample render
to a checked document, five times to the same bytes; the policy and the
absence of anything that loads; the check rejects each kind of change it
looks for; a hostile string (markup, a closing script tag, a comment opener,
quotes, ESC sequences, a bidi override, NUL) in every untrusted field stays
text; one chain reaches every uncovered place; every status is a word; the
filter carries the numbers of each context; landmarks, headings, scoped
table headers, labels and focusable scroll regions; an unavailable source;
CRLF and tabs. The behavior in a browser (filter, keys, no policy
violation) was checked by hand for CV-309; WCAG 2.2 AA is an R1 gate
(COV-REP-007).
