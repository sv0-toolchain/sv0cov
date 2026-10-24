<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Cobertura export: `sv0cov-cobertura-r1-core`

`sv0cov.formats.cobertura` (CV-402, SPEC 21.5) writes the one Cobertura
profile R1 defines. Every document is valid against the Cobertura 0.4 DTD at
commit `e5eea867` (`coverage-04.dtd`, 2,162 bytes, SHA-256 `e467cb82…7917`),
vendored in `tests/vendor/cobertura/` with its manifest and checked offline.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<coverage line-rate=… branch-rate=… lines-covered=… lines-valid=…
          branches-covered=… branches-valid=… complexity="0.0"
          version="sv0cov-r1-core" timestamp="0">
  <sources><source>.</source></sources>
  <packages>
    <package name="(root)" …><classes>
      <class name="main.sv0" filename="main.sv0" …>
        <methods><method name="classify" signature="" …><lines>…</lines></method></methods>
        <lines>
          <line number="10" hits="1" branch="false"/>
          <line number="11" hits="1" branch="true" condition-coverage="50% (1/2)">
            <conditions><condition number="0" type="jump" coverage="50% (1/2)"/></conditions>
          </line>
        </lines>
      </class>
    </classes></package>
  </packages>
</coverage>
```

## What is written

- **Sources:** root-project (`user`) sources only, as for LCOV, so the
  totals equal the native project summary (SPEC 18.1; owner decision). The
  one `source` is `.`; never a host path.
- **Packages:** sources grouped by their build package, in bytewise name
  order. A source without a package belongs to `(root)` (owner decision,
  CV-402; SPEC 21.5 names a reserved spelling but not which, so a SPEC
  amendment is owed). Parentheses cannot occur in a canonical package
  identity, so it cannot collide.
- **Classes:** one per source, in source order; `name` and `filename` are
  the logical path.
- **Methods:** one per function the native function metric counts;
  `signature` is empty (no Java-signature claim). A method's lines are the
  class lines its own regions touch, repeated exactly, so either level
  reads the same status.
- **Lines:** every executable line. `hits` is `1` only for native status
  `covered`; `partial` and `uncovered` are `0`.
- **Branches:** a decision with eligible outcomes sits on the first line of
  its span. When that line is not executable (the header of a `loop`), it
  sits on the first executable line inside its span instead. Such a line
  has `branch="true"`, `condition-coverage="P% (C/T)"` and one `condition`
  per decision, numbered from zero, `type="jump"`, with its own `P% (C/T)`.
  `C` counts covered outcomes and `T` eligible ones, `P` is
  `floor(100 * C / T)`. Other lines have `branch="false"`.
- **Rates** are exact fractions to six digits, rounded half to even;
  `0.000000` for a zero denominator. They are display values only.
- `timestamp` is the reproducible-build epoch the caller passes, `0` by
  default; every `complexity` is `0.0` (unavailable, not measured).

## What is never written

A `DOCTYPE`, entities, comments, CDATA sections, processing instructions,
namespaces, vendor elements or attributes, absolute paths. Regions,
contracts, exact outcome and function-entry counts, exclusions, context
names and partial-line state are lost; the export manifest (CV-403) lists
them. Native JSON stays authoritative.

Text XML 1.0 cannot carry (control characters) is refused with `COV4401`;
markup-sensitive text is escaped. A saturated or lower-bound count is
refused with `COV4020` (the explicit lossy export is CV-420).

## Reading back

`parse_cobertura` refuses anything outside the profile before and while
parsing (no DTD or entity is ever loaded), checks the grammar narrowed from
the DTD, then recomputes every line, condition, rate and total.
`check_cobertura` also requires the classes, methods and line and branch
totals to equal the report's. Everything else is `COV4401`.

## On the command line

As for LCOV, `report --format cobertura` and `run --report cobertura`
publish the document with its native JSON report and an export commit
manifest (CV-403; [export-manifest.md](export-manifest.md)).
`--reproducible-epoch` (or `reproducible_epoch`) sets `timestamp`. The
GitLab visualization smoke fixture is CV-419.

Goldens: `tests/fixtures/cobertura/` (rebuilt by its `build.py`). Tests:
`tests/test_cobertura.py`; the DTD validator used as the independent oracle
is `tools/dtd_validate.py` (`tests/test_dtd_validate.py`).
