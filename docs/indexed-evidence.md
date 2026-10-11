<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Indexed evidence 1.0

`sv0cov.indexed` 1.0 is the merge result: one self-contained JSON document
that `report` and `check` read without the original maps or raw profiles
(SPEC §16.5). It embeds one `sv0cov.indexed-semantic` 1.0 object, the
source-level meaning of the run, and wraps it in the transport evidence that
says how the counts were obtained.

This page covers what exists today (CV-220): the two closed schemas, the
record-level rules, and the frozen structure fixtures. Building the semantic
object from maps and profiles (CV-221), the reader's cross-validation
(CV-222), and the merge engine (CV-223) come next.

## The two schemas

| Schema | File | Top-level properties |
|---|---|---|
| `sv0cov.indexed` 1.0 | `schemas/sv0cov.indexed-1.0.schema.json` | 11: `diagnostics`, `execution`, `map_inputs`, `maps`, `merge`, `profile_inputs`, `run_selection`, `schema`, `semantic`, `semantic_projection_sha256`, `version` |
| `sv0cov.indexed-semantic` 1.0 | `schemas/sv0cov.indexed-semantic-1.0.schema.json` | 18: `branches`, `capabilities`, `complete`, `contexts`, `contracts`, `diagnostics`, `entities`, `exclusions`, `lines`, `map_ids`, `map_version`, `point_identity_version`, `points`, `regions`, `saturation`, `schema`, `sources`, `version` |

Both are closed: every object lists its exact properties, and there are no
optional fields, extensions, or vendor namespaces. Source, entity, span,
expression-term, and exclusion records are the map 1.0 definitions, referenced
from the map schema, so a record that is valid in a map has the same shape
here. The generated validators are
`sv0cov._generated.validators.sv0cov_indexed_1_0` and
`sv0cov_indexed_semantic_1_0`.

## What is checked now

`sv0cov.formats.indexed` checks a document in three steps:

1. **Bytes and shape.** Canonical JSON (SPEC §16.2), then the generated
   closed-schema validator: property sets, types, enumerations, integer and
   length bounds.
2. **Record-level rules.** Everything one record decides by itself:
   - lexical forms: digests, stable codes, run and profile identities, input
     basenames, compiler identity, byte bounds of strings;
   - scalar arrays are strictly ordered and unique;
   - a count record's flags (`saturated` equals `lower_bound`, an exact zero
     context is omitted, an exact aggregate is the sum of its contexts);
   - the null and value rules fixed by a record's own status, mode, kind, or
     enforcement: the execution record, the tier ceilings, accepted versus
     rejected inputs, one binding per counter, run-selection modes, outcome
     status and evidence, contract counts, evidence and `runtime_result`, the
     saturation record.
3. **Projection digest.** `semantic_projection_sha256` is the SHA-256 of the
   embedded semantic object serialized alone as canonical JSON, final LF
   included. No wrapper field takes part (§16.5.6).

Failures raise `IndexedError` with `COV3010` (invalid indexed evidence) or
`COV3011` (projection mismatch).

A document that passes is well formed. It is not yet accepted evidence. The
rules that relate records to each other are the reader's cross-validation
and arrive with CV-222: references and index positions, record-array order,
bindings that cover each map's counters, region counts recomputed from
expressions, line membership and status, branch and contract results against
points, exclusions against classifications, the saturation inventory against
count flags, and `complete`.

## Fixtures

`tests/fixtures/indexed/` holds hand-written structure fixtures, built and
checked by `build.py`:

| File | Purpose |
|---|---|
| `empty.json` | Diagnostic evidence with no input at all. |
| `all-kinds.json` | Every record kind and every enumeration value. |
| `bounds.json` | Every integer and length at its largest value. |
| `mutations.json` | Single changes to those documents, each with its outcome: `valid`, `COV3010`, or `COV3011`. |

Their digests are made up and their counts are not derived from a real map,
so they prove structure only. `tests/test_indexed_structure.py` also removes,
adds, and mistypes every property of every record in the three documents,
rejects noncanonical bytes, and requires every record-level rule to be
reached by some corpus entry.
