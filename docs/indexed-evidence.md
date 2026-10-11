<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Indexed evidence 1.0

`sv0cov.indexed` 1.0 is the merge result: one self-contained JSON document
that `report` and `check` read without the original maps or raw profiles
(SPEC §16.5). It embeds one `sv0cov.indexed-semantic` 1.0 object, the
source-level meaning of the run, and wraps it in the transport evidence that
says how the counts were obtained.

This page covers what exists today: the two closed schemas, the record-level
rules and the frozen structure fixtures (CV-220), the builder of the semantic
object (CV-221), and the full object with its cross-validating reader
(CV-222). The merge engine, which classifies inputs and selects runs, is
described in [Merge](merge.md) (CV-223).

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

## The structure layer

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

A document that passes is well formed. It is accepted evidence only after the
reader below has cross-validated it.

## Building the semantic object

`sv0cov.model.semantic.build_semantic(maps, profiles)` takes validated maps
and decoded, accepted raw profiles and returns the semantic object.

- **Union.** Records from every map are merged and reindexed in the
  canonical orders. Equal definitions deduplicate. Two definitions that
  disagree for one identity fail with `COV3002`. One path with two digests
  is a source-version conflict: both sources stay, `COV3004` is recorded, and
  `complete` is false.
- **Contexts.** Every distinct profile context, absent first, then bytewise
  UTF-8. The caller can add the contexts of rejected profiles, which
  contribute no count.
- **Point counts.** A profile's counts reach points through its own map's
  counter bindings and add per context with 64-bit saturation. A count is a
  lower bound when a contribution was `UINT64_MAX` or a sum passed it.
- **Region counts.** Each expression is evaluated per context with interval
  lower bounds, then the context results are added (SPEC §11.1). An inexact
  zero is kept.
- **Lines.** Membership comes from the regions' `line_numbers` alone; no
  source file is opened. A line is listed when any region names it, and
  `region_indices` are its `line_contributing` regions. The status comes from
  the contributing `user` regions: all executed is `covered`, some `partial`,
  none `uncovered`. A lower-bound zero is not executed. A line with no such
  region is `excluded` when an excluded region names it, else
  `non_executable`.
- **Branches and contracts.** An outcome's count is its point's count. A
  runtime-checked clause reports `mixed`, `evaluated_true`, `evaluated_false`
  or `not_evaluated` from its two counts.
- **Saturation.** The inexact points and the inexact regions.

The result does not depend on the order of the maps or the profiles.

Two fields are the caller's to supply, because they depend on facts outside
the model:

- `complete` starts from the caller's transport verdict (inputs and run
  selection) and is false whenever the model records a diagnostic.
- The saturation `policy` defaults to `fail`. `ineligible_uses` is left
  empty: which exact uses exist is known only when a report is made.

The oracle is `tests/fixtures/semantic/<fixture>/expected-semantic.json`,
written by the fixture builder from the hand-stated plan, counts, and line
statuses, with no code shared with the model. The model must equal it for
all eight reviewed fixtures, from synthetic profiles in sv0cov's tests and
from real native and sv0vm runs in sv0c's `run_vm_profile.py`.

## The full object

`sv0cov.model.indexed.build_indexed(map_inputs, profile_inputs, ...)`
assembles the eleven-property object from inputs a merge has already
classified:

- the **inventory**: one record per map and profile artifact, with its
  SHA-256, length, basename, status, and diagnostics. Exact copies of an
  accepted artifact appear once. No directory or absolute path is stored;
- the **bindings**: for each accepted map, its compiler identity, target,
  sources, and the point each counter index names;
- the **run selection**, the **execution** record, and the **merge** record
  (tool version, diagnostic registry, tier ceilings, the override flag);
- the semantic object and its projection digest.

`complete` is true exactly when (SPEC §16.5.7) at least one profile is
accepted, every map and profile input is accepted, the override flag is off,
the run selection holds (one run when implicit, the declared set exactly
otherwise), and both diagnostic arrays are empty. The producer records:

| Code | When |
|---|---|
| `COV3001` | no profile was accepted |
| `COV3002` | a map or profile input was rejected or incomplete |
| `COV3003` | the run selection does not hold |
| `COV3004` | one source path has two versions (also in the semantic array) |

The override flag alone makes evidence incomplete without a code: the flag
itself is the stated reason.

The bytes do not depend on the order of the inputs. A native run and an
sv0vm run of the same program give the same semantic projection; only their
transport records differ.

## The reader

`sv0cov.model.indexed.read_indexed(bytes)` is what every consumer starts
from. It reads nothing but the artifact. After the structure layer it
re-derives each retained fact and rejects any disagreement:

- canonical order and index positions of every record array;
- every reference between records;
- each point ID, recomputed from its definition (SPEC §10.3);
- bindings: each accepted map binds its counters to distinct counted points,
  and a point no map binds has the exact zero count (`COV3012`);
- point counts are physical and aggregate by saturating sum; region counts
  recompute from their expressions per context;
- line membership is exactly the inversion of the regions' `line_numbers`,
  and each status recomputes;
- outcome and contract results equal their points; exclusions equal
  classifications; the saturation inventory equals the count flags;
- the inventory names the bindings, the selected runs are the accepted
  profiles' runs, every context is used, every stored code is in the
  diagnostic registry the artifact names, and `complete` and the four codes
  above are exactly what their conditions give.

So a report or check can work from the artifact alone, with the maps and raw
profiles deleted.

What a reader cannot do is recheck the omitted bytes: that the counts are the
sum of the raw profiles, or that a binding is really the map's. The artifact
digests record what the producer validated. Evidence that must prove the
original bytes has to keep them (§16.5.7).

## Fixtures

`tests/fixtures/indexed/` holds hand-written structure fixtures, built and
checked by `build.py`:

| File | Purpose |
|---|---|
| `empty.json` | Diagnostic evidence with no input at all. Also valid for the reader. |
| `all-kinds.json` | Every record kind and every enumeration value. |
| `bounds.json` | Every integer and length at its largest value. |
| `mutations.json` | Single changes to those documents, each with its outcome: `valid`, `COV3010`, or `COV3011`. |

The digests in `all-kinds.json` and `bounds.json` are made up and their
counts are not derived from a real map, so they prove structure only and the
reader rejects both. `tests/test_indexed_structure.py` also removes,
adds, and mistypes every property of every record in the three documents,
rejects noncanonical bytes, and requires every record-level rule to be
reached by some corpus entry.
