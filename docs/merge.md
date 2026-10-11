<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Merge

`sv0cov.model.merge.merge(maps, profiles, ...)` turns the bytes of the
supplied maps and raw profiles into [indexed evidence](indexed-evidence.md)
(SPEC §17). It is the engine behind the future `merge` command; reading
files and publishing the result are that command's job (CV-226, CV-227).

## Order of work

Nothing is combined until every input has been classified.

1. **Inventory.** Each input is an `Artifact(name, data)`: a basename and its
   bytes, or `None` when the bytes could not be read. Every input ends up in
   the result's inventory, accepted or not.
2. **Maps.** A map is accepted when the map validator accepts its bytes and
   its definitions agree with every other accepted map. When two maps define
   the same source, entity, point, region, line, branch, contract or
   exclusion differently, both are rejected (`COV3002`).
3. **Profiles.** Each profile is decoded on its own, then against its map.
4. **Copies and collisions.** See below.
5. **Run selection and counts.** Counts add by point and context with 64-bit
   saturation. A sum that lands exactly on 2^64 - 1 is saturated.

## What happens to a profile

| Finding | Status | Code |
|---|---|---|
| Bytes could not be read | rejected | `COV2010` |
| Truncated, or no completion marker | incomplete | `COV2011` |
| Checksum mismatch | rejected | `COV2012` |
| Unsupported version | rejected | `COV2103` |
| Any other structural fault, or a counter outside its map | rejected | `COV2110` |
| Its map was not supplied, is invalid, or was rejected | rejected | `COV2111` |
| Its profile ID is also used by different bytes | rejected | `COV2112` |
| Exact counts that make a region of its map negative | rejected | `COV3002` |
| Over the tier's byte or counter ceiling | rejected | `COV6001` |

The last-but-one row catches a file that is well formed and checksummed but
whose counts no run of the mapped program can produce, such as a branch body
that ran more often than its function. A saturated counter is a lower bound,
not a contradiction, and is accepted.

For an input that is not accepted, the inventory record keeps what its fixed
header says (backend, map, run, profile ID, context) when that header is
intact. Those fields are diagnostic only: they come from a file that failed
validation.

## Copies, collisions, and equal runs

- The same profile ID and the same bytes are one profile. It counts once,
  under the bytewise-smallest name, and `MergeResult.duplicates` records how
  many extra copies were supplied. The same holds for maps.
- One profile ID with different bytes is a collision. Every valid input that
  uses the ID is rejected, even when the decoded counts are equal.
- Different profile IDs are different profiles and both count, however equal
  their contents are.
- Names decide nothing. Two different files may share a basename.

A corrupt file is rejected for its own fault. It does not discredit a valid
profile whose ID its header claims.

## Run selection

`select_runs(expect_runs=None, manifest=None)` gives the selection for the
two command-line forms:

| Request | Mode | Complete when |
|---|---|---|
| Neither | `implicit-single` | the accepted profiles carry exactly one run ID |
| `--expect-run` values | `explicit-list` | the accepted profiles' run IDs are exactly the declared set |
| `--run-manifest` bytes | `manifest` | the same, and the manifest digest is recorded |

A malformed request raises `MergeError` `COV3003` and produces no evidence:
both forms together, an empty list, a repeated or invalid ID, or an invalid
manifest. The `none` mode of the schema is therefore never written.

An incomplete or rejected profile blocks completeness whichever run it
belongs to.

## The result

`MergeResult` holds the indexed object, its canonical bytes, and:

- `complete`: the evidence's own `semantic.complete` (SPEC §16.5.7).
- `publishable`: whether a merge command may write the bytes. Always when
  complete; otherwise only under `allow_rejected_inputs`, which itself marks
  the evidence incomplete, so it can never pass a policy check.
- `findings`: one entry per rejected input and code, plus the whole-merge
  codes (`COV3001`..`COV3004`).
- `duplicates`: accepted artifacts supplied more than once.

Before returning, the engine reads its own bytes back through the indexed
reader. Evidence its reader would reject is never returned.

The bytes, findings and duplicates do not depend on the order of the inputs.
Two versions of one source path are both kept, diagnosed with `COV3004`, and
make the evidence incomplete.

## Limits

- The engine works on bytes in memory. Size-limited reading of files belongs
  to the `merge` command.
- When two maps conflict, both are rejected; the engine does not guess which
  one is right.
