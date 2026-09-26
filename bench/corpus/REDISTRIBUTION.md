<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->
# Benchmark corpus redistribution review (COV-LIC-011)

Reviewed 2026-09-25 for corpus version 1.0.

| Snapshot | Origin | Revision | License | Decision |
|---|---|---|---|---|
| `real/sv0c-behavior` | `sv0-toolchain/sv0c` (`test/behavior/cases`) | `d1a51004aa5c77d0de426e49136866ade54efcd9` | MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE` in the origin) | Redistributable: same copyright holder and license as sv0cov; copied unmodified |
| `real/sv0-mathlib-v0.2.0` | `sv0-toolchain/sv0-mathlib` (`lib/`, `test/property/`) | `6710b9d96d7e4a921f7cae92b10b5eaa4777d919` (tag `v0.2.0`) | MIT OR Apache-2.0 | Redistributable: same copyright holder and license; copied unmodified |

- Files are copied byte for byte from `git show <revision>:<path>` by
  `bench/corpus.py refresh-snapshots`; their SHA-256 digests are recorded in
  `manifest.json` and checked by `bench/corpus.py check`.
- The copies carry no SPDX header of their own (they are unmodified), so
  `REUSE.toml` annotates `bench/corpus/real/**` with the origin's license.
- Generated fixtures are produced by `bench/corpus.py` (MIT OR Apache-2.0)
  and are not checked in.
- No private or proprietary source is part of the corpus.
