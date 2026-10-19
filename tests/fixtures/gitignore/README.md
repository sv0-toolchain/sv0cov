<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->
# Gitignore scope-pattern oracle corpus (CV-030)

`cases.py` defines one virtual tree of logical source paths and ordered
root-level pattern files covering SPEC 18.3 and AC-100: comments, escaped
prefixes, trailing spaces, slash anchoring, directory-only patterns,
wildcards, bracket expressions, negation, parent pruning, every documented
`**` form and other consecutive asterisks, a terminal backslash, case, and
exact-byte Unicode.

`corpus.json` is the frozen oracle: for each case, the paths Git 2.55.0
`check-ignore --no-index` classifies as ignored (selected) and the line of
the last matching pattern. It is produced only by `tools/gitignore_oracle.py`
with a Git 2.55.0 built from the checksum-pinned source release, fully
isolated from system, global, repository, and `info/exclude` ignore sources.
The production matcher (CV-310) must reproduce it without running Git.

The reference capture (2026-09-25) used Homebrew's `git` 2.55.0, built from
the kernel.org `git-2.55.0.tar.xz` whose SHA-256 is pinned in the tool
(`457fdb04…7505357`); the executable's digest is recorded in `corpus.json`.

Capture (needs a case-sensitive filesystem; on macOS a case-sensitive APFS
sparse image works):

    tools/gitignore_oracle.py --git <git-2.55.0>/git --workdir <case-sensitive dir> --write

Replay the capture and require identical bytes by omitting `--write`.
Without `--git`, the tool checks that `corpus.json` was captured from the
current cases and Git pin.

## The matcher corpus (CV-310)

`matcher-corpus.json` is a second, wider oracle for the production matcher
`sv0cov.gitignore`: 351 groups (6,479 file paths) of patterns and paths, each
group its own virtual tree, covering every form of SPEC 18.3 plus large
groups. `build.py --write` captures it from Git 2.55.0 `check-ignore
--no-index` (it refuses any other version) with the same isolation; `build.py`
alone checks the file and its `cases_sha256`, and re-captures and compares
when Git 2.55.0 is on `PATH`. `tests/test_gitignore.py` requires the matcher
to reproduce it, and `tests/test_gitignore_corpus.py` requires it to reproduce
`corpus.json` above, deciding lines included.
