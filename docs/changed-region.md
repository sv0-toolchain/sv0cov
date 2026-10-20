<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Changed-region coverage: the Git model

Changed-region coverage (SPEC 22.3) asks how well the lines changed since a
base are covered. `sv0cov.gitdiff` is the Git side of it (CV-311): it finds
the base, records what the program is built from, and says which lines
changed. The changed-region metrics and their wiring into `run`, `report`
and `check` come with CV-312.

## The base

The base is always explicit: `--diff-base <ref>` or `[tool.sv0cov.diff].base`.
sv0cov never guesses one. It does not read a tracking branch, a default or
conventional branch, a parent commit or a CI variable, and it never fetches.

`resolve_base` resolves the reference locally and takes the merge bases of
it and `HEAD`. Exactly one must exist.

| Situation | Code |
|---|---|
| No base given | `COV4301` |
| Not a Git working tree; Git not installed | `COV4302` |
| `HEAD` has no commit yet | `COV4302` |
| The reference does not name a local commit | `COV4302` |
| The repository is shallow (any shallow clone; fetch the full history) | `COV4302` |
| No common ancestor | `COV4302` |
| More than one merge base (every candidate is listed) | `COV4303` |

A shallow clone always fails, because a merge base computed from cut history
can be wrong without any sign. In GitHub Actions use `fetch-depth: 0`.

## The capture

`capture` runs before the program is instrumented and records:

- `HEAD`, the reference's commit, and the merge base;
- for every compiled source, its logical and repository path, whether it is
  unchanged, modified, added or renamed (with the old path), whether it has
  staged and/or unstaged changes, the SHA-256 of its exact bytes on disk,
  and its changed lines;
- a canonical zero-context diff from the merge base to the working tree of
  the compiled sources, and its SHA-256;
- the fixed diff options and the Git implementation (version and executable
  digest).

The current side is the working tree: `HEAD` plus staged and unstaged
changes, exactly the bytes the compiler reads. `clean` is true when no
compiled source has a staged or unstaged change; only then is a result
reproducible from `HEAD` alone. A dirty run is reproducible only with its
diff and source digests.

A compiled source that is untracked, or ignored by Git, has no tracked diff
and stops the evaluation with `COV4304`. A compiled source with a merge
conflict, or one Git diffs as binary, stops it with `COV4302`. Untracked
files that are not compiled play no part.

The changed lines of a source are the current-side lines its hunks add or
modify. Deleted lines have no current line. Renames are detected with the
fixed options below.

## Staleness

`stale_paths` compares every compiled source with its captured digest just
before a report is published. Any difference, including a deleted file,
makes the result stale (`COV4305`): the program was not built from what the
capture describes.

## How Git is run

Git is run so that nothing outside the command can change what it reports:

- every `GIT_*` variable of the caller (`GIT_DIR`, `GIT_WORK_TREE`,
  `GIT_INDEX_FILE`, ...) is dropped, and system and global configuration are
  not read;
- no transfer protocol is allowed and lazy fetching is off, so no command can
  reach the network;
- the output options are given on the command line: `--no-ext-diff
  --no-textconv --no-color --unified=0 --find-renames=50%
  --diff-algorithm=myers --no-relative --src-prefix=a/ --dst-prefix=b/`, with
  quoting, prefixes, color, relative paths and rename settings fixed by `-c`,
  so repository configuration such as an external diff or a textconv driver
  cannot change the diff;
- paths are literal pathspecs, read at the repository's top level.

Repository clean and smudge filters still run when Git reads the working
tree, as they do for every Git command in that repository.
