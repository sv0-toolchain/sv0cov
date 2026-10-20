<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Changed-region coverage

Changed-region coverage (SPEC 22.3) asks how well the lines changed since a
base are covered. `sv0cov.gitdiff` is the Git side of it (CV-311): it finds
the base, records what the program is built from, and says which lines
changed. The changed-region metrics, the report's `changes` record, and the
wiring into `run`, `check` and `report` are CV-312, described at the end.

## The base

The base is always explicit: `--diff-base <ref>` or `[tool.sv0cov.diff].base`.
`merge-base:<ref>` and `<ref>` mean the same, and the spelling is recorded as
given. sv0cov never guesses one. It does not read a tracking branch, a default or
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

## Changed-region checks (CV-312)

### What is changed

From the current-side changed lines of each user source:

| Metric | In the denominator |
|---|---|
| `line` | an executable line (covered, partial or uncovered) that is a changed line |
| `region` | a `user` region whose span (first to last line) meets a changed line |
| `branch` | each eligible outcome of a branch whose span meets a changed line |

Everything else follows the ordinary metrics: excluded, unreachable and
support records never count, a region is covered when it ran, an outcome
when it was taken. A changed comment or blank line is no executable line,
and a deleted line has no current line, so neither enters a denominator
(COV-POL-004). Changed-line and changed-region coverage are separate
metrics.

### The diff assertion

The `diff` assertion has one evaluation for each of `line`, `region` and
`branch`, named `diff`. Its threshold is `[tool.sv0cov.diff].<metric>` (or
`--diff-<metric>`), with `threshold_source` `diff`; a metric with none
reports its fraction and checks nothing. No project threshold is inherited.
A zero denominator follows the `empty` policy, like any assertion. Members:
the sources with a changed line, and the metric's own records.

### The `changes` record

The report keeps the capture as `changes` (null without a diff policy):

- `base`: the spelling as given, the commit it names (`reference`), `head`
  and `merge_base`;
- `clean`, `diff_sha256`, the fixed `diff_options`, and `git` (version and
  executable SHA-256);
- for every user source, by `source_index`: `repo_path`, `state`,
  `old_path` (renames only), `staged`, `unstaged`, `sha256` and
  `changed_lines`.

Each `sha256` must equal the source's digest in the evidence: the capture
describes exactly the compiled bytes. The reader works the diff evaluations
out again from `changes` and the detail records, and rejects a capture that
does not hold each user source once with its compiled digest. The terminal
and HTML reports show the merge base, the spelling, `HEAD`, the number of
changed lines and whether the run is clean; the HTML provenance section
lists every source's state.

### In the commands

The diff policy applies wherever the configuration has one: `run` and
`check` take `--diff-base` and `--diff-<metric>`, and `report` evaluates the
`sv0.toml` table like `check`, so the two never disagree.

- **`run`** resolves the base before it reserves a run directory, so a
  missing, unresolvable or ambiguous base builds nothing. It then snapshots
  every `.sv0` file Git tracks below the project, builds, runs, and keeps
  the compiled user sources of the evidence. A compiled source the snapshot
  does not hold is untracked or ignored (`COV4304`). The snapshot digest
  must equal the digest compiled, the bytes read for the report must equal
  it, and just before the reports are published every source is read once
  more; any difference is `COV4305` and no report is made or published.
- **`check`** and **`report`** capture when they evaluate. The capture is
  bound to the evidence by source digest, so a source changed since it was
  compiled, or deleted, is `COV4305`. `--allow-source-mismatch` does not
  let it through to a changed-region result.

| Code | Exit |
|---|---|
| `COV4301`, `COV4302`, `COV4303` (the base) | 2 |
| `COV4304`, `COV4305` (the sources) | 5 |

None of them produces a changed-region number.

### Tests

`tests/test_changed.py`: the producer against an independent oracle on every
semantic fixture under many changed-line sets, exact threshold boundaries,
no inheritance, the empty policy, the reader rejecting every altered fact,
the terminal and HTML views; `check` and `report` on real repositories
(AC-016 at the root and in a subdirectory, deleted lines, AC-045 with no Git
run, unresolvable and ambiguous bases with every candidate, AC-047 staged
and unstaged sources, AC-048 compiled and unrelated untracked files, AC-049
edited and deleted sources, a shallow clone); and `run` with the stand-in
driver (the capture recorded, no build for a bad base, a source edited by
the test command, a compiled untracked source).
