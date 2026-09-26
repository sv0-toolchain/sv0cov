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

Capture (needs a case-sensitive filesystem; on macOS a case-sensitive APFS
sparse image works):

    tools/gitignore_oracle.py --git <git-2.55.0>/git --workdir <case-sensitive dir> --write

Replay the capture and require identical bytes by omitting `--write`.
Without `--git`, the tool checks that `corpus.json` was captured from the
current cases and Git pin.
