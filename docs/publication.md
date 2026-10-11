<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Publication

sv0cov never overwrites an output. There is no force or replace option
(SPEC §20.2.3). `sv0cov.publish` is the one place that writes a final
artifact, and every command that produces one goes through it.

## How an artifact is published

1. The destination's parent directory is opened. Every later step works
   relative to that open directory, so swapping an ancestor meanwhile cannot
   redirect the write.
2. The destination is checked to be absent. This only gives an early, clear
   error; correctness does not depend on it.
3. The bytes are written to a temporary in the same directory, named
   `.sv0cov-tmp-` plus 32 random hexadecimal characters, created exclusively
   with mode `0600`.
4. The temporary is synchronized, closed, read back, compared with what was
   meant to be written, and given to the caller's validator.
5. The temporary is committed to the final name by one atomic operation that
   cannot replace anything.
6. The directory is synchronized where the filesystem allows it.

On any failure the temporary is removed and the destination is exactly as it
was.

## Shapes

| Function | Publishes | Mode |
|---|---|---|
| `publish_file(final, data)` | one file | `0600` |
| `publish_bundle(final, files)` | a directory of files, built in a sibling temporary directory and committed by one rename | `0700`, files `0600` |
| `publish_stdout(stream, data)` | bytes to stdout | n/a |

The modes are requested when the file or directory is created. A umask can
remove permissions and never adds any.

Writing to stdout is the stated non-atomic exception. The bytes are complete
and validated before the first write. A short or failed write raises, so the
caller publishes no commit record for it.

## Where a destination may be

- **Explicit** (a path the user named, such as `--output`): the parent
  directory must already exist. No ancestor is created.
- **Managed** (below the project root, such as `.sv0cov/runs/<id>/reports`):
  missing directories are created with mode `0700`. No component below the
  root may be a symlink or a non-directory.

In both cases the final name must not exist in any form: a file, a
directory (empty or not), a symlink, a dangling symlink, or anything else.

## The commit primitive

| Host | Files and directories | Files only, as a fallback |
|---|---|---|
| macOS | `renameatx_np` with `RENAME_EXCL` | `linkat`, then `unlinkat` |
| Linux | `renameat2` with `RENAME_NOREPLACE` (the C library's wrapper, or the raw system call on x86_64 and aarch64 when there is no wrapper) | `linkat`, then `unlinkat` |

- `link` never replaces a name, so it is a sound fallback for a file when the
  rename primitive is missing or the filesystem refuses its flag.
- A directory cannot be hard-linked. When the primitive is unavailable, a
  bundle is not published at all.
- Nothing falls back to a plain `rename`, which replaces, or to copying
  across filesystems. The temporary is always a sibling of the destination,
  so both are on one filesystem.

The native runtime publishes raw profiles with the same primitives
(`runtime/c/sv0cov_rt.c`).

## Failures

`PublishError.reason` is one of:

| Reason | Meaning | Code |
|---|---|---|
| `collision` | the destination exists | `COV4010` |
| `unsafe` | a symlink or non-directory on the way, or a name that is not a single path component | `COV6002` |
| `failed` | anything else: missing parent, write or synchronization error, validation failure, no primitive | `COV4011` |

The command decides the exit code: 5 for the indexed profile, 6 for reports.

## Limits

- Durability is against partial files and process crashes, not power loss
  (SPEC §20.2.3).
- A crash can leave a `.sv0cov-tmp-…` entry behind. It is never a valid
  artifact name.
- Destination routing (default paths, companions, the three-file export
  sequence) belongs to the `merge` and `report` commands.
