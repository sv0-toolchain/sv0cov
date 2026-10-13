<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The clean command

```text
sv0cov clean [options]
```

`clean` removes the output directory, `[tool.sv0cov].output_dir` (default
`.sv0cov`, or `--output-dir`), below the working directory. It removes it
only when everything inside is something sv0cov puts there (SPEC 18.4).
Destinations named with `--output` outside that directory are never
touched.

## What is recognized

| Where | What |
|---|---|
| The output directory | `coverage.sv0covdata.json`, `reports/`, `runs/` |
| `reports/` | `coverage.txt`, `coverage.html`, `coverage.json`, `lcov.info`, `cobertura.xml`; the export companions `lcov.manifest.json`, `cobertura.manifest.json`, `lcov.info.sv0cov.json`, `lcov.info.manifest.json`, `cobertura.xml.sv0cov.json`, `cobertura.xml.manifest.json`; the directories `lcov-stdout-support/` and `cobertura-stdout-support/` with their two files |
| `runs/` | Directories named by a run ID: 32 lowercase hexadecimal characters |
| Below a run directory | Regular files and directories, at most 32 levels deep |
| At any of the levels above | A leftover publication temporary: `.sv0cov-tmp-` and 32 hexadecimal characters, file or directory |

A known name of the wrong type (a file called `reports`) is not recognized.

## How it removes

1. The output directory is reached from the project root one component at a
   time, never through a symlink. The configuration cannot name the project
   root, a parent, or an absolute path (exit 2).
2. The whole tree is examined. A symlink anywhere, a special file, an
   unrecognized entry, a mount point, or a tree deeper than the bound is a
   refusal. Up to 20 refusals are reported (`COV6002`), then a count of the
   rest.
3. If anything was refused, nothing is removed and the command exits 5.
4. Otherwise the examined entries are removed bottom up, through open
   directory descriptors that do not follow symlinks. Something that
   appears, disappears or changes type meanwhile stops the removal with
   `COV6002` and exit 5; what was not examined is never deleted.

A missing output directory is not an error: the command says so and exits
0. `--quiet` removes the one line of summary.
