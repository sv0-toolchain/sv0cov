<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Command line

```text
sv0cov run     [options] -- <test-command> [args...]
sv0cov merge   [options] <raw-or-directory>...
sv0cov report  [options] <indexed-profile>
sv0cov check   [options] <indexed-profile-or-native-report>
sv0cov clean   [options]
sv0cov doctor  [options]
sv0cov version [--json]
```

This page describes the framework every command shares (SPEC §18.2.3,
§20.1 to §20.3, §20.5.2). Today `version`, [`merge`](merge.md),
[`report`](report.md), [`check`](check.md) and [`clean`](clean.md) are
implemented; the other commands are checked for correct usage and then
report that this build does not provide them yet.

## Arguments

- The command comes first and is one of the seven exact names. There are no
  aliases, abbreviations, short options, or options before the command.
- A valued option is written `--name value` or `--name=value`. A flag takes
  no value.
- `--` ends the options. For `run`, everything after it is the test command,
  passed on as separate arguments and never joined into a shell string. For
  other commands, what follows are operands, so an operand may begin with
  `-`.
- `--` is never taken as an option's value. Write `--context=--` if you mean
  it.
- Operand counts are exact: `merge` needs at least one, `report` and `check`
  exactly one, `run` none before `--`, the rest none.

Which options a command accepts, which may repeat, and which conflict is the
option table in [Configuration](configuration.md).

## Order of checks

1. The diagnostic format and color mode are read from the arguments first,
   so even a usage error is rendered as asked.
2. The arguments are split.
3. `run`, `merge`, `report`, `check` and `clean` read `sv0.toml` from the
   working directory. `version` and `doctor` do not.
4. Options and file are resolved.
5. The command runs.

Steps 2 to 4 fail with exit 2 before any artifact is touched. A usage error
is reported even when the file is also broken.

## Exit codes

| Code | Meaning |
|---:|---|
| 0 | Command and coverage policy passed. |
| 1 | Coverage policy failed. |
| 2 | Usage or configuration error. |
| 3 | Build or instrumentation failure. |
| 4 | The test command failed. |
| 5 | Profile, map, merge, indexed-output or source-integrity failure. |
| 6 | Report generation or publication failure. |
| 7 | Unsupported capability or version. A valid invocation of a command this build does not implement yet ends here, with `COV5001`. |
| 8 | Internal failure. The diagnostic names only the exception type. |

## Output

- **Diagnostics** go to stderr. `--diagnostic-format human` (the default)
  writes escaped text; `--diagnostic-format json-lines` writes one canonical
  `sv0cov.diagnostic` 1.0 object per line and nothing else. Diagnostics are
  ordered by phase, then code, and each is written once.
- **`--quiet`** suppresses incidental human output on stdout. It never
  suppresses diagnostics or a format explicitly sent to stdout.
- **`--color auto|always|never`** affects only human text. `auto` colors when
  the stream is a terminal. JSON Lines never contain terminal sequences, and
  text taken from input is always escaped. No environment variable is
  consulted.

When the last `--diagnostic-format` or `--color` before `--` has an invalid
value, the usage error about it is rendered in the default (`human`, `auto`).

## For implementers

A command is a function registered with `sv0cov.cli.command(name)`. It
receives a `Context` (the split invocation, the resolved configuration, the
console, the working directory) and returns its exit code. It reports
problems with `console.report(Diagnostic(...))`, prints summaries with
`console.say(...)`, and writes a requested stdout artifact with
`console.write_artifact(bytes)`.
