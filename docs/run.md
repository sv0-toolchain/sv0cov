<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The run command

```text
sv0cov run [options] -- <test-command> [args...]
```

`run` is the whole lifecycle: it builds the project in the working directory
with coverage instrumentation, runs a test command against it, merges what
the run left, publishes the reports, and checks the policy.

```sh
cd myproject
sv0cov run -- myproject --self-test      # the instrumented program itself
sv0cov run -- ./tests/run-all.sh         # or a script that calls `myproject`
sv0cov run --threshold-line 85 --report term --report json -- myproject
```

## What happens

1. **Checks that create nothing.** The project name is the working
   directory's name and must be a plain file name (letters, digits, `.`,
   `_`, `-`). The test command must be findable. The toolchain driver must
   exist.
2. **Run ID.** `--run-id <32 lowercase hex>` if given. Otherwise 16 bytes
   from the operating system's secure random source. There is no fallback:
   an entropy failure or an all-zero value aborts (`COV2002`). A
   `SV0COV_RUN_ID` in the caller's environment never selects it.
3. **Reservation.** `<output_dir>/runs/<run_id>` is created exclusively with
   mode `0700`, reached from the project root without following a symlink. A
   run directory that already exists is a collision (`COV4010`), also for an
   explicit run ID.
4. **Build.** Through the toolchain checkout this sv0cov is a submodule of:

   ```text
   <root>/scripts/sv0 native-compile --coverage=instrument
       --coverage-map <run>/maps/<name>.sv0covmap.json
       -o <run>/bin/<name> --project .
   ```

   The driver is found from sv0cov's own location, never through `PATH` or
   a variable. Its output goes to `<run>/build.log`, not to sv0cov's
   streams. The build must leave an executable and a coverage map this
   sv0cov accepts. The resolved raw-profile tier is passed on.
5. **Execution.** The test command runs as the exact argv vector after
   `--`. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to sv0cov meanwhile are
   passed on to it.
6. **Collection and merge.** Whatever happened to the command, the maps and
   every profile in the run directory are merged for exactly this run ID,
   with the command's result as the execution record.
7. **Publication.** Complete evidence becomes
   `<run>/coverage.sv0covdata.json`. The selected nonterminal reports become
   the bundle `<run>/reports`. A selected terminal report goes to stdout
   unless `--quiet`.
8. **Check.** Every assertion that did not pass is a diagnostic on stderr,
   as in [`check`](check.md).

## The run directory

```text
<output_dir>/runs/<run_id>/
    bin/<name>                    the instrumented program
    maps/<name>.sv0covmap.json    its coverage map
    profiles/                     one raw profile per process image
    build.log                     what the driver printed
    coverage.sv0covdata.json      the merged evidence, when it is complete
    reports/coverage.json         the nonterminal reports, when selected
```

`sv0cov clean` removes it.

## The test command

Everything after `--` is the command: one program and its arguments. It is
never joined into a string and never given to a shell, so spaces, quotes,
globs, `$(...)`, `;`, `|` and newlines reach the program unchanged. Shell
behavior needs a shell you name yourself: `sv0cov run -- sh -c '...'`.

The program is looked up as usual: a name with a `/` is a path relative to
the working directory; a bare name is searched on `PATH`. The run's `bin`
directory is first on the command's `PATH`. That is how the command, or any
script it starts, reaches the instrumented program by its name.

## The environment

The command's environment is the caller's, with:

- every variable whose name begins with `SV0COV_` removed, whatever it is;
- `SV0COV_PROFILE_DIR`, `SV0COV_RUN_ID` and `SV0COV_REQUIRED=1` set from the
  run;
- `SV0COV_CONTEXT` set only when a context is resolved from `--context` or
  `sv0.toml` (an explicitly empty context is set as empty; `--no-context`
  removes a configured one);
- the run's `bin` directory first on `PATH`.

The build gets the caller's environment without any `SV0COV_` variable and
without the transport. The caller's own environment is not changed. No
environment variable configures policy: thresholds, reports, saturation and
limits come only from the command line and `sv0.toml`.

## Reports

`run` takes its formats from `[tool.sv0cov].reports` (default `["term"]`) or
from `--report`, which replaces the configured list. `--format` belongs to
[`report`](report.md). This build produces `term` and `json`; asking for
another format stops the run before anything is created (exit 7).

## Incomplete runs

A run is complete only when every profile in its directory is whole and
belongs to it, and there is at least one. Otherwise each problem is
reported (a profile cut short, a runtime's uncommitted temporary, a profile
of another run, no profile at all), nothing is published, and no report is
made. An interrupted run is never shown as zero coverage.

## A failing test command

The run is still merged, reported and checked. The integrity evaluation
fails with `COV2130` (test command failed), the report records the exit
status or signal, and the coverage thresholds are evaluated and shown
beside it. A run whose test command failed can never be passing evidence.

## Exit status

| Test command | sv0cov's own result | Exit |
|---|---|---:|
| passed | everything passed | 0 |
| passed | the policy did not pass | 1 |
| passed | the evidence is incomplete, or a source changed since the build | 5 |
| passed | the reports could not be published | 6 |
| exited nonzero | anything | 4 |
| ended by signal N | anything | 128 + N |

`--prefer-coverage-exit` changes the last two rows to 1 when the coverage
policy itself also failed (a threshold, an empty metric, saturation). It
never turns a failing test command into success.

Before the test command runs:

| Exit | Meaning |
|---:|---|
| 2 | Invalid usage or configuration, a project name that cannot name a program, or a test command that cannot be found or started. |
| 3 | The build failed, or left no executable or no valid coverage map (`COV1020`). |
| 5 | The run directory exists (`COV4010`) or cannot be created safely (`COV6002`). |
| 7 | No toolchain checkout beside this sv0cov, or a report format this build lacks. |
| 8 | No secure random bytes for a run ID. |

## Not in this build

- The VM backend. `run` builds the generated-C executable only.
- The `html`, `lcov` and `cobertura` formats.
