<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# The run command

```text
sv0cov run [options] -- <test-command> [args...]
```

`run` builds the project in the working directory with coverage
instrumentation and runs a test command against it. This page describes the
first half of the lifecycle, which is what this build implements: reserve,
build, execute. Collecting, merging, reporting and checking the run are the
second half and arrive with CV-234.

```sh
cd myproject
sv0cov run -- myproject --self-test      # the instrumented program itself
sv0cov run -- ./tests/run-all.sh         # or a script that calls `myproject`
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
   `--`.

## The run directory

```text
<output_dir>/runs/<run_id>/
    bin/<name>                    the instrumented program
    maps/<name>.sv0covmap.json    its coverage map
    profiles/                     one raw profile per process image
    build.log                     what the driver printed
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

## Exit status

| Exit | Meaning |
|---:|---|
| 2 | Invalid usage or configuration, a project name that cannot name a program, or a test command that cannot be found or started. |
| 3 | The build failed, or left no executable or no valid coverage map (`COV1020`). |
| 4 | The test command exited nonzero or was ended by a signal. |
| 5 | The run directory exists (`COV4010`) or cannot be created safely (`COV6002`). |
| 7 | No toolchain checkout beside this sv0cov; or, for now, a run whose test command passed (see below). |
| 8 | No secure random bytes for a run ID. |

**Until the second half exists**, a run whose test command passed ends with
`COV5001` and exit 7 rather than 0: nothing has been merged or checked, so
the run has not passed. The evidence is complete and usable:

```sh
sv0cov merge .sv0cov/runs/<id>/maps .sv0cov/runs/<id>/profiles --expect-run <id>
sv0cov check .sv0cov/coverage.sv0covdata.json
```

## Not in this build

- The VM backend. `run` builds the generated-C executable only.
- Signal forwarding to the test command, and the host's conventional exit
  status for a signalled command.
- Merge, reports, policy and the combined exit status.
