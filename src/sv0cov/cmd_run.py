# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``run`` command, first half (CV-233; SPEC 14.3, 20.1, 20.2.2, 20.4,
23.3; COV-CLI-001, COV-CLI-003, COV-SEC-006, AC-018, AC-098)::

    sv0cov run [options] -- <test-command> [args...]

What happens, in order:

1. **Checks that cost nothing.** The project name (the working directory's
   name) must be a plain file name; the test command must be findable; the
   toolchain driver must exist. Nothing is created before these pass.
2. **Run ID.** ``--run-id`` if given, else 16 bytes from the operating
   system's secure source as 32 lowercase hex. An all-zero value or an
   entropy failure aborts. Nothing in the caller's environment selects it.
3. **Reservation.** ``<output_dir>/runs/<run_id>`` is created, exclusively,
   with mode ``0700``, with ``bin/``, ``maps/`` and ``profiles/`` inside. A
   run directory that already exists is a collision, also for an explicit
   run ID.
4. **Build.** The project in the working directory is built for the
   generated-C backend with coverage instrumentation, through the toolchain
   driver this checkout belongs to::

       <root>/scripts/sv0 native-compile --coverage=instrument
           --coverage-map <run>/maps/<name>.sv0covmap.json
           -o <run>/bin/<name> --project .

   The driver's output goes to ``<run>/build.log``. The build must leave an
   executable and a valid coverage map.
5. **Execution.** The test command is started as the argv vector it was
   given: no shell, no joining, no splitting, no expansion. Its environment
   is the caller's with every ``SV0COV_*`` variable removed, then
   ``SV0COV_PROFILE_DIR``, ``SV0COV_RUN_ID``, ``SV0COV_REQUIRED=1`` and,
   when a context is resolved, ``SV0COV_CONTEXT``; and ``<run>/bin`` first
   on ``PATH``, which is how the command (or a script it runs) reaches the
   instrumented program by name. The caller's own environment is not
   changed. The build gets the same environment without the transport.

Collecting, merging, reporting and checking the run are the second half
(CV-234). Until then a run whose test command succeeded ends with
``COV5001`` and exit 7, after saying where the evidence is; ``sv0cov merge``
can take it from there.

**Exit status.** 2 usage (including a test command that cannot be found); 3
the build failed or left no valid map; 4 the test command failed; 5 the run
directory exists or cannot be created safely; 7 no toolchain driver, or the
unimplemented second half; 8 no entropy.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path
from typing import Callable, Mapping

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.map import MapError, map_limits, validate_map
from sv0cov.formats import runset
from sv0cov.formats.runset import RunIdError, parse_run_id
from sv0cov.publish import DIR_MODE, PublishError, _open_parent

RESERVED_PREFIX = "SV0COV_"
TRANSPORT = ("SV0COV_PROFILE_DIR", "SV0COV_RUN_ID", "SV0COV_CONTEXT", "SV0COV_REQUIRED")
RUNS_DIR = "runs"
SUBDIRS = ("bin", "maps", "profiles")
BUILD_LOG = "build.log"
MAP_SUFFIX = ".sv0covmap.json"
RE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
LOG_BYTES = 1 << 20


class _Stop(Exception):
    def __init__(self, status: int, code: str, phase: str, **facts: str) -> None:
        super().__init__(code)
        self.status = status
        self.diagnostic = Diagnostic(code, phase, facts=tuple((k, cli.fact_text(v)) for k, v in sorted(facts.items())))


def new_run_id(entropy: Callable[[int], bytes] | None = None) -> str:
    """Sixteen bytes from the secure source, as a run ID (SPEC 14.3). There
    is no fallback: a failure or an all-zero value raises."""
    try:
        return runset.new_run_id(entropy or os.urandom)
    except (OSError, NotImplementedError, RunIdError):
        raise _Stop(cli.EXIT_INTERNAL, "COV2002", "execution",
                    detail="the operating system gave no usable secure random bytes for a run ID") from None


def child_environment(base: Mapping[str, str], *, profile_dir: str, run_id: str, context: str | None,
                      bin_dir: str | None = None) -> dict[str, str]:
    """The environment of the launched command (SPEC 14.3; COV-SEC-006):
    ``base`` without any reserved variable, then exactly the transport that
    applies. ``base`` itself is not changed."""
    env = {k: v for k, v in base.items() if not k.upper().startswith(RESERVED_PREFIX)}
    env["SV0COV_PROFILE_DIR"] = profile_dir
    env["SV0COV_RUN_ID"] = run_id
    env["SV0COV_REQUIRED"] = "1"
    if context is not None:
        env["SV0COV_CONTEXT"] = context
    if bin_dir is not None:
        env["PATH"] = bin_dir + (os.pathsep + env["PATH"] if env.get("PATH") else "")
    return env


def build_environment(base: Mapping[str, str]) -> dict[str, str]:
    """The environment of the build: the caller's without any reserved variable."""
    return {k: v for k, v in base.items() if not k.upper().startswith(RESERVED_PREFIX)}


def toolchain_driver() -> Path | None:
    """``scripts/sv0`` of the toolchain checkout this sv0cov is a submodule
    of, or ``None``. It is found from this file's own location, never
    through ``PATH`` or the environment."""
    root = Path(__file__).resolve().parents[3]
    driver = root / "scripts" / "sv0"
    try:
        st = os.lstat(driver)
    except OSError:
        return None
    return driver if stat.S_ISREG(st.st_mode) and os.access(driver, os.X_OK) else None


def project_name(cwd: Path) -> str:
    name = cwd.resolve().name
    if not RE_NAME.match(name):
        raise _Stop(cli.EXIT_USAGE, "COV0001", "invocation", subject="run",
                    detail="the project directory's name must be a plain file name (letters, digits, '.', '_', '-') to name the program")
    return name


def find_command(program: str, cwd: Path, path: str | None) -> str | None:
    """The file ``program`` names: as given when it has a directory part
    (relative to ``cwd``), otherwise the first match on ``path``."""
    if "/" in program:
        full = program if os.path.isabs(program) else str(cwd / program)
        return full if os.path.isfile(full) and os.access(full, os.X_OK) else None
    return shutil.which(program, path=path or "")


def reserve(cwd: Path, output_dir: str, run_id: str) -> Path:
    """Create ``<output_dir>/runs/<run_id>`` and its subdirectories, or raise."""
    relative = f"{output_dir}/{RUNS_DIR}/{run_id}"
    try:
        parent, name = _open_parent(relative, str(cwd))
    except PublishError as exc:
        raise _Stop(cli.EXIT_EVIDENCE, exc.code, "publication", artifact="run-directory", detail=exc.detail) from None
    try:
        try:
            os.mkdir(name, DIR_MODE, dir_fd=parent)
        except FileExistsError:
            raise _Stop(cli.EXIT_EVIDENCE, "COV4010", "publication", artifact="run-directory",
                        detail=f"the run directory {relative} already exists") from None
        except OSError as exc:
            raise _Stop(cli.EXIT_EVIDENCE, "COV4011", "publication", artifact="run-directory",
                        detail=f"the run directory cannot be created ({os.strerror(exc.errno)})") from None
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        try:
            for sub in SUBDIRS:
                os.mkdir(sub, DIR_MODE, dir_fd=fd)
        finally:
            os.close(fd)
    finally:
        os.close(parent)
    return cwd / relative


def build(driver: Path, cwd: Path, run_dir: Path, name: str, tier, env: Mapping[str, str]) -> tuple[Path, Path]:
    """Build the project in ``cwd`` with instrumentation; the executable and its map."""
    exe, cmap = run_dir / "bin" / name, run_dir / "maps" / (name + MAP_SUFFIX)
    argv = [str(driver), "native-compile", "--coverage=instrument", "--coverage-map", str(cmap)]
    if tier.name != "standard":
        argv.append(f"--coverage-tier={tier.name}")
    if tier.name == "custom":
        argv += ["--coverage-max-counters", str(tier.max_counters), "--coverage-max-bytes", str(tier.max_bytes)]
    argv += ["-o", str(exe), "--project", "."]
    log = run_dir / BUILD_LOG
    fd = os.open(log, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        try:
            done = subprocess.run(argv, cwd=cwd, env=dict(env), stdin=subprocess.DEVNULL, stdout=fd, stderr=subprocess.STDOUT, check=False)
        except OSError as exc:
            raise _Stop(cli.EXIT_BUILD, "COV1020", "build", detail=f"the toolchain driver could not be started ({type(exc).__name__})") from None
    finally:
        os.close(fd)
    where = f"see {BUILD_LOG} in the run directory"
    if done.returncode != 0:
        raise _Stop(cli.EXIT_BUILD, "COV1020", "build", detail=f"the instrumented build failed with status {done.returncode}; {where}")
    for path, what in ((exe, "executable"), (cmap, "coverage map")):
        try:
            st = os.lstat(path)
        except OSError:
            st = None
        if st is None or not stat.S_ISREG(st.st_mode):
            raise _Stop(cli.EXIT_BUILD, "COV1020", "build", detail=f"the build left no {what}; {where}")
    limits = map_limits(tier.name)
    try:
        if os.path.getsize(cmap) > limits.max_bytes:
            raise MapError("COV6001", "the coverage map is over the tier's size")
        validate_map(cmap.read_bytes(), limits=limits)
    except (MapError, OSError) as exc:
        code = exc.code if isinstance(exc, MapError) else "COV1010"
        raise _Stop(cli.EXIT_BUILD, code, "build", detail="the build left a coverage map this sv0cov does not accept") from None
    if not os.access(exe, os.X_OK):
        raise _Stop(cli.EXIT_BUILD, "COV1020", "build", detail=f"the built program is not executable; {where}")
    return exe, cmap


def _descriptor(stream: object) -> int | None:
    try:
        return stream.fileno()
    except (AttributeError, OSError, ValueError):
        return None


def execute(argv: tuple[str, ...], program: str, cwd: Path, env: Mapping[str, str], console) -> int:
    """Run the test command as the exact argv vector, without a shell. The
    result is its exit status, or the negated signal number."""
    out, err = _descriptor(console.stdout), _descriptor(console.stderr)
    console.stdout.flush()
    console.stderr.flush()
    captured = out is None or err is None  # only a test double has no descriptor
    try:
        child = subprocess.Popen(list(argv), executable=program, cwd=cwd, env=dict(env), shell=False, close_fds=True,
                                 stdout=subprocess.PIPE if captured else out, stderr=subprocess.PIPE if captured else err)
    except OSError as exc:
        raise _Stop(cli.EXIT_USAGE, "COV0001", "invocation", subject="run",
                    detail=f"the test command could not be started ({type(exc).__name__})") from None
    if captured:
        got_out, got_err = child.communicate()
        console.stdout.write(got_out.decode("utf-8", "replace"))
        console.stderr.write(got_err.decode("utf-8", "replace"))
    else:
        child.wait()
    return child.returncode


@cli.command("run")
def cmd_run(ctx: cli.Context) -> int:
    console, config = ctx.console, ctx.config
    argv = ctx.invocation.test_command
    caller = dict(os.environ)
    try:
        name = project_name(ctx.cwd)
        if argv[0] != name and find_command(argv[0], ctx.cwd, caller.get("PATH")) is None:
            raise _Stop(cli.EXIT_USAGE, "COV0001", "invocation", subject="run",
                        detail="the test command was not found or is not executable")
        driver = toolchain_driver()
        if driver is None:
            raise _Stop(cli.EXIT_UNSUPPORTED, "COV5001", "build",
                        detail="sv0cov run needs the sv0 toolchain checkout it is a submodule of; scripts/sv0 was not found beside it")
        explicit = config.controls.get("--run-id")
        if explicit is not None:
            try:
                run_id = parse_run_id(explicit).hex()
            except RunIdError:
                raise _Stop(cli.EXIT_USAGE, "COV0001", "invocation", subject="--run-id", detail="is not a run ID") from None
        else:
            run_id = new_run_id()
        output_dir = config.value("output_dir")
        run_dir = reserve(ctx.cwd, output_dir, run_id)
        shown = f"{output_dir}/{RUNS_DIR}/{run_id}"
        exe, _ = build(driver, ctx.cwd, run_dir, name, config.tier(), build_environment(caller))
        env = child_environment(caller, profile_dir=str(run_dir / "profiles"), run_id=run_id, context=config.value("context"),
                                bin_dir=str(run_dir / "bin"))
        program = str(exe) if argv[0] == name else find_command(argv[0], ctx.cwd, env["PATH"])
        if program is None:
            raise _Stop(cli.EXIT_USAGE, "COV0001", "invocation", subject="run", detail="the test command was not found or is not executable")
        console.say(f"run {run_id}: built {name}; running the test command")
        status = execute(argv, program, ctx.cwd, env, console)
    except _Stop as stop:
        console.report(stop.diagnostic)
        return stop.status
    if status != 0:
        how = f"was ended by signal {-status}" if status < 0 else f"exited with status {status}"
        console.say(f"run {run_id}: the test command {how}; its evidence is in {shown}")
        return cli.EXIT_TEST
    console.say(f"run {run_id}: the test command passed; maps and profiles are in {shown}")
    console.report(Diagnostic("COV5001", "collection", facts=(
        ("command", "run"), ("detail", "this build of sv0cov does not merge, report and check a run yet; use sv0cov merge on its maps and profiles"))))
    return cli.EXIT_UNSUPPORTED
