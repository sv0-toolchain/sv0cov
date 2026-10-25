# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``run`` command (CV-233, CV-234; SPEC 14.3, 17, 20.1 to 20.4, 23.3;
COV-CLI-001, COV-CLI-003, COV-CLI-004, COV-INS-008, COV-SEC-006, AC-018,
AC-022, AC-098)::

    sv0cov run [options] -- <test-command> [args...]

What happens, in order:

1. **Checks that cost nothing.** The project name (the working directory's
   name) must be a plain file name; the test command must be findable; the
   selected report formats must be ones this build produces; the toolchain
   driver must exist. Nothing is created before these pass.
   With a diff policy the changed-region base is resolved here too
   (SPEC 22.3): no base, an unresolvable or an ambiguous one stops the run
   with 2 before anything is built.
2. **Run ID.** ``--run-id`` if given, else 16 bytes from the operating
   system's secure source as 32 lowercase hex. An all-zero value or an
   entropy failure aborts. Nothing in the caller's environment selects it.
3. **Reservation.** ``<output_dir>/runs/<run_id>`` is created, exclusively,
   with mode ``0700``, with ``bin/``, ``maps/`` and ``profiles/`` inside. A
   run directory that already exists is a collision, also for an explicit
   run ID.
4. **Capture and build.** With a diff policy, every ``.sv0`` file Git
   tracks below the project is captured first: its state, digest and
   changed lines against the base (:func:`sv0cov.gitdiff.snapshot`). Then
   the project in the working directory is built for the
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
   SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to sv0cov meanwhile are passed
   on to the command.
6. **Collection and merge.** Whatever the command's fate, the maps and every
   profile in the run directory are merged for exactly this run ID, with the
   command's result as the execution record. A profile that is cut short,
   a runtime's uncommitted temporary, a profile of another run, or no
   profile at all makes the evidence incomplete: each is reported, nothing
   is published, and no report is made, because a missing profile is never
   zero coverage.
7. **Publication.** Complete evidence becomes
   ``<run>/coverage.sv0covdata.json``. The selected nonterminal reports
   become the bundle ``<run>/reports``; LCOV and Cobertura add the shared
   ``coverage.json`` and their export manifests (CV-403), and a saturated
   count refuses them (``COV4020``, 6). A selected terminal report goes to
   stdout unless ``--quiet``. With a diff policy, a compiled user source
   that is untracked or ignored (``COV4304``), or whose bytes differ from
   the capture at any point up to publication (``COV4305``), stops it: no
   report is made or published.
8. **Check.** Every assertion that did not pass is a diagnostic, as in
   ``check``. A failed or signalled command fails the integrity evaluation
   with ``COV2130`` and the coverage policy is still evaluated and reported
   beside it.

**Exit status** (SPEC 20.3). With a test command that passed: 0, or 1 when
the policy did not pass, 5 when the evidence is incomplete or a source
changed, 6 when the reports could not be published. With a test command
that failed: 4, or 128 plus the number of the signal that ended it, whatever
else went wrong; ``--prefer-coverage-exit`` gives 1 instead when the
coverage policy itself also failed. Before the command runs: 2 usage
(including a test command that cannot be found), 3 the build failed, 5 the
run directory exists, 7 no toolchain driver or an unimplemented report
format, 8 no entropy.
"""

from __future__ import annotations

import os
import re
import shutil
import signal
import stat
import subprocess
from pathlib import Path
from typing import Callable, Mapping

from sv0cov import cli, evidence, exports, gitdiff
from sv0cov.cmd_check import coverage_failed, evaluation_diagnostics, exit_status
from sv0cov.cmd_merge import INDEXED_NAME, collect
from sv0cov.cmd_report import FILENAMES, IMPLEMENTED, REPORTS_DIR
from sv0cov.diagnostics import Diagnostic
from sv0cov.evidence import report_of
from sv0cov.exports import STANDARD
from sv0cov.formats import runset
from sv0cov.formats.html import check_html, render_html
from sv0cov.formats.map import MapError, map_limits, validate_map
from sv0cov.formats.runset import RunIdError, parse_run_id
from sv0cov.formats.terminal import render_terminal
from sv0cov.model.indexed import read_indexed
from sv0cov.model.merge import MergeError, merge, select_runs
from sv0cov.model.report import read_report
from sv0cov.publish import DIR_MODE, PublishError, _open_parent, publish_bundle, publish_file

RESERVED_PREFIX = "SV0COV_"
TRANSPORT = ("SV0COV_PROFILE_DIR", "SV0COV_RUN_ID", "SV0COV_CONTEXT", "SV0COV_REQUIRED")
RUNS_DIR = "runs"
SUBDIRS = ("bin", "maps", "profiles")
BUILD_LOG = "build.log"
MAP_SUFFIX = ".sv0covmap.json"
RE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
#: Signals passed on to the running test command.
FORWARDED = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGQUIT)


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
    # Project-relative spellings: the driver runs in the project and echoes what it is given into
    # build.log, which is published with the run, so no absolute host path may reach it (CV-424).
    rel_exe, rel_map = os.path.relpath(exe, cwd), os.path.relpath(cmap, cwd)
    argv = [str(driver), "native-compile", "--coverage=instrument", "--coverage-map", rel_map]
    if tier.name != "standard":
        argv.append(f"--coverage-tier={tier.name}")
    if tier.name == "custom":
        argv += ["--coverage-max-counters", str(tier.max_counters), "--coverage-max-bytes", str(tier.max_bytes)]
    argv += ["-o", rel_exe, "--project", "."]
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
    result is its exit status, or the negated signal number.

    While it runs, the termination signals sent to sv0cov are passed on to
    it, so that ending sv0cov ends the command and sv0cov still gets to say
    what the run left (SPEC 23.3)."""
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

    def forward(number: int, _frame: object) -> None:
        try:
            child.send_signal(number)
        except OSError:
            pass  # it has already ended

    previous = {}
    for number in FORWARDED:
        try:
            previous[number] = signal.signal(number, forward)
        except (ValueError, OSError):
            pass  # not the main thread: nothing can be forwarded from here
    try:
        if captured:
            got_out, got_err = child.communicate()
            console.stdout.write(got_out.decode("utf-8", "replace"))
            console.stderr.write(got_err.decode("utf-8", "replace"))
        else:
            child.wait()
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)
    return child.returncode


def execution_record(status: int) -> dict:
    """The indexed ``execution`` record of a wait status (SPEC 16.5)."""
    if status == 0:
        return {"exit_code": 0, "signal": None, "status": "passed"}
    if status < 0:
        return {"exit_code": None, "signal": -status, "status": "signaled"}
    return {"exit_code": status, "signal": None, "status": "failed"}


def final_status(status: int, stage: int, coverage_failed: bool, prefer_coverage: bool) -> int:
    """The combined exit status (SPEC 20.3).

    ``stage`` is what sv0cov's own work came to: 0, 1 (policy), 5 (evidence)
    or 6 (reports). A test command that passed leaves that as the result. A
    test command that failed is 4, or 128 plus the signal that ended it,
    whatever else failed; except that ``--prefer-coverage-exit`` gives 1
    when the coverage policy itself also failed."""
    if status == 0:
        return stage
    if prefer_coverage and coverage_failed:
        return cli.EXIT_POLICY
    return 128 - status if status < 0 else cli.EXIT_TEST


def finish(ctx: cli.Context, run_dir: Path, shown: str, run_id: str, status: int,
           snap: gitdiff.Capture | None = None) -> tuple[int, bool]:
    """Collect, merge, report and check what the run left. Returns sv0cov's
    own stage status and whether the coverage policy failed. ``snap`` is the
    changed-region snapshot taken before the build."""
    console, config = ctx.console, ctx.config
    tier = config.tier()
    formats = [f for f in FILENAMES if f in config.value("reports")]
    maps, profiles = collect((f"{shown}/maps", f"{shown}/profiles"), ctx.cwd, tier)
    try:
        result = merge(maps, profiles, run_selection=select_runs([run_id]), tier=tier, execution=execution_record(status),
                       saturation_policy=config.value("integrity.saturation"))
    except MergeError as exc:
        raise _Stop(cli.EXIT_EVIDENCE, exc.code, "merge", detail=exc.detail) from None
    for f in result.findings:
        facts = [("detail", cli.fact_text(f.detail)), ("input_kind", f.kind)]
        if f.name is not None:
            facts.append(("name", cli.fact_text(f.name)))
        console.report(Diagnostic(f.code, "merge", facts=tuple(facts)))
    inputs = result.indexed["profile_inputs"]
    accepted = sum(1 for r in inputs if r["status"] == "accepted")
    if not result.publishable:
        # Incomplete evidence is never turned into a report: a missing or cut profile is not zero coverage.
        console.say(f"run {run_id}: the evidence is incomplete ({accepted} of {len(inputs)} profiles accepted) and was not reported")
        return cli.EXIT_EVIDENCE, False
    try:
        publish_file(f"{shown}/{INDEXED_NAME}", result.data, anchor=str(ctx.cwd), validate=lambda data: read_indexed(data, tier=tier.name))
    except PublishError as exc:
        raise _Stop(cli.EXIT_EVIDENCE, exc.code, "publication", artifact="indexed-profile", detail=exc.detail) from None
    try:
        sources: dict[str, bytes | None] = {}
        report, encoded = report_of(ctx, result.data, standard_export=any(f in STANDARD for f in formats), sources_out=sources,
                                    capture=snap)
        if snap is not None:
            # The last look before publication: the bytes are still the captured, compiled ones (SPEC 22.3).
            stale = gitdiff.stale_paths(snap.restrict([s["path"] for s in report["sources"] if s["ownership"] == "user"]), ctx.cwd)
            if stale:
                raise evidence.Stop(gitdiff.STALE, "policy", f"source {stale[0]} changed during the coverage run; "
                                                            "no changed-region result is published", cli.EXIT_EVIDENCE)
    except evidence.Stop as stop:
        console.report(stop.diagnostic)
        return stop.status, False
    files = {FILENAMES[f]: (render_html(report, sources) if f == "html" else encoded) for f in formats if f not in ("term", *STANDARD)}
    checks = {FILENAMES["json"]: lambda data: read_report(data, tier=tier.name), FILENAMES["html"]: check_html}
    try:
        extra, export_checks = exports.bundle(formats, report, encoded, timestamp=config.value("reproducible_epoch"), tier=tier.name)
    except exports.ExportStop as stop:
        console.report(stop.diagnostic)
        return stop.status, coverage_failed(report)
    files.update(extra)
    checks.update(export_checks)
    if files:
        try:
            publish_bundle(f"{shown}/{REPORTS_DIR}", files, anchor=str(ctx.cwd), validate={name: checks[name] for name in files})
        except PublishError as exc:
            console.report(Diagnostic(exc.code, "publication", facts=(("artifact", "report"), ("detail", cli.fact_text(exc.detail)))))
            return cli.EXIT_REPORT, coverage_failed(report)
    for diagnostic in evaluation_diagnostics(report):
        console.report(diagnostic)
    if "term" in formats:
        console.say(render_terminal(report, color=console.colored(console.stdout)).rstrip("\n"))
    console.say(f"run {run_id}: merged {accepted} of {len(inputs)} profiles; evidence and reports are in {shown}")
    return exit_status(report), coverage_failed(report)


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
        missing = [f for f in config.value("reports") if f not in IMPLEMENTED]
        if missing:
            raise _Stop(cli.EXIT_UNSUPPORTED, "COV5001", "invocation", format=missing[0],
                        detail="this build of sv0cov does not produce this report format yet")
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
        try:
            base = evidence.diff_base(ctx)
            snap = None if base is None else gitdiff.snapshot(base, gitdiff.tracked_sources(base))
        except gitdiff.GitDiffError as exc:
            raise evidence.git_stop(exc) from None
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
    except (_Stop, evidence.Stop) as stop:
        console.report(stop.diagnostic)
        return stop.status
    if status != 0:
        how = f"was ended by signal {-status}" if status < 0 else f"exited with status {status}"
        console.say(f"run {run_id}: the test command {how}")
    try:
        stage, failed = finish(ctx, run_dir, shown, run_id, status, snap)
    except _Stop as stop:
        console.report(stop.diagnostic)
        stage, failed = stop.status, False
    return final_status(status, stage, failed, bool(config.controls.get("--prefer-coverage-exit")))
