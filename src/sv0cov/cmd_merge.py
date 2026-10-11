# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``merge`` command (CV-227; SPEC 17, 20.1, 20.2; COV-CLI-002,
COV-CLI-006)::

    sv0cov merge [options] <raw-or-directory>...

It gathers maps and raw profiles from the operands, hands their bytes to the
merge engine (:mod:`sv0cov.model.merge`), and publishes the indexed profile
without replacing anything (:mod:`sv0cov.publish`).

**Operands.** Each operand is resolved from the working directory.

- A directory contributes the regular files directly inside it (it is not
  searched recursively) whose names end in ``.sv0covmap.json`` (maps) or
  ``.sv0profraw`` (raw profiles). A runtime's uncommitted temporary
  (``.<name>.sv0profraw.tmp-…``) is inventoried as an incomplete profile
  and never replayed (SPEC 14.3). An entry with one of those names that is
  not a regular file (a symlink, a directory) is a rejected input. Every
  other entry is ignored.
- A file is a map when its name ends in ``.sv0covmap.json`` and a raw
  profile otherwise. A named file may be a symlink; what it resolves to is
  read. A path that does not exist or cannot be read is a rejected input.

Names are only how inputs are found: what an input is, and which map a
profile belongs to, is decided from its bytes.

**Limits.** A profile over the raw-profile tier, or a map over the map
ceiling of that tier (SPEC 16.3.9), is rejected from its size alone and
never read into memory.

**Destination.** ``--output <path>`` names the file; its parent must exist.
``--output -`` writes only the canonical indexed JSON to stdout. Otherwise
the file is ``<output_dir>/coverage.sv0covdata.json`` below the working
directory. The destination is checked before any input is read.

**Result.**

- Complete evidence: published, exit 0.
- Any rejected input, a failed run selection or a source-version conflict:
  every finding is reported, nothing is published, exit 5.
- The same under ``--allow-rejected-inputs``: the visibly incomplete
  evidence is published for diagnosis and the command exits 0. That
  evidence can never pass a check.
- A destination that exists, or any publication failure: exit 5.
"""

from __future__ import annotations

import errno
import os
import stat
from pathlib import Path

from sv0cov import cli
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.map import map_limits
from sv0cov.formats.rawprofile import Tier
from sv0cov.model.indexed import read_indexed
from sv0cov.model.merge import Artifact, MergeError, merge, select_runs
from sv0cov.publish import PublishError, check_destination, publish_file, publish_stdout

MAP_SUFFIX = ".sv0covmap.json"
PROFILE_SUFFIX = ".sv0profraw"
TEMP_MARK = PROFILE_SUFFIX + ".tmp-"
INDEXED_NAME = "coverage.sv0covdata.json"
MANIFEST_BYTES = 1 << 20


class _Stop(Exception):
    """The command cannot go on; the diagnostic has been reported."""


def _name_ok(name: str) -> bool:
    try:
        size = len(name.encode("utf-8"))
    except UnicodeEncodeError:
        return False
    return 1 <= size <= 255 and not any(c in name for c in "\x00/\\\r\n")


def _read(path: Path, limit: int, *, follow: bool) -> tuple[bytes | None, tuple[str, str] | None]:
    """The bytes of a regular file of at most ``limit`` bytes, or the reason
    it was not read."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | (0 if follow else os.O_NOFOLLOW)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno in (errno.ELOOP, errno.EMLINK):
            return None, ("COV6002", "is a symlink")
        return None, None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None, ("COV6002", "is not a regular file")
        if st.st_size > limit:
            return None, ("COV6001", f"is {st.st_size} bytes; the tier allows {limit}")
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:  # it grew while being read
                return None, ("COV6001", f"is over {limit} bytes")
            chunks.append(chunk)
        return b"".join(chunks), None
    except OSError:
        return None, None
    finally:
        os.close(fd)


def collect(operands: tuple[str, ...], cwd: Path, tier: Tier) -> tuple[list[Artifact], list[Artifact]]:
    """The map and profile artifacts the operands name, in operand order."""
    maps: list[Artifact] = []
    profiles: list[Artifact] = []
    limits = {True: map_limits(tier.name).max_bytes, False: tier.max_bytes}

    def add(path: Path, name: str, *, follow: bool, temporary: bool = False) -> None:
        if not _name_ok(name):
            raise _Stop(Diagnostic("COV6002", "collection", facts=(("detail", "an input name is not a usable artifact basename"),)))
        is_map = name.endswith(MAP_SUFFIX)
        data, fault = _read(path, limits[is_map], follow=follow)
        if temporary:
            fault = ("COV2011", "is an uncommitted temporary profile; its process did not finish publishing")
        (maps if is_map else profiles).append(Artifact(name, data, fault))

    for operand in operands:
        path = cwd / operand
        if path.is_dir():
            try:
                names = sorted(os.listdir(path), key=os.fsencode)
            except OSError:
                raise _Stop(Diagnostic("COV2010", "collection", facts=(("detail", "an input directory cannot be listed"),))) from None
            for name in names:
                if name.startswith(".") and TEMP_MARK in name:
                    add(path / name, name, follow=False, temporary=True)
                elif not name.startswith(".") and name.endswith((MAP_SUFFIX, PROFILE_SUFFIX)):
                    add(path / name, name, follow=False)
        else:
            add(path, path.name or operand, follow=True)
    return maps, profiles


def _selection(ctx: cli.Context):
    controls = ctx.config.controls
    manifest = None
    if "--run-manifest" in controls:
        manifest, fault = _read(ctx.cwd / controls["--run-manifest"], MANIFEST_BYTES, follow=True)
        if manifest is None:
            detail = "the run manifest " + (fault[1] if fault else "cannot be read")
            raise _Stop(Diagnostic("COV3003", "merge", facts=(("detail", detail),)))
    try:
        return select_runs(controls.get("--expect-run"), manifest)
    except MergeError as exc:
        raise _Stop(Diagnostic(exc.code, "merge", facts=(("detail", cli.fact_text(exc.detail)),))) from None


def _publish_failure(exc: PublishError) -> Diagnostic:
    return Diagnostic(exc.code, "publication", facts=(("artifact", "indexed-profile"), ("detail", cli.fact_text(exc.detail))))


@cli.command("merge")
def cmd_merge(ctx: cli.Context) -> int:
    console, config = ctx.console, ctx.config
    output = config.controls.get("--output")
    to_stdout = output == "-"
    if output is None:
        final, anchor = f"{config.value('output_dir')}/{INDEXED_NAME}", str(ctx.cwd)
    else:
        final, anchor = str(ctx.cwd / output), None
    try:
        if not to_stdout:
            try:
                check_destination(final, anchor=anchor)
            except PublishError as exc:
                raise _Stop(_publish_failure(exc)) from None
        tier = config.tier()
        selection = _selection(ctx)
        maps, profiles = collect(ctx.invocation.operands, ctx.cwd, tier)
        allow = bool(config.controls.get("--allow-rejected-inputs"))
        try:
            result = merge(maps, profiles, run_selection=selection, allow_rejected_inputs=allow, tier=tier,
                           saturation_policy=config.value("integrity.saturation"))
        except MergeError as exc:
            raise _Stop(Diagnostic(exc.code, "merge", facts=(("detail", cli.fact_text(exc.detail)),))) from None
    except _Stop as stop:
        console.report(stop.args[0])
        return cli.EXIT_EVIDENCE

    for f in result.findings:
        facts = [("detail", cli.fact_text(f.detail)), ("input_kind", f.kind)]
        if f.name is not None:
            facts.append(("name", cli.fact_text(f.name)))
        console.report(Diagnostic(f.code, "merge", facts=tuple(facts)))
    if not result.publishable:
        return cli.EXIT_EVIDENCE

    def validate(data: bytes) -> None:
        read_indexed(data, tier=tier.name)

    try:
        if to_stdout:
            publish_stdout(console.binary_stdout(), result.data, validate=validate)
        else:
            publish_file(final, result.data, anchor=anchor, validate=validate)
    except PublishError as exc:
        if to_stdout:
            console.abandon_stdout()
        console.report(_publish_failure(exc))
        return cli.EXIT_EVIDENCE

    if not to_stdout:  # stdout carries the artifact and nothing else (SPEC 20.2)
        inputs = result.indexed["profile_inputs"]
        accepted = sum(1 for r in inputs if r["status"] == "accepted")
        copies = sum(d.copies for d in result.duplicates)
        state = "complete" if result.complete else "INCOMPLETE (diagnostic only)"
        console.say(f"merged {accepted} of {len(inputs)} profiles over {len(result.indexed['maps'])} maps: {state}"
                    + (f"; {copies} duplicate copies counted once" if copies else ""))
        console.say(f"wrote {final if output is None else output}")
    return cli.EXIT_OK
