# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``clean`` command (CV-232; SPEC 18.4, 20.2.2)::

    sv0cov clean [options]

It removes the output directory (``[tool.sv0cov].output_dir``, default
``.sv0cov``) below the working directory, and only when everything in it
is something sv0cov puts there. Explicit ``--output`` destinations outside
that directory are never touched.

**What is recognized.**

=======================  ==================================================
where                    what
=======================  ==================================================
the output directory     ``coverage.sv0covdata.json``, ``reports/``, ``runs/``
``reports/``             the canonical report files and their companions;
                         ``lcov-stdout-support/`` and
                         ``cobertura-stdout-support/`` with their two files
``runs/``                directories named by a run ID (32 lowercase hex)
below a run directory    regular files and directories, to a bounded depth
anywhere above           a leftover publication temporary
                         (``.sv0cov-tmp-`` and 32 hex), file or directory
=======================  ==================================================

**Two passes.** The whole tree is examined first. A symlink anywhere, a
special file, an unknown name, a known name of the wrong type, a mount
point, or a tree deeper than the bound is a refusal: every refusal is
reported (``COV6002``), nothing is removed, and the command exits 5. Only
a fully recognized tree is removed, bottom up, through open directory
descriptors that never follow a symlink. If the tree changes while it is
being removed, removal stops and the command exits 5.

The output directory is reached from the project root one component at a
time without following symlinks, and the configuration cannot name the
project root itself. A missing output directory is not an error.
"""

from __future__ import annotations

import os
import re
import stat

from sv0cov import cli
from sv0cov.cmd_merge import INDEXED_NAME
from sv0cov.diagnostics import Diagnostic
from sv0cov.publish import TEMP_PREFIX, PublishError, _Missing, _open_parent

_PRIMARY = ("coverage.txt", "coverage.html", "coverage.json", "lcov.info", "cobertura.xml")
REPORT_FILES = frozenset((*_PRIMARY, "lcov.manifest.json", "cobertura.manifest.json", "lcov.info.sv0cov.json", "lcov.info.manifest.json",
                          "cobertura.xml.sv0cov.json", "cobertura.xml.manifest.json"))
SUPPORT = {"lcov-stdout-support": frozenset(("coverage.json", "lcov.manifest.json")),
           "cobertura-stdout-support": frozenset(("coverage.json", "cobertura.manifest.json"))}
RE_RUN = re.compile(r"[0-9a-f]{32}\Z")
RE_TEMP = re.compile(re.escape(TEMP_PREFIX) + r"[0-9a-f]{32}\Z")
MAX_DEPTH = 32
MAX_REPORTED = 20
_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC

# A level says which names it may hold: (file names, {directory name: level}).
FREE = "free"
_SUPPORT_LEVELS = {name: (files, {}) for name, files in SUPPORT.items()}
ROOT_LEVEL = (frozenset((INDEXED_NAME,)), {"reports": (REPORT_FILES, _SUPPORT_LEVELS), "runs": "runs"})


class _Refused(Exception):
    pass


def _child_level(level, name: str, is_dir: bool):
    """The level of a directory entry, ``True`` for an owned file, or ``None`` when it is not recognized."""
    if level == FREE:
        return FREE if is_dir else True
    if RE_TEMP.match(name):
        return FREE if is_dir else True
    if level == "runs":
        return FREE if is_dir and RE_RUN.match(name) else None
    files, dirs = level
    if is_dir:
        return dirs.get(name)
    return True if name in files else None


def _scan(fd: int, level, where: str, device: int, depth: int, refused: list[str]) -> dict:
    """The plan for one directory: name -> ``None`` for a file, a nested plan for a directory."""
    plan: dict = {}
    if depth > MAX_DEPTH:
        refused.append(f"{where} is nested deeper than {MAX_DEPTH} directories")
        return plan
    with os.scandir(fd) as entries:
        listing = sorted(entries, key=lambda e: os.fsencode(e.name))
    for entry in listing:
        path = f"{where}/{entry.name}"
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            refused.append(f"{path} cannot be examined")
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        if stat.S_ISLNK(st.st_mode):
            refused.append(f"{path} is a symlink")
        elif not is_dir and not stat.S_ISREG(st.st_mode):
            refused.append(f"{path} is not a regular file or a directory")
        elif st.st_dev != device:
            refused.append(f"{path} is on another filesystem")
        else:
            child = _child_level(level, entry.name, is_dir)
            if child is None:
                refused.append(f"{path} is not something sv0cov puts there")
            elif not is_dir:
                plan[entry.name] = None
            else:
                try:
                    sub = os.open(entry.name, _DIR, dir_fd=fd)
                except OSError:
                    refused.append(f"{path} cannot be opened as a directory")
                    continue
                try:
                    plan[entry.name] = _scan(sub, child, path, device, depth + 1, refused)
                finally:
                    os.close(sub)
    return plan


def _remove(parent: int, name: str, plan: dict, where: str, counts: list[int]) -> None:
    """Remove the planned directory ``name`` of the open directory ``parent``."""
    try:
        fd = os.open(name, _DIR, dir_fd=parent)
    except OSError:
        raise _Refused(f"{where} changed while it was being removed") from None
    try:
        for child, sub in plan.items():
            path = f"{where}/{child}"
            if sub is None:
                try:
                    os.unlink(child, dir_fd=fd)
                except OSError:
                    raise _Refused(f"{path} changed while it was being removed") from None
                counts[0] += 1
            else:
                _remove(fd, child, sub, path, counts)
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=parent)
    except OSError:
        raise _Refused(f"{where} changed while it was being removed") from None
    counts[1] += 1


@cli.command("clean")
def cmd_clean(ctx: cli.Context) -> int:
    console = ctx.console
    output_dir = ctx.config.value("output_dir")

    def refuse(details: list[str]) -> int:
        for detail in details[:MAX_REPORTED]:
            console.report(Diagnostic("COV6002", "publication", facts=(("detail", cli.fact_text(detail)),)))
        if len(details) > MAX_REPORTED:
            console.report(Diagnostic("COV6002", "publication", facts=(
                ("detail", f"{len(details) - MAX_REPORTED} more entries were refused"),)))
        return cli.EXIT_EVIDENCE

    try:
        parent, name = _open_parent(output_dir, str(ctx.cwd), create=False)
    except _Missing:
        console.say(f"nothing to clean: {output_dir} does not exist")
        return cli.EXIT_OK
    except PublishError as exc:
        return refuse([f"{output_dir}: {exc.detail}"])
    try:
        try:
            st = os.lstat(name, dir_fd=parent)
        except FileNotFoundError:
            console.say(f"nothing to clean: {output_dir} does not exist")
            return cli.EXIT_OK
        if not stat.S_ISDIR(st.st_mode):
            return refuse([f"{output_dir} is a symlink or not a directory"])
        here = os.fstat(parent)
        root = os.stat(ctx.cwd)
        if (st.st_dev, st.st_ino) == (root.st_dev, root.st_ino) or st.st_dev != here.st_dev:
            return refuse([f"{output_dir} is the project root or on another filesystem"])
        try:
            fd = os.open(name, _DIR, dir_fd=parent)
        except OSError:
            return refuse([f"{output_dir} cannot be opened as a directory"])
        refused: list[str] = []
        try:
            plan = _scan(fd, ROOT_LEVEL, output_dir, st.st_dev, 1, refused)
        finally:
            os.close(fd)
        if refused:
            return refuse(refused)
        counts = [0, 0]
        try:
            _remove(parent, name, plan, output_dir, counts)
        except _Refused as exc:
            return refuse([str(exc)])
    finally:
        os.close(parent)
    console.say(f"removed {output_dir}: {counts[0]} files, {counts[1]} directories")
    return cli.EXIT_OK
