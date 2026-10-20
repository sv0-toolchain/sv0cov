# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The Git diff model of changed-region coverage (CV-311; SPEC 22.3;
COV-POL-012..020, BL-049, BL-076, BL-077, AC-045..049).

Three steps, each failing closed with a registry code before any
changed-region number exists:

1. :func:`resolve_base` turns an explicit base spelling into exactly one
   merge base with the current ``HEAD``. Nothing is inferred: no tracking
   branch, default branch, conventional name, parent, CI variable or fetch
   (COV-POL-012/013). No spelling is ``COV4301``; no repository, Git
   missing, an unborn ``HEAD``, a missing reference or object, a shallow
   repository (owner's choice: any shallow repository fails, as its merge
   base can be silently wrong) or no common ancestor is ``COV4302``; more
   than one merge base is ``COV4303`` with every candidate (COV-POL-014,
   AC-046).
2. :func:`capture`, run before instrumentation, records ``HEAD`` and the
   merge base, the state of every compiled source (clean, staged and/or
   unstaged, added, renamed with its old path), its SHA-256 over the exact
   bytes on disk, a canonical zero-context base-to-working-tree diff of the
   compiled sources and its digest, the fixed diff options, and the Git
   implementation identity (COV-POL-017, COV-POL-019). The current side is
   the working tree: ``HEAD`` plus staged and unstaged changes. A compiled
   source that is untracked or ignored is ``COV4304`` (AC-048); one that is
   conflicted, or that Git diffs as binary, is ``COV4302`` (owner's
   choice). Untracked files outside the compiled sources play no part.
3. :func:`stale_paths`, before a report is published, names every compiled
   source whose bytes no longer match the capture; a caller turns a
   nonempty answer into ``COV4305`` (COV-POL-020, AC-049).

The changed lines of a source are the current-side lines its hunks add or
modify; deleted lines have no current line. Renames use the fixed rename
detection below and keep the old path.

Git runs with an environment and configuration that nothing in the
repository or the user's setup can redirect: every ``GIT_*`` variable of
the caller is dropped, system and global configuration are not read, no
protocol is allowed (no fetch, not even a lazy one), and the output options
are fixed on the command line so repository configuration (external diff,
textconv, prefixes, color, quoting, rename settings) cannot change the diff.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping

MISSING, UNRESOLVED, AMBIGUOUS, UNTRACKED, STALE = "COV4301", "COV4302", "COV4303", "COV4304", "COV4305"

#: ``merge-base:<ref>`` is the configuration's spelling of ``--diff-base <ref>`` (SPEC 18.2, 22.3).
PREFIX = "merge-base:"
#: The fixed diff options (SPEC 22.3): recorded with every capture.
DIFF_OPTIONS = ("--no-ext-diff", "--no-textconv", "--no-color", "--unified=0", "--find-renames=50%",
                "--diff-algorithm=myers", "--no-relative", "--src-prefix=a/", "--dst-prefix=b/")
_CONFIG = ("core.quotepath=false", "status.relativePaths=false", "core.fsmonitor=false", "core.untrackedCache=false", "color.ui=false",
           "diff.noprefix=false", "diff.mnemonicPrefix=false", "diff.relative=false", "diff.renames=true",
           "diff.renameLimit=0", "status.renames=true", "protocol.allow=never", "core.pager=cat", "advice.statusHints=false")
_HUNK = re.compile(rb"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_TIMEOUT = 120


class GitDiffError(Exception):
    """``code`` is a registry code (COV4301..COV4304); ``candidates`` lists
    every merge base for COV4303."""

    def __init__(self, code: str, detail: str, candidates: tuple[str, ...] = ()) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.candidates = candidates


def git_environment(base: Mapping[str, str] | None = None) -> dict[str, str]:
    """The caller's environment without any ``GIT_*`` variable, plus the
    settings that keep Git local and its output fixed."""
    env = {k: v for k, v in (os.environ if base is None else base).items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
                "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "", "GIT_NO_REPLACE_OBJECTS": "1",
                "GIT_LITERAL_PATHSPECS": "1", "GIT_PAGER": "cat", "PAGER": "cat", "LC_ALL": "C", "LANG": "C"})
    return env


@dataclass(frozen=True)
class Git:
    """One Git executable run in one directory."""

    executable: str
    cwd: Path

    @staticmethod
    def find(cwd: Path, executable: str | None = None) -> "Git":
        found = executable or shutil.which("git")
        if not found:
            raise GitDiffError(UNRESOLVED, "Git is not installed or not on PATH; changed-region coverage needs it")
        return Git(found, Path(cwd))

    def run(self, *args: str, ok: Iterable[int] = (0,)) -> subprocess.CompletedProcess:
        argv = [self.executable]
        for c in _CONFIG:
            argv += ["-c", c]
        try:
            p = subprocess.run([*argv, *args], cwd=self.cwd, env=git_environment(), capture_output=True, timeout=_TIMEOUT,
                               stdin=subprocess.DEVNULL)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise GitDiffError(UNRESOLVED, f"git {args[0]} could not run: {exc}") from None
        if p.returncode not in tuple(ok):
            why = p.stderr.decode("utf-8", "replace").strip().splitlines()
            raise GitDiffError(UNRESOLVED, f"git {args[0]} failed: {why[-1] if why else f'exit {p.returncode}'}")
        return p

    def text(self, *args: str) -> str:
        return self.run(*args).stdout.decode("utf-8").strip()

    def identity(self) -> dict:
        """The Git implementation identity (SPEC 22.3): version and the
        executable's SHA-256."""
        digest = hashlib.sha256(Path(self.executable).read_bytes()).hexdigest()
        return {"executable_sha256": digest, "version": self.text("--version")}


@dataclass(frozen=True)
class Base:
    """A resolved changed-region base (SPEC 22.3, COV-POL-015)."""

    spelling: str
    reference: str  # the commit the spelling names
    head: str
    merge_base: str
    toplevel: Path
    prefix: str  # the project directory relative to the repository, "" or ending in "/"


def _commit(git: Git, spelling: str) -> str | None:
    p = git.run("rev-parse", "--verify", "--quiet", "--end-of-options", f"{spelling}^{{commit}}", ok=(0, 1, 128))
    return p.stdout.decode().strip() if p.returncode == 0 else None


def resolve_base(project: Path, spelling: str | None, *, executable: str | None = None) -> Base:
    """Exactly one merge base of the explicit ``spelling`` and ``HEAD``.
    ``merge-base:<ref>`` and ``<ref>`` mean the same; the spelling is kept as given."""
    if spelling is None or spelling == "" or spelling == PREFIX:
        raise GitDiffError(MISSING, "changed-region coverage needs an explicit base: --diff-base <ref> or "
                                    "[tool.sv0cov.diff].base; none is inferred")
    ref = spelling[len(PREFIX):] if spelling.startswith(PREFIX) else spelling
    git = Git.find(project, executable)
    if git.run("rev-parse", "--is-inside-work-tree", ok=(0, 128)).returncode != 0:
        raise GitDiffError(UNRESOLVED, f"{project} is not inside a Git working tree")
    toplevel = Path(git.text("rev-parse", "--show-toplevel"))
    prefix = git.text("rev-parse", "--show-prefix")
    if git.text("rev-parse", "--is-shallow-repository") == "true":
        raise GitDiffError(UNRESOLVED, "the repository is shallow, so its merge base cannot be trusted; fetch the full "
                                       "history (for example fetch-depth: 0) and run again")
    head = _commit(git, "HEAD")
    if head is None:
        raise GitDiffError(UNRESOLVED, "HEAD has no commit yet (an unborn branch)")
    reference = _commit(git, ref)
    if reference is None:
        raise GitDiffError(UNRESOLVED, f"the base {spelling!r} does not name a commit in this repository "
                                       "(nothing is fetched or guessed)")
    found = git.run("merge-base", "--all", "--end-of-options", head, reference, ok=(0, 1)).stdout.decode().split()
    if not found:
        raise GitDiffError(UNRESOLVED, f"the base {spelling!r} and HEAD have no common ancestor")
    if len(found) > 1:
        raise GitDiffError(AMBIGUOUS, f"the base {spelling!r} has {len(found)} merge bases with HEAD: {', '.join(sorted(found))}",
                           tuple(sorted(found)))
    return Base(spelling, reference, head, found[0], toplevel, prefix)


@dataclass(frozen=True)
class SourceState:
    """One compiled source at capture time."""

    path: str  # logical, relative to the project
    repo_path: str
    state: str  # "unchanged", "modified", "added" or "renamed"
    staged: bool
    unstaged: bool
    old_path: str | None  # repository path before a rename
    sha256: str
    changed_lines: tuple[int, ...]


@dataclass(frozen=True)
class Capture:
    """Everything recorded before instrumentation (SPEC 22.3).

    A snapshot (:func:`snapshot`) may hold candidates that cannot take part
    (``problems``: untracked, ignored, conflicted or binary); :meth:`restrict`
    keeps the compiled ones and fails on any of those."""

    base: Base
    git: dict
    sources: tuple[SourceState, ...]
    diff: bytes = field(repr=False)
    diff_sha256: str = ""
    patches: Mapping[str, bytes] = field(default_factory=dict, repr=False)
    problems: Mapping[str, tuple[str, str]] = field(default_factory=dict, repr=False)
    executable: str | None = field(default=None, repr=False)

    @property
    def clean(self) -> bool:
        """No compiled source has a staged or unstaged change: the result is
        reproducible from ``HEAD`` alone."""
        return not any(s.staged or s.unstaged for s in self.sources)

    def restrict(self, compiled: Iterable[str]) -> "Capture":
        """The capture of exactly the ``compiled`` sources. One that is a
        problem, or that the snapshot did not hold (it is not tracked), fails."""
        paths = sorted(set(compiled), key=lambda p: p.encode("utf-8"))
        held = {s.path: s for s in self.sources}
        unknown = [p for p in paths if p not in held and p not in self.problems]
        problems = dict(self.problems)
        if unknown:  # not among the candidates: ask Git why
            problems.update(snapshot(self.base, unknown, executable=self.executable).problems)
        for p in paths:
            if p in problems:
                raise GitDiffError(*problems[p])
            if p not in held:
                raise GitDiffError(UNTRACKED, f"the compiled source {p} is not tracked by Git, so it has no tracked diff to cover")
        diff = b"".join(self.patches.get(p, b"") for p in paths)
        return Capture(self.base, self.git, tuple(held[p] for p in paths), diff, hashlib.sha256(diff).hexdigest(),
                       {p: self.patches[p] for p in paths if p in self.patches}, {}, self.executable)

    def record(self) -> dict:
        """The capture as plain data, in a fixed order (provenance)."""
        b = self.base
        return {
            "base": {"head": b.head, "merge_base": b.merge_base, "reference": b.reference, "spelling": b.spelling},
            "clean": self.clean,
            "diff_options": list(DIFF_OPTIONS),
            "diff_sha256": self.diff_sha256,
            "git": dict(self.git),
            "sources": [{"changed_lines": list(s.changed_lines), "old_path": s.old_path, "path": s.path, "repo_path": s.repo_path,
                         "sha256": s.sha256, "staged": s.staged, "state": s.state, "unstaged": s.unstaged} for s in self.sources],
        }


def _status(git: Git, repo_paths: list[str]) -> tuple[dict[str, tuple[str, str, str | None]], dict[str, tuple[str, str]]]:
    """Porcelain v2 status of the compiled paths: repo path -> (X, Y, old
    path), and repo path -> the failure of an untracked, ignored or
    conflicted entry."""
    out = git.run("status", "--porcelain=v2", "-z", "--untracked-files=all", "--ignored=matching", "--", *repo_paths).stdout
    fields = out.split(b"\0")
    states: dict[str, tuple[str, str, str | None]] = {}
    problems: dict[str, tuple[str, str]] = {}
    i = 0
    while i < len(fields):
        f = fields[i].decode("utf-8")
        i += 1
        if not f:
            continue
        kind = f[0]
        if kind in "?!":
            problems[f[2:]] = (UNTRACKED, f"the compiled source {f[2:]} is {'untracked' if kind == '?' else 'ignored'} by Git, "
                                          "so it has no tracked diff to cover; add and commit or stage it")
        elif kind == "u":
            path = f.split(" ", 10)[10]
            problems[path] = (UNRESOLVED, f"the compiled source {path} has a merge conflict")
        elif kind == "1":
            parts = f.split(" ", 8)
            states[parts[8]] = (parts[1][0], parts[1][1], None)
        elif kind == "2":
            parts = f.split(" ", 9)
            old = fields[i].decode("utf-8")
            i += 1
            states[parts[9]] = (parts[1][0], parts[1][1], old)
    return states, problems


def _name_status(git: Git, merge_base: str) -> list[tuple[str, str, str | None]]:
    """(status letter, new path, old path) of base-to-working-tree changes."""
    out = git.run("diff", "--name-status", "-z", *DIFF_OPTIONS, merge_base, "--").stdout.split(b"\0")
    entries = []
    i = 0
    while i < len(out) - 1:
        status = out[i].decode()
        if status[:1] in "RC":
            entries.append((status[0], out[i + 2].decode("utf-8"), out[i + 1].decode("utf-8")))
            i += 3
        else:
            entries.append((status[0], out[i + 1].decode("utf-8"), None))
            i += 2
    return entries


def changed_lines(patch: bytes) -> tuple[int, ...]:
    """Current-side lines a zero-context patch of one file adds or modifies."""
    lines: set[int] = set()
    for raw in patch.split(b"\n"):
        m = _HUNK.match(raw)
        if m:
            start, count = int(m.group(1)), 1 if m.group(2) is None else int(m.group(2))
            lines.update(range(start, start + count))
    return tuple(sorted(lines))


def _project(base: Base) -> Path:
    return base.toplevel / base.prefix if base.prefix else base.toplevel


def tracked_sources(base: Base, suffix: str = ".sv0", *, executable: str | None = None) -> list[str]:
    """Logical paths of the files below the project directory that Git
    tracks (in the index) and end in ``suffix``: the candidates ``run``
    snapshots before it knows what the build compiles."""
    git = Git.find(base.toplevel, executable)
    out = git.run("ls-files", "-z", "--cached", "--", base.prefix or ".").stdout.split(b"\0")
    found = {f.decode("utf-8") for f in out if f}
    return sorted((f[len(base.prefix):] for f in found if f.endswith(suffix)), key=lambda p: p.encode("utf-8"))


def snapshot(base: Base, candidates: Iterable[str], *, executable: str | None = None) -> Capture:
    """Capture the ``candidates`` (logical paths, relative to the project
    directory ``base`` was resolved in). A candidate that is untracked,
    ignored, conflicted or binary is held as a problem, not raised: only
    :meth:`Capture.restrict` decides whether it matters."""
    project = _project(base)
    # Pathspecs are relative to Git's working directory: run at the top
    # level and name repository paths.
    git = Git.find(base.toplevel, executable)
    paths = sorted(set(candidates), key=lambda p: p.encode("utf-8"))
    repo = {p: base.prefix + p for p in paths}
    states, bad = _status(git, [repo[p] for p in paths]) if paths else ({}, {})
    problems = {}
    for p in paths:
        # Status names a wholly untracked or ignored directory once, as "dir/".
        hit = repo[p] if repo[p] in bad else next((k for k in bad if k.endswith("/") and repo[p].startswith(k)), None)
        if hit is not None:
            code, detail = bad[hit]
            problems[p] = (code, detail.replace(f" {hit} ", f" {repo[p]} ", 1))
    wanted = {repo[p] for p in paths if p not in problems}
    entries = {new: (letter, old) for letter, new, old in _name_status(git, base.merge_base) if new in wanted} if wanted else {}
    sources, patches = [], {}
    for p in paths:
        if p in problems:
            continue
        rp = repo[p]
        try:
            data = (project / p).read_bytes()
        except OSError as exc:  # a tracked candidate deleted from the working tree
            problems[p] = (STALE, f"the compiled source {p} cannot be read ({type(exc).__name__}): it changed after it was compiled")
            continue
        letter, old = entries.get(rp, (None, None))
        patch = b""
        if letter is not None:
            spec = [rp] if old is None else [old, rp]
            patch = git.run("diff", *DIFF_OPTIONS, base.merge_base, "--", *spec).stdout
            if b"\nBinary files " in b"\n" + patch or b"GIT binary patch" in patch:
                problems[p] = (UNRESOLVED, f"Git diffs the compiled source {p} as binary")
                continue
            patches[p] = patch
        x, y, _ = states.get(rp, (".", ".", None))
        state = {"A": "added", "R": "renamed", "C": "added"}.get(letter or "", "modified" if letter else "unchanged")
        sources.append(SourceState(p, rp, state, x != ".", y != ".", old if letter == "R" else None,
                                   hashlib.sha256(data).hexdigest(), changed_lines(patch)))
    diff = b"".join(patches[s.path] for s in sources if s.path in patches)
    return Capture(base, git.identity(), tuple(sources), diff, hashlib.sha256(diff).hexdigest(), patches, problems, executable)


def capture(base: Base, compiled: Iterable[str], *, executable: str | None = None) -> Capture:
    """Capture the compiled sources (logical paths, relative to the project
    directory ``base`` was resolved in) before instrumentation."""
    compiled = list(compiled)
    return snapshot(base, compiled, executable=executable).restrict(compiled)


def stale_paths(snapshot: Capture, project: Path, current: Mapping[str, bytes] | None = None) -> list[str]:
    """Compiled sources whose bytes (from ``current``, else the disk) no
    longer match the capture; a missing file counts as changed."""
    out = []
    for s in snapshot.sources:
        data = None if current is None else current.get(s.path)
        if data is None:
            try:
                data = (Path(project) / s.path).read_bytes()
            except OSError:
                out.append(s.path)
                continue
        if hashlib.sha256(data).hexdigest() != s.sha256:
            out.append(s.path)
    return out
