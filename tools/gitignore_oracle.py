#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Capture the Gitignore scope-pattern oracle corpus (CV-030; SPEC 18.3).

For every case in ``tests/fixtures/gitignore/cases.py`` this materializes the
virtual tree in a fresh directory, writes the case's patterns as the root
``.gitignore``, and asks Git which paths it would ignore:

    git check-ignore --no-index -v -n -z --stdin

Git runs fully isolated: ``env -i`` with a minimal PATH, an empty HOME and
XDG_CONFIG_HOME, no system or global configuration, ``core.excludesFile``
pointing at an empty file, no ``info/exclude`` (empty init template), and
``core.ignorecase=false`` / ``core.precomposeunicode=false`` so matching is
exact-byte and case-sensitive. A path is *selected* when its last matching
pattern is not negated; parent-directory exclusion is Git's own.

Only Git 2.55.0 built from the pinned source release is accepted; the
executable's digest is recorded. Capture needs a case-sensitive filesystem
(the tree has ``src/`` and ``Src/``); on macOS use a case-sensitive APFS
volume via ``--workdir``.

    tools/gitignore_oracle.py --git /path/to/git-2.55.0/git --write
    tools/gitignore_oracle.py                  # check inputs match corpus.json

Without ``--git`` the tool checks that the frozen corpus was captured from
exactly the current case definitions (their digest) with the pinned Git.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HERE = ROOT / "tests" / "fixtures" / "gitignore"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import cases as C  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402

GIT_VERSION = "2.55.0"
# The upstream source release the oracle executable was built from. The
# reference capture used Homebrew's git 2.55.0, whose formula builds from this
# exact tarball; any build from these bytes is an acceptable oracle.
GIT_SOURCE = {
    "sha256": "457fdb04dc8728e007d4688695e6912e6f680727920f2a40bf11eacc17505357",
    "url": "https://www.kernel.org/pub/software/scm/git/git-2.55.0.tar.xz",
}
CORPUS = HERE / "corpus.json"


def inputs() -> dict:
    return {
        "cases": [{"id": cid, "patterns": list(lines)} for cid, lines in C.CASES],
        "tree": [{"kind": kind, "path": path} for path, kind in C.paths()],
    }


def inputs_sha256() -> str:
    return hashlib.sha256(encode(inputs())).hexdigest()


def _materialize(root: Path) -> None:
    for path, kind in C.paths():
        target = root / path
        if kind == "dir":
            target.mkdir(parents=True, exist_ok=True)
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(b"")


def _case_sensitive(work: Path) -> bool:
    probe = Path(tempfile.mkdtemp(dir=work))
    (probe / "a").write_bytes(b"")
    try:
        return not (probe / "A").exists()
    finally:
        (probe / "a").unlink()
        probe.rmdir()


def _git_env(home: Path) -> dict:
    return {"PATH": "/usr/bin:/bin", "HOME": str(home), "XDG_CONFIG_HOME": str(home / "xdg"), "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / "empty"), "LC_ALL": "C"}


def capture(git: str, work: Path) -> dict:
    version = subprocess.run([git, "--version"], capture_output=True, text=True, check=True).stdout.strip()
    if version != f"git version {GIT_VERSION}":
        sys.exit(f"gitignore_oracle: need git {GIT_VERSION}, got {version!r}")
    if GIT_SOURCE["sha256"] is None:
        sys.exit("gitignore_oracle: GIT_SOURCE sha256 is not pinned yet")
    if not _case_sensitive(work):
        sys.exit(f"gitignore_oracle: {work} is case-insensitive; pass --workdir on a case-sensitive volume")
    git_digest = hashlib.sha256(Path(git).read_bytes()).hexdigest()
    query = b"".join(p.encode("utf-8") + b"\0" for p, _ in C.paths())
    results = []
    for cid, lines in C.CASES:
        with tempfile.TemporaryDirectory(dir=work) as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            (home / "empty").write_bytes(b"")
            repo = Path(tmp) / "repo"
            repo.mkdir()
            env = _git_env(home)
            subprocess.run([git, "init", "-q", "--template=", "."], cwd=repo, env=env, check=True)
            _materialize(repo)
            (repo / ".gitignore").write_bytes(b"".join(line.encode("utf-8") + b"\n" for line in lines))
            cmd = [git, "-c", "core.ignorecase=false", "-c", "core.precomposeunicode=false", "-c", f"core.excludesFile={home / 'empty'}",
                   "check-ignore", "--no-index", "-v", "-n", "-z", "--stdin"]
            out = subprocess.run(cmd, cwd=repo, env=env, input=query, capture_output=True)
            if out.returncode not in (0, 1) or out.stderr:
                sys.exit(f"gitignore_oracle: {cid}: git failed: {out.stderr.decode(errors='replace')}")
            fields = out.stdout.split(b"\0")[:-1]
            if len(fields) != 4 * len(C.paths()):
                sys.exit(f"gitignore_oracle: {cid}: unexpected output shape")
            matched = {}
            selected = []
            for i in range(0, len(fields), 4):
                source, line, pattern, path = (f.decode("utf-8") for f in fields[i : i + 4])
                if not source:
                    continue
                if source != ".gitignore":
                    sys.exit(f"gitignore_oracle: {cid}: pattern from unexpected source {source!r}")
                matched[path] = int(line)
                if not pattern.startswith("!"):
                    selected.append(path)
            results.append({"id": cid, "matched_line": matched, "selected": selected})
    return {
        "git": {"executable_sha256": git_digest, "source": GIT_SOURCE, "version": GIT_VERSION},
        "inputs_sha256": inputs_sha256(),
        "results": results,
        "schema": "sv0cov.gitignore-oracle-corpus",
        "version": "1.0",
        **inputs(),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git")
    ap.add_argument("--workdir", default=None)
    ap.add_argument("--write", action="store_true")
    args = ap.parse_args()
    if args.git:
        work = Path(args.workdir or tempfile.gettempdir())
        data = encode(capture(args.git, work))
        if args.write:
            CORPUS.write_bytes(data)
            print(f"gitignore oracle: wrote {len(C.CASES)} cases")
            return 0
        if not CORPUS.is_file() or CORPUS.read_bytes() != data:
            print("gitignore oracle: capture differs from corpus.json", file=sys.stderr)
            return 1
        print("gitignore oracle: capture reproduces corpus.json")
        return 0
    if not CORPUS.is_file():
        print("gitignore oracle: corpus.json has not been captured", file=sys.stderr)
        return 1
    import json

    corpus = json.loads(CORPUS.read_bytes())
    if corpus["inputs_sha256"] != inputs_sha256() or corpus["git"]["version"] != GIT_VERSION or corpus["git"]["source"] != GIT_SOURCE:
        print("gitignore oracle: corpus.json is stale for the current cases or Git pin", file=sys.stderr)
        return 1
    print("gitignore oracle: corpus.json matches the current cases")
    return 0


if __name__ == "__main__":
    sys.exit(main())
