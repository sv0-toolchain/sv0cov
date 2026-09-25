# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""What this build advertises, and its identity (SPEC 20.6).

``ADVERTISED`` grows only as each command, backend, profile, or feature
passes its release gate; a producer must never advertise more.

Identity sources:

- product version: the static ``[project].version`` (from ``pyproject.toml``
  in a source checkout, else from installed distribution metadata);
- implementation revision: the Git commit of the source checkout the code
  runs from, read directly from ``.git`` without running Git. An installed
  distribution has no reliable revision source yet: SPEC 20.6 requires the
  40-hex commit while SPEC 25.2.7 forbids build hooks and dynamic metadata.
  This gap is recorded in the planning hub; until it is resolved, an
  installed distribution fails ``version --json`` rather than guess.
"""

from __future__ import annotations

import platform
import tomllib
from importlib import metadata
from pathlib import Path

from sv0cov.formats.version_manifest import Advertised, ManifestError
from sv0cov.model.inventory import RE_REVISION

ADVERTISED = Advertised(commands=("version",), backends=(), bytecode_profiles=(), features=())

_CHECKOUT = Path(__file__).resolve().parents[2]


def _is_checkout() -> bool:
    pyproject = _CHECKOUT / "pyproject.toml"
    if not pyproject.is_file() or not (_CHECKOUT / "src" / "sv0cov" / "__init__.py").is_file():
        return False
    try:
        return tomllib.loads(pyproject.read_text(encoding="utf-8"))["project"]["name"] == "sv0cov"
    except (OSError, KeyError, tomllib.TOMLDecodeError):
        return False


def tool_version() -> str:
    if _is_checkout():
        return tomllib.loads((_CHECKOUT / "pyproject.toml").read_text(encoding="utf-8"))["project"]["version"]
    return metadata.version("sv0cov")


def _git_dir(root: Path) -> Path:
    dot_git = root / ".git"
    if dot_git.is_dir():
        return dot_git
    if dot_git.is_file():  # a submodule checkout: "gitdir: <path>"
        text = dot_git.read_text(encoding="utf-8").strip()
        if text.startswith("gitdir: "):
            return (root / text[len("gitdir: ") :]).resolve()
    raise ManifestError("no Git metadata for the source checkout")


def revision() -> str:
    """The 40-hex commit of the running source checkout."""
    if not _is_checkout():
        raise ManifestError("implementation revision is unavailable for an installed distribution")
    git = _git_dir(_CHECKOUT)
    head = (git / "HEAD").read_text(encoding="utf-8").strip()
    if head.startswith("ref: "):
        ref = head[len("ref: ") :]
        common = git
        if (git / "commondir").is_file():
            common = (git / (git / "commondir").read_text(encoding="utf-8").strip()).resolve()
        for base in (git, common):
            if (base / ref).is_file():
                head = (base / ref).read_text(encoding="utf-8").strip()
                break
        else:
            packed = common / "packed-refs"
            lines = packed.read_text(encoding="utf-8").splitlines() if packed.is_file() else []
            head = next((line.split(" ", 1)[0] for line in lines if line.endswith(" " + ref)), "")
    if not RE_REVISION.fullmatch(head):
        raise ManifestError("could not resolve the checkout's commit")
    return head


def runtime_version() -> str:
    return platform.python_version()
