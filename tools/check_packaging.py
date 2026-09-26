#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Packaging and dependency-policy checks (CV-004, CV-005).

Subcommands:

``policy``
    Validate ``pyproject.toml`` and ``uv.lock`` against SPEC 25.2.1 and
    25.2.5-25.2.7: static zero-dependency metadata, the exact ten dependency
    groups, the single PyPI index, registry-only requirements and lock
    sources, an equality-pinned Hatchling backend that matches the ``build``
    group, and a hash-bound wheel for every third-party package on all eight
    host/interpreter cells. Also rejects ambient uv source overrides.

``dist DIR``
    Inspect one built sdist and wheel: member allowlists, zero
    ``Requires-Dist``, no extras, ``py3-none-any``, the console entry point,
    and ``RECORD`` hashes.

``build OUT``
    Build twice from a clean environment (``uv build``, sdist then wheel from
    that sdist), run ``dist`` on the result, and require byte-identical
    archives.

Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import email.parser
import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

GROUPS = frozenset(
    {
        "accessibility",
        "audit",
        "build",
        "consumer",
        "docs",
        "fuzz",
        "generator",
        "oracle",
        "release",
        "test",
    }
)
PYPI = "https://pypi.org/simple"
UV_ALLOWED_KEYS = {"default-groups", "index-strategy", "keyring-provider", "no-sources", "index"}
HATCH_ALLOWED_KEYS = {"build"}
FORBIDDEN_FILES = ("hatch.toml", "hatch_build.py", "requirements.txt", "constraints.txt", "pylock.toml")
AMBIENT_UV_VARS = (
    "UV_INDEX",
    "UV_INDEX_URL",
    "UV_DEFAULT_INDEX",
    "UV_EXTRA_INDEX_URL",
    "UV_FIND_LINKS",
    "UV_NO_INDEX",
    "UV_INDEX_STRATEGY",
    "UV_KEYRING_PROVIDER",
    "UV_CONFIG_FILE",
    "UV_NO_SOURCES",
)
# (python tag prefix, platform predicate) cells: 2 interpreters x 4 hosts.
PYTHONS = ("cp313", "cp314")
HOSTS = {
    "macos-arm64": lambda p: p.startswith("macosx_") and (p.endswith("_arm64") or p.endswith("_universal2")),
    "macos-x86_64": lambda p: p.startswith("macosx_") and (p.endswith("_x86_64") or p.endswith("_universal2")),
    "linux-arm64": lambda p: p.startswith(("manylinux", "linux_")) and p.endswith("_aarch64"),
    "linux-x86_64": lambda p: p.startswith(("manylinux", "linux_")) and p.endswith("_x86_64"),
}
RE_REQ = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([0-9][A-Za-z0-9.!+-]*)$")

SDIST_ALLOW = {
    "README.md",
    "LICENSE",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "LICENSES",
    "REUSE.toml",
    "pyproject.toml",
    "uv.lock",
    "src",
    "registries",
    "schemas",
    "docs",
    "tests",
    "tools",
    "scripts",
    "bench",
    "PKG-INFO",
}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def pinned(req: object) -> tuple[str, str] | None:
    """(normalized name, version) for an ``name==version`` requirement, else None."""
    m = RE_REQ.match(req.strip()) if isinstance(req, str) else None
    return (normalize(m.group(1)), m.group(2)) if m else None


# ── policy ──────────────────────────────────────────────────────────────────


def check_pyproject(py: dict) -> list[str]:
    errors: list[str] = []
    project = py.get("project", {})
    if project.get("dependencies", []) != []:
        errors.append("[project].dependencies must be absent or []")
    for key in ("optional-dependencies", "dynamic"):
        if key in project:
            errors.append(f"[project].{key} is forbidden")
    if not isinstance(project.get("version"), str):
        errors.append("[project].version must be a static string")

    groups = py.get("dependency-groups", {})
    if set(groups) != GROUPS:
        errors.append(f"dependency groups must be exactly {sorted(GROUPS)}, got {sorted(groups)}")
    seen: dict[str, str] = {}
    for group, reqs in groups.items():
        if not isinstance(reqs, list):
            errors.append(f"group {group!r} must be a list")
            continue
        for req in reqs:
            if not isinstance(req, str):
                errors.append(f"group {group!r}: include-group or non-string entry {req!r} forbidden")
                continue
            m = RE_REQ.match(req.strip())
            if not m:
                errors.append(f"group {group!r}: {req!r} must be an equality-pinned registry requirement")
                continue
            name = normalize(m.group(1))
            if name in seen:
                errors.append(f"{name!r} appears in groups {seen[name]!r} and {group!r}")
            seen[name] = group

    bs = py.get("build-system", {})
    if bs.get("build-backend") != "hatchling.build":
        errors.append("build-backend must be exactly 'hatchling.build'")
    if "backend-path" in bs:
        errors.append("backend-path is forbidden")
    requires = [pinned(r) for r in bs.get("requires", [])]
    build_hatchling = [p for p in (pinned(r) for r in groups.get("build", [])) if p and p[0] == "hatchling"]
    if len(requires) != 1 or requires[0] is None or requires[0][0] != "hatchling":
        errors.append("build-system.requires must be exactly one equality-pinned hatchling requirement")
    elif build_hatchling != requires:
        errors.append("build-system.requires must equal the hatchling entry of the build group")

    tool = py.get("tool", {})
    uv = tool.get("uv", {})
    extra = set(uv) - UV_ALLOWED_KEYS
    if extra:
        errors.append(f"[tool.uv] has forbidden keys {sorted(extra)}")
    if uv.get("default-groups") != []:
        errors.append("[tool.uv].default-groups must be []")
    if uv.get("index-strategy") != "first-index":
        errors.append("[tool.uv].index-strategy must be 'first-index'")
    if uv.get("keyring-provider") != "disabled":
        errors.append("[tool.uv].keyring-provider must be 'disabled'")
    if uv.get("no-sources") is not True:
        errors.append("[tool.uv].no-sources must be true")
    if uv.get("index") != [{"name": "pypi", "url": PYPI, "default": True}]:
        errors.append(f"[[tool.uv.index]] must be exactly one {{name='pypi', url={PYPI!r}, default=true}}")
    hatch = tool.get("hatch", {})
    extra = set(hatch) - HATCH_ALLOWED_KEYS
    if extra:
        errors.append(f"[tool.hatch] has forbidden keys {sorted(extra)} (no envs, version, metadata hooks)")
    build = hatch.get("build", {})
    if "hooks" in build or any("hooks" in t for t in build.get("targets", {}).values()):
        errors.append("hatch build hooks are forbidden")
    for name in ("sdist", "wheel"):
        target = build.get("targets", {}).get(name, {})
        if target.get("reproducible") is not True:
            errors.append(f"hatch {name} target must set reproducible = true")
        if not target.get("only-include"):
            errors.append(f"hatch {name} target must use an only-include allowlist")
    return errors


def wheel_cells(wheels: list[dict]) -> set[tuple[str, str]]:
    cells: set[tuple[str, str]] = set()
    for w in wheels:
        fname = w.get("url", w.get("filename", "")).rsplit("/", 1)[-1]
        if not fname.endswith(".whl") or not w.get("hash", "").startswith("sha256:"):
            continue
        py_tags, abi_tags, plat_tags = fname[:-4].split("-")[-3:]
        for py_tag in py_tags.split("."):
            for plat in plat_tags.split("."):
                for py in PYTHONS:
                    py_ok = (
                        py_tag in ("py3", "py2.py3")
                        or py_tag == py
                        or (abi_tags == "abi3" and py_tag.startswith("cp3") and int(py_tag[3:]) <= int(py[3:]))
                    )
                    if not py_ok:
                        continue
                    for host, pred in HOSTS.items():
                        if plat == "any" or pred(plat):
                            cells.add((py, host))
    return cells


def check_lock(lock: dict) -> list[str]:
    errors: list[str] = []
    all_cells = {(py, host) for py in PYTHONS for host in HOSTS}
    for pkg in lock.get("package", []):
        name = pkg.get("name")
        source = pkg.get("source", {})
        if name == "sv0cov":
            if source != {"editable": "."}:
                errors.append(f"root package source must be the local project, got {source}")
            continue
        if source != {"registry": PYPI}:
            errors.append(f"{name}: source must be the PyPI registry, got {source}")
        missing = all_cells - wheel_cells(pkg.get("wheels", []))
        if missing:
            errors.append(f"{name}: no hash-bound wheel for cells {sorted(missing)}")
    return errors


def check_environment(environ: dict[str, str]) -> list[str]:
    return [f"ambient uv source/config override {k} is set" for k in AMBIENT_UV_VARS if k in environ]


def check_tree(root: Path) -> list[str]:
    errors = [f"forbidden file {f} present" for f in FORBIDDEN_FILES if (root / f).exists()]
    errors += [f"forbidden file {p.name}" for p in root.glob("requirements-*.txt")]
    return errors


def cmd_policy(root: Path) -> list[str]:
    py = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    lock = tomllib.loads((root / "uv.lock").read_text(encoding="utf-8"))
    return check_pyproject(py) + check_lock(lock) + check_environment(dict(os.environ)) + check_tree(root)


# ── dist ────────────────────────────────────────────────────────────────────


def check_wheel_metadata(metadata: str, wheel: str, entry_points: str) -> list[str]:
    errors: list[str] = []
    msg = email.parser.Parser().parsestr(metadata)
    if msg.get_all("Requires-Dist"):
        errors.append(f"wheel METADATA has Requires-Dist: {msg.get_all('Requires-Dist')}")
    if msg.get_all("Provides-Extra"):
        errors.append("wheel METADATA has Provides-Extra")
    if msg.get("License-Expression") != "MIT OR Apache-2.0":
        errors.append(f"License-Expression must be 'MIT OR Apache-2.0', got {msg.get('License-Expression')!r}")
    wmsg = email.parser.Parser().parsestr(wheel)
    if wmsg.get_all("Tag") != ["py3-none-any"]:
        errors.append(f"wheel Tag must be exactly py3-none-any, got {wmsg.get_all('Tag')}")
    if wmsg.get("Root-Is-Purelib") != "true":
        errors.append("wheel must be purelib")
    if "sv0cov = sv0cov.cli:main" not in entry_points:
        errors.append("console entry point 'sv0cov = sv0cov.cli:main' missing")
    return errors


def check_sdist(path: Path, prefix: str) -> list[str]:
    errors: list[str] = []
    with tarfile.open(path) as tf:
        for m in tf.getmembers():
            if not (m.isfile() or m.isdir()):
                errors.append(f"sdist member {m.name} is not a regular file or directory")
            parts = m.name.split("/")
            if parts[0] != prefix:
                errors.append(f"sdist member {m.name} outside {prefix}/")
                continue
            if len(parts) > 1 and parts[1] not in SDIST_ALLOW:
                errors.append(f"sdist member {m.name} not allowlisted")
            if len(parts) > 2 and parts[1:3] == ["tests", "vendor"]:
                errors.append(f"sdist member {m.name}: tests/vendor is excluded")
            if "__pycache__" in parts or m.name.endswith(".pyc"):
                errors.append(f"sdist member {m.name} is a cache file")
            if m.isfile() and m.name == f"{prefix}/PKG-INFO":
                pkg = email.parser.Parser().parsestr(tf.extractfile(m).read().decode("utf-8"))
                if pkg.get_all("Requires-Dist"):
                    errors.append("sdist PKG-INFO has Requires-Dist")
                if "Dynamic" in pkg:
                    errors.append("sdist PKG-INFO declares Dynamic metadata")
    return errors


def check_wheel(path: Path, distinfo: str) -> list[str]:
    errors: list[str] = []
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        for n in names:
            top = n.split("/", 1)[0]
            if top not in ("sv0cov", distinfo):
                errors.append(f"wheel member {n} not allowlisted")
            if "__pycache__" in n or n.endswith(".pyc"):
                errors.append(f"wheel member {n} is a cache file")
        errors += check_wheel_metadata(
            zf.read(f"{distinfo}/METADATA").decode("utf-8"),
            zf.read(f"{distinfo}/WHEEL").decode("utf-8"),
            zf.read(f"{distinfo}/entry_points.txt").decode("utf-8"),
        )
        record = zf.read(f"{distinfo}/RECORD").decode("utf-8").splitlines()
        recorded = set()
        for line in record:
            name, digest, _size = line.rsplit(",", 2)
            recorded.add(name)
            if not digest:
                continue
            algo, want = digest.split("=", 1)
            got = base64.urlsafe_b64encode(hashlib.new(algo, zf.read(name)).digest()).rstrip(b"=").decode()
            if got != want:
                errors.append(f"RECORD hash mismatch for {name}")
        if recorded != set(names):
            errors.append(f"RECORD does not list exactly the archive members: {sorted(set(names) ^ recorded)}")
    return errors


def cmd_dist(outdir: Path, root: Path) -> list[str]:
    py = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = py["project"]["version"]
    sdist = outdir / f"sv0cov-{version}.tar.gz"
    wheel = outdir / f"sv0cov-{version}-py3-none-any.whl"
    errors = [f"missing {p.name}" for p in (sdist, wheel) if not p.is_file()]
    others = sorted(p.name for p in outdir.iterdir() if p not in (sdist, wheel) and p.name != ".gitignore")
    if others:
        errors.append(f"unexpected build outputs {others}")
    if errors:
        return errors
    return check_sdist(sdist, f"sv0cov-{version}") + check_wheel(wheel, f"sv0cov-{version}.dist-info")


# ── build ───────────────────────────────────────────────────────────────────


def build_once(root: Path, out: Path, epoch: str, venv: Path) -> None:
    """Build sdist, then the wheel from that sdist, without build isolation.

    The backend comes only from the locked ``build`` group synced into a fresh
    environment (SPEC 25.2.7); no build dependency is resolved ad hoc.
    """
    env = {k: v for k, v in os.environ.items() if not k.startswith(("HATCH_", "UV_", "PIP_", "PYTHON"))}
    env["SOURCE_DATE_EPOCH"] = epoch
    env["UV_PROJECT_ENVIRONMENT"] = str(venv)
    common = ["--no-config", "--no-python-downloads"]
    subprocess.run(
        [
            "uv", "sync", *common, "--locked", "--no-default-groups", "--group", "build",
            "--no-install-project", "--python", sys.executable,
        ],
        check=True,
        env=env,
        cwd=root,
    )
    subprocess.run(
        ["uv", "build", *common, "--no-build-isolation", "--python", str(venv / "bin" / "python"), "--out-dir", str(out)],
        check=True,
        env=env,
        cwd=root,
    )


def cmd_build(root: Path, out: Path) -> list[str]:
    epoch = subprocess.run(
        ["git", "log", "-1", "--format=%ct"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    if out.exists():
        shutil.rmtree(out)
    with tempfile.TemporaryDirectory() as tmp:
        first, second = Path(tmp, "a"), Path(tmp, "b")
        build_once(root, first, epoch, Path(tmp, "venv-a"))
        build_once(root, second, epoch, Path(tmp, "venv-b"))
        errors = cmd_dist(first, root)
        for p in sorted(first.iterdir()):
            if p.name == ".gitignore":
                continue
            other = second / p.name
            if not other.is_file() or other.read_bytes() != p.read_bytes():
                errors.append(f"{p.name} is not byte-identical across two builds")
        shutil.copytree(first, out)
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="sv0cov packaging policy checks")
    ap.add_argument("--root", type=Path, default=ROOT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("policy")
    d = sub.add_parser("dist")
    d.add_argument("dir", type=Path)
    b = sub.add_parser("build")
    b.add_argument("out", type=Path)
    args = ap.parse_args(argv)
    root = args.root.resolve()
    if args.cmd == "policy":
        errors = cmd_policy(root)
    elif args.cmd == "dist":
        errors = cmd_dist(args.dir, root)
    else:
        errors = cmd_build(root, args.out)
    for e in errors:
        print(f"check_packaging {args.cmd}: {e}", file=sys.stderr)
    if errors:
        return 1
    print(f"check_packaging {args.cmd}: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
