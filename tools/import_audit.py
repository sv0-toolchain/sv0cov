#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Production import-boundary audit (CV-033; SPEC 25.2.1, COV-PKG-016, AC-121).

The R1 production closure is the qualified CPython standard library plus
project-owned ``sv0cov`` code. Two independent views must both find exactly
that:

- **static**: parse every module under ``src/sv0cov`` and classify each
  import by top-level name. Anything that is neither in
  ``sys.stdlib_module_names`` nor ``sv0cov`` is a violation, as are relative
  imports that escape the package, dynamic-import and installer hooks
  (``__import__``, ``importlib.import_module``, ``importlib.util``,
  ``entry_points``, ``ensurepip``, ``venv``, ``site``, ``pkgutil``), and any
  non-Python member (binary extension, archive, vendored tree).
- **runtime**: in a fresh ``-I -B`` interpreter with ``src`` first on
  ``sys.path``, import every ``sv0cov`` module and drive representative CLI
  paths, then classify every loaded module by origin: builtin/frozen,
  a file under the interpreter's standard-library directories, or a file
  under ``src/sv0cov``. Any other origin, including a stdlib name shadowed
  from elsewhere, is a violation.

The runtime view also reports every sv0cov module it loaded; the audit
requires that set to equal the static inventory.

``--poison-site DIR`` (tests only) processes DIR as a site directory before
anything is imported, simulating a poisoned environment. ``--no-site`` runs
the child with ``-S`` (an empty site). The default interpreter is the
physical target of the running one, so a virtual environment's own ``.pth``
hooks (uv's ``_virtualenv``) are not mistaken for production imports.

    python3 tools/import_audit.py [--src DIR] [--python EXE]
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "sv0cov"
FORBIDDEN_STDLIB = {"ensurepip", "venv", "site", "pkgutil", "runpy", "zipimport", "imp"}
FORBIDDEN_BUILTINS = {"__import__", "exec", "eval", "compile"}
FORBIDDEN_METHODS = {"import_module", "entry_points", "spec_from_file_location", "module_from_spec", "addsitedir"}
FORBIDDEN_IMPORTLIB = {"importlib.util", "importlib.machinery", "importlib.abc"}
ALLOWED_MEMBERS = {".py", ".gitignore"}
VENDOR_NAMES = {"_vendor", "vendor", "vendored", "third_party", "thirdparty", "extern", "_extern", "site-packages"}


def module_name(src: Path, path: Path) -> str:
    parts = list(path.relative_to(src).with_suffix("").parts)
    if parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def static_audit(src: Path) -> tuple[list[str], set[str]]:
    violations: list[str] = []
    modules: set[str] = set()
    pkg = src / PACKAGE
    for path in sorted(pkg.rglob("*")):
        rel = path.relative_to(src).as_posix()
        if "__pycache__" in path.parts:
            continue
        if path.is_dir():
            if path.name in VENDOR_NAMES or path.name.endswith((".dist-info", ".egg-info")):
                violations.append(f"{rel}: vendored or distribution directory")
            continue
        if path.suffix not in ALLOWED_MEMBERS and path.name not in ALLOWED_MEMBERS:
            violations.append(f"{rel}: non-Python member")
            continue
        if path.suffix != ".py":
            continue
        name = module_name(src, path)
        modules.add(name)
        tree = ast.parse(path.read_bytes(), filename=rel)
        for node in ast.walk(tree):
            for target in _imports(node, name, path.name == "__init__.py"):
                if target is None:
                    violations.append(f"{rel}:{node.lineno}: relative import escapes the package")
                    continue
                top = target.split(".")[0]
                if top == PACKAGE:
                    continue
                elif top not in sys.stdlib_module_names:
                    violations.append(f"{rel}:{node.lineno}: third-party import {target!r}")
                elif top in FORBIDDEN_STDLIB or any(target == f or target.startswith(f + ".") for f in FORBIDDEN_IMPORTLIB):
                    violations.append(f"{rel}:{node.lineno}: forbidden dynamic-loading or installer module {target!r}")
            if isinstance(node, ast.Call):
                fn = node.func
                if isinstance(fn, ast.Name) and fn.id in FORBIDDEN_BUILTINS | FORBIDDEN_METHODS or isinstance(fn, ast.Attribute) and fn.attr in FORBIDDEN_METHODS:
                    called = fn.id if isinstance(fn, ast.Name) else fn.attr
                    violations.append(f"{rel}:{node.lineno}: forbidden dynamic call {called}()")
    return violations, modules


def _imports(node: ast.AST, module: str, is_package: bool) -> list:
    if isinstance(node, ast.Import):
        return [a.name for a in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    if node.level == 0:
        base = node.module or ""
        return [base] + [f"{base}.{a.name}" for a in node.names if base == "importlib"]
    parts = module.split(".")
    if not is_package:
        parts = parts[:-1]
    if node.level - 1 > len(parts) - 1:
        return [None]
    anchor = parts[: len(parts) - (node.level - 1)]
    return [".".join(anchor + ([node.module] if node.module else []))]


# Runs inside the audited interpreter; prints one JSON object.
HARNESS = r'''
import io, json, os, sys, sysconfig
src, poison, modules = sys.argv[1], sys.argv[2], json.loads(sys.argv[3])
if poison:
    import site
    site.addsitedir(poison)
sys.path.insert(0, src)
import importlib
for name in modules:
    importlib.import_module(name)
from sv0cov import cli
for argv in (["version"], ["version", "--json"], ["version", "--bogus"], [], ["no-such-command"]):
    out, err = io.TextIOWrapper(io.BytesIO(), encoding="utf-8"), io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
    real = sys.stdout, sys.stderr
    sys.stdout, sys.stderr = out, err
    try:
        cli.main(argv)
    except BaseException:  # the audit is about imports; command errors are the CLI tests' concern
        pass
    finally:
        sys.stdout, sys.stderr = real
stdlib_dirs = sorted({os.path.realpath(sysconfig.get_path(k)) for k in ("stdlib", "platstdlib")})
pkg_dir = os.path.realpath(os.path.join(src, "sv0cov"))
report = {}
for name, mod in sorted(sys.modules.items()):
    if mod is None:
        continue
    origin = getattr(getattr(mod, "__spec__", None), "origin", None) or getattr(mod, "__file__", None)
    if name in sys.builtin_module_names or origin in ("built-in", "frozen", None):
        kind = "builtin"
    else:
        path = os.path.realpath(origin)
        if os.path.commonpath([path, pkg_dir]) == pkg_dir:
            kind = "project"
        elif any(os.path.commonpath([path, d]) == d and "site-packages" not in os.path.relpath(path, d).split(os.sep) for d in stdlib_dirs):
            kind = "stdlib"
        else:
            kind = "other:" + path
    report[name] = kind
print(json.dumps(report))
'''


def runtime_audit(src: Path, python: str, modules: set[str], *, poison: Path | None = None, no_site: bool = False) -> tuple[list[str], set[str]]:
    flags = ["-I", "-B"] + (["-S"] if no_site else [])
    cmd = [python, *flags, "-c", HARNESS, str(src), str(poison or ""), json.dumps(sorted(modules))]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return [f"runtime harness failed: {r.stderr.strip()[-2000:]}"], set()
    report = json.loads(r.stdout)
    violations = []
    loaded = set()
    for name, kind in report.items():
        top = name.split(".")[0]
        if top == PACKAGE:
            loaded.add(name)
            if kind != "project":
                violations.append(f"runtime: {name} loaded from outside the checkout ({kind})")
        elif kind == "project":
            violations.append(f"runtime: non-sv0cov module {name} loaded from the package tree")
        elif kind.startswith("other:"):
            violations.append(f"runtime: third-party or shadowed module {name} ({kind})")
    return violations, loaded


def audit(src: Path, python: str, *, poison: Path | None = None, no_site: bool = False) -> list[str]:
    violations, modules = static_audit(src)
    rt_violations, loaded = runtime_audit(src, python, modules, poison=poison, no_site=no_site)
    violations += rt_violations
    if not rt_violations and loaded != modules:
        violations.append(f"static and runtime closures disagree: static-only {sorted(modules - loaded)}, runtime-only {sorted(loaded - modules)}")
    return violations


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", type=Path, default=ROOT / "src")
    ap.add_argument("--python", default=os.path.realpath(sys.executable))
    ap.add_argument("--poison-site", type=Path)
    ap.add_argument("--no-site", action="store_true")
    args = ap.parse_args()
    violations = audit(args.src.resolve(), args.python, poison=args.poison_site, no_site=args.no_site)
    for v in violations:
        print(f"import audit: {v}", file=sys.stderr)
    if violations:
        return 1
    print("import audit: production closure is stdlib + sv0cov")
    return 0


if __name__ == "__main__":
    sys.exit(main())
