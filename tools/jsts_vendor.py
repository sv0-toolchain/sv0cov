#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Vendored JSON Schema Test Suite: materialize and verify (CV-012, SPEC 25.2.4).

The complete tracked tree of https://github.com/json-schema-org/JSON-Schema-Test-Suite.git
at one full commit lives at ``tests/vendor/json-schema-test-suite/`` and is
bound by the canonical manifest ``tests/vendor/json-schema-test-suite.manifest.json``.

``verify`` (default; offline, used by tests and CI)
    Every manifest entry exists with the recorded type, mode, size, and SHA-256
    (symlinks: exact target bytes, never followed); nothing else exists under
    the vendor root; no entry is unsafe.

``materialize CLONE``
    Explicit maintainer operation: copy every tracked entry of ``CLONE``'s
    ``HEAD`` into the vendor root (after the maintainer has fetched and
    reviewed the proposed commit) and rewrite the manifest. Never run by tests.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import unicodedata
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402

REPOSITORY = "https://github.com/json-schema-org/JSON-Schema-Test-Suite.git"
VENDOR = ROOT / "tests" / "vendor" / "json-schema-test-suite"
MANIFEST = ROOT / "tests" / "vendor" / "json-schema-test-suite.manifest.json"
MODES = {"100644": "blob", "100755": "blob", "120000": "symlink"}


def _git(repo: Path, *args: str) -> bytes:
    return subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True).stdout


def _check_path(rel: str) -> list[str]:
    problems = []
    p = PurePosixPath(rel)
    if p.is_absolute() or any(part in ("", ".", "..") for part in rel.split("/")) or "\\" in rel:
        problems.append(f"{rel}: unsafe path")
    if unicodedata.normalize("NFC", rel) != rel:
        problems.append(f"{rel}: path is not NFC")
    return problems


def _check_link(rel: str, target: str) -> list[str]:
    if target.startswith("/"):
        return [f"{rel}: absolute symlink"]
    resolved = PurePosixPath(rel).parent
    for part in target.split("/"):
        if part == "..":
            if resolved == PurePosixPath("."):
                return [f"{rel}: symlink escapes the vendor root"]
            resolved = resolved.parent
        elif part not in ("", "."):
            resolved = resolved / part
    return []


def materialize(clone: Path) -> dict:
    commit = _git(clone, "rev-parse", "HEAD").decode().strip()
    tree = _git(clone, "rev-parse", "HEAD^{tree}").decode().strip()
    status = _git(clone, "status", "--porcelain").decode()
    if status:
        raise SystemExit("clone has local changes; refusing to vendor")
    listing = _git(clone, "ls-tree", "-r", "-z", "--full-tree", "HEAD").split(b"\0")
    entries = []
    problems: list[str] = []
    seen_folded: dict[str, str] = {}
    if VENDOR.exists():
        shutil.rmtree(VENDOR)
    for raw in filter(None, listing):
        meta, path_b = raw.split(b"\t", 1)
        mode, kind, _obj = meta.decode().split(" ")
        rel = path_b.decode("utf-8")
        if mode not in MODES or kind != "blob":
            problems.append(f"{rel}: unsupported entry mode {mode} {kind}")
            continue
        problems += _check_path(rel)
        folded = unicodedata.normalize("NFC", rel).casefold()
        if folded in seen_folded:
            problems.append(f"{rel}: collides with {seen_folded[folded]} under case/Unicode folding")
        seen_folded[folded] = rel
        data = _git(clone, "cat-file", "blob", f"HEAD:{rel}")
        dest = VENDOR / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        entry = {"mode": mode, "path": rel, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        if mode == "120000":
            target = data.decode("utf-8")
            problems += _check_link(rel, target)
            os.symlink(target, dest)
            entry["link_target"] = target
            entry["type"] = "symlink"
        else:
            dest.write_bytes(data)
            os.chmod(dest, 0o755 if mode == "100755" else 0o644)
            entry["link_target"] = None
            entry["type"] = "blob"
        entries.append(entry)
    if problems:
        raise SystemExit("unsafe upstream tree:\n" + "\n".join(problems))
    entries.sort(key=lambda e: e["path"].encode("utf-8"))
    license_entry = next(e for e in entries if e["path"] == "LICENSE")
    manifest = {
        "commit": commit,
        "entries": entries,
        "license": {"file": "LICENSE", "sha256": license_entry["sha256"], "spdx": "MIT"},
        "repository": REPOSITORY,
        "schema": "sv0cov.vendor-manifest",
        "tree": tree,
        "version": "1.0",
    }
    MANIFEST.write_bytes(encode(manifest))
    return manifest


def load_manifest() -> dict:
    return decode_canonical(MANIFEST.read_bytes())


def verify(manifest: dict | None = None, root: Path = VENDOR) -> list[str]:
    """Compare the vendored tree with the manifest. Returns problems (empty = OK)."""
    m = manifest or load_manifest()
    problems: list[str] = []
    expected = {}
    paths = [e["path"] for e in m["entries"]]
    if paths != sorted(paths, key=lambda p: p.encode("utf-8")) or len(set(paths)) != len(paths):
        problems.append("manifest entries must be unique and sorted by UTF-8 path")
    for e in m["entries"]:
        rel = e["path"]
        expected[rel] = e
        problems += _check_path(rel)
        p = root / rel
        if e["type"] == "symlink":
            problems += _check_link(rel, e["link_target"])
            if not p.is_symlink():
                problems.append(f"{rel}: expected a symlink")
            elif os.readlink(p) != e["link_target"]:
                problems.append(f"{rel}: symlink target changed")
            continue
        if p.is_symlink() or not p.is_file():
            problems.append(f"{rel}: missing or not a regular file")
            continue
        st = p.lstat()
        if st.st_nlink != 1:
            problems.append(f"{rel}: hard link")
        executable = bool(st.st_mode & stat.S_IXUSR)
        if executable != (e["mode"] == "100755"):
            problems.append(f"{rel}: executable bit does not match mode {e['mode']}")
        data = p.read_bytes()
        if len(data) != e["size"] or hashlib.sha256(data).hexdigest() != e["sha256"]:
            problems.append(f"{rel}: content changed")
    if root.exists():
        for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
            for name in filenames + [d for d in dirnames if (Path(dirpath) / d).is_symlink()]:
                rel = (Path(dirpath) / name).relative_to(root).as_posix()
                if "__pycache__" in rel:
                    continue
                if rel not in expected:
                    problems.append(f"{rel}: not in the manifest")
            for d in list(dirnames):
                full = Path(dirpath) / d
                if full.is_symlink():
                    dirnames.remove(d)
                elif not any(e.startswith((full.relative_to(root).as_posix() + "/")) for e in expected):
                    problems.append(f"{full.relative_to(root).as_posix()}/: directory not in the manifest")
                    dirnames.remove(d)
    else:
        problems.append("vendor root is missing")
    lic = m["license"]
    if lic != {"file": "LICENSE", "sha256": expected.get("LICENSE", {}).get("sha256"), "spdx": "MIT"}:
        problems.append("license record does not match the vendored LICENSE")
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("verify")
    mat = sub.add_parser("materialize")
    mat.add_argument("clone", type=Path)
    args = ap.parse_args(argv)
    if args.cmd == "materialize":
        m = materialize(args.clone)
        print(f"vendored {len(m['entries'])} entries at {m['commit']}")
    problems = verify()
    for p in problems:
        print(f"jsts_vendor: {p}", file=sys.stderr)
    if problems:
        return 1
    print("jsts_vendor: vendored tree matches the manifest")
    return 0


if __name__ == "__main__":
    sys.exit(main())
