#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""LCOV consumer conformance for ``sv0cov-lcov-r1-core`` (CV-418; SPEC 21.4;
COV-REP-009, AC-050, R1-G4).

For each pinned LCOV distribution and each tracefile golden in
``tests/fixtures/lcov/``, this runs ``lcov --summary`` and ``genhtml`` with
branch coverage enabled, in a scratch copy of the fixture's sources (genhtml
reads them), and requires:

- both commands exit 0 with no warning, error, ignored-error or message
  line in their output (LCOV 2.x's "Message summary" must say none were
  reported);
- both commands' function, line and branch totals equal the tracefile's own
  totals (``parse_lcov``), which equal the native report's.

The distributions are the release tarballs, verified against the digests in
``tests/conformance/lcov-distributions.json`` before anything is extracted,
and run straight from their ``bin/`` with the host ``perl``. Nothing here
touches the network: fetching the tarballs is a separate, explicit step
(``--fetch-into DIR`` prints the commands; CI runs them).

    python3 tools/lcov_conformance.py --tarball 1.16=PATH --tarball 2.5=PATH
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.lcov import parse_lcov  # noqa: E402

PINS = ROOT / "tests" / "conformance" / "lcov-distributions.json"
GOLDENS = ROOT / "tests" / "fixtures" / "lcov"
SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"
TOTAL = re.compile(r"^\s*(lines|functions|branches)\.*:\s*(?:[\d.]+%|no data found)\s*(?:\((\d+) of (\d+) \w+\))?", re.M)
TROUBLE = re.compile(r"(?i)\b(warning|error|ignored|ignoring|skipping|unexpected|inconsistent|mismatch)\b")


def pins() -> dict:
    return json.loads(PINS.read_text())


def unpack(version: str, tarball: Path, into: Path) -> Path:
    """The verified distribution's directory (``lcov-<version>``)."""
    want = pins()["distributions"][version]
    data = tarball.read_bytes()
    if (len(data), hashlib.sha256(data).hexdigest()) != (want["size"], want["sha256"]):
        raise SystemExit(f"lcov {version}: {tarball} is not the pinned distribution (size/digest mismatch)")
    with tarfile.open(tarball) as tf:
        tf.extractall(into, filter="data")
    top = into / f"lcov-{version}"
    if not (top / "bin" / "lcov").is_file():
        raise SystemExit(f"lcov {version}: no bin/lcov in the distribution")
    return top


def branch_flags(version: str) -> list[str]:
    return ["--rc", "lcov_branch_coverage=1"] if version.startswith("1.") else ["--branch-coverage"]


def totals(text: str) -> dict[str, tuple[int, int]]:
    out = {}
    for name, hit, found in TOTAL.findall(text):
        out[{"lines": "line", "functions": "function", "branches": "branch"}[name]] = (int(hit or 0), int(found or 0))
    return out


def check_one(version: str, dist: Path, name: str, work: Path) -> list[str]:
    errors = []
    case = work / f"{version}-{name}"
    shutil.copytree(SEMANTIC / name, case, ignore=shutil.ignore_patterns("*.json", "__pycache__"))
    info = case / f"{name}.info"
    shutil.copyfile(GOLDENS / f"{name}.info", info)
    recs = parse_lcov(info.read_bytes())
    want = {m: (sum(r[m][0] for r in recs), sum(r[m][1] for r in recs)) for m in ("line", "function", "branch")}
    env = {"PATH": "/usr/bin:/bin", "LC_ALL": "C", "HOME": str(case)}
    runs = {
        "lcov --summary": ["perl", str(dist / "bin" / "lcov"), "--summary", info.name, *branch_flags(version)],
        "genhtml": ["perl", str(dist / "bin" / "genhtml"), *branch_flags(version), "--output-directory", "html", info.name],
    }
    for what, argv in runs.items():
        p = subprocess.run(argv, cwd=case, env=env, capture_output=True, text=True, timeout=300)
        text = p.stdout + p.stderr
        where = f"lcov {version} {what} {name}"
        if p.returncode != 0:
            errors.append(f"{where}: exit {p.returncode}: {text.strip()[-600:]}")
            continue
        bad = [line for line in text.splitlines() if TROUBLE.search(line) and "no messages were reported" not in line]
        if bad:
            errors.append(f"{where}: {bad[:3]}")
        if version.startswith("2.") and "no messages were reported" not in text:
            errors.append(f"{where}: LCOV reported messages: {text.strip()[-400:]}")
        got = totals(text)
        for metric, (hit, found) in want.items():
            g = got.get(metric, (0, 0))
            if found == 0 and metric not in got:
                continue  # LCOV leaves an empty metric out of its summary
            if g != (hit, found):
                errors.append(f"{where}: {metric} {g[0]}/{g[1]}, the tracefile says {hit}/{found}")
        if what == "genhtml" and not (case / "html" / "index.html").is_file():
            errors.append(f"{where}: no index.html was written")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--tarball", action="append", default=[], metavar="VERSION=PATH")
    ap.add_argument("--fetch-into", metavar="DIR", help="print the commands that fetch the pinned tarballs into DIR, and exit")
    args = ap.parse_args(argv)
    if args.fetch_into:
        for version, d in pins()["distributions"].items():
            print(f"curl -sSfL --proto '=https' -o {args.fetch_into}/lcov-{version}.tar.gz {d['url']}")
        return 0
    if not args.tarball:
        ap.error("give --tarball VERSION=PATH for every pinned version")
    given = dict(t.split("=", 1) for t in args.tarball)
    if sorted(given) != sorted(pins()["distributions"]):
        ap.error(f"exactly the pinned versions are required: {sorted(pins()['distributions'])}")
    names = sorted(p.stem for p in GOLDENS.glob("*.info"))
    errors: list[str] = []
    with tempfile.TemporaryDirectory() as td:
        work = Path(td)
        for version in sorted(given):
            dist = unpack(version, Path(given[version]), work / f"dist-{version}")
            for name in names:
                errors += check_one(version, dist, name, work)
    for e in errors:
        print(f"lcov conformance: FAIL: {e}", file=sys.stderr)
    if not errors:
        print(f"lcov conformance: OK ({len(names)} goldens x {len(given)} LCOV versions, lcov --summary and genhtml)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
