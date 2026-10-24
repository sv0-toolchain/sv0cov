# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The `sv0cov-cobertura-r1-core` goldens (CV-402): one document per semantic
fixture. `--write` regenerates them; without it, any difference fails."""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES  # noqa: E402
from test_report import fixture_report  # noqa: E402

from sv0cov.formats.cobertura import render_cobertura  # noqa: E402


def artifacts() -> dict[Path, bytes]:
    return {HERE / f"{name}.xml": render_cobertura(fixture_report(name)[0]) for name in FIXTURES}


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print(f"cobertura goldens: stale: {', '.join(stale)} (run with --write)", file=sys.stderr)
        return 1
    print("cobertura goldens: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
