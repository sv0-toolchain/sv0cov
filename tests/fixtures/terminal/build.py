# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Golden terminal reports (CV-230; SPEC 21.1; COV-REP-001).

One colorless ``.txt`` per report: the four hand-built native reports in
``tests/fixtures/report`` and one report built from each semantic fixture.
``python3 tests/fixtures/terminal/build.py`` checks them; ``--write``
regenerates them.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_reader import FIXTURES  # noqa: E402
from test_report import fixture_report  # noqa: E402

from sv0cov.formats.terminal import terminal_bytes  # noqa: E402

STRUCTURE = ("empty", "passing", "all-kinds", "bounds")


def reports() -> dict[str, dict]:
    out = {f"structure-{name}": json.loads((ROOT / "tests" / "fixtures" / "report" / f"{name}.json").read_bytes())
           for name in STRUCTURE}
    for name in FIXTURES:
        out[f"fixture-{name}"] = fixture_report(name)[0]
    return out


def artifacts() -> dict[Path, bytes]:
    return {HERE / f"{name}.txt": terminal_bytes(report) for name, report in reports().items()}


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print("stale terminal goldens: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("terminal goldens: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
