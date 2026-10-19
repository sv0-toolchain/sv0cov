# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Golden doctor reports (CV-022; SPEC 20.7).

The two goldens in this directory are built by ``GOLDENS`` in
``tests/test_manifests.py``: a standalone pass and a toolchain run that fails
at D012. ``python3 tests/fixtures/doctor/build.py`` checks them; ``--write``
regenerates them.
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_manifests import GOLDENS  # noqa: E402


def artifacts() -> dict[Path, bytes]:
    return {HERE / name: make() for name, make in GOLDENS.items()}


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print("stale doctor goldens: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("doctor goldens: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
