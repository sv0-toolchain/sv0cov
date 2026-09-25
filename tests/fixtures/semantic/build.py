#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Build or check the semantic fixtures' expected artifacts.

For each fixture directory: ``expected-map.json`` (canonical sv0cov.map 1.0)
and ``expected-counts.json`` (per-point counts for the fixed input). Also
``index.json`` (fixtures, exit codes, SPEC 28.2 rows exercised).

    python3 tests/fixtures/semantic/build.py            # check (exit 1 if stale)
    python3 tests/fixtures/semantic/build.py --write    # rewrite after review
"""

from __future__ import annotations

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from fixtures import FIXTURES  # noqa: E402
from plan import dump  # noqa: E402


def artifacts() -> dict[Path, bytes]:
    out: dict[Path, bytes] = {}
    index = []
    for name, make in FIXTURES.items():
        fx = make()
        m = fx.plan.build()
        out[HERE / name / "expected-map.json"] = dump(m)
        out[HERE / name / "expected-counts.json"] = dump(
            {"counts": fx.plan.counts(fx.counts), "exit_code": fx.exit_code, "fixture": name, "map_id": m["map_id"]}
        )
        index.append({"exit_code": fx.exit_code, "fixture": name, "map_id": m["map_id"], "matrix": sorted(fx.matrix), "sources": sorted(fx.plan.sources)})
    out[HERE / "index.json"] = dump({"fixtures": index, "schema": "sv0cov.semantic-fixture-index", "version": "1.0"})
    return out


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(str(path.relative_to(HERE)))
    if stale:
        print("stale semantic fixture artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("semantic fixtures: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
