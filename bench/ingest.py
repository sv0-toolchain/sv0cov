#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Provisional ingest measurement for merge/report-scale fixtures (CV-036/037).

Validates ``scale.sv0covmap.json`` against ``scale.sv0`` and decodes every
``*.sv0profraw`` bound to that map: the input side of merge and report,
measurable before those commands exist. Run as ``python -I -B bench/ingest.py DIR``.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats import rawprofile as RP  # noqa: E402
from sv0cov.formats.canonical_json import Limits  # noqa: E402
from sv0cov.formats.map import validate_map  # noqa: E402


def main() -> int:
    d = Path(sys.argv[1])
    # The same explicit bound as bench/corpus.py (pending decision D-8).
    limits = Limits(max_bytes=1024 * 1024 * 1024)
    m = validate_map((d / "scale.sv0covmap.json").read_bytes(), sources={"scale.sv0": (d / "scale.sv0").read_bytes()}, limits=limits)
    map_id = bytes.fromhex(m["map_id"])
    total = 0
    for raw in sorted(d.glob("*.sv0profraw")):
        p = RP.decode(raw.read_bytes(), map_counter_count=m["program_counter_count"], expected_map_id=map_id)
        total += len(p.counts)
    return 0 if total else 1


if __name__ == "__main__":
    sys.exit(main())
