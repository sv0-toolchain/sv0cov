# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Hand-reviewed semantic fixtures (CV-027, CV-028; SPEC 28.2, 28.3).

- The checked-in expected maps, counts, and index are current.
- Every expected map passes the full map validator with its source bytes
  (this is also CV-018's acceptance of the F0 map).
- Line statuses recomputed from each map and its expected counts (SPEC
  11.4) equal the statuses derived by hand in the fixture definition.
"""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tests" / "fixtures" / "semantic"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

from fixtures import FIXTURES  # noqa: E402

from sv0cov.formats.map import validate_map  # noqa: E402

MATRIX_ROWS = {"functions", "regions", "if", "loops", "match", "source text", "projects"}


def line_statuses(m: dict, counts: dict[str, int], sources: dict[str, bytes]) -> dict[str, list[str]]:
    """SPEC 11.4 line status from region expressions and point counts."""
    out = {}
    for s in m["sources"]:
        data = sources[s["path"]]
        n_lines = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
        statuses = []
        for line in range(1, n_lines + 1):
            regions = [
                r for r in m["regions"]
                if r["source_index"] == s["source_index"] and r["line_contributing"]
                and r["classification"] == "user" and line in r["line_numbers"]
            ]
            if not regions:
                statuses.append("non_executable")
                continue
            executed = [sum(t["coefficient"] * counts[t["point_id"]] for t in r["counter_expression"]["terms"]) > 0 for r in regions]
            statuses.append("covered" if all(executed) else "partial" if any(executed) else "uncovered")
        out[s["path"]] = statuses
    return out


class SemanticFixtureTest(unittest.TestCase):
    def test_artifacts_are_current(self) -> None:
        result = subprocess.run([sys.executable, str(HERE / "build.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_fixture(self) -> None:
        for name, make in FIXTURES.items():
            with self.subTest(fixture=name):
                fx = make()
                data = (HERE / name / "expected-map.json").read_bytes()
                m = validate_map(data, sources=fx.plan.sources)
                expected = json.loads((HERE / name / "expected-counts.json").read_bytes())
                self.assertEqual(expected["map_id"], m["map_id"])
                counts = {c["point_id"]: c["count"] for c in expected["counts"]}
                self.assertEqual(set(counts), {p["point_id"] for p in m["points"] if p["counter_index"] is not None})
                self.assertEqual(line_statuses(m, counts, fx.plan.sources), fx.lines)

    def test_index_covers_the_r0_matrix(self) -> None:
        index = json.loads((HERE / "index.json").read_bytes())
        rows = {entry.split(":")[0] for f in index["fixtures"] for entry in f["matrix"]}
        self.assertLessEqual(MATRIX_ROWS, rows, f"missing SPEC 28.2 rows: {MATRIX_ROWS - rows}")

    def test_f0_by_hand(self) -> None:
        m = json.loads((HERE / "f0" / "expected-map.json").read_bytes())
        self.assertEqual(m["program_counter_count"], 9)  # 3 entries + 2 if + 2 loop + 2 match arms
        self.assertEqual([b["kind"] for b in m["branches"]], ["if", "loop", "match"])
        arm0 = next(r for r in m["regions"] if r["kind"] == "match_arm")
        self.assertEqual((arm0["span"]["start_line"], arm0["span"]["start_column"]), (24, 21))
        counts = json.loads((HERE / "f0" / "expected-counts.json").read_bytes())
        self.assertEqual(sum(c["count"] for c in counts["counts"]), 1 + 1 + 3 + 1 + 1 + 1 + 1)


if __name__ == "__main__":
    unittest.main()
