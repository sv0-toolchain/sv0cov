# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Line coverage derivation (CV-202, BL-021; SPEC 11.4, COV-MET-003).

The partial-line matrix over small hand-built maps: covered, partial,
uncovered, and non_executable lines; a line held only by a container or an
unreachable region; non-user regions ignored; physical-line counting (no
final newline, CRLF, empty source); the line metric (partial is not
covered); and the CLI on the f0 fixture through a real raw profile. sv0c's
run_lines.py checks the same derivation on real native and VM runs.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from sv0cov.lines import line_metric, line_records, line_statuses, main, physical_lines  # noqa: E402
from test_resolve import by_counter, fixture, profile  # noqa: E402

SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"


def region(i: int, lines: list[int], point: str | None, lc: bool = True, cls: str = "user") -> dict:
    terms = [] if point is None else [{"coefficient": 1, "point_id": point}]
    return {"classification": cls, "counter_expression": {"terms": terms}, "line_contributing": lc,
            "line_numbers": lines, "region_index": i, "source_index": 0}


def one_source(regions: list[dict]) -> dict:
    return {"regions": regions, "sources": [{"path": "main.sv0", "source_index": 0}]}


class LinesTest(unittest.TestCase):
    def test_partial_line_matrix(self) -> None:
        counts = {"ran": 2, "idle": 0, "a": 3, "b": 3}
        m = one_source([
            region(0, [1], "ran"),                      # line 1: one region, executed
            region(1, [2], "ran"), region(2, [2], "idle"),  # line 2: one of two
            region(3, [3], "idle"),                     # line 3: none executed
            region(4, [4, 5, 6], "ran", lc=False),      # container: no line of its own
            region(5, [5], "idle"),                     # line 5: inside the container
            region(6, [7], None, lc=False, cls="statically_unreachable"),
            region(7, [8], "ran", cls="synthetic_support"),  # not a user region
            region(8, [9], "a") | {"counter_expression": {"terms": [  # a - b == 0
                {"coefficient": 1, "point_id": "a"}, {"coefficient": -1, "point_id": "b"}]}},
        ])
        statuses = line_statuses(m, counts, {"main.sv0": b"x\n" * 9})
        self.assertEqual(statuses["main.sv0"], [
            "covered", "partial", "uncovered", "non_executable", "uncovered",
            "non_executable", "non_executable", "non_executable", "uncovered"])

    def test_records(self) -> None:
        m = one_source([region(0, [1, 2], "p"), region(1, [2], "q")])
        recs = line_records(m, {"p": 1, "q": 0}, {"main.sv0": b"a\nb\n\n"})
        self.assertEqual(recs, [
            {"line": 1, "line_index": 0, "region_indices": [0], "source_index": 0, "status": "covered"},
            {"line": 2, "line_index": 1, "region_indices": [0, 1], "source_index": 0, "status": "partial"},
            {"line": 3, "line_index": 2, "region_indices": [], "source_index": 0, "status": "non_executable"},
        ])
        self.assertEqual(line_metric(recs), {"covered": 1, "partial": 1, "total": 2})

    def test_physical_lines(self) -> None:
        self.assertEqual(physical_lines(b""), 0)
        self.assertEqual(physical_lines(b"a"), 1)
        self.assertEqual(physical_lines(b"a\n"), 1)
        self.assertEqual(physical_lines(b"a\r\nb\r\n"), 2)
        self.assertEqual(physical_lines(b"a\n\nb"), 3)

    def test_sources_in_index_order(self) -> None:
        m = {"regions": [region(0, [1], "p") | {"source_index": 1}],
             "sources": [{"path": "b.sv0", "source_index": 1}, {"path": "a.sv0", "source_index": 0}]}
        recs = line_records(m, {"p": 1}, {"a.sv0": b"x\n", "b.sv0": b"y\n"})
        self.assertEqual([(r["source_index"], r["status"]) for r in recs], [(0, "non_executable"), (1, "covered")])
        self.assertEqual([r["line_index"] for r in recs], [0, 1])

    def test_cli_on_f0(self) -> None:
        data, m, expected = fixture("f0")
        counts = {c["point_id"]: c["count"] for c in expected["counts"]}
        source = (SEMANTIC / "f0" / "main.sv0").read_bytes()
        want = line_statuses(m, counts, {"main.sv0": source})["main.sv0"]
        self.assertIn("partial", want)
        with TemporaryDirectory() as td:
            prof = Path(td) / "a.sv0profraw"
            prof.write_bytes(profile(m, by_counter(m, counts)))
            out = io.StringIO()
            with redirect_stdout(out):
                rc = main([str(SEMANTIC / "f0" / "expected-map.json"), str(SEMANTIC / "f0"), str(prof)])
        self.assertEqual(rc, 0)
        self.assertEqual(out.getvalue().splitlines(), [f"main.sv0:{i} {s}" for i, s in enumerate(want, 1)])
        self.assertEqual(json.loads(data)["map_id"], m["map_id"])


if __name__ == "__main__":
    unittest.main()
