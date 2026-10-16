# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Parser fuzzing and resource limits (CV-236; SPEC 28.4; COV-SEC-004,
COV-FMT-022).

Every regression input found by ``tools/fuzz.py`` is replayed; every harness
handles its seeds and a short deterministic fuzz run without a finding; the
fuzzer's own rules (crash, hang, memory, unregistered code) are shown to
work; and the declared sizes and spans that once made a reader allocate
without bound are pinned.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

_spec = importlib.util.spec_from_file_location("sv0cov_fuzz_tool", ROOT / "tools" / "fuzz.py")
fuzz = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = fuzz  # dataclasses look their module up while the class is created
_spec.loader.exec_module(fuzz)

from sv0cov import expr  # noqa: E402
from sv0cov.formats import rawprofile  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.map import MapError, map_id, validate_map  # noqa: E402

REGRESSIONS = ROOT / "tests" / "fixtures" / "fuzz"
#: Iterations per harness in the unit suite; CI's fuzz job runs far longer with a fresh seed.
QUICK = 150


def peak(fn) -> tuple[int, float, object]:
    """Peak traced allocation and seconds of ``fn()``, and what it returned or raised."""
    tracemalloc.start()
    start = time.monotonic()
    try:
        out = fn()
    except Exception as exc:  # noqa: BLE001 - the caller inspects it
        out = exc
    finally:
        _, top = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    return top, time.monotonic() - start, out


class RegressionTest(unittest.TestCase):
    def test_every_regression_input_is_handled(self) -> None:
        paths = sorted(REGRESSIONS.glob("*/*.bin"))
        self.assertGreaterEqual(len(paths), 2)
        self.assertTrue(all(p.parent.name in fuzz.HARNESSES for p in paths))
        self.assertEqual(fuzz.replay(REGRESSIONS), [])


class HarnessTest(unittest.TestCase):
    def test_the_harness_inventory(self) -> None:
        self.assertEqual(sorted(fuzz.HARNESSES), ["compatibility", "doctor", "expr", "indexed", "json", "manifest", "map", "merge",
                                                  "rawprofile", "registry", "release", "report", "runset"])

    def test_every_harness_handles_its_seeds_and_a_short_run(self) -> None:
        for name, harness in sorted(fuzz.HARNESSES.items()):
            with self.subTest(harness=name):
                seeds = harness.seeds()
                self.assertTrue(seeds)
                for s in seeds:
                    fuzz.check(harness, s)
                findings = fuzz.fuzz([name], seed=236, iterations=QUICK // (5 if name == "merge" else 1), seconds=None, crash_dir=None,
                                     log=lambda _line: None)
                self.assertEqual(findings, [])

    def test_fix_ups_reach_past_the_digests(self) -> None:
        """Without them nearly every mutation would stop at a checksum or a self-digest."""
        import random

        h = fuzz.HARNESSES["rawprofile"]
        seed = h.seeds()[0]
        mutated = fuzz._mutate_bytes(random.Random(1), seed, [])
        fixed = h.fix_bytes(mutated)
        try:
            rawprofile.decode(fixed)
        except rawprofile.RawProfileError as exc:
            self.assertNotEqual(exc.code, "COV2012")  # the checksum is not what stopped it
        m = json.loads(fuzz.HARNESSES["map"].seeds()[0])
        m["target"]["name"] = "renamed"
        fuzz.HARNESSES["map"].fix_tree(m)
        self.assertEqual(m["map_id"], map_id(m))


class OracleTest(unittest.TestCase):
    """The fuzzer's rules work: a wrong exception, a hang, unbounded memory and an unregistered code are findings."""

    def harness(self, target, errors=(ValueError,)) -> fuzz.Harness:
        return fuzz.Harness("probe", lambda: [b"x"], target, errors)

    def signature(self, harness, data=b"x", **kw) -> str | None:
        try:
            fuzz.check(harness, data, **kw)
        except fuzz.Finding as f:
            return f.signature
        return None

    def test_rules(self) -> None:
        self.assertIsNone(self.signature(self.harness(lambda d: None)))
        self.assertIsNone(self.signature(self.harness(lambda d: (_ for _ in ()).throw(ValueError("documented")))))
        self.assertTrue(self.signature(self.harness(lambda d: {}["k"])).startswith("probe/KeyError@"))
        self.assertEqual(self.signature(self.harness(lambda d: self.recurse())), "probe/RecursionError")

        class Coded(ValueError):
            code = "COV9999"

        self.assertEqual(self.signature(self.harness(lambda d: (_ for _ in ()).throw(Coded()), (Coded,))), "probe/code:COV9999")
        with mock.patch.object(fuzz, "TIME_LIMIT", 0.2):
            self.assertEqual(self.signature(self.harness(lambda d: time.sleep(5))), "probe/hang")
        self.assertEqual(self.signature(self.harness(lambda d: bytearray(fuzz.BASE + 1 << 1)), measure=True), "probe/memory")

    def recurse(self):
        return self.recurse()

    def test_minimize_keeps_the_finding_and_drops_the_rest(self) -> None:
        h = self.harness(lambda d: {}["k"] if b"!" in d else None)
        small = fuzz.minimize(h, b"abc!def" * 20, self.signature(h, b"!"))
        self.assertEqual(small, b"!")

    def test_findings_are_written_minimized(self) -> None:
        import tempfile

        h = fuzz.Harness("probe", lambda: [b"seed"], lambda d: {}["k"] if b"\xff" in d else None, (ValueError,))
        with tempfile.TemporaryDirectory() as tmp, mock.patch.dict(fuzz.HARNESSES, {"probe": h}):
            findings = fuzz.fuzz(["probe"], seed=1, iterations=400, seconds=None, crash_dir=Path(tmp), log=lambda _l: None)
            self.assertEqual(len(findings), 1)
            name, signature, path = findings[0]
            self.assertEqual((name, path.read_bytes()), ("probe", b"\xff"))
            self.assertTrue(signature.startswith("probe/KeyError@"))


class ResourceLimitTest(unittest.TestCase):
    """COV-FMT-022: a declared size or span is not trusted before it is checked."""

    def test_a_map_declaring_billions_of_counters_is_refused_cheaply(self) -> None:
        """The first CV-236 finding: ``program_counter_count`` drove an allocation of its own size."""
        m = json.loads(fuzz.HARNESSES["map"].seeds()[0])
        for count in (2**31 - 2, 2**32 - 1, len([p for p in m["points"] if p["counter_index"] is not None]) + 1):
            with self.subTest(count=count):
                bad = dict(m, program_counter_count=count)
                bad["map_id"] = map_id(bad)
                top, seconds, out = peak(lambda: validate_map(encode(bad)))
                self.assertIsInstance(out, MapError)
                self.assertEqual(out.code, "COV1015")
                self.assertLess(top, 32 << 20)
                self.assertLess(seconds, 5)

    def test_a_report_span_of_billions_of_lines_is_cheap(self) -> None:
        """Found while sweeping for the same pattern: the line indexes of an exclusion
        enumerated each branch or clause span line by line, in the producer and the reader."""
        from sv0cov.model import report as model

        lines = [{"line": n, "line_index": i, "source_index": 0} for i, n in enumerate((3, 7, 4_000_000_000))]
        r = {"lines": lines, "regions": [{"line_numbers": [3], "source_index": 0}],
             "branches": [{"source_index": 0, "span": {"start_line": 5, "end_line": 2**32 - 1}}],
             "contracts": [{"source_index": 1, "span": {"start_line": 1, "end_line": 2**32 - 1}}]}
        affected = {"region_indices": [0], "branch_indices": [0], "clause_indices": [0]}
        top, seconds, out = peak(lambda: model._line_indices(r, affected))
        self.assertEqual(out, [0, 1, 2])  # the region's line, and both lines inside the branch; the clause is in another source
        self.assertLess(top, 1 << 20)
        self.assertLess(seconds, 1)
        self.assertEqual(model._line_indices(r, {"region_indices": [], "branch_indices": [], "clause_indices": [0]}), [])

    def test_raw_profile_counts_are_checked_against_the_bytes_first(self) -> None:
        seed = fuzz.HARNESSES["rawprofile"].seeds()[0]
        profile = rawprofile.decode(seed)
        at = 80 + 4 + len((profile.context or "").encode())  # pair_count follows the context
        for declared in (2**32 - 1, 2**22, 2**22 + 1):
            with self.subTest(pair_count=declared):
                data = seed[:at] + declared.to_bytes(4, "little") + seed[at + 4:]
                top, seconds, out = peak(lambda: rawprofile.decode(fuzz._fix_raw(data)))
                self.assertIsInstance(out, rawprofile.RawProfileError)
                self.assertIn(out.code, ("COV2011", "COV2110", "COV6001"))
                self.assertLess(top, 8 << 20)

    def test_canonical_json_bounds(self) -> None:
        from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical

        for label, data in (("deep nesting", b"[" * 100000 + b"]" * 100000 + b"\n"), ("huge integer", b"9" * 100000 + b"\n"),
                            ("long string", b'"' + b"a" * (1 << 20) + b'"\n')):
            with self.subTest(case=label):
                top, seconds, out = peak(lambda: decode_canonical(data))
                if isinstance(out, Exception):
                    self.assertIsInstance(out, CanonicalJsonError)
                self.assertLess(top, 64 * len(data) + (8 << 20))
                self.assertLess(seconds, 5)

    def test_an_unencodable_point_id_is_a_coded_refusal(self) -> None:
        """The second CV-236 finding: a lone surrogate escaped as UnicodeEncodeError."""
        with self.assertRaises(expr.ExprError) as ctx:
            expr.check_expression({"terms": [{"coefficient": 1, "point_id": "\ud8bb"}]})
        self.assertEqual(ctx.exception.code, "COV1010")


if __name__ == "__main__":
    unittest.main()
