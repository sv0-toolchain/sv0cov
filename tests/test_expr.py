# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Normalized linear counter expressions (CV-204; SPEC 11.1, COV-MAP-016,
COV-MET-017, AC-109).

- tests/fixtures/expressions/expressions.json, hand-derived: empty, direct,
  addition, subtraction, exact zero, negative (COV3002), large coefficients
  whose products cancel only with unbounded intermediates, the signed
  32-bit bounds, results above UINT64_MAX, saturated positive and negative
  terms, the zero clamp, per-context evaluation with the saturating
  aggregate, and every malformed encoding (order, duplicate, zero, range,
  non-integer, uncounted reference, extra properties, nesting: COV1010);
- properties: on exact counts the result is the plain sum; context order
  and dict order do not matter; aggregate = saturating sum of contexts;
- every region of every semantic fixture map (byte-identical to sv0c's
  maps) is normalized, references only counted points, and evaluates on its
  expected counts to the same value the fixture's line statuses assume.
"""

from __future__ import annotations

import json
import random
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.expr import (  # noqa: E402
    U64_MAX,
    Count,
    ExprError,
    check_expression,
    evaluate,
    evaluate_contexts,
)

CORPUS = json.loads((ROOT / "tests" / "fixtures" / "expressions" / "expressions.json").read_bytes())
SEMANTIC = ROOT / "tests" / "fixtures" / "semantic"


def contexts(raw: dict) -> dict[int, dict[str, Count]]:
    return {int(i): {p: Count(v, sat) for p, (v, sat) in pts.items()} for i, pts in raw.items()}


class ExpressionFixtureTest(unittest.TestCase):
    def test_evaluate_corpus(self) -> None:
        self.assertGreaterEqual(len(CORPUS["evaluate"]), 15)
        for case in CORPUS["evaluate"]:
            with self.subTest(case=case["name"]):
                terms = check_expression({"terms": case["terms"]}, CORPUS["counted"])
                if isinstance(case["expect"], str):
                    with self.assertRaises(ExprError) as cm:
                        evaluate_contexts(terms, contexts(case["contexts"]))
                    self.assertEqual(cm.exception.code, case["expect"])
                    continue
                rec = evaluate_contexts(terms, contexts(case["contexts"]))
                got = {"value": rec.value, "inexact": rec.inexact,
                       "by_context": [[i, c.value, c.inexact] for i, c in rec.by_context]}
                self.assertEqual(got, case["expect"])
                j = rec.to_json()
                self.assertEqual(j["saturated"], j["lower_bound"])
                self.assertTrue(all(b["saturated"] == b["lower_bound"] for b in j["by_context"]))

    def test_invalid_corpus(self) -> None:
        self.assertGreaterEqual(len(CORPUS["invalid"]), 10)
        for case in CORPUS["invalid"]:
            with self.subTest(case=case["name"]):
                with self.assertRaises(ExprError) as cm:
                    check_expression(case["expression"], CORPUS["counted"])
                self.assertEqual(cm.exception.code, case["code"])

    def test_physical_count(self) -> None:
        self.assertEqual(Count.physical(U64_MAX), Count(U64_MAX, True))
        self.assertEqual(Count.physical(U64_MAX - 1), Count(U64_MAX - 1, False))


class ExpressionPropertyTest(unittest.TestCase):
    def test_exact_counts_give_the_plain_sum(self) -> None:
        rng = random.Random(204)
        ids = sorted(f"{i:064x}" for i in range(6))
        for _ in range(2000):
            chosen = sorted(rng.sample(ids, rng.randint(0, 5)))
            terms = [(rng.choice([-3, -2, -1, 1, 2, 3, 2147483647, -2147483648]), p) for p in chosen]
            counts = {p: rng.choice([0, 1, 7, 2**40, U64_MAX - 1]) for p in ids}
            plain = sum(c * counts[p] for c, p in terms)
            exact = {p: Count(v) for p, v in counts.items()}
            if plain < 0:
                with self.assertRaises(ExprError):
                    evaluate(terms, exact)
            elif plain > U64_MAX:
                self.assertEqual(evaluate(terms, exact), Count(U64_MAX, True))
            else:
                self.assertEqual(evaluate(terms, exact), Count(plain, False))

    def test_context_order_and_aggregate(self) -> None:
        rng = random.Random(2041)
        a, b = "a" * 64, "b" * 64
        terms = [(2, a), (-1, b)]
        for _ in range(500):
            ctxs = {}
            for i in range(rng.randint(1, 5)):
                bv = rng.choice([0, 3, 2**62])
                sat_b = rng.random() < 0.2
                ctxs[i] = {a: Count(U64_MAX, True) if rng.random() < 0.2 else Count(bv + rng.choice([0, 5])),
                           b: Count(U64_MAX, True) if sat_b else Count(bv)}
            rec = evaluate_contexts(terms, ctxs)
            shuffled = dict(rng.sample(list(ctxs.items()), len(ctxs)))
            self.assertEqual(evaluate_contexts(terms, shuffled), rec)
            per = [evaluate(terms, ctxs[i]) for i in sorted(ctxs)]
            self.assertEqual(rec.value, min(sum(c.value for c in per), U64_MAX))
            self.assertEqual(rec.inexact, any(c.inexact for c in per) or sum(c.value for c in per) > U64_MAX)
            self.assertEqual([i for i, _ in rec.by_context],
                             [i for i, c in zip(sorted(ctxs), per) if c.value or c.inexact])


class SemanticFixtureExpressionTest(unittest.TestCase):
    def test_fixture_regions(self) -> None:
        names = sorted(p.parent.name for p in SEMANTIC.glob("*/expected-map.json"))
        self.assertEqual(len(names), 7)
        for name in names:
            with self.subTest(fixture=name):
                m = json.loads((SEMANTIC / name / "expected-map.json").read_bytes())
                counts = {c["point_id"]: c["count"] for c in json.loads((SEMANTIC / name / "expected-counts.json").read_bytes())["counts"]}
                counted = {p["point_id"] for p in m["points"] if p["counter_index"] is not None}
                for r in m["regions"]:
                    terms = check_expression(r["counter_expression"], counted)
                    if r["classification"] != "user":
                        self.assertEqual(terms, [])
                        continue
                    got = evaluate(terms, {p: Count(counts[p]) for _, p in terms})
                    self.assertFalse(got.inexact)
                    self.assertEqual(got.value, sum(c * counts[p] for c, p in terms))


if __name__ == "__main__":
    unittest.main()
