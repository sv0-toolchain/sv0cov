# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The merge engine (CV-223; SPEC 17.1-17.3, 17.5; COV-MRG-001..010,
AC-011, AC-012, AC-013, AC-089, AC-097).

Every input is inventoried and classified before anything is combined; a
copy counts once, a profile-ID collision rejects, distinct profile IDs stay
distinct; run sets are implicit-single or exactly the declared set; counts
add with saturation; and the bytes do not depend on input order.
"""

from __future__ import annotations

import copy
import hashlib
import itertools
import random
import struct
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import map_samples as ms  # noqa: E402
from test_indexed_reader import RUN_A, RUN_B, U64, fixture_inputs, raw  # noqa: E402
from test_semantic_model import TINY, tiny  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.crc32c import crc32c  # noqa: E402
from sv0cov.formats.rawprofile import HEADER, Tier, peek_header  # noqa: E402
from sv0cov.formats.runset import encode_run_set  # noqa: E402
from sv0cov.model.indexed import RunSelection, read_indexed  # noqa: E402
from sv0cov.model.merge import Artifact, Duplicate, MergeError, merge, select_runs  # noqa: E402

RUN_C = "00000000000000000000000000000001"
V = "0.0.0-test"


def run(maps, profiles, **kw):
    return merge(maps, profiles, tool_version=V, **kw)


def fixture(name: str) -> tuple[Artifact, dict, dict[str, int]]:
    data, m, counts = fixture_inputs(name)
    return Artifact(f"{name}.sv0covmap.json", data), m, counts


def tiny_map(text: str = TINY, target: str = "tiny") -> tuple[Artifact, dict, object]:
    m, p = tiny(text, target)
    return Artifact(f"{target}.sv0covmap.json", encode(m)), m, p


def points(result) -> dict[str, dict]:
    return {p["point_id"]: p["count"] for p in result.indexed["semantic"]["points"]}


def inputs(result, key: str = "profile_inputs") -> list[tuple]:
    return [(r["name"], r["status"], tuple(r["diagnostics"])) for r in result.indexed[key]]


def codes(result) -> list[tuple]:
    return [(f.kind, f.name, f.code) for f in result.findings]


def resealed(data: bytes) -> bytes:
    """``data`` with its trailing CRC32C recomputed."""
    return data[:-4] + struct.pack("<I", crc32c(data[:-4]))


class ValidationTest(unittest.TestCase):
    """SPEC 17.1, COV-MRG-001, COV-MRG-007, AC-012."""

    def setUp(self) -> None:
        self.map, self.m, self.counts = fixture("f0")
        self.good = Artifact("good.sv0profraw", raw(self.m, self.counts, 1))

    def test_a_clean_merge_is_complete_and_reads_back(self) -> None:
        r = run([self.map], [self.good])
        self.assertTrue(r.complete and r.publishable)
        self.assertEqual((r.findings, r.duplicates), ((), ()))
        self.assertEqual(read_indexed(r.data), r.indexed)
        self.assertEqual(encode(r.indexed), r.data)
        self.assertEqual({k: v["value"] for k, v in points(r).items() if v["value"]}, {k: v for k, v in self.counts.items() if v})
        self.assertEqual(r.indexed["run_selection"]["mode"], "implicit-single")
        self.assertEqual(r.indexed["merge"]["allow_rejected_inputs"], False)

    def test_one_bad_profile_fails_the_merge_and_is_identified(self) -> None:
        bad = bytearray(raw(self.m, self.counts, 2))
        bad[-1] ^= 1
        r = run([self.map], [self.good, Artifact("bad.sv0profraw", bytes(bad))])
        self.assertFalse(r.complete or r.publishable)
        self.assertEqual(codes(r), [("merge", None, "COV3002"), ("profile", "bad.sv0profraw", "COV2012")])
        self.assertEqual(inputs(r), [("good.sv0profraw", "accepted", ()), ("bad.sv0profraw", "rejected", ("COV2012",))])
        self.assertEqual(r.indexed["diagnostics"], ["COV3002"])
        # The rejected artifact stays in the inventory with its digest; it adds no count.
        rec = r.indexed["profile_inputs"][1]
        self.assertEqual((rec["artifact_sha256"], rec["byte_length"]), (hashlib.sha256(bytes(bad)).hexdigest(), len(bad)))
        self.assertEqual(points(r), points(run([self.map], [self.good])))
        # The override publishes it only as incomplete diagnostic evidence.
        o = run([self.map], [self.good, Artifact("bad.sv0profraw", bytes(bad))], allow_rejected_inputs=True)
        self.assertTrue(o.publishable and not o.complete)
        self.assertTrue(o.indexed["merge"]["allow_rejected_inputs"])
        self.assertEqual(read_indexed(o.data)["semantic"]["complete"], False)

    def test_the_override_alone_makes_clean_evidence_incomplete(self) -> None:
        r = run([self.map], [self.good], allow_rejected_inputs=True)
        self.assertEqual((r.complete, r.publishable, r.findings), (False, True, ()))

    def test_each_kind_of_bad_profile_is_classified(self) -> None:
        data = self.good.data
        other, om, ocounts = fixture("loops")
        version = bytearray(data)
        version[8:12] = struct.pack("<HH", 1, 1)
        magic = b"X" + data[1:]
        out_of_map = raw(om, ocounts, 9)
        out_of_map = resealed(out_of_map[:16] + bytes.fromhex(self.m["map_id"]) + out_of_map[48:])
        self.assertGreater(om["program_counter_count"], self.m["program_counter_count"])
        cases = {
            "truncated in the header": (data[:40], "incomplete", "COV2011"),
            "truncated in the pairs": (data[: HEADER + 10], "incomplete", "COV2011"),
            "no completion marker": (data[:-12] + bytes(8) + data[-4:], "incomplete", "COV2011"),
            "empty file": (b"", "incomplete", "COV2011"),
            "checksum": (data[:-1] + bytes([data[-1] ^ 0x80]), "rejected", "COV2012"),
            "version": (bytes(version), "rejected", "COV2103"),
            "magic": (magic, "rejected", "COV2110"),
            "trailing byte": (data + b"\0", "rejected", "COV2110"),
            "unknown map": (raw(om, ocounts, 9), "rejected", "COV2111"),
            "counters beyond the map": (out_of_map, "rejected", "COV2110"),
            "unreadable": (None, "rejected", "COV2010"),
        }
        for name, (bad, status, code) in cases.items():
            with self.subTest(case=name):
                r = run([self.map], [self.good, Artifact("x.sv0profraw", bad)])
                self.assertFalse(r.complete or r.publishable)
                self.assertIn(("x.sv0profraw", status, (code,)), inputs(r))
                self.assertIn(("profile", "x.sv0profraw", code), codes(r))
                self.assertEqual(points(r), points(run([self.map], [self.good])))
                read_indexed(r.data)

    def test_a_profile_over_the_tier_is_rejected(self) -> None:
        small = Tier.custom(4194304, len(self.good.data) - 1)
        r = run([self.map], [self.good], tier=small)
        self.assertEqual(inputs(r), [("good.sv0profraw", "rejected", ("COV6001",))])
        self.assertEqual(r.indexed["diagnostics"], ["COV3001", "COV3002", "COV3003"])
        self.assertEqual(r.indexed["merge"]["limits"], {"max_bytes": small.max_bytes, "max_counters": 4194304, "tier": "custom"})
        few = Tier.custom(1, 67108864)
        self.assertEqual(inputs(run([self.map], [self.good], tier=few)), [("good.sv0profraw", "rejected", ("COV6001",))])

    def test_what_a_broken_profiles_header_says_is_kept(self) -> None:
        data = raw(self.m, self.counts, 7, run=RUN_B, context="shard-2", backend="vm-v1")
        r = run([self.map], [self.good, Artifact("cut.sv0profraw", data[:-20])])
        rec = next(x for x in r.indexed["profile_inputs"] if x["name"] == "cut.sv0profraw")
        ctx = r.indexed["semantic"]["contexts"]
        self.assertEqual((rec["status"], rec["backend"], rec["map_id"], rec["run_id"], rec["profile_id"]),
                         ("incomplete", "vm-v1", self.m["map_id"], RUN_B, (7).to_bytes(16, "big").hex()))
        self.assertEqual(ctx[rec["context_index"]]["value"], "shard-2")
        # Its run is not selected and its context holds no count.
        self.assertEqual(r.indexed["run_selection"]["selected_run_ids"], [RUN_A])
        self.assertTrue(all(c["context_index"] != rec["context_index"] for p in points(r).values() for c in p["by_context"]))
        # Cut inside the context, or with no header: nothing is claimed beyond what was read.
        short = run([self.map], [Artifact("cut.sv0profraw", data[: HEADER + 3])]).indexed["profile_inputs"][0]
        self.assertEqual((short["context_index"], short["run_id"]), (None, RUN_B))
        none = run([self.map], [Artifact("cut.sv0profraw", data[:50])]).indexed["profile_inputs"][0]
        self.assertEqual((none["backend"], none["run_id"], none["profile_id"], none["map_id"]), (None, None, None, None))

    def test_peek_header_refuses_what_decode_refuses(self) -> None:
        data = raw(self.m, self.counts, 7, context="é")
        self.assertEqual(peek_header(data).context, "é")
        self.assertIsNone(peek_header(data[: HEADER - 1]))
        for at, value in ((0, b"X"), (8, b"\x02"), (12, b"\xff"), (12, b"\x01"), (12, b"\x0d")):
            self.assertIsNone(peek_header(data[:at] + value + data[at + len(value):]), at)
        self.assertIsNone(peek_header(data[:48] + bytes(16) + data[64:]))
        self.assertIsNone(peek_header(data[:64] + bytes(16) + data[80:]))
        self.assertIsNone(peek_header(data[:80] + struct.pack("<I", 257) + data[84:]))
        plain = raw(self.m, self.counts, 7)
        self.assertEqual((peek_header(plain).has_context, peek_header(plain).context), (True, None))
        self.assertIsNone(peek_header(plain[:80] + struct.pack("<I", 1) + plain[84:]))
        bad_utf8 = data[:HEADER] + b"\xff" + data[HEADER + 1:]
        self.assertEqual((peek_header(bad_utf8).has_context, peek_header(bad_utf8).context), (False, None))

    def test_each_kind_of_bad_map_is_rejected_with_its_profiles(self) -> None:
        tampered = self.map.data.replace(b'"line_contributing":true', b'"line_contributing":false', 1)
        self.assertNotEqual(tampered, self.map.data)
        cases = {"not JSON": (b"{", "COV1010"), "tampered": (tampered, "COV1013"), "unreadable": (None, "COV1010")}
        for name, (bad, code) in cases.items():
            with self.subTest(case=name):
                r = run([Artifact("m.json", bad)], [self.good])
                self.assertEqual(inputs(r, "map_inputs"), [("m.json", "rejected", (code,))])
                self.assertEqual(inputs(r), [("good.sv0profraw", "rejected", ("COV2111",))])
                self.assertIn("not supplied or is invalid", next(f.detail for f in r.findings if f.kind == "profile"))
                self.assertEqual(r.indexed["diagnostics"], ["COV3001", "COV3002", "COV3003"])
                self.assertEqual((r.indexed["maps"], r.indexed["semantic"]["points"]), ([], []))
                self.assertFalse(r.publishable)
                read_indexed(r.data)
        # A bad extra map beside the good one still fails the merge.
        r = run([self.map, Artifact("m.json", b"{")], [self.good])
        self.assertEqual(inputs(r), [("good.sv0profraw", "accepted", ())])
        self.assertEqual((r.complete, r.indexed["diagnostics"]), (False, ["COV3002"]))

    def test_no_input_is_diagnostic_evidence(self) -> None:
        r = run([], [])
        self.assertEqual((r.indexed["diagnostics"], r.complete, r.publishable), (["COV3001", "COV3003"], False, False))
        self.assertEqual(codes(r), [("merge", None, "COV3001"), ("merge", None, "COV3003")])
        only_map = run([self.map], [])
        self.assertEqual(only_map.indexed["diagnostics"], ["COV3001", "COV3003"])
        self.assertTrue(all(p["count"]["value"] == 0 for p in only_map.indexed["semantic"]["points"]))


class IdentityTest(unittest.TestCase):
    """SPEC 17.3, COV-MRG-002, AC-013, AC-089."""

    def setUp(self) -> None:
        self.map, self.m, self.counts = fixture("branches")
        self.one = raw(self.m, self.counts, 1)

    def test_distinct_profile_ids_with_equal_contents_both_count(self) -> None:
        two = raw(self.m, self.counts, 2)
        r = run([self.map], [Artifact("a", self.one), Artifact("b", two)])
        self.assertTrue(r.complete)
        self.assertEqual({k: v["value"] for k, v in points(r).items()}, {k: 2 * v for k, v in self.counts.items()})
        self.assertEqual(len(r.indexed["profile_inputs"]), 2)
        # Names decide nothing: the same two profiles under one basename.
        same_name = run([self.map], [Artifact("p", self.one), Artifact("p", two)])
        self.assertEqual(points(same_name), points(r))

    def test_an_exact_copy_counts_once_and_is_recorded(self) -> None:
        once = run([self.map], [Artifact("a", self.one)])
        for label, arts in (("same path twice", [Artifact("a", self.one), Artifact("a", self.one)]),
                            ("copied elsewhere", [Artifact("z", self.one), Artifact("a", self.one), Artifact("m", self.one)])):
            with self.subTest(case=label):
                r = run([self.map, self.map], arts)
                self.assertTrue(r.complete)
                self.assertEqual(r.data, once.data)
                sha = hashlib.sha256(self.one).hexdigest()
                self.assertEqual(r.duplicates, (Duplicate("map", self.map.name, hashlib.sha256(self.map.data).hexdigest(), 1),
                                                Duplicate("profile", "a", sha, len(arts) - 1)))
        self.assertEqual(once.duplicates, ())

    def test_one_profile_id_with_different_bytes_rejects_every_user(self) -> None:
        variants = {
            "other counts": raw(self.m, {k: v + 1 for k, v in self.counts.items()}, 1),
            "same counts, other backend": raw(self.m, self.counts, 1, backend="vm-v1"),
            "same counts, other run": raw(self.m, self.counts, 1, run=RUN_B),
        }
        for label, other in variants.items():
            with self.subTest(case=label):
                r = run([self.map], [Artifact("a", self.one), Artifact("b", other), Artifact("c", raw(self.m, self.counts, 3))])
                self.assertEqual(inputs(r)[0], ("c", "accepted", ()))
                self.assertEqual(sorted(inputs(r)[1:]), [("a", "rejected", ("COV2112",)), ("b", "rejected", ("COV2112",))])
                self.assertFalse(r.complete or r.publishable)
                self.assertEqual({k: v["value"] for k, v in points(r).items()}, self.counts)
        # A collision with a profile whose map is missing is still a collision.
        other_map, om, ocounts = fixture("loops")
        r = run([self.map], [Artifact("a", self.one), Artifact("b", raw(om, ocounts, 1))])
        self.assertEqual(sorted(inputs(r)), [("a", "rejected", ("COV2112",)), ("b", "rejected", ("COV2111", "COV2112"))])
        # A corrupt file is rejected for itself and does not discredit the valid profile whose ID it claims.
        broken = self.one[:-1] + bytes([self.one[-1] ^ 1])
        r = run([self.map], [Artifact("a", self.one), Artifact("b", broken)])
        self.assertEqual(inputs(r), [("a", "accepted", ()), ("b", "rejected", ("COV2012",))])
        self.assertFalse(r.publishable)


class MapCompatibilityTest(unittest.TestCase):
    """SPEC 17.3, COV-MRG-003, COV-MRG-006."""

    def test_maps_that_define_one_thing_differently_are_both_rejected(self) -> None:
        a, am, p = tiny_map(TINY, "one")

        def variant(change) -> Artifact:
            o = copy.deepcopy(am)
            change(o)
            o["target"]["name"] = "two"
            return Artifact("two.sv0covmap.json", encode(ms.finalize(o, fragments=False)))

        other, om, ocounts = fixture("loops")
        cases = {
            "source ownership": lambda o: o["sources"][0].update(ownership="dependency", package="dep"),
            "region line flag": lambda o: o["regions"][0].update(line_contributing=not o["regions"][0]["line_contributing"]),
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                b = variant(change)
                profs = [Artifact("pa", raw(am, {p.entry: 1, p.true: 1}, 1)), Artifact("po", raw(om, ocounts, 2))]
                r = run([a, b, other], profs)
                self.assertEqual(sorted(inputs(r, "map_inputs")), [("loops.sv0covmap.json", "accepted", ()),
                                                                    ("one.sv0covmap.json", "rejected", ("COV3002",)),
                                                                    ("two.sv0covmap.json", "rejected", ("COV3002",))])
                self.assertEqual(sorted(inputs(r)), [("pa", "rejected", ("COV2111",)), ("po", "accepted", ())])
                self.assertEqual(r.indexed["semantic"]["map_ids"], [om["map_id"]])
                self.assertIn("was rejected", next(f.detail for f in r.findings if f.name == "pa"))
                self.assertFalse(r.complete or r.publishable)
                self.assertEqual(r.data, run([other, b, a], profs[::-1]).data)
                read_indexed(r.data)

    def test_two_targets_sharing_a_source_merge(self) -> None:
        a, am, p = tiny_map(TINY, "one")
        b, bm, _ = tiny_map(TINY, "two")
        r = run([a, b], [Artifact("pa", raw(am, {p.entry: 2, p.true: 2}, 1)), Artifact("pb", raw(bm, {p.entry: 3, p.false: 3}, 2))])
        self.assertTrue(r.complete)
        self.assertEqual({k: v["value"] for k, v in points(r).items()}, {p.entry: 5, p.true: 2, p.false: 3})
        self.assertEqual(len(r.indexed["maps"]), 2)

    def test_two_versions_of_one_source_are_kept_and_block_completeness(self) -> None:
        a, am, pa = tiny_map(TINY, "one")
        b, bm, pb = tiny_map(TINY + "/* edited */\n", "two")
        r = run([a, b], [Artifact("pa", raw(am, {pa.entry: 1, pa.true: 1}, 1)), Artifact("pb", raw(bm, {pb.entry: 1, pb.false: 1}, 2))])
        self.assertTrue(all(s == "accepted" for _, s, _ in inputs(r, "map_inputs")))
        self.assertTrue(all(s == "accepted" for _, s, _ in inputs(r)))
        self.assertEqual((r.indexed["diagnostics"], r.indexed["semantic"]["diagnostics"]), (["COV3004"], ["COV3004"]))
        self.assertEqual([s["path"] for s in r.indexed["semantic"]["sources"]], ["main.sv0", "main.sv0"])
        self.assertFalse(r.complete or r.publishable)
        self.assertEqual(codes(r), [("merge", None, "COV3004")])
        self.assertTrue(run([a, b], [Artifact("pa", raw(am, {pa.entry: 1}, 1))], allow_rejected_inputs=True).publishable)


class CombinationTest(unittest.TestCase):
    """SPEC 17.3, COV-MRG-004: counts add by point and context, saturating."""

    def test_merged_counts_are_the_saturating_sum_of_the_accepted_profiles(self) -> None:
        rng = random.Random(223)
        f0, m0, c0 = fixture("f0")
        qn, mq, cq = fixture("question")
        contexts = [None, "", "a", "shard-1"]
        saturating = 0
        for trial in range(25):
            profs, want = [], {}
            for n in range(1, rng.randint(3, 8)):
                m, base = rng.choice([(m0, c0), (mq, cq)])
                ctx = rng.choice(contexts if trial % 2 else [None, "a"])
                # Any multiple of a real run is a possible run; one saturated counter is always possible.
                big = (U64 - 1) // max(base.values())
                k = rng.choice([0, 1, 3, big, big, big])
                counts = {pid: k * v for pid, v in base.items() if k * v}
                if counts and rng.random() < 0.3:
                    counts[rng.choice(sorted(counts))] = U64
                self.assertTrue(all(v <= U64 for v in counts.values()))
                profs.append(Artifact(f"p{n}", raw(m, counts, n, context=ctx)))
                if rng.random() < 0.3:
                    profs.append(Artifact(f"copy{n}", profs[-1].data))
                for pid, v in counts.items():
                    total, inexact = want.get((pid, ctx), (0, False))
                    want[(pid, ctx)] = (total + v, inexact or v == U64)
            rng.shuffle(profs)
            r = run([f0, qn], profs)
            self.assertEqual([x for x in inputs(r) if x[1] != "accepted"], [])
            sem = r.indexed["semantic"]
            value = {c["context_index"]: c["value"] for c in sem["contexts"]}
            got = {(pid, value[c["context_index"]]): (c["value"], c["lower_bound"]) for pid, cnt in points(r).items() for c in cnt["by_context"]}
            self.assertEqual(got, {k: (min(v, U64), bad or v >= U64) for k, (v, bad) in want.items()}, trial)
            saturating += sum(1 for v, bad in want.values() if v > U64 and not bad)
            for pid, cnt in points(r).items():
                mine = [x for (q, _), x in want.items() if q == pid]
                total = sum(min(v, U64) for v, _ in mine)
                self.assertEqual((cnt["value"], cnt["lower_bound"]), (min(total, U64), total > U64 or any(bad or v >= U64 for v, bad in mine)))
        self.assertGreater(saturating, 5)

    def test_a_valid_profile_with_impossible_counts_is_rejected_alone(self) -> None:
        a, am, p = tiny_map()
        good = Artifact("good", raw(am, {p.entry: 4, p.true: 1, p.false: 3}, 1))
        # The branch body ran more often than its function: `entry - true` is negative.
        bad = Artifact("bad", raw(am, {p.entry: 1, p.true: 2}, 2))
        r = run([a], [good, bad])
        self.assertEqual(inputs(r), [("good", "accepted", ()), ("bad", "rejected", ("COV3002",))])
        self.assertEqual({k: v["value"] for k, v in points(r).items()}, {p.entry: 4, p.true: 1, p.false: 3})
        self.assertFalse(r.complete or r.publishable)
        self.assertIn("region", next(f.detail for f in r.findings if f.name == "bad"))
        # With a saturated counter the same shape is a lower bound, not a contradiction.
        ok = run([a], [good, Artifact("sat", raw(am, {p.entry: 1, p.true: U64}, 2))])
        self.assertEqual(inputs(ok), [("good", "accepted", ()), ("sat", "accepted", ())])

    def test_a_sum_landing_exactly_on_the_maximum_is_saturated(self) -> None:
        a, am, p = tiny_map()
        half = (U64 - 1) // 2
        r = run([a], [Artifact("x", raw(am, {p.entry: half, p.false: half}, 1)), Artifact("y", raw(am, {p.entry: half + 1, p.false: half + 1}, 2))])
        self.assertEqual(half + half + 1, U64)
        self.assertEqual((points(r)[p.entry]["value"], points(r)[p.entry]["lower_bound"]), (U64, True))
        below = run([a], [Artifact("x", raw(am, {p.entry: half, p.false: half}, 1)), Artifact("y", raw(am, {p.entry: half, p.false: half}, 2))])
        self.assertEqual((points(below)[p.entry]["value"], points(below)[p.entry]["lower_bound"]), (U64 - 1, False))

    def test_a_zero_counter_profile_is_enough(self) -> None:
        a, am, _ = tiny_map()
        r = run([a], [Artifact("p", raw(am, {}, 1))])
        self.assertTrue(r.complete)
        self.assertTrue(all(c["value"] == 0 for c in points(r).values()))


class OrderTest(unittest.TestCase):
    """SPEC 17.5, COV-MRG-005, AC-011."""

    def test_input_order_does_not_change_the_bytes(self) -> None:
        f0, m0, c0 = fixture("f0")
        lp, ml, cl = fixture("loops")
        good = raw(m0, c0, 1)
        profs = [Artifact("a", good), Artifact("copy", good), Artifact("b", raw(m0, c0, 2, context="x", backend="vm-v1")),
                 Artifact("c", raw(ml, cl, 3, context="")), Artifact("cut", raw(ml, cl, 4)[:-9]), Artifact("bad", b"nonsense"),
                 Artifact("clash1", raw(ml, cl, 5)), Artifact("clash2", raw(ml, cl, 5, context="y"))]
        maps = [f0, lp, Artifact("junk.json", b"[]"), f0]
        first = run(maps, profs)
        self.assertEqual(len({r["status"] for r in first.indexed["profile_inputs"]}), 3)
        rng = random.Random(11)
        for _ in range(30):
            ms_, ps = maps[:], profs[:]
            rng.shuffle(ms_)
            rng.shuffle(ps)
            other = run(ms_, ps)
            self.assertEqual(other.data, first.data)
            self.assertEqual((other.findings, other.duplicates, other.complete), (first.findings, first.duplicates, first.complete))

    def test_every_permutation_of_shard_profiles_gives_the_same_bytes(self) -> None:
        f0, m0, c0 = fixture("f0")
        shards = [Artifact(f"shard{n}", raw(m0, {k: v * n for k, v in c0.items()}, n, context=f"s{n % 2}")) for n in range(1, 6)]
        first = run([f0], shards)
        self.assertTrue(first.complete)
        for perm in itertools.permutations(shards):
            self.assertEqual(run([f0], perm).data, first.data)


class RunSelectionTest(unittest.TestCase):
    """SPEC 17.2, COV-MRG-008..010, AC-097."""

    def setUp(self) -> None:
        self.map, self.m, self.counts = fixture("match")
        self.a = Artifact("a", raw(self.m, self.counts, 1, run=RUN_A))
        self.b = Artifact("b", raw(self.m, self.counts, 2, run=RUN_B))

    def test_one_run_is_accepted_implicitly(self) -> None:
        r = run([self.map], [self.a, Artifact("a2", raw(self.m, self.counts, 3, run=RUN_A))])
        self.assertTrue(r.complete)
        self.assertEqual(r.indexed["run_selection"], {"manifest_sha256": None, "mode": "implicit-single", "requested_run_ids": [],
                                                      "selected_run_ids": [RUN_A]})

    def test_two_runs_need_a_declaration(self) -> None:
        r = run([self.map], [self.a, self.b])
        self.assertFalse(r.complete or r.publishable)
        self.assertEqual((r.indexed["diagnostics"], codes(r)), (["COV3003"], [("merge", None, "COV3003")]))
        self.assertEqual(r.indexed["run_selection"]["selected_run_ids"], sorted([RUN_A, RUN_B]))

    def test_declared_runs_combine_in_either_order_and_by_manifest(self) -> None:
        one = run([self.map], [self.a, self.b], run_selection=select_runs([RUN_A, RUN_B]))
        two = run([self.map], [self.b, self.a], run_selection=select_runs([RUN_B, RUN_A]))
        self.assertTrue(one.complete)
        self.assertEqual(one.data, two.data)
        self.assertEqual(one.indexed["run_selection"], {"manifest_sha256": None, "mode": "explicit-list",
                                                        "requested_run_ids": sorted([RUN_A, RUN_B]),
                                                        "selected_run_ids": sorted([RUN_A, RUN_B])})
        manifest = encode_run_set([RUN_B, RUN_A])
        three = run([self.map], [self.a, self.b], run_selection=select_runs(manifest=manifest))
        self.assertTrue(three.complete)
        self.assertEqual(three.indexed["run_selection"], {**one.indexed["run_selection"], "mode": "manifest",
                                                          "manifest_sha256": hashlib.sha256(manifest).hexdigest()})
        self.assertEqual(three.indexed["semantic"], one.indexed["semantic"])
        self.assertEqual({k: v["value"] for k, v in points(one).items()}, {k: 2 * v for k, v in self.counts.items()})

    def test_the_declared_set_must_be_exactly_the_runs_found(self) -> None:
        cut = Artifact("cut", raw(self.m, self.counts, 9, run=RUN_B)[:-5])
        cases = {
            "a declared run is absent": ([self.a], [RUN_A, RUN_B], ["COV3003"]),
            "an undeclared run is present": ([self.a, self.b], [RUN_A], ["COV3003"]),
            "a declared run has an incomplete profile": ([self.a, self.b, cut], [RUN_A, RUN_B], ["COV3002"]),
            "the only profile of a declared run is incomplete": ([self.a, cut], [RUN_A, RUN_B], ["COV3002", "COV3003"]),
            "nothing accepted": ([cut], [RUN_B], ["COV3001", "COV3002", "COV3003"]),
        }
        for label, (profs, declared, want) in cases.items():
            for form in ("list", "manifest"):
                with self.subTest(case=label, form=form):
                    sel = select_runs(declared) if form == "list" else select_runs(manifest=encode_run_set(declared))
                    r = run([self.map], profs, run_selection=sel)
                    self.assertEqual(r.indexed["diagnostics"], want)
                    self.assertFalse(r.complete or r.publishable)
                    # The override exposes the state; it never makes it complete.
                    o = run([self.map], profs, run_selection=sel, allow_rejected_inputs=True)
                    self.assertEqual((o.complete, o.publishable, o.indexed["diagnostics"]), (False, True, want))
        ok = run([self.map], [self.a], run_selection=select_runs([RUN_A]))
        self.assertTrue(ok.complete)

    def test_malformed_requests_are_refused(self) -> None:
        manifest = encode_run_set([RUN_A])
        bad = {
            "both forms": dict(expect_runs=[RUN_A], manifest=manifest),
            "empty list": dict(expect_runs=[]),
            "repeated": dict(expect_runs=[RUN_A, RUN_A]),
            "uppercase": dict(expect_runs=[RUN_A.upper()]),
            "short": dict(expect_runs=[RUN_A[:-1]]),
            "zero": dict(expect_runs=["0" * 32]),
            "not text": dict(expect_runs=[5]),
            "manifest without final LF": dict(manifest=manifest[:-1]),
            "manifest unsorted": dict(manifest=manifest.replace(RUN_A.encode(), (RUN_B + '","' + RUN_A).encode())),
            "manifest empty": dict(manifest=b'{"run_ids":[],"schema":"sv0cov.run-set","version":"1.0"}\n'),
            "manifest extra key": dict(manifest=manifest.replace(b'"schema"', b'"extra":1,"schema"')),
        }
        for label, kw in bad.items():
            with self.subTest(case=label), self.assertRaises(MergeError) as ctx:
                select_runs(**kw)
            self.assertEqual(ctx.exception.code, "COV3003")
        self.assertEqual(select_runs(), RunSelection())
        self.assertEqual(select_runs([RUN_B, RUN_C, RUN_A]).requested, (RUN_C, RUN_A, RUN_B))

    def test_fresh_runs_share_a_projection_and_keep_their_provenance(self) -> None:
        one = run([self.map], [self.a])
        two = run([self.map], [Artifact("b", raw(self.m, self.counts, 2, run=RUN_B, backend="vm-v1"))])
        self.assertTrue(one.complete and two.complete)
        self.assertEqual(one.indexed["semantic_projection_sha256"], two.indexed["semantic_projection_sha256"])
        self.assertEqual(encode(one.indexed["semantic"]), encode(two.indexed["semantic"]))
        self.assertNotEqual(one.data, two.data)
        self.assertEqual([(r["run_id"], r["backend"]) for r in two.indexed["profile_inputs"]], [(RUN_B, "vm-v1")])
        # Re-merging the same inputs gives the same full bytes.
        self.assertEqual(run([self.map], [self.a]).data, one.data)


if __name__ == "__main__":
    unittest.main()
