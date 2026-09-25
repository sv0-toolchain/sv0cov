# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Closed coverage map 1.0 (CV-014 .. CV-018, SPEC 16.3).

COV-FMT-038, COV-FMT-039, COV-MAP-013/015/016/017, COV-MET-003, AC-091,
AC-108, AC-109, AC-111. A valid two-source map passes (with and without
source bytes); each single forbidden change is rejected with its code.
"""

from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import map_samples as ms  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.map import MapError, validate_map  # noqa: E402


def code_of(obj: dict, *, sources: dict | None = None) -> str | None:
    try:
        validate_map(encode(obj), sources=sources)
    except MapError as exc:
        return exc.code
    return None


class Case(unittest.TestCase):
    def assert_codes(self, cases: dict, *, refragment: bool = True, sources: dict | None = None) -> None:
        for name, (fn, code) in cases.items():
            with self.subTest(case=name):
                got = code_of(ms.mutated(fn, refragment=refragment), sources=sources)
                self.assertEqual(got, code, name)


def pt(o: dict, kind: str, n: int = 0) -> dict:
    return [p for p in o["points"] if p["kind"] == kind][n]


class ValidMapTest(unittest.TestCase):
    def test_sample_is_valid(self) -> None:
        data = encode(ms.build())
        validate_map(data)
        validate_map(data, sources=ms.SOURCES)

    def test_hand_checked_coordinates(self) -> None:
        o = ms.build()
        ret_div = o["regions"][0]
        self.assertEqual((ret_div["span"]["start_line"], ret_div["span"]["start_column"]), (4, 5))
        self.assertEqual(ret_div["line_numbers"], [4])
        req = o["entities"][1]["span"]
        self.assertEqual((req["start_line"], req["start_column"], req["end_line"], req["end_column"]), (2, 5, 2, 21))

    def test_noncanonical_bytes_rejected(self) -> None:
        pretty = json.dumps(ms.build(), indent=1).encode() + b"\n"
        with self.assertRaises(MapError) as ctx:
            validate_map(pretty)
        self.assertEqual(ctx.exception.code, "COV1010")


class TopLevelTest(Case):
    """CV-014: closed top-level schema, versions, capabilities."""

    def test_rejections(self) -> None:
        self.assert_codes(
            {
                "unknown property": (lambda o: o.__setitem__("extension", {}), "COV1010"),
                "missing property": (lambda o: o.pop("exclusions"), "COV1010"),
                "mistyped count": (lambda o: o.__setitem__("program_counter_count", "6"), "COV1010"),
                "wrong schema": (lambda o: o.__setitem__("schema", "sv0cov.maps"), "COV1010"),
                "version 1.1": (lambda o: o.__setitem__("version", "1.1"), "COV1011"),
                "version 2.0": (lambda o: o.__setitem__("version", "2.0"), "COV1011"),
                "identity version": (lambda o: o.__setitem__("point_identity_version", "2.0"), "COV1011"),
                "extra capability": (lambda o: o["capabilities"].append("zz-future"), "COV1012"),
                "missing capability": (lambda o: o["capabilities"].pop(), "COV1012"),
                "unsorted capabilities": (lambda o: o["capabilities"].reverse(), "COV1012"),
                "compiler name": (lambda o: o["compiler"].__setitem__("name", "other"), "COV1010"),
                "compiler identity space": (lambda o: o["compiler"].__setitem__("identity", "sv0c @x"), "COV1010"),
                "compiler identity empty": (lambda o: o["compiler"].__setitem__("identity", ""), "COV1010"),
                "target kind": (lambda o: o["target"].__setitem__("kind", "library"), "COV1010"),
                "target newline": (lambda o: o["target"].__setitem__("name", "a\nb"), "COV1010"),
                "unknown nested property": (lambda o: o["sources"][0].__setitem__("mtime", 0), "COV1010"),
                "bool as integer": (lambda o: o["regions"][0]["span"].__setitem__("start_line", True), "COV1010"),
            }
        )

    def test_map_id_mismatch(self) -> None:
        o = ms.build()
        o["target"]["name"] = "renamed"
        self.assertEqual(code_of(o), "COV1013")


class SourcesEntitiesPointsTest(Case):
    """CV-015: sources, entities, points, point identity."""

    def test_rejections(self) -> None:
        self.assert_codes(
            {
                "source order": (lambda o: o["sources"].reverse(), "COV1010"),
                "source index": (lambda o: o["sources"][0].__setitem__("source_index", 1), "COV1010"),
                "absolute path": (lambda o: o["sources"][0].__setitem__("path", "/src/math.sv0"), "COV1010"),
                "uppercase digest": (lambda o: o["sources"][0].__setitem__("digest", o["sources"][0]["digest"].upper()), "COV1010"),
                "empty package": (lambda o: o["sources"][0].__setitem__("package", ""), "COV1010"),
                "entity order": (lambda o: o["entities"].reverse(), "COV1010"),
                "entity dangling source": (lambda o: o["entities"][0].__setitem__("source_index", 9), "COV1010"),
                "entity span reversed": (lambda o: o["entities"][1]["span"].__setitem__("end_byte", 33), "COV1010"),
                "point id tampered": (lambda o: o["points"][0].__setitem__("point_id", "0" * 64), "COV1014"),
                "point discriminator changed": (lambda o: o["points"][0].__setitem__("semantic_discriminator", "other"), "COV1014"),
                "point span changed": (lambda o: pt(o, "function_entry")["span"].__setitem__("end_byte", pt(o, "function_entry")["span"]["end_byte"] - 1), "COV1014"),
                "points unsorted": (lambda o: o["points"].reverse(), "COV1010"),
                "counter without fragment": (lambda o: pt(o, "function_entry").__setitem__("fragment_index", None), "COV1015"),
                "excluded point counted": (lambda o: [p for p in o["points"] if p["classification"] == "excluded"][0].update(counter_index=6, fragment_index=1) or o.__setitem__("program_counter_count", 7), "COV1015"),
                "duplicate counter": (lambda o: pt(o, "branch_outcome", 1).__setitem__("counter_index", pt(o, "branch_outcome", 0)["counter_index"]), "COV1015"),
                "counter gap": (lambda o: o.__setitem__("program_counter_count", 7), "COV1015"),
                "ordinal on entry": (lambda o: pt(o, "function_entry").__setitem__("outcome_ordinal", 0), "COV1010"),
                "contract point as user": (lambda o: pt(o, "contract_true").__setitem__("classification", "user"), "COV1010"),
                "region classified contract": (lambda o: pt(o, "function_entry").__setitem__("classification", "contract"), "COV1010"),
                "entry owned by contract": (lambda o: pt(o, "function_entry").__setitem__("entity_index", 1), "COV1010"),
                "dangling entity": (lambda o: pt(o, "function_entry").__setitem__("entity_index", 99), "COV1010"),
                "discriminator too long": (lambda o: pt(o, "function_entry").__setitem__("semantic_discriminator", "x" * 257), "COV1010"),
            }
        )


class FragmentsTest(Case):
    """CV-016: fragments, slices, counter bijection, fragment identity."""

    def test_rejections(self) -> None:
        def swap_fragments(o):
            o["fragments"].reverse()
            for n, f in enumerate(o["fragments"]):
                f["fragment_index"] = n

        self.assert_codes(
            {
                "slice gap": (lambda o: o["fragments"][1].__setitem__("slice_base", 4), "COV1015"),
                "slice beyond count": (lambda o: o["fragments"][1].__setitem__("slice_length", 4), "COV1015"),
                "fragment order": (swap_fragments, "COV1010"),
                "source indices unordered": (lambda o: o["fragments"][0].__setitem__("source_indices", [1, 0]), "COV1010"),
                "empty source indices": (lambda o: o["fragments"][0].__setitem__("source_indices", []), "COV1010"),
                "point in wrong fragment": (lambda o: pt(o, "function_entry").__setitem__("fragment_index", 1 - pt(o, "function_entry")["fragment_index"]), "COV1015"),
                "zero-length base wrong": (
                    lambda o: o["fragments"].append({"fragment_id": "", "fragment_index": 2, "slice_base": 0, "slice_length": 0, "source_indices": [1]}),
                    "COV1015",
                ),
            }
        )

    def test_fragment_id_tamper(self) -> None:
        o = ms.build()
        o["fragments"][0]["fragment_id"] = "a" * 64
        ms.finalize(o, fragments=False)
        self.assertEqual(code_of(o), "COV1015")

    def test_zero_length_fragment_at_end_is_valid(self) -> None:
        o = copy.deepcopy(ms.build())
        o["sources"].append({"digest": "0" * 64, "ownership": "user", "package": None, "path": "src/z.sv0", "source_index": 2})
        o["fragments"].append({"fragment_id": "", "fragment_index": 2, "slice_base": 6, "slice_length": 0, "source_indices": [2]})
        ms.finalize(o)
        self.assertIsNone(code_of(o))


class RegionsTest(Case):
    """CV-017: regions, normalized counter expressions, line membership."""

    def test_rejections(self) -> None:
        def terms(o, n):
            return o["regions"][n]["counter_expression"]["terms"]

        self.assert_codes(
            {
                "zero coefficient": (lambda o: terms(o, 0)[0].__setitem__("coefficient", 0), "COV1010"),
                "coefficient out of range": (lambda o: terms(o, 0)[0].__setitem__("coefficient", 2**31), "COV1010"),
                "duplicate term": (lambda o: terms(o, 3).append(dict(terms(o, 3)[0])), "COV1010"),
                "unordered terms": (lambda o: terms(o, 3).reverse(), "COV1010"),
                "uncounted reference": (lambda o: terms(o, 0)[0].__setitem__("point_id", [p for p in o["points"] if p["counter_index"] is None][0]["point_id"]), "COV1010"),
                "unknown point": (lambda o: terms(o, 0)[0].__setitem__("point_id", "f" * 64), "COV1010"),
                "cross-entity term": (lambda o: terms(o, 0)[0].__setitem__("point_id", pt(o, "branch_outcome")["point_id"]), "COV1010"),
                "user region empty": (lambda o: o["regions"][0]["counter_expression"].__setitem__("terms", []), "COV1010"),
                "excluded region counted": (lambda o: terms(o, 1).append({"coefficient": 1, "point_id": pt(o, "function_entry")["point_id"]}), "COV1010"),
                "line outside span": (lambda o: o["regions"][0].__setitem__("line_numbers", [5]), "COV1010"),
                "lines unordered": (lambda o: o["regions"][0].__setitem__("line_numbers", [4, 4]), "COV1010"),
                "region owned by contract": (lambda o: o["regions"][0].__setitem__("entity_index", 1), "COV1010"),
                "region outside owner": (lambda o: o["regions"][2].__setitem__("entity_index", 0), "COV1010"),
                "unknown kind": (lambda o: o["regions"][0].__setitem__("kind", "statement"), "COV1010"),
                "regions unordered": (lambda o: o["regions"].reverse(), "COV1010"),
                "region index": (lambda o: o["regions"][0].__setitem__("region_index", 5), "COV1010"),
            }
        )

    def test_source_backed_checks(self) -> None:
        def bad_lines(o):
            o["regions"][0]["line_numbers"] = []

        def bad_column(o):
            o["regions"][0]["span"]["start_column"] += 1

        def mid_utf8(o):
            # Point the excluded-attribute span into the middle of "é".
            data = ms.MATH
            at = data.index("é".encode()) + 1
            sp = o["exclusions"][0]["span"]
            sp.update(start_byte=at, end_byte=at)

        for fn in (bad_lines, bad_column, mid_utf8):
            with self.subTest(case=fn.__name__):
                o = ms.mutated(fn)
                self.assertEqual(code_of(o, sources=ms.SOURCES), "COV1010")

    def test_whitespace_only_lines_do_not_count(self) -> None:
        from sv0cov.formats.map import _Text

        text = _Text(b"a\n  \n\t\r\nb c\n")
        self.assertEqual(text.line_numbers(0, 12), [1, 4])
        self.assertEqual(text.position(9), (4, 2))  # "b c": offset 9 is the space after "b"

    def test_source_digest_mismatch(self) -> None:
        sources = dict(ms.SOURCES)
        sources["src/sign.sv0"] = ms.SIGN + b"\n"
        self.assertEqual(code_of(ms.build(), sources=sources), "COV1004")


class BranchesContractsExclusionsTest(Case):
    """CV-018: branches and outcomes, contracts, exclusions."""

    def test_branch_rejections(self) -> None:
        def outcomes(o):
            return o["branches"][0]["outcomes"]

        self.assert_codes(
            {
                "wrong outcome names": (lambda o: outcomes(o)[0].__setitem__("name", "yes"), "COV1010"),
                "loop names on if": (lambda o: o["branches"][0].__setitem__("kind", "loop"), "COV1010"),
                "ordinal mismatch": (lambda o: outcomes(o)[1].__setitem__("ordinal", 0), "COV1010"),
                "unreachable without evidence": (lambda o: outcomes(o)[1].__setitem__("classification", "statically_unreachable"), "COV1010"),
                "evidence on eligible": (lambda o: outcomes(o)[1].__setitem__("evidence_identity", "proof"), "COV1010"),
                "outcome references entry": (lambda o: outcomes(o)[0].__setitem__("point_id", pt(o, "function_entry", 1)["point_id"]), "COV1010"),
                "outcome referenced twice": (lambda o: outcomes(o)[1].__setitem__("point_id", outcomes(o)[0]["point_id"]), "COV1010"),
                "classification disagreement": (lambda o: outcomes(o)[0].__setitem__("classification", "excluded"), "COV1010"),
                "empty outcomes": (lambda o: o["branches"][0].__setitem__("outcomes", []), "COV1010"),
            }
        )

    def test_orphan_outcome_point(self) -> None:
        o = ms.build()
        o["branches"] = []
        ms.finalize(o)
        self.assertEqual(code_of(o), "COV1010")

    def test_contract_rejections(self) -> None:
        def c(o):
            return o["contracts"][0]

        self.assert_codes(
            {
                "runtime without points": (lambda o: c(o).__setitem__("true_point_id", None), "COV1010"),
                "runtime with evidence": (lambda o: c(o).__setitem__("evidence_identity", "proof"), "COV1010"),
                "same true and false": (lambda o: c(o).__setitem__("false_point_id", c(o)["true_point_id"]), "COV1010"),
                "swapped points": (lambda o: c(o).update(true_point_id=c(o)["false_point_id"], false_point_id=c(o)["true_point_id"]), "COV1010"),
                "verified with points": (lambda o: c(o).update(enforcement="statically_verified", evidence_identity="z3:proof"), "COV1010"),
                "disabled with points": (lambda o: c(o).__setitem__("enforcement", "disabled"), "COV1010"),
                "entity is a function": (lambda o: c(o).__setitem__("entity_index", 0), "COV1010"),
                "owner is a contract": (lambda o: c(o).__setitem__("function_entity_index", 1), "COV1010"),
                "clause missing": (lambda o: o.__setitem__("contracts", []), "COV1010"),
                "machine alias kind": (lambda o: c(o).__setitem__("kind", "precondition"), "COV1010"),
            }
        )

    def test_statically_verified_clause_is_valid(self) -> None:
        def verified(o):
            ids = {o["contracts"][0]["true_point_id"], o["contracts"][0]["false_point_id"]}
            o["contracts"][0].update(enforcement="statically_verified", evidence_identity="sv0-verify:div#0", true_point_id=None, false_point_id=None)
            o["points"] = [p for p in o["points"] if p["point_id"] not in ids]
            # Renumber counters: the two contract counters (1, 2) disappear.
            remap = {0: 0, 3: 1, 4: 2, 5: 3}
            for p in o["points"]:
                if p["counter_index"] is not None:
                    p["counter_index"] = remap[p["counter_index"]]
            o["program_counter_count"] = 4
            o["fragments"][0]["slice_length"] = 1
            o["fragments"][1]["slice_base"] = 1

        self.assertIsNone(code_of(ms.mutated(verified)))

    def test_exclusion_rejections(self) -> None:
        def x(o):
            return o["exclusions"][0]

        self.assert_codes(
            {
                "no reason": (lambda o: x(o).__setitem__("reason", ""), "COV1010"),
                "affects nothing": (lambda o: x(o).__setitem__("affected", {k: [] for k in x(o)["affected"]}), "COV1010"),
                "excluded point unclaimed": (lambda o: x(o)["affected"].__setitem__("point_ids", []), "COV1010"),
                "excluded region unclaimed": (lambda o: x(o)["affected"].__setitem__("region_indices", []), "COV1010"),
                "claims a user region": (lambda o: x(o)["affected"].__setitem__("region_indices", [0, 1]), "COV1010"),
                "off claims a clause": (lambda o: x(o)["affected"].__setitem__("clause_indices", [0]), "COV1010"),
                "branch_off without branch": (lambda o: x(o).__setitem__("mode", "branch_off"), "COV1010"),
                "contract_off on function": (lambda o: x(o).__setitem__("mode", "contract_off"), "COV1010"),
                "duplicate exclusion": (lambda o: o["exclusions"].append(dict(x(o), exclusion_index=1, reason="again")), "COV1010"),
                "dangling index": (lambda o: x(o)["affected"].__setitem__("entity_indices", [9]), "COV1010"),
                "unknown origin": (lambda o: x(o).__setitem__("origin", "config"), "COV1010"),
            }
        )


if __name__ == "__main__":
    unittest.main()
