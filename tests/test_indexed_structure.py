# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Indexed evidence 1.0: closed schemas and record-level rules (CV-220).

SPEC 16.5; COV-FMT-040, COV-FMT-041 (structure), BL-023 (seed). The frozen
fixtures under tests/fixtures/indexed are accepted; every entry of the
mutation corpus has its recorded outcome; every property removed, added, or
mistyped anywhere in a fixture is rejected; noncanonical bytes are rejected;
and every rule of ``sv0cov.formats.indexed`` is reached by some fixture.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import sys
import traceback
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "indexed"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(FIXTURES))

import build  # noqa: E402

from sv0cov.formats import indexed  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.indexed import (  # noqa: E402
    IndexedError,
    check_indexed_structure,
    decode_indexed_structure,
    decode_semantic_structure,
    projection_sha256,
    semantic_projection,
)

NAMES = ("empty", "all-kinds", "bounds")


def load(name: str) -> dict:
    return decode_canonical((FIXTURES / f"{name}.json").read_bytes())


def outcome(obj: dict) -> tuple[str, IndexedError | None]:
    try:
        check_indexed_structure(obj)
    except IndexedError as exc:
        return exc.code, exc
    return "valid", None


def rehashed(obj: dict, pointer: str = "") -> dict:
    """Recompute the projection digest, unless the digest is the field under test."""
    if pointer != "/semantic_projection_sha256" and isinstance(obj.get("semantic"), dict):
        obj["semantic_projection_sha256"] = projection_sha256(obj["semantic"])
    return obj


def nodes(value: object, pointer: str = ""):
    """(pointer, container, key) for every member of every object and array."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield f"{pointer}/{k}", value, k
            yield from nodes(v, f"{pointer}/{k}")
    elif isinstance(value, list):
        for n, v in enumerate(value):
            yield f"{pointer}/{n}", value, n
            yield from nodes(v, f"{pointer}/{n}")


class FixtureTest(unittest.TestCase):
    def test_artifacts_are_current(self) -> None:
        for path, data in build.artifacts().items():
            with self.subTest(file=path.name):
                self.assertEqual(path.read_bytes(), data, "rerun tests/fixtures/indexed/build.py --write after review")

    def test_fixtures_are_accepted(self) -> None:
        for name in NAMES:
            with self.subTest(fixture=name):
                data = (FIXTURES / f"{name}.json").read_bytes()
                obj = decode_indexed_structure(data)
                self.assertEqual(encode(obj), data)
                self.assertEqual(sorted(obj), ["diagnostics", "execution", "map_inputs", "maps", "merge", "profile_inputs",
                                               "run_selection", "schema", "semantic", "semantic_projection_sha256", "version"])
                self.assertEqual(len(obj["semantic"]), 18)

    def test_projection_is_the_standalone_semantic_object(self) -> None:
        """SPEC 16.5.6: the digest covers the embedded object's own canonical
        bytes (final LF included) and no wrapper field."""
        for name in NAMES:
            with self.subTest(fixture=name):
                obj = load(name)
                proj = semantic_projection(obj["semantic"])
                self.assertTrue(proj.endswith(b"}\n") and proj.startswith(b'{"branches":'))
                self.assertEqual(hashlib.sha256(proj).hexdigest(), obj["semantic_projection_sha256"])
                self.assertEqual(decode_semantic_structure(proj), obj["semantic"])
                wrapper = copy.deepcopy(obj)
                wrapper["merge"]["tool"]["version"] = "9.9.9"
                wrapper["execution"] = {"exit_code": None, "signal": 9, "status": "signaled"}
                self.assertEqual(projection_sha256(wrapper["semantic"]), obj["semantic_projection_sha256"])
                self.assertEqual(outcome(wrapper)[0], "valid")

    def test_fixtures_use_every_enumeration_value(self) -> None:
        """all-kinds.json (with the other two) exercises every value the two
        schemas enumerate, so no enum branch of a validator goes unused."""
        seen: set[str] = set()
        for name in NAMES:
            for _, container, key in nodes(load(name)):
                if isinstance(container[key], str):
                    seen.add(container[key])
        for entry in decode_canonical((FIXTURES / "mutations.json").read_bytes())["mutations"]:
            if entry["expect"] == "valid":
                for _, container, key in nodes(build.apply(load(entry["base"]), entry)):
                    if isinstance(container[key], str):
                        seen.add(container[key])
        missing = []
        for schema in ("sv0cov.indexed-1.0.schema.json", "sv0cov.indexed-semantic-1.0.schema.json"):
            for pointer, container, key in nodes(decode_canonical((ROOT / "schemas" / schema).read_bytes())):
                if key == "enum":
                    missing += [f"{schema}{pointer}: {v}" for v in container[key] if v not in seen]
        self.assertEqual(missing, [])


class MutationCorpusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = decode_canonical((FIXTURES / "mutations.json").read_bytes())["mutations"]

    def test_names_are_unique(self) -> None:
        names = [m["name"] for m in self.corpus]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 240)
        self.assertEqual({m["expect"] for m in self.corpus}, {"valid", "COV3010", "COV3011"})

    def test_every_mutation_has_its_recorded_outcome(self) -> None:
        for m in self.corpus:
            with self.subTest(mutation=m["name"]):
                obj = build.apply(load(m["base"]), m)
                got, exc = outcome(obj)
                self.assertEqual(got, m["expect"], str(exc))
                # The same verdict from bytes.
                if m["expect"] == "valid":
                    decode_indexed_structure(encode(obj))
                else:
                    with self.assertRaises(IndexedError) as ctx:
                        decode_indexed_structure(encode(obj))
                    self.assertEqual(ctx.exception.code, m["expect"])

    def test_every_rule_is_reached(self) -> None:
        """Each `_fail` call in sv0cov.formats.indexed is raised by at least
        one corpus entry: no record-level rule is untested."""
        source = Path(indexed.__file__).read_text().splitlines()
        sites = {n for n, line in enumerate(source, 1) if re.search(r"\b_fail\(", line) and not line.startswith("def ")}
        hit: set[int] = set()
        # A lone surrogate cannot be written in canonical JSON, so the corpus
        # cannot hold it; a caller checking a decoded object still can.
        surrogate = load("all-kinds")
        surrogate["map_inputs"][0]["name"] = "app\ud800.json"
        self.assertEqual(outcome(surrogate)[0], "COV3010")
        for obj in [build.apply(load(m["base"]), m) for m in self.corpus] + [surrogate]:
            _, exc = outcome(obj)
            if exc is not None:
                for frame in traceback.extract_tb(exc.__traceback__):
                    if frame.filename == indexed.__file__ and frame.lineno in sites:
                        hit.add(frame.lineno)
        missed = [f"{n}: {source[n - 1].strip()}" for n in sorted(sites - hit)]
        self.assertEqual(missed, [])


class ClosedShapeTest(unittest.TestCase):
    """Every property of every record, in every fixture."""

    def test_removing_any_property_is_rejected(self) -> None:
        for name in NAMES:
            base = load(name)
            for pointer, container, key in list(nodes(base)):
                if not isinstance(container, dict):
                    continue
                with self.subTest(fixture=name, pointer=pointer):
                    saved = container.pop(key)
                    try:
                        code, _ = outcome(rehashed(copy.deepcopy(base), pointer))
                    finally:
                        container[key] = saved
                    self.assertEqual(code, "COV3010")

    def test_adding_a_property_to_any_object_is_rejected(self) -> None:
        for name in NAMES:
            base = load(name)
            objects = [("", base)] + [(p, c[k]) for p, c, k in list(nodes(base)) if isinstance(c[k], dict)]
            for pointer, obj in objects:
                for extra in ("extension", "x-vendor", "$comment"):
                    with self.subTest(fixture=name, pointer=pointer, extra=extra):
                        obj[extra] = None
                        try:
                            code, _ = outcome(rehashed(copy.deepcopy(base)))
                        finally:
                            del obj[extra]
                        self.assertEqual(code, "COV3010")

    def test_mistyping_any_value_is_rejected(self) -> None:
        def wrong(v: object) -> list[object]:
            if isinstance(v, bool):
                return [int(v), "true" if v else "false", None]
            if isinstance(v, int):
                return [str(v), [v], True]
            if isinstance(v, str):
                return [0, [v], {"value": v}]
            if v is None:
                return [{}, [], False]
            if isinstance(v, list):
                return [{}, "[]", 0]
            return [[], "{}", 0]

        for name in NAMES:
            base = load(name)
            for pointer, container, key in list(nodes(base)):
                saved = container[key]
                for bad in wrong(saved):
                    with self.subTest(fixture=name, pointer=pointer, bad=repr(bad)[:20]):
                        container[key] = bad
                        try:
                            code, _ = outcome(rehashed(copy.deepcopy(base), pointer))
                        finally:
                            container[key] = saved
                        self.assertEqual(code, "COV3010")


class BytesTest(unittest.TestCase):
    def assert_rejected(self, data: bytes, code: str = "COV3010") -> None:
        with self.assertRaises(IndexedError) as ctx:
            decode_indexed_structure(data)
        self.assertEqual(ctx.exception.code, code)

    def test_noncanonical_bytes_are_rejected(self) -> None:
        good = (FIXTURES / "empty.json").read_bytes()
        obj = json.loads(good)
        cases = {
            "no final LF": good[:-1],
            "two final LFs": good + b"\n",
            "BOM": b"\xef\xbb\xbf" + good,
            "indented": json.dumps(obj, indent=1, sort_keys=True).encode() + b"\n",
            "spaces after separators": json.dumps(obj, sort_keys=True).encode() + b"\n",
            "keys unsorted": json.dumps(dict(reversed(list(obj.items()))), separators=(",", ":")).encode() + b"\n",
            "duplicate key": good.replace(b'{"diagnostics":', b'{"diagnostics":[],"diagnostics":', 1),
            "float": good.replace(b'"diagnostic_registry_revision":2', b'"diagnostic_registry_revision":2.0', 1),
            "exponent": good.replace(b'"diagnostic_registry_revision":2', b'"diagnostic_registry_revision":2e0', 1),
            "leading zero": good.replace(b'"diagnostic_registry_revision":2', b'"diagnostic_registry_revision":02', 1),
            "escaped ASCII": good.replace(b'"sv0cov.indexed"', b'"sv0cov.\\u0069ndexed"', 1),
            "empty": b"",
            "not JSON": b"sv0cov.indexed\n",
            "an array": b"[]\n",
            "trailing value": good + good,
        }
        for name, data in cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(data, good)
                self.assert_rejected(data)

    def test_a_count_above_u64_is_not_canonical(self) -> None:
        good = (FIXTURES / "bounds.json").read_bytes()
        self.assertIn(b"18446744073709551615", good)
        self.assert_rejected(good.replace(b"18446744073709551615", b"18446744073709551616"))

    def test_semantic_bytes_are_checked_standalone(self) -> None:
        proj = semantic_projection(load("all-kinds")["semantic"])
        decode_semantic_structure(proj)
        for name, data in {
            "no final LF": proj[:-1],
            "wrapper bytes": (FIXTURES / "all-kinds.json").read_bytes(),
            "unknown property": proj.replace(b'{"branches":', b'{"a":1,"branches":', 1),
            "version": proj.replace(b'"version":"1.0"}\n', b'"version":"1.1"}\n'),
        }.items():
            with self.subTest(case=name), self.assertRaises(IndexedError) as ctx:
                decode_semantic_structure(data)
            self.assertEqual(ctx.exception.code, "COV3010")


if __name__ == "__main__":
    unittest.main()
