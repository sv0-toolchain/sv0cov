# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Schema preflight (CV-010) and validator generation (CV-011).

COV-FMT-045/046, AC-122, AC-123. A small bundle that uses every permitted
keyword must pass preflight; each single forbidden change must fail it. The
generated validators must agree with the jsonschema oracle, when the oracle
is installed, on every instance in the corpus.
"""

from __future__ import annotations

import copy
import importlib
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools" / "schemagen"))

import generate  # noqa: E402
import preflight  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.structural import StructuralError  # noqa: E402

DIALECT = preflight.DIALECT

RECORD = {
    "$schema": DIALECT,
    "$defs": {
        "count": {"maximum": 18446744073709551615, "minimum": 0, "type": "integer"},
        "name": {"maxLength": 8, "minLength": 1, "type": "string"},
    },
    "additionalProperties": False,
    "properties": {
        "count": {"$ref": "#/$defs/count"},
        "kind": {"enum": ["a", "b", 3, None, True]},
        "pair": {
            "items": False,
            "maxItems": 2,
            "minItems": 2,
            "prefixItems": [{"$ref": "#/$defs/name"}, {"type": "boolean"}],
            "type": "array",
        },
        "schema": {"const": "demo", "title": "fixed tag"},
        "tags": {"items": {"$ref": "common-1.0.schema.json#/$defs/tag"}, "maxItems": 3, "type": "array"},
        "value": {"anyOf": [{"type": "null"}, {"$ref": "#/$defs/name"}]},
        "which": {"oneOf": [{"maximum": 10, "minimum": 0, "type": "integer"}, {"maximum": 20, "minimum": 5, "type": "integer"}]},
        "z": {"not": {"const": 0}},
    },
    "required": ["count", "kind", "pair", "schema", "tags", "value", "which", "z"],
    "type": "object",
}
COMMON = {
    "$schema": DIALECT,
    "$defs": {"tag": {"maxLength": 4, "minLength": 1, "type": "string"}},
    "$comment": "shared definitions",
    "maxLength": 16,
    "minLength": 0,
    "type": "string",
}


def bundle(record: dict = RECORD, common: dict = COMMON) -> dict[str, bytes]:
    return {"record-1.0.schema.json": encode(record), "common-1.0.schema.json": encode(common)}


VALID = {
    "count": 3,
    "kind": "a",
    "pair": ["ab", True],
    "schema": "demo",
    "tags": ["x", "yy"],
    "value": None,
    "which": 1,
    "z": 1,
}
INSTANCES = [
    VALID,
    {**VALID, "count": 0},
    {**VALID, "count": 18446744073709551615},
    {**VALID, "count": -1},
    {**VALID, "count": 18446744073709551616},
    {**VALID, "count": 1.0},
    {**VALID, "count": 1.5},
    {**VALID, "count": True},
    {**VALID, "kind": 3},
    {**VALID, "kind": 3.0},
    {**VALID, "kind": 1},
    {**VALID, "kind": None},
    {**VALID, "kind": True},
    {**VALID, "kind": "c"},
    {**VALID, "pair": ["ab"]},
    {**VALID, "pair": ["ab", True, 1]},
    {**VALID, "pair": ["", True]},
    {**VALID, "pair": ["ab", 1]},
    {**VALID, "schema": "other"},
    {**VALID, "tags": []},
    {**VALID, "tags": ["toolong"]},
    {**VALID, "tags": ["a", "b", "c", "d"]},
    {**VALID, "tags": "x"},
    {**VALID, "value": "ok"},
    {**VALID, "value": ""},
    {**VALID, "value": 7},
    {**VALID, "which": 3},
    {**VALID, "which": 7},
    {**VALID, "which": 15},
    {**VALID, "which": 25},
    {**VALID, "z": 0},
    {**VALID, "z": 0.0},
    {**VALID, "extra": 1},
    {k: v for k, v in VALID.items() if k != "count"},
    {**VALID, "value": "é" * 8},
    {**VALID, "value": "é" * 9},
    [],
    "x",
    None,
]


def load_generated(files: dict[str, bytes], tmp: Path, package: str):
    schemas = tmp / "schemas"
    schemas.mkdir()
    for name, data in files.items():
        (schemas / name).write_bytes(data)
    out = tmp / package
    generate.write(generate.generate(schemas), out)
    sys.path.insert(0, str(tmp))
    try:
        return importlib.import_module(f"{package}.record_1_0"), out
    finally:
        sys.path.remove(str(tmp))


class PreflightTest(unittest.TestCase):
    def test_valid_bundle(self) -> None:
        self.assertEqual(preflight.check_bundle(bundle(), metaschema=False), [])

    def mutate(self, fn, target: str = "record") -> list:
        rec, com = copy.deepcopy(RECORD), copy.deepcopy(COMMON)
        fn(rec if target == "record" else com)
        # Raw sorted-key JSON, not sv0cov's encoder: some mutations (fractional
        # or out-of-range bounds) cannot be canonically encoded at all, and the
        # preflight itself must reject them.
        raw = lambda d: (json.dumps(d, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()  # noqa: E731
        files = {"record-1.0.schema.json": raw(rec), "common-1.0.schema.json": raw(com)}
        return preflight.check_bundle(files, metaschema=False)

    def test_each_forbidden_change_fails(self) -> None:
        props = lambda r: r["properties"]  # noqa: E731
        cases = {
            "pattern keyword": lambda r: props(r)["schema"].__setitem__("pattern", "^d"),
            "format keyword": lambda r: props(r)["schema"].__setitem__("format", "uri"),
            "$id keyword": lambda r: r.__setitem__("$id", "urn:x"),
            "allOf": lambda r: props(r).__setitem__("x", {"allOf": [{}, {}]}),
            "if/then": lambda r: props(r)["schema"].__setitem__("if", {}),
            "uniqueItems": lambda r: props(r)["tags"].__setitem__("uniqueItems", True),
            "default": lambda r: props(r)["schema"].__setitem__("default", "demo"),
            "exclusiveMinimum": lambda r: r["$defs"]["count"].__setitem__("exclusiveMinimum", 0),
            "extension keyword": lambda r: props(r)["schema"].__setitem__("x-note", 1),
            "wrong dialect": lambda r: r.__setitem__("$schema", "https://json-schema.org/draft-07/schema"),
            "missing dialect": lambda r: r.pop("$schema"),
            "nested $schema": lambda r: props(r)["schema"].__setitem__("$schema", DIALECT),
            "nested $defs": lambda r: props(r)["schema"].__setitem__("$defs", {}),
            "bad def name": lambda r: r["$defs"].__setitem__("1bad", {"type": "null"}),
            "additionalProperties true": lambda r: r.__setitem__("additionalProperties", True),
            "missing required keyword": lambda r: r.pop("required"),
            "unsorted required": lambda r: r["required"].reverse(),
            "incomplete required": lambda r: r["required"].pop(),
            "object keywords without type": lambda r: r.pop("type"),
            "type list": lambda r: props(r)["schema"].__setitem__("type", ["string", "null"]),
            "unknown type": lambda r: props(r)["schema"].__setitem__("type", "float"),
            "integer without bounds": lambda r: r["$defs"]["count"].pop("maximum"),
            "fractional bound": lambda r: r["$defs"]["count"].__setitem__("maximum", 1.5),
            "bound out of range": lambda r: r["$defs"]["count"].__setitem__("maximum", 2**64),
            "minimum above maximum": lambda r: r["$defs"]["count"].__setitem__("minimum", 2**64 - 1)
            or r["$defs"]["count"].__setitem__("maximum", 0),
            "minLength above maxLength": lambda r: r["$defs"]["name"].__setitem__("minLength", 9),
            "maxItems too large": lambda r: props(r)["tags"].__setitem__("maxItems", 16777217),
            "tuple without items false": lambda r: props(r)["pair"].pop("items"),
            "tuple bounds mismatch": lambda r: props(r)["pair"].__setitem__("maxItems", 3),
            "items false outside tuple": lambda r: props(r)["tags"].__setitem__("items", False),
            "empty enum": lambda r: props(r)["kind"].__setitem__("enum", []),
            "duplicate enum": lambda r: props(r)["kind"]["enum"].append("a"),
            "object const": lambda r: props(r)["schema"].__setitem__("const", {"a": 1}),
            "one-branch anyOf": lambda r: props(r)["value"].__setitem__("anyOf", [{"type": "null"}]),
            "ref with sibling": lambda r: props(r)["count"].__setitem__("type", "integer"),
            "root ref": lambda r: props(r)["count"].__setitem__("$ref", "#"),
            "remote ref": lambda r: props(r)["count"].__setitem__("$ref", "https://x.invalid/s.json#/$defs/a"),
            "parent ref": lambda r: props(r)["count"].__setitem__("$ref", "../common-1.0.schema.json#/$defs/tag"),
            "pointer escape ref": lambda r: props(r)["count"].__setitem__("$ref", "#/$defs/a~1b"),
            "unresolved ref": lambda r: props(r)["count"].__setitem__("$ref", "#/$defs/missing"),
            "ref outside bundle": lambda r: props(r)["count"].__setitem__("$ref", "other-1.0.schema.json#/$defs/a"),
            "cycle": lambda r: r["$defs"].__setitem__("loop", {"$ref": "#/$defs/loop"}),
            "boolean subschema": lambda r: props(r).__setitem__("x", True),
            "long comment": lambda r: r.__setitem__("$comment", "c" * 1025),
        }
        for name, fn in cases.items():
            with self.subTest(case=name):
                self.assertNotEqual(self.mutate(fn), [], name)

    def test_cross_file_cycle_fails(self) -> None:
        rec, com = copy.deepcopy(RECORD), copy.deepcopy(COMMON)
        rec["$defs"]["name"] = {"$ref": "common-1.0.schema.json#/$defs/tag"}
        com["$defs"]["tag"] = {"$ref": "record-1.0.schema.json#/$defs/name"}
        findings = preflight.check_bundle(bundle(rec, com), metaschema=False)
        self.assertTrue(any("cycle" in f.message for f in findings), findings)

    def test_noncanonical_bytes_fail(self) -> None:
        files = bundle()
        files["common-1.0.schema.json"] = b'{"type": "string"}\n'
        self.assertNotEqual(preflight.check_bundle(files, metaschema=False), [])

    def test_bad_file_name_fails(self) -> None:
        files = bundle()
        files["common.json"] = files.pop("common-1.0.schema.json")
        self.assertNotEqual(preflight.check_bundle(files, metaschema=False), [])

    @unittest.skipUnless(preflight.metaschema_available(), "oracle group not installed")
    def test_bundle_passes_the_draft_2020_12_metaschema(self) -> None:
        self.assertEqual(preflight.check_bundle(bundle(), metaschema=True), [])


class GeneratorTest(unittest.TestCase):
    def test_output_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schemas = Path(tmp)
            for name, data in bundle().items():
                (schemas / name).write_bytes(data)
            self.assertEqual(generate.generate(schemas), generate.generate(schemas))

    def test_generated_validator_behaviour(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            mod, _ = load_generated(bundle(), Path(tmp), "gen_behaviour")
            mod.validate(VALID)
            with self.assertRaises(StructuralError) as ctx:
                mod.validate({**VALID, "pair": ["ab", 1]})
            self.assertEqual((ctx.exception.pointer, ctx.exception.keyword), ("/pair/1", "type"))
            with self.assertRaises(StructuralError) as ctx:
                mod.validate({**VALID, "extra": 1, "count": -1})
            # additionalProperties is checked before properties (frozen order).
            self.assertEqual(ctx.exception.keyword, "additionalProperties")
            self.assertEqual(mod.SCHEMA_NAME, "record")
            self.assertEqual(mod.SCHEMA_VERSION, "1.0")

    def test_generated_code_does_not_read_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _, out = load_generated(bundle(), Path(tmp), "gen_imports")
            forbidden = re.compile(r"^\s*(import|from)\s+(json|jsonschema|importlib|referencing)\b|\b(eval|exec|open|compile)\(", re.M)
            for py in out.glob("*.py"):
                text = py.read_text(encoding="utf-8")
                self.assertIsNone(forbidden.search(text), py.name)
                imports = {m.group(1) for m in re.finditer(r"^from (\S+) import", text, re.M)}
                self.assertLessEqual(imports, {"__future__", "sv0cov.formats.structural", "."}, py.name)

    def test_check_detects_stale_and_orphaned_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            schemas = Path(tmp, "schemas")
            schemas.mkdir()
            for name, data in bundle().items():
                (schemas / name).write_bytes(data)
            out = Path(tmp, "out")
            outputs = generate.generate(schemas)
            generate.write(outputs, out)
            self.assertEqual(generate.check(outputs, out), [])
            (out / "record_1_0.py").write_text("# edited\n", encoding="utf-8")
            (out / "orphan.py").write_text("", encoding="utf-8")
            problems = generate.check(outputs, out)
            self.assertTrue(any("stale" in p for p in problems), problems)
            self.assertTrue(any("orphan" in p for p in problems), problems)

    def test_checked_in_validators_are_current(self) -> None:
        schemas = ROOT / "schemas"
        if not any(schemas.glob("*.schema.json")):
            self.skipTest("no canonical schemas yet")
        self.assertEqual(generate.check(generate.generate(schemas), generate.DEFAULT_OUT), [])


@unittest.skipUnless(preflight.metaschema_available(), "oracle group not installed")
class OracleDifferentialTest(unittest.TestCase):
    """Generated validators and Draft202012Validator agree on valid/invalid."""

    def test_agreement(self) -> None:
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource

        files = bundle()
        registry = Registry().with_resources(
            (name, Resource.from_contents(json.loads(data))) for name, data in files.items()
        )
        record = json.loads(files["record-1.0.schema.json"])
        oracle = Draft202012Validator(record, registry=registry)
        with tempfile.TemporaryDirectory() as tmp:
            mod, _ = load_generated(files, Path(tmp), "gen_oracle")
            for i, instance in enumerate(INSTANCES):
                with self.subTest(instance=i):
                    try:
                        mod.validate(instance)
                        ours = True
                    except StructuralError:
                        ours = False
                    self.assertEqual(ours, oracle.is_valid(instance), instance)


if __name__ == "__main__":
    unittest.main()
