# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Structural differential evidence (CV-012, SPEC 25.2.4).

COV-FMT-047, COV-PKG-017, AC-124, AC-125.

- The vendored JSON Schema Test Suite matches its manifest (offline).
- The checked-in selection manifest equals a fresh mechanical selection.
- For every applicable upstream test, the generated validator, the oracle
  (when installed), and the upstream expected result agree.
- For the project-owned profile corpus, the generated validator and the
  oracle agree on Boolean validity.
"""

from __future__ import annotations

import importlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("src", "tools", "tools/schemagen", "tests/conformance"):
    sys.path.insert(0, str(ROOT / sub))

import generate  # noqa: E402
import jsts_select  # noqa: E402
import jsts_vendor  # noqa: E402
import preflight  # noqa: E402
import profile_corpus  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.structural import StructuralError  # noqa: E402

ORACLE = preflight.metaschema_available()


def compile_schema(schema: dict, tmp: Path, package: str):
    """Generate a validator for a single-file bundle and import it."""
    schemas = tmp / f"{package}_schemas"
    schemas.mkdir()
    (schemas / "case-1.0.schema.json").write_bytes(encode(schema))
    generate.write(generate.generate(schemas), tmp / package)
    sys.path.insert(0, str(tmp))
    try:
        return importlib.import_module(f"{package}.case_1_0")
    finally:
        sys.path.remove(str(tmp))


def ours(module, instance: object) -> bool:
    try:
        module.validate(instance)
    except StructuralError:
        return False
    return True


def oracle(schema: dict):
    from jsonschema import Draft202012Validator

    return Draft202012Validator(schema)


class VendorTest(unittest.TestCase):
    def test_vendored_tree_matches_manifest(self) -> None:
        self.assertEqual(jsts_vendor.verify(), [])

    def test_manifest_pins_a_full_commit(self) -> None:
        m = jsts_vendor.load_manifest()
        self.assertRegex(m["commit"], r"^[0-9a-f]{40}$")
        self.assertEqual(m["repository"], jsts_vendor.REPOSITORY)
        self.assertEqual(m["license"]["spdx"], "MIT")

    def test_tampering_is_detected(self) -> None:
        m = jsts_vendor.load_manifest()
        with tempfile.TemporaryDirectory() as tmp:
            tree = Path(tmp) / "t"
            import shutil

            shutil.copytree(jsts_vendor.VENDOR, tree, symlinks=True)
            self.assertEqual(jsts_vendor.verify(m, tree), [])
            victim = tree / "tests" / "draft2020-12" / "type.json"
            victim.write_bytes(victim.read_bytes() + b" ")
            (tree / "extra.txt").write_text("x")
            problems = jsts_vendor.verify(m, tree)
            self.assertTrue(any("type.json: content changed" in p for p in problems), problems)
            self.assertTrue(any("extra.txt: not in the manifest" in p for p in problems), problems)


class SelectionTest(unittest.TestCase):
    def test_checked_in_selection_is_current(self) -> None:
        self.assertEqual(encode(jsts_select.build_selection()), jsts_select.SELECTION.read_bytes())

    def test_selection_does_not_import_validators(self) -> None:
        source = (ROOT / "tools" / "jsts_select.py").read_text(encoding="utf-8")
        for forbidden in ("_generated", "jsonschema", "import generate", "StructuralError"):
            self.assertNotIn(forbidden, source)

    def test_counts_are_consistent(self) -> None:
        sel = jsts_select.load_selection()
        applicable = [c for c in sel["cases"] if c["applicable"]]
        self.assertEqual(sel["counts"]["applicable_cases"], len(applicable))
        self.assertEqual(sel["counts"]["applicable_tests"], sum(len(c["tests"]) for c in applicable))
        self.assertTrue(all(c["exclusion_reasons"] for c in sel["cases"] if not c["applicable"]))
        self.assertGreater(len(applicable), 0)


class UpstreamDifferentialTest(unittest.TestCase):
    def test_applicable_upstream_cases(self) -> None:
        sel = jsts_select.load_selection()
        with tempfile.TemporaryDirectory() as tmp:
            for n, case in enumerate(c for c in sel["cases"] if c["applicable"]):
                doc = json.loads((jsts_vendor.VENDOR / case["file"]).read_bytes())
                upstream = doc[case["index"]]
                module = compile_schema(upstream["schema"], Path(tmp), f"jsts_{n}")
                ref = oracle(upstream["schema"]) if ORACLE else None
                for t in case["tests"]:
                    instance = upstream["tests"][t["index"]]["data"]
                    with self.subTest(file=case["file"], case=case["description"], test=t["description"]):
                        got = ours(module, instance)
                        self.assertEqual(got, t["expected"])
                        if ref is not None:
                            self.assertEqual(ref.is_valid(instance), t["expected"])


class ProjectCorpusTest(unittest.TestCase):
    def test_every_corpus_schema_passes_preflight(self) -> None:
        for name, schema, _ in profile_corpus.CORPUS:
            with self.subTest(schema=name):
                self.assertEqual(preflight.check_bundle({"case-1.0.schema.json": encode(schema)}, metaschema=ORACLE), [])

    @unittest.skipUnless(ORACLE, "oracle group not installed")
    def test_generated_validators_agree_with_oracle(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for n, (name, schema, instances) in enumerate(profile_corpus.CORPUS):
                module = compile_schema(schema, Path(tmp), f"corpus_{n}")
                ref = oracle(schema)
                for i, instance in enumerate(instances):
                    with self.subTest(schema=name, instance=i):
                        self.assertEqual(ours(module, instance), ref.is_valid(instance), instance)


if __name__ == "__main__":
    unittest.main()
