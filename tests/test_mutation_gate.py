# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Mutation gate: every generated structural check is killed (CV-013).

SPEC 25.2.2 and COV-FMT-045 require that deleting any generated check makes
at least one fixture fail. Covers the checked-in generated validators and
every schema of the project-owned profile corpus.
"""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for sub in ("src", "tools/schemagen", "tests/conformance"):
    sys.path.insert(0, str(ROOT / sub))

import generate  # noqa: E402
import mutation  # noqa: E402
import preflight  # noqa: E402
import profile_corpus  # noqa: E402

from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402


def synth_fixtures(schema_dir: Path) -> dict[str, list[object]]:
    files = preflight.load_bundle(schema_dir)
    bundle = {name: decode_canonical(data) for name, data in files.items()}
    synth = mutation.Synth(bundle)
    return {generate.module_name(name): synth.fixtures(name) for name in files}


class GeneratedModulesTest(unittest.TestCase):
    def test_every_check_in_the_shipped_validators_is_killed(self) -> None:
        fixtures = synth_fixtures(ROOT / "schemas")
        # Checked-in instances join the synthesized ones.
        registry = decode_canonical((ROOT / "registries" / "diagnostics-v1.json").read_bytes())
        fixtures["sv0cov_diagnostic_registry_1_0"].append(registry)
        total, survivors = mutation.run_gate(generate.DEFAULT_OUT, fixtures)
        self.assertGreater(total, 0)
        self.assertEqual(survivors, [], f"{len(survivors)} of {total} mutants survived")


class CorpusModulesTest(unittest.TestCase):
    def test_every_check_in_the_corpus_validators_is_killed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            for n, (name, schema, instances) in enumerate(profile_corpus.CORPUS):
                with self.subTest(schema=name):
                    schemas = Path(tmp, f"s{n}")
                    schemas.mkdir()
                    (schemas / "case-1.0.schema.json").write_bytes(encode(schema))
                    out = Path(tmp, f"p{n}")
                    generate.write(generate.generate(schemas), out)
                    fixtures = synth_fixtures(schemas)
                    fixtures["case_1_0"] += list(instances)
                    total, survivors = mutation.run_gate(out, fixtures)
                    self.assertEqual(survivors, [], f"{len(survivors)} of {total} mutants survived")


class SynthTest(unittest.TestCase):
    def test_synthesis_is_deterministic(self) -> None:
        self.assertEqual(repr(synth_fixtures(ROOT / "schemas")), repr(synth_fixtures(ROOT / "schemas")))

    def test_check_sites_found(self) -> None:
        src = "def f(v, p):\n    if x:\n        fail(p, 'type', 'y')\n"
        self.assertEqual(mutation.check_sites(src), [2])


if __name__ == "__main__":
    unittest.main()
