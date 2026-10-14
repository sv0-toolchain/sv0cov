# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Native report 1.0 and resolved configuration 1.0: schemas and
record-level rules (CV-228; SPEC 21.3; COV-REP-017, COV-CFG-007, BL-036).

The frozen fixtures are accepted and byte-stable, every mutation has its
recorded outcome, every property of every record is required, closed and
typed, noncanonical bytes are rejected, and every rule of the structure
layer is reached by some case.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import random
import re
import sys
import traceback
import unittest
from fractions import Fraction
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "report"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_indexed_structure import nodes  # noqa: E402

from sv0cov import config as C  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats import report  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.map import MAP_CEILINGS  # noqa: E402
from sv0cov.formats.report import ReportError, check_report_structure, check_resolved_configuration, decode_report_structure, ratio  # noqa: E402

_spec = importlib.util.spec_from_file_location("report_fixture_build", FIXTURES / "build.py")
build = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(build)

NAMES = ("empty", "passing", "all-kinds", "bounds")
TOP = ["branches", "capabilities", "complete", "contexts", "contracts", "entities", "evidence_eligibility", "exclusions", "inputs", "lines",
       "maps", "points", "policy", "provenance", "regions", "resolved_configuration", "saturation", "schema", "sources", "summary", "tool",
       "version"]
U64 = 2**64 - 1


def load(name: str) -> dict:
    return decode_canonical((FIXTURES / f"{name}.json").read_bytes())


def outcome(obj: dict) -> tuple[str, ReportError | None]:
    try:
        check_report_structure(obj)
    except ReportError as exc:
        return exc.code, exc
    return "valid", None


class FixtureTest(unittest.TestCase):
    def test_artifacts_are_current(self) -> None:
        for path, data in build.artifacts().items():
            with self.subTest(file=path.name):
                self.assertEqual(path.read_bytes(), data, "rerun tests/fixtures/report/build.py --write after review")

    def test_fixtures_are_accepted(self) -> None:
        for name in NAMES:
            with self.subTest(fixture=name):
                data = (FIXTURES / f"{name}.json").read_bytes()
                obj = decode_report_structure(data)
                self.assertEqual(encode(obj), data)
                self.assertEqual(sorted(obj), TOP)
                self.assertEqual(len(TOP), 22)
                self.assertEqual(sorted(obj["resolved_configuration"]), ["coverage", "report", "schema", "version"])
                self.assertEqual(len(obj["provenance"]), 13)

    def test_record_shapes_are_the_specified_ones(self) -> None:
        """Property inventories restated from SPEC 21.3.3-21.3.8."""
        a = load("all-kinds")
        want = {
            "sources": "digest observed_digest ownership package path source_index source_state summary",
            "maps": "compiler_identity map_id program_counter_count source_indices target",
            "contexts": "context_index value",
            "entities": "entity_index kind qualified_name source_index span summary",
            "points": "classification count entity_index kind outcome_ordinal point_id semantic_discriminator source_index span",
            "regions": "classification count counter_expression entity_index kind line_contributing line_numbers point_ids "
                       "region_index source_index span",
            "lines": "line line_index region_indices source_index status",
            "branches": "branch_index entity_index kind outcomes source_index span",
            "contracts": "clause_index count_false count_true enforcement entity_index evidence_identity function_entity_index kind "
                         "runtime_result source_index span",
            "exclusions": "affected exclusion_index mode origin reason source_index span",
            "inputs": "artifact_sha256 backend byte_length context_index diagnostics map_id name profile_id run_id status",
        }
        for key, props in want.items():
            self.assertEqual(sorted(a[key][0]), props.split(), key)
        self.assertEqual(sorted(a["exclusions"][0]["affected"]),
                         "branch_indices clause_indices entity_indices line_indices point_ids region_indices".split())
        self.assertEqual(sorted(a["branches"][0]["outcomes"][0]), "count evidence_identity name ordinal point_id status".split())
        ev = a["policy"]["evaluations"][0]
        self.assertEqual(sorted(ev), "actual assertion_kind assertion_name comparison diagnostics limit members metric result "
                                     "threshold_source".split())
        self.assertEqual(sorted(ev["members"]),
                         "branch_indices clause_indices entity_indices line_indices region_indices source_indices".split())
        self.assertEqual(sorted(a["policy"]), ["evaluations", "passed"])
        self.assertEqual(sorted(a["summary"]), "branch contract function line region".split())
        self.assertEqual(sorted(a["summary"]["line"]), "covered partial ratio total".split())
        self.assertEqual(sorted(a["tool"]), "diagnostic_registry_revision diagnostic_registry_sha256 name version".split())
        self.assertEqual(sorted(a["saturation"]),
                         "affected_point_ids affected_region_indices any eligible_metrics ineligible_uses policy".split())
        self.assertEqual(sorted(a["provenance"]), "backends execution_exit_code execution_signal execution_status "
                         "indexed_diagnostic_registry_revision indexed_diagnostic_registry_sha256 indexed_input_sha256 map_ids run_ids "
                         "run_manifest_sha256 run_selection semantic_projection_sha256 source_accuracy".split())
        self.assertEqual(a["capabilities"], ["branch-outcomes", "contexts", "contract-coverage", "exclusion-audit", "policy-assertions",
                                             "saturation-lower-bounds", "source-integrity"])

    def test_fixtures_use_every_enumeration_value(self) -> None:
        seen: set[str] = set()
        docs = [load(n) for n in NAMES]
        for entry in decode_canonical((FIXTURES / "mutations.json").read_bytes())["mutations"]:
            if entry["expect"] == "valid":
                docs.append(build.apply(load(entry["base"]), entry))
        for doc in docs:
            for _, container, key in nodes(doc):
                if isinstance(container[key], str):
                    seen.add(container[key])
        missing = []
        for schema in ("sv0cov.report-1.0.schema.json", "sv0cov.resolved-configuration-1.0.schema.json"):
            for pointer, container, key in nodes(decode_canonical((ROOT / "schemas" / schema).read_bytes())):
                if key == "enum":
                    missing += [f"{schema}{pointer}: {v}" for v in container[key] if v not in seen]
        self.assertEqual(missing, [])

    def test_no_report_holds_a_private_fact(self) -> None:
        """SPEC 21.3.2 and 21.3.7: no host, user, process, time or invocation-transport field."""
        banned = {"hostname", "host", "user", "username", "pid", "timestamp", "generated_at", "cwd", "argv", "environment", "output",
                  "format", "quiet", "color"}
        for name in NAMES:
            keys = {k for _, c, k in nodes(load(name)) if isinstance(c, dict)}
            self.assertFalse(keys & banned, name)


class MutationCorpusTest(unittest.TestCase):
    def setUp(self) -> None:
        self.corpus = decode_canonical((FIXTURES / "mutations.json").read_bytes())["mutations"]

    def test_names_are_unique(self) -> None:
        names = [m["name"] for m in self.corpus]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 240)
        self.assertEqual({m["expect"] for m in self.corpus}, {"valid", "COV4001"})
        self.assertGreaterEqual(sum(m["expect"] == "valid" for m in self.corpus), 18)

    def test_every_mutation_has_its_recorded_outcome(self) -> None:
        for m in self.corpus:
            with self.subTest(mutation=m["name"]):
                obj = build.apply(load(m["base"]), m)
                got, exc = outcome(obj)
                self.assertEqual(got, m["expect"], str(exc))
                if m["expect"] == "valid":
                    decode_report_structure(encode(obj))
                else:
                    with self.assertRaises(ReportError) as ctx:
                        decode_report_structure(encode(obj))
                    self.assertEqual(ctx.exception.code, m["expect"])

    def test_every_rule_is_reached(self) -> None:
        """Each `_fail` call in sv0cov.formats.report is raised by at least one case."""
        source = Path(report.__file__).read_text().splitlines()
        sites = {n for n, line in enumerate(source, 1) if re.search(r"\b_fail\(", line) and not line.startswith("def ")}
        hit: set[int] = set()
        # A lone surrogate cannot be written in canonical JSON; a caller checking a decoded object can still hold one.
        surrogate = load("all-kinds")
        surrogate["resolved_configuration"]["coverage"]["scopes"][0]["include"]["value"] = ["src\ud800"]
        self.assertEqual(outcome(surrogate)[0], "COV4001")
        for obj in [build.apply(load(m["base"]), m) for m in self.corpus] + [surrogate]:
            _, exc = outcome(obj)
            if exc is not None:
                for frame in traceback.extract_tb(exc.__traceback__):
                    if frame.filename == report.__file__ and frame.lineno in sites:
                        hit.add(frame.lineno)
        missed = [f"{n}: {source[n - 1].strip()}" for n in sorted(sites - hit)]
        self.assertEqual(missed, [])


class ClosedShapeTest(unittest.TestCase):
    """Every property of every record, in every fixture."""

    def test_removing_any_property_is_rejected(self) -> None:
        checked = 0
        for name in NAMES:
            base = load(name)
            for pointer, container, key in list(nodes(base)):
                if not isinstance(container, dict):
                    continue
                saved = container.pop(key)
                try:
                    code, _ = outcome(base)
                finally:
                    container[key] = saved
                self.assertEqual(code, "COV4001", (name, pointer))
                checked += 1
        self.assertGreater(checked, 2000)

    def test_adding_a_property_to_any_object_is_rejected(self) -> None:
        for name in NAMES:
            base = load(name)
            objects = [("", base)] + [(p, c[k]) for p, c, k in list(nodes(base)) if isinstance(c[k], dict)]
            for pointer, obj in objects:
                for extra in ("extension", "x-vendor"):
                    obj[extra] = None
                    try:
                        code, _ = outcome(base)
                    finally:
                        del obj[extra]
                    self.assertEqual(code, "COV4001", (name, pointer, extra))

    def test_mistyping_any_value_is_rejected(self) -> None:
        def wrong(v: object) -> list[object]:
            if isinstance(v, bool):
                return [int(v), "true" if v else "false"]
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
                    container[key] = bad
                    try:
                        code, _ = outcome(base)
                    finally:
                        container[key] = saved
                    self.assertEqual(code, "COV4001", (name, pointer, repr(bad)[:20]))


class BytesTest(unittest.TestCase):
    def assert_rejected(self, data: bytes, code: str = "COV4001") -> None:
        with self.assertRaises(ReportError) as ctx:
            decode_report_structure(data)
        self.assertEqual(ctx.exception.code, code)

    def test_noncanonical_bytes_are_rejected(self) -> None:
        good = (FIXTURES / "passing.json").read_bytes()
        obj = json.loads(good)
        cases = {
            "no final LF": good[:-1],
            "two final LFs": good + b"\n",
            "BOM": b"\xef\xbb\xbf" + good,
            "indented": json.dumps(obj, indent=1, sort_keys=True).encode() + b"\n",
            "spaces after separators": json.dumps(obj, sort_keys=True).encode() + b"\n",
            "keys unsorted": json.dumps(dict(reversed(list(obj.items()))), separators=(",", ":")).encode() + b"\n",
            "duplicate key": good.replace(b'{"branches":', b'{"branches":[],"branches":', 1),
            "float": good.replace(b'"diagnostic_registry_revision":2', b'"diagnostic_registry_revision":2.0', 1),
            "exponent": good.replace(b'"diagnostic_registry_revision":2', b'"diagnostic_registry_revision":2e0', 1),
            "ratio as a JSON number": good.replace(b'"ratio":"1.000000"', b'"ratio":1.000000', 1),
            "escaped ASCII": good.replace(b'"sv0cov.report"', b'"sv0cov.\\u0072eport"', 1),
            "empty": b"",
            "not JSON": b"sv0cov.report\n",
            "an array": b"[]\n",
            "an indexed profile": (ROOT / "tests" / "fixtures" / "indexed" / "empty.json").read_bytes(),
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

    def test_bytes_over_the_readers_tier_are_refused_before_parsing(self) -> None:
        good = (FIXTURES / "all-kinds.json").read_bytes()
        with mock.patch.dict(MAP_CEILINGS, {"standard": len(good) - 1, "large": len(good)}):
            self.assert_rejected(good, "COV6001")
            self.assert_rejected(b"x" * len(good), "COV6001")
            self.assertEqual(len(decode_report_structure(good, tier="large")), 22)


class RatioTest(unittest.TestCase):
    """SPEC 21.3.1: exact covered / total, half to even, six digits, integers only."""

    def oracle(self, covered: int, total: int) -> str:
        scaled = round(Fraction(covered * 1000000, total))  # Python rounds a Fraction half to even
        return f"{scaled // 1000000}.{scaled % 1000000:06d}"

    def test_boundaries(self) -> None:
        self.assertIsNone(ratio(0, 0))
        cases = {(0, 1): "0.000000", (1, 1): "1.000000", (1, 3): "0.333333", (2, 3): "0.666667", (1, 2000000): "0.000000",
                 (3, 2000000): "0.000002", (5, 2000000): "0.000002", (7, 2000000): "0.000004", (999999, 1000000): "0.999999",
                 (1999999, 2000000): "1.000000", (U64 - 1, U64): "1.000000", (U64, U64): "1.000000", (1, U64): "0.000000",
                 (84, 99): "0.848485", (85, 100): "0.850000"}
        for (covered, total), want in cases.items():
            self.assertEqual(ratio(covered, total), want, (covered, total))
            self.assertEqual(self.oracle(covered, total), want, (covered, total))

    def test_against_exact_rational_arithmetic(self) -> None:
        rng = random.Random(228)
        for _ in range(20000):
            total = rng.choice([rng.randint(1, 50), rng.randint(1, 10**7), rng.randint(1, U64), 2000000 * rng.randint(1, 10**6)])
            covered = rng.choice([rng.randint(0, total), total // 2000000 * rng.randrange(1, 2000000, 2) if total % 2000000 == 0 else 0])
            covered = min(covered, total)
            got = ratio(covered, total)
            self.assertEqual(got, self.oracle(covered, total), (covered, total))
            self.assertRegex(got, r"\A(0\.[0-9]{6}|1\.000000)\Z")
        body = Path(report.__file__).read_text().split("def ratio")[1].split("def _metric")[0]
        self.assertNotIn("float", body.split('"""')[2])
        self.assertNotIn(" / ", body.split('"""')[2])


class ResolvedConfigurationTest(unittest.TestCase):
    """SPEC 21.3.7, COV-CFG-007: one generated schema, one default snapshot."""

    def test_the_schema_is_generated_from_the_inventory(self) -> None:
        schema = decode_canonical((ROOT / "schemas" / "sv0cov.resolved-configuration-1.0.schema.json").read_bytes())
        record = schema["$defs"]["resolved_configuration"]["properties"]
        self.assertEqual(sorted(record), ["coverage", "report", "schema", "version"])
        for table in C.TABLES:
            node = record["coverage"]
            for part in table.path.split(".")[2:]:
                node = node["properties"][part]
                node = node["anyOf"][1] if "anyOf" in node else node
                node = node["items"] if "items" in node else node
            want = sorted([k.name for k in table.keys] + list(table.tables))
            self.assertEqual((sorted(node["properties"]), node["required"], node["additionalProperties"]), (want, want, False), table.path)
        line = record["coverage"]["properties"]["thresholds"]["properties"]["line"]["properties"]
        self.assertEqual(line, {"source": {"enum": ["cli", "default", "sv0.toml"]},
                                "value": {"anyOf": [{"type": "null"}, {"maximum": 10000, "minimum": 0, "type": "integer"}]}})
        self.assertEqual(sorted(record["report"]["properties"]), ["allow_lossy_saturated_export", "allow_source_mismatch"])

    def test_the_default_snapshot_is_what_the_resolver_gives(self) -> None:
        snapshot = (ROOT / "tests" / "fixtures" / "config" / "resolved-defaults.json").read_bytes()
        self.assertEqual(snapshot, resolve("check").to_bytes())
        doc = check_resolved_configuration(decode_canonical(snapshot))
        self.assertEqual({leaf["source"] for _, leaf in report._leaves(doc, "")}, {"default"})
        self.assertEqual(load("empty")["resolved_configuration"], doc)

    def test_everything_the_resolver_produces_is_valid(self) -> None:
        cases = json.loads((ROOT / "tests" / "fixtures" / "config" / "file-cases.json").read_bytes())["cases"]
        checked = 0
        for case in cases:
            if case["toml"] is None:
                continue
            try:
                resolved = resolve("run", (), case["toml"].encode())
            except C.ConfigError:
                continue
            with self.subTest(case=case["id"]):
                check_resolved_configuration(resolved.document())
                checked += 1
        self.assertGreater(checked, 200)
        options = [("--no-context", None), ("--threshold-line", "85"), ("--report", "json"), ("--report", "term"), ("--diff-base", "HEAD"),
                   ("--diff-line", "100"), ("--ratchet-baseline", "b.json"), ("--ratchet-metric", "region"), ("--ratchet-metric", "branch"),
                   ("--raw-profile-tier", "custom"), ("--raw-profile-max-counters", "9"), ("--raw-profile-max-bytes", "99"),
                   ("--allow-lossy-saturated-export", None), ("--saturation-policy", "allow-ordinary")]
        check_resolved_configuration(resolve("run", options).document())

    def test_a_standalone_record_is_checked_like_the_embedded_one(self) -> None:
        good = load("all-kinds")["resolved_configuration"]
        check_resolved_configuration(copy.deepcopy(good))
        for label, change in {
            "unsorted set": lambda c: c["coverage"]["ratchet"]["metrics"].__setitem__("value", ["line", "branch"]),
            "unknown key": lambda c: c["coverage"].__setitem__("parallel", {"source": "default", "value": 1}),
            "cli scope": lambda c: c["coverage"]["scopes"][0]["line"].__setitem__("source", "cli"),
            "wrong schema": lambda c: c.__setitem__("schema", "sv0cov.report"),
        }.items():
            bad = copy.deepcopy(good)
            change(bad)
            with self.subTest(case=label), self.assertRaises(ReportError) as ctx:
                check_resolved_configuration(bad)
            self.assertEqual(ctx.exception.code, "COV4001")


if __name__ == "__main__":
    unittest.main()
