# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Coverage configuration schema 1.0 and CLI mapping (CV-029; SPEC 18.2).

The frozen corpus in ``tests/fixtures/config`` is regenerated and compared
byte for byte. Independently of that corpus, the defaults and the CLI-only
applicability table are restated here from SPEC 18.2.2-18.2.3.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import config as C  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "config"
CASES = json.loads((FIXTURES / "file-cases.json").read_bytes())["cases"]

try:
    from jsonschema import Draft202012Validator

    ORACLE = Draft202012Validator(json.loads((FIXTURES / "config.schema.json").read_bytes()))
except ImportError:
    ORACLE = None

SPEC_DEFAULTS = {
    "coverage.output_dir": ".sv0cov",
    "coverage.reports": ["term"],
    "coverage.empty": "fail",
    "coverage.reproducible_epoch": 0,
    "coverage.integrity.saturation": "fail",
    "coverage.limits.raw_profile.tier": "standard",
    "coverage.ratchet.tolerance_basis_points": 0,
    "coverage.exclusions.forbidden_reasons": [],
    "coverage.exclusions.forbidden_sources": [],
}

SPEC_CLI_ONLY = {
    "--run-id": {"run"},
    "--expect-run": {"merge"},
    "--run-manifest": {"merge"},
    "--output": {"merge", "report"},
    "--format": {"report"},
    "--quiet": {"run", "merge", "report", "check", "clean", "doctor"},
    "--color": {"run", "merge", "report", "check", "doctor"},
    "--diagnostic-format": set(C.COMMANDS),
    "--json": {"doctor", "version"},
    "--toolchain-root": {"doctor"},
    "--allow-source-mismatch": {"report"},
    "--allow-rejected-inputs": {"merge"},
    "--prefer-coverage-exit": {"run"},
    "--allow-lossy-saturated-export": {"run", "report"},
}

SPEC_MAPPED = [
    "--output-dir", "--report", "--empty", "--context", "--no-context", "--reproducible-epoch", "--saturation-policy",
    "--threshold-function", "--threshold-region", "--threshold-line", "--threshold-branch", "--threshold-contract",
    "--diff-base", "--diff-line", "--diff-region", "--diff-branch", "--ratchet-baseline", "--ratchet-metric",
    "--ratchet-tolerance-basis-points", "--raw-profile-tier", "--raw-profile-max-counters", "--raw-profile-max-bytes",
]


def case_bytes(case: dict) -> bytes:
    return case["toml"].encode("utf-8") if case["toml"] is not None else bytes.fromhex(case["toml_hex"])


def outcome(data: bytes) -> dict:
    try:
        return {"resolved": C.validate_bytes(data)}
    except C.ConfigError as exc:
        return {"code": exc.code, "path": exc.path}


class ConfigTest(unittest.TestCase):
    def test_artifacts_are_current(self) -> None:
        result = subprocess.run([sys.executable, str(ROOT / "tools" / "configgen.py")], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_file_corpus(self) -> None:
        for case in CASES:
            with self.subTest(case=case["id"]):
                self.assertEqual(outcome(case_bytes(case)), case["expect"])

    def test_every_key_path_has_valid_and_invalid_cases(self) -> None:
        ids = {c["id"] for c in CASES}
        for table in C.TABLES:
            self.assertIn(f"{table.path}/unknown-key", ids)
            for key in table.keys:
                if key.kind is C.SCHEMA:
                    continue
                prefix = f"{table.path}.{key.name}/"
                ok = [c for c in CASES if c["id"].startswith(prefix + "valid") and "resolved" in c["expect"]]
                bad = [c for c in CASES if c["id"].startswith(prefix + "invalid") and "code" in c["expect"]]
                self.assertTrue(ok, f"no accepted case for {prefix}")
                self.assertTrue(bad, f"no rejected case for {prefix}")
                all_prefix = [c for c in CASES if c["id"].startswith(prefix)]
                self.assertTrue(all(("resolved" in c["expect"]) == ("/valid-" in c["id"]) for c in all_prefix), prefix)

    def test_threshold_forms_resolve_identically(self) -> None:
        got = C.validate_bytes(b'[coverage]\nschema = "1.0"\n[coverage.thresholds]\nline = 85\nbranch = "8500bp"\n')
        self.assertEqual(got["thresholds"], {"line": 8500, "branch": 8500})
        self.assertEqual(C.check_cli_value("--threshold-line", "85", "check"), C.check_cli_value("--threshold-line", "8500bp", "check"))
        for bad in ("08500bp", "+85", "85%", "85.0", "1e2", " 85", "85 ", "101", "10001bp"):
            with self.assertRaises(C.ConfigError) as cm:
                C.parse_threshold(bad, "t")
            self.assertEqual(cm.exception.code, "COV0015")
        for bad in (85.0, True, 101, -1):
            with self.assertRaises(C.ConfigError):
                C.parse_threshold(bad, "t")

    def test_defaults_match_the_spec(self) -> None:
        self.assertEqual(C.defaults(), SPEC_DEFAULTS)
        snap = json.loads((FIXTURES / "defaults.json").read_bytes())
        self.assertEqual(snap["defaults"], SPEC_DEFAULTS)

    def test_cli_table_matches_the_spec(self) -> None:
        mapped = [o.name for o in C.OPTIONS if o.key is not None]
        self.assertEqual(mapped, SPEC_MAPPED)
        cli_only = {o.name: set(o.commands) for o in C.OPTIONS if o.key is None}
        self.assertEqual(cli_only, SPEC_CLI_ONLY)
        for opt in C.OPTIONS:
            if opt.key is not None and opt.name != "--no-context":
                table, _, leaf = opt.key.rpartition(".")
                self.assertEqual(opt.commands, C.TABLE[table].key(leaf).commands, opt.name)
        self.assertEqual(C.OPTION["--report"].commands, ("run",))
        self.assertEqual({C.OPTION[o].arity for o in ("--report", "--ratchet-metric", "--expect-run", "--format")}, {"repeatable"})

    def test_cli_applicability_is_a_usage_error(self) -> None:
        corpus = json.loads((FIXTURES / "cli-cases.json").read_bytes())
        for option, commands in corpus["applicability"].items():
            for command in C.COMMANDS:
                if command in commands or C.OPTION[option].arity == "flag":
                    continue
                with self.subTest(option=option, command=command), self.assertRaises(C.ConfigError) as cm:
                    C.check_cli_value(option, "x", command)
                self.assertEqual(cm.exception.code, "COV0001")
        for v in corpus["values"]:
            with self.subTest(option=v["option"], text=v["text"]):
                try:
                    got = {"value": C.check_cli_value(v["option"], v["text"], v["command"])}
                except C.ConfigError as exc:
                    got = {"code": exc.code, "path": exc.path}
                self.assertEqual(got, v["expect"])

    @unittest.skipUnless(ORACLE, "oracle group not installed")
    def test_structural_schema_agrees(self) -> None:
        """Accepted cases pass the schema; unknown keys and bad schema versions fail it."""
        checked = 0
        for case in CASES:
            if case["toml"] is None:
                continue
            try:
                doc = tomllib.loads(case["toml"])
            except tomllib.TOMLDecodeError:
                continue
            code = case["expect"].get("code")
            if "coverage" not in doc or code not in (None, "COV0010", "COV0011") or _has_datetime(doc["coverage"]):
                continue
            with self.subTest(case=case["id"]):
                self.assertEqual(ORACLE.is_valid(doc["coverage"]), code is None)
                checked += 1
        self.assertGreater(checked, 200)

    def test_outside_keys_are_not_examined(self) -> None:
        self.assertIsNone(C.validate_bytes(b"[package]\nname = 1\nwhatever = 1979-05-27\n"))
        got = C.validate_bytes(b'[tool.other]\ncoverage = "x"\n[coverage]\nschema = "1.0"\n')
        self.assertEqual(got, {"schema": "1.0"})


def _has_datetime(v: object) -> bool:
    if isinstance(v, dict):
        return any(_has_datetime(x) for x in v.values())
    if isinstance(v, list):
        return any(_has_datetime(x) for x in v)
    return not isinstance(v, (str, int, float, bool))


if __name__ == "__main__":
    unittest.main()
