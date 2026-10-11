# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Configuration resolution (CV-224; SPEC 18.2, 21.3.7; COV-CFG-001..005,
AC-098).

CLI over file over default for every mapped option, the source of every
leaf, the exact resolved-configuration shape, usage errors before anything
else, relations on the effective values, and a caller environment that
changes nothing.
"""

from __future__ import annotations

import ast
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import config as C  # noqa: E402
from sv0cov.config_resolve import Leaf, resolve  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical  # noqa: E402
from sv0cov.formats.rawprofile import Tier  # noqa: E402

HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
RUN = "0123456789abcdef0123456789abcdef"

# Restated by hand from SPEC 18.2.2 / 21.3.7: every leaf of the resolved `coverage` tree and its default.
SCALARS = {
    "schema": "1.0", "output_dir": ".sv0cov", "reports": ["term"], "empty": "fail", "context": None, "reproducible_epoch": 0,
    "integrity.saturation": "fail",
    "limits.raw_profile.tier": "standard", "limits.raw_profile.max_counters": None, "limits.raw_profile.max_bytes": None,
    "thresholds.function": None, "thresholds.region": None, "thresholds.line": None, "thresholds.branch": None,
    "thresholds.contract": None,
    "exclusions.max_records": None, "exclusions.function_basis_points": None, "exclusions.region_basis_points": None,
    "exclusions.line_basis_points": None, "exclusions.branch_basis_points": None, "exclusions.contract_basis_points": None,
    "exclusions.forbidden_reasons": [], "exclusions.forbidden_sources": [],
}
DIFF = {"base": None, "line": None, "region": None, "branch": None}
RATCHET = {"baseline": None, "metrics": None, "tolerance_basis_points": 0}
SCOPE = ("name", "include", "packages", "sources", "function", "region", "line", "branch", "contract")
ENTITY = ("name", "source", "qualified_name", "kind", "function", "region", "line", "branch", "contract")

# option -> (key, command, table header, file line, file value, CLI texts, CLI value). Restated from SPEC 18.2.3.
T, D, R, L = "thresholds", "diff", "ratchet", "limits.raw_profile"
MAPPED = {
    "--output-dir": ("output_dir", "run", "", 'output_dir = "out/a"', "out/a", ["build/cov"], "build/cov"),
    "--report": ("reports", "run", "", 'reports = ["json", "term"]', ["json", "term"], ["html", "lcov"], ["html", "lcov"]),
    "--empty": ("empty", "check", "", 'empty = "pass"', "pass", ["fail"], "fail"),
    "--context": ("context", "run", "", 'context = "file-ctx"', "file-ctx", ["cli-ctx"], "cli-ctx"),
    "--reproducible-epoch": ("reproducible_epoch", "run", "", "reproducible_epoch = 7", 7, ["9223372036854775807"], 2**63 - 1),
    "--saturation-policy": ("integrity.saturation", "merge", "integrity", 'saturation = "allow-ordinary"', "allow-ordinary", ["fail"], "fail"),
    "--threshold-function": (f"{T}.function", "check", T, "function = 90", 9000, ["91"], 9100),
    "--threshold-region": (f"{T}.region", "check", T, 'region = "8250bp"', 8250, ["1bp"], 1),
    "--threshold-line": (f"{T}.line", "run", T, "line = 85", 8500, ["8501bp"], 8501),
    "--threshold-branch": (f"{T}.branch", "check", T, "branch = 0", 0, ["100"], 10000),
    "--threshold-contract": (f"{T}.contract", "check", T, "contract = 100", 10000, ["0bp"], 0),
    "--diff-base": (f"{D}.base", "check", D, 'base = "HEAD"\nline = 1', "HEAD", ["merge-base:origin/main"], "merge-base:origin/main"),
    "--diff-line": (f"{D}.line", "check", D, 'base = "HEAD"\nline = 100', 10000, ["99"], 9900),
    "--diff-region": (f"{D}.region", "check", D, 'base = "HEAD"\nregion = 100', 10000, ["9999bp"], 9999),
    "--diff-branch": (f"{D}.branch", "run", D, 'base = "HEAD"\nbranch = 50', 5000, ["51"], 5100),
    "--ratchet-baseline": (f"{R}.baseline", "check", R, 'baseline = "a.json"\nmetrics = ["line"]', "a.json", ["b/c.json"], "b/c.json"),
    "--ratchet-metric": (f"{R}.metrics", "check", R, 'baseline = "a.json"\nmetrics = ["region", "line"]', ["line", "region"],
                         ["line", "function", "branch"], ["branch", "function", "line"]),
    "--ratchet-tolerance-basis-points": (f"{R}.tolerance_basis_points", "check", R,
                                         'baseline = "a.json"\nmetrics = ["line"]\ntolerance_basis_points = 5', 5, ["10000"], 10000),
    "--raw-profile-tier": (f"{L}.tier", "merge", L, 'tier = "large"', "large", ["standard"], "standard"),
    "--raw-profile-max-counters": (f"{L}.max_counters", "merge", L, 'tier = "custom"\nmax_counters = 5\nmax_bytes = 6', 5, ["4294967295"], 2**32 - 1),
    "--raw-profile-max-bytes": (f"{L}.max_bytes", "run", L, 'tier = "custom"\nmax_counters = 5\nmax_bytes = 6', 6, ["68719476736"], 2**36),
}


def toml(table: str, body: str) -> bytes:
    return (HEAD + body + "\n" if table == "" else HEAD + f"\n[tool.sv0cov.{table}]\n{body}\n").encode()


def leaves(node: object, prefix: str = "") -> dict[str, Leaf]:
    out: dict[str, Leaf] = {}
    if isinstance(node, Leaf):
        out[prefix] = node
    elif isinstance(node, dict):
        for k, v in node.items():
            out.update(leaves(v, f"{prefix}.{k}" if prefix else k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            out.update(leaves(v, f"{prefix}[{i}]"))
    return out


def error(command: str, options=(), data: bytes | None = None) -> tuple[str, str]:
    try:
        resolve(command, options, data)
    except C.ConfigError as exc:
        return exc.code, exc.path
    raise AssertionError("resolved")


class DefaultsTest(unittest.TestCase):
    def test_no_configuration_gives_every_default(self) -> None:
        for data in (None, b"", b'[package]\nname = "x"\n', b'[coverage]\nschema = "1.0"\nempty = "pass"\n'):
            with self.subTest(data=data):
                r = resolve("run", (), data)
                got = leaves(r.coverage)
                self.assertEqual({k: v.value for k, v in got.items()}, SCALARS)
                self.assertEqual({v.source for v in got.values()}, {"default"})
                self.assertEqual((r.coverage["diff"], r.coverage["ratchet"], r.coverage["scopes"], r.coverage["entities"]), (None, None, [], []))
                self.assertEqual(r.to_bytes(), resolve("check").to_bytes())
        self.assertEqual(r.tier(), Tier.standard())

    def test_the_document_has_exactly_the_specified_shape(self) -> None:
        doc = resolve("run").document()
        self.assertEqual(list(doc), ["coverage", "report", "schema", "version"])
        self.assertEqual((doc["schema"], doc["version"]), ("sv0cov.resolved-configuration", "1.0"))
        self.assertEqual(doc["report"], {"allow_lossy_saturated_export": {"source": "default", "value": False},
                                         "allow_source_mismatch": {"source": "default", "value": False}})
        cov = doc["coverage"]
        self.assertEqual(sorted(cov), sorted(["schema", "output_dir", "reports", "empty", "context", "reproducible_epoch", "integrity",
                                              "limits", "thresholds", "scopes", "entities", "diff", "ratchet", "exclusions"]))
        self.assertEqual(cov["limits"], {"raw_profile": {k: {"source": "default", "value": v} for k, v in
                                                         (("tier", "standard"), ("max_counters", None), ("max_bytes", None))}})
        self.assertEqual(cov["context"], {"source": "default", "value": None})
        self.assertEqual(decode_canonical(resolve("run").to_bytes()), doc)
        # The defaults are the frozen default snapshot of the inventory, nothing else.
        snapshot = json.loads(C.default_snapshot())["defaults"]
        self.assertEqual({f"tool.sv0cov.{k}": v for k, v in SCALARS.items() if v is not None and k != "schema"},
                         {k: v for k, v in snapshot.items() if "ratchet" not in k})

    def test_a_declared_table_makes_schema_a_file_value(self) -> None:
        r = resolve("run", (), HEAD.encode())
        self.assertEqual(r.leaf("schema"), Leaf("1.0", "sv0.toml"))
        self.assertEqual({v.source for k, v in leaves(r.coverage).items() if k != "schema"}, {"default"})


class PrecedenceTest(unittest.TestCase):
    """COV-CFG-001, COV-CFG-003."""

    def test_the_table_covers_every_mapped_option(self) -> None:
        self.assertEqual(set(MAPPED) | {"--no-context"}, {o.name for o in C.OPTIONS if o.key})
        self.assertEqual(len(MAPPED), 21)

    def test_cli_beats_file_beats_default_for_every_mapped_option(self) -> None:
        for option, (key, command, table, body, file_value, texts, cli_value) in MAPPED.items():
            with self.subTest(option=option):
                data = toml(table, body)
                occurrences = [(option, t) for t in texts]
                # Options that only make sense with companions (a diff base, custom ceilings) get them from the file.
                plain = resolve(command)
                self.assertEqual(plain.coverage[key.split(".")[0]] is None or plain.source(key) == "default", True)
                from_file = resolve(command, (), data)
                self.assertEqual(from_file.leaf(key), Leaf(file_value, "sv0.toml"))
                both = resolve(command, occurrences, data)
                self.assertEqual(both.leaf(key), Leaf(cli_value, "cli"))
                # Only that leaf changed.
                a, b = leaves(from_file.coverage), leaves(both.coverage)
                self.assertEqual({k for k in a if a[k] != b[k]}, {key})

    def test_cli_alone_over_defaults(self) -> None:
        r = resolve("run", [("--output-dir", "o"), ("--report", "json"), ("--empty", "pass"), ("--context", ""),
                            ("--reproducible-epoch", "1"), ("--saturation-policy", "allow-ordinary"), ("--threshold-line", "85"),
                            ("--raw-profile-tier", "large")])
        got = {k: v for k, v in leaves(r.coverage).items() if v.source != "default"}
        self.assertEqual(got, {"output_dir": Leaf("o", "cli"), "reports": Leaf(["json"], "cli"), "empty": Leaf("pass", "cli"),
                               "context": Leaf("", "cli"), "reproducible_epoch": Leaf(1, "cli"),
                               "integrity.saturation": Leaf("allow-ordinary", "cli"), "thresholds.line": Leaf(8500, "cli"),
                               "limits.raw_profile.tier": Leaf("large", "cli")})
        self.assertEqual(r.tier(), Tier.large())

    def test_no_context_replaces_a_file_context_with_absence(self) -> None:
        data = toml("", 'context = "file-ctx"')
        self.assertEqual(resolve("run", [("--no-context", None)], data).leaf("context"), Leaf(None, "cli"))
        self.assertEqual(resolve("run", [("--no-context", None)]).leaf("context"), Leaf(None, "cli"))
        self.assertEqual(resolve("run", (), data).leaf("context"), Leaf("file-ctx", "sv0.toml"))
        self.assertEqual(resolve("run").leaf("context"), Leaf(None, "default"))
        for order in ([("--context", "x"), ("--no-context", None)], [("--no-context", None), ("--context", "x")]):
            self.assertEqual(error("run", order, data)[0], "COV0001")

    def test_repeated_list_options_replace_the_file_array(self) -> None:
        data = toml("", 'reports = ["term", "json", "html"]')
        r = resolve("run", [("--report", "lcov"), ("--report", "term")], data)
        self.assertEqual(r.leaf("reports"), Leaf(["lcov", "term"], "cli"))  # CLI order kept: reports are ordered
        m = resolve("check", [("--ratchet-metric", "region"), ("--ratchet-metric", "branch")],
                    toml("ratchet", 'baseline = "a.json"\nmetrics = ["line", "function"]'))
        self.assertEqual(m.leaf("ratchet.metrics"), Leaf(["branch", "region"], "cli"))  # a set: canonical order
        self.assertEqual(error("run", [("--report", "term"), ("--report", "term")])[1], "--report")
        self.assertEqual(error("run", [("--report", "term,html")]), ("COV0001", "--report"))
        self.assertEqual(error("run", [("--report", "pdf")])[1], "--report")

    def test_equivalent_threshold_spellings_resolve_identically(self) -> None:
        """COV-CFG-005."""
        want = Leaf(8500, "sv0.toml")
        self.assertEqual(resolve("check", (), toml(T, "line = 85")).leaf("thresholds.line"), want)
        self.assertEqual(resolve("check", (), toml(T, 'line = "8500bp"')).leaf("thresholds.line"), want)
        a = resolve("check", [("--threshold-line", "85")]).to_bytes()
        self.assertEqual(a, resolve("check", [("--threshold-line", "8500bp")]).to_bytes())
        for bad in ("085", "+85", "85%", "85.0", "8.5e1", " 85", "101", "10001bp", "85BP", "-1", ""):
            with self.subTest(text=bad):
                self.assertEqual(error("check", [("--threshold-line", bad)]), ("COV0015", "--threshold-line"))

    def test_source_is_default_exactly_when_nothing_set_the_leaf(self) -> None:
        every = (ROOT / "tests" / "fixtures" / "config" / "file-cases.json").read_bytes()
        case = next(c for c in json.loads(every)["cases"] if c["id"] == "every-key")
        r = resolve("run", [("--threshold-branch", "1"), ("--no-context", None)], case["toml"].encode())
        configured = C.validate_bytes(case["toml"].encode())
        for key, leaf in leaves(r.coverage).items():
            if "[" in key or key == "schema":
                continue
            node: object = configured
            for part in key.split("."):
                node = node.get(part) if isinstance(node, dict) else None
            want = "cli" if key in ("thresholds.branch", "context") else "sv0.toml" if node is not None else "default"
            self.assertEqual(leaf.source, want, key)
            if leaf.source == "default":
                self.assertEqual(leaf.value, SCALARS.get(key, {**{f"diff.{k}": v for k, v in DIFF.items()},
                                                               **{f"ratchet.{k}": v for k, v in RATCHET.items()}}.get(key)), key)


class TablesTest(unittest.TestCase):
    def test_diff_and_ratchet_are_null_until_something_configures_them(self) -> None:
        r = resolve("check", (), toml(D, 'base = "HEAD"\nline = 100'))
        self.assertEqual(r.coverage["diff"], {"base": Leaf("HEAD", "sv0.toml"), "line": Leaf(10000, "sv0.toml"),
                                              "region": Leaf(None, "default"), "branch": Leaf(None, "default")})
        self.assertIsNone(r.coverage["ratchet"])
        self.assertEqual(sorted(r.document()["coverage"]["diff"]), sorted(DIFF))
        # The CLI alone can create either table.
        d = resolve("check", [("--diff-base", "HEAD~1"), ("--diff-region", "90")])
        self.assertEqual(d.coverage["diff"], {"base": Leaf("HEAD~1", "cli"), "line": Leaf(None, "default"),
                                              "region": Leaf(9000, "cli"), "branch": Leaf(None, "default")})
        t = resolve("check", [("--ratchet-baseline", "b.json"), ("--ratchet-metric", "line")])
        self.assertEqual(t.coverage["ratchet"], {"baseline": Leaf("b.json", "cli"), "metrics": Leaf(["line"], "cli"),
                                                 "tolerance_basis_points": Leaf(0, "default")})
        # A command the diff options do not apply to still records the file's table.
        self.assertEqual(resolve("merge", (), toml(D, 'base = "HEAD"\nline = 100')).coverage["diff"], r.coverage["diff"])

    def test_scopes_and_entities_are_sorted_and_complete(self) -> None:
        data = (HEAD + '''
[[tool.sv0cov.scopes]]
name = "zeta"
include = ["b/**", "!b/x", "a/**"]
packages = ["p2", "p1"]
line = 95
[[tool.sv0cov.scopes]]
name = "Alpha"
sources = ["src/z.sv0", "src/a.sv0"]
[[tool.sv0cov.entities]]
name = "e2"
source = "src/a.sv0"
qualified_name = "f#requires0"
kind = "contract"
contract = "1bp"
[[tool.sv0cov.entities]]
name = "e1"
source = "src/a.sv0"
qualified_name = "f"
kind = "function"
branch = 50
[tool.sv0cov.exclusions]
forbidden_reasons = ["todo", "later"]
forbidden_sources = ["z/**", "a/**"]
''').encode()
        r = resolve("check", [("--threshold-line", "80")], data)
        scopes, entities = r.coverage["scopes"], r.coverage["entities"]
        self.assertEqual([s["name"].value for s in scopes], ["Alpha", "zeta"])
        self.assertEqual([e["name"].value for e in entities], ["e1", "e2"])
        self.assertTrue(all(tuple(s) == SCOPE for s in scopes) and all(tuple(e) == ENTITY for e in entities))
        zeta = scopes[1]
        self.assertEqual(zeta["include"], Leaf(["b/**", "!b/x", "a/**"], "sv0.toml"))  # pattern order is semantic
        self.assertEqual(zeta["packages"], Leaf(["p1", "p2"], "sv0.toml"))  # sets are canonical
        self.assertEqual((zeta["sources"], zeta["line"], zeta["branch"]), (Leaf(None, "default"), Leaf(9500, "sv0.toml"), Leaf(None, "default")))
        self.assertEqual(scopes[0]["sources"], Leaf(["src/a.sv0", "src/z.sv0"], "sv0.toml"))
        self.assertEqual((entities[1]["contract"], entities[1]["line"]), (Leaf(1, "sv0.toml"), Leaf(None, "default")))
        self.assertEqual(r.leaf("exclusions.forbidden_reasons"), Leaf(["later", "todo"], "sv0.toml"))
        self.assertEqual(r.leaf("exclusions.forbidden_sources"), Leaf(["z/**", "a/**"], "sv0.toml"))
        # A project threshold from the CLI does not rewrite a scope's own value.
        self.assertEqual((r.leaf("thresholds.line"), zeta["line"].source), (Leaf(8000, "cli"), "sv0.toml"))
        # Declaration order of the array-tables does not change the bytes.
        blocks = data.decode().split("[[")
        swapped = (blocks[0] + "[[" + blocks[2] + "[[" + blocks[1] + "[[" + blocks[3] + "[[" + blocks[4]).encode()
        self.assertEqual(resolve("check", (), swapped).to_bytes(), resolve("check", (), data).to_bytes())


class RelationTest(unittest.TestCase):
    """COV-CFG-002: relations hold on the effective values."""

    def test_custom_tier_needs_both_ceilings_wherever_they_come_from(self) -> None:
        file_custom = toml(L, 'tier = "custom"\nmax_counters = 5\nmax_bytes = 6')
        self.assertEqual(resolve("merge", (), file_custom).tier(), Tier.custom(5, 6))
        both = [("--raw-profile-tier", "custom"), ("--raw-profile-max-counters", "7"), ("--raw-profile-max-bytes", "8")]
        self.assertEqual(resolve("run", both).tier(), Tier.custom(7, 8))
        mixed = resolve("merge", [("--raw-profile-max-bytes", "9")], file_custom)
        self.assertEqual((mixed.tier(), mixed.source("limits.raw_profile.max_bytes"), mixed.source("limits.raw_profile.max_counters")),
                         (Tier.custom(5, 9), "cli", "sv0.toml"))
        self.assertEqual(error("merge", both[:2]), ("COV0013", "--raw-profile-tier"))
        self.assertEqual(error("merge", both[:1]), ("COV0013", "--raw-profile-tier"))
        self.assertEqual(error("merge", both[1:2]), ("COV0013", "--raw-profile-max-counters"))
        self.assertEqual(error("merge", [("--raw-profile-max-bytes", "9")], toml(L, 'tier = "large"')),
                         ("COV0013", "--raw-profile-max-bytes"))
        # The CLI cannot drop a file key: a non-custom tier over file ceilings is a conflict, not a silent change.
        self.assertEqual(error("merge", [("--raw-profile-tier", "standard")], file_custom),
                         ("COV0013", "tool.sv0cov.limits.raw_profile.max_counters"))

    def test_cli_made_tables_must_be_whole(self) -> None:
        self.assertEqual(error("check", [("--diff-line", "100")]), ("COV0013", "tool.sv0cov.diff"))
        self.assertEqual(error("check", [("--diff-base", "HEAD")]), ("COV0013", "tool.sv0cov.diff"))
        self.assertEqual(error("check", [("--ratchet-metric", "line")]), ("COV0013", "tool.sv0cov.ratchet"))
        self.assertEqual(error("check", [("--ratchet-baseline", "b.json")]), ("COV0013", "tool.sv0cov.ratchet"))
        self.assertEqual(error("check", [("--ratchet-tolerance-basis-points", "1")]), ("COV0013", "tool.sv0cov.ratchet"))

    def test_file_errors_stop_resolution(self) -> None:
        cases = {
            b"[tool.sv0cov]\n": "COV0010",
            HEAD.encode() + b"bogus = 1\n": "COV0011",
            HEAD.encode() + b'empty = "maybe"\n': "COV0012",
            HEAD.encode() + b'empty = "fail"\nempty = "pass"\n': "COV0002",
            toml(T, "line = 101"): "COV0015",
            toml(T, "lines = 1"): "COV0011",
            HEAD.encode() + b'run_id = "x"\n': "COV0011",  # CLI-only controls are never file keys
            HEAD.encode() + b"quiet = true\n": "COV0011",
        }
        for data, code in cases.items():
            with self.subTest(data=data):
                self.assertEqual(error("run", (), data)[0], code)
                # A valid CLI override of the broken key does not rescue the file.
                self.assertEqual(error("run", [("--empty", "pass"), ("--threshold-line", "1")], data)[0], code)


class UsageTest(unittest.TestCase):
    """SPEC 18.2.3: usage errors before any artifact processing."""

    SAMPLE = {"scalar": "x", "repeatable": "x", "flag": None}

    def test_every_option_is_refused_by_every_inapplicable_command(self) -> None:
        refused = 0
        for opt in C.OPTIONS:
            for command in C.COMMANDS:
                if command not in opt.commands:
                    self.assertEqual(error(command, [(opt.name, self.SAMPLE[opt.arity])]), ("COV0001", opt.name), (opt.name, command))
                    refused += 1
        self.assertEqual(refused, sum(len(C.COMMANDS) - len(o.commands) for o in C.OPTIONS))
        self.assertGreater(refused, 150)

    def test_arity_and_shape(self) -> None:
        for opt in C.OPTIONS:
            command = next(c for c in opt.commands if c != "report") if opt.commands != ("report",) else "report"
            fmt = [("--format", "json")] if command == "report" and opt.name != "--format" else []
            with self.subTest(option=opt.name):
                if opt.arity == "flag":
                    self.assertEqual(error(command, fmt + [(opt.name, "yes")]), ("COV0001", opt.name))
                    self.assertEqual(error(command, fmt + [(opt.name, None), (opt.name, None)]), ("COV0001", opt.name))
                else:
                    self.assertEqual(error(command, fmt + [(opt.name, None)]), ("COV0001", opt.name))
                if opt.arity == "scalar":
                    good = {"--color": "auto", "--diagnostic-format": "human", "--run-id": RUN}.get(opt.name) \
                        or (MAPPED[opt.name][5][0] if opt.name in MAPPED else "x")
                    self.assertEqual(error(command, fmt + [(opt.name, good), (opt.name, good)]), ("COV0001", opt.name))

    def test_unknown_and_conflicting_and_required(self) -> None:
        self.assertEqual(error("run", [("--threshold", "1")]), ("COV0001", "--threshold"))
        self.assertEqual(error("run", [("--schema", "1.0")]), ("COV0001", "--schema"))
        self.assertEqual(error("fly"), ("COV0001", "fly"))
        self.assertEqual(error("merge", [("--expect-run", RUN), ("--run-manifest", "m.json")])[0], "COV0001")
        self.assertEqual(error("merge", [("--run-manifest", "m.json"), ("--expect-run", RUN)])[0], "COV0001")
        self.assertEqual(error("merge", [("--expect-run", RUN), ("--expect-run", RUN)]), ("COV0001", "--expect-run"))
        self.assertEqual(error("merge", [("--expect-run", RUN.upper())]), ("COV0001", "--expect-run"))
        self.assertEqual(error("report"), ("COV0001", "--format"))
        self.assertEqual(error("report", [("--format", "json"), ("--format", "json")]), ("COV0001", "--format"))
        self.assertEqual(error("report", [("--format", "json,html")]), ("COV0001", "--format"))
        self.assertEqual(error("run", [("--color", "blue")]), ("COV0001", "--color"))
        # A usage error is reported even when the file is broken too.
        self.assertEqual(error("run", [("--format", "json")], b"[tool.sv0cov]\n"), ("COV0001", "--format"))

    def test_controls_are_returned_and_never_serialized(self) -> None:
        other = "fedcba9876543210fedcba9876543210"
        m = resolve("merge", [("--expect-run", RUN), ("--expect-run", other), ("--output", "-"), ("--allow-rejected-inputs", None),
                              ("--quiet", None), ("--color", "never"), ("--diagnostic-format", "json-lines")])
        self.assertEqual(m.controls, {"--expect-run": [RUN, other], "--output": "-", "--allow-rejected-inputs": True, "--quiet": True,
                                      "--color": "never", "--diagnostic-format": "json-lines"})
        self.assertEqual(m.to_bytes(), resolve("merge").to_bytes())
        rep = resolve("report", [("--format", "html"), ("--format", "json"), ("--output", "/abs/out"), ("--allow-source-mismatch", None),
                                 ("--allow-lossy-saturated-export", None)])
        self.assertEqual(rep.controls["--format"], ["html", "json"])
        self.assertEqual(rep.document()["report"], {"allow_lossy_saturated_export": {"source": "cli", "value": True},
                                                    "allow_source_mismatch": {"source": "cli", "value": True}})
        self.assertNotIn(b"/abs/out", rep.to_bytes())
        self.assertNotIn(b"html", rep.to_bytes())
        self.assertEqual(resolve("run", [("--run-id", RUN), ("--prefer-coverage-exit", None)]).controls,
                         {"--run-id": RUN, "--prefer-coverage-exit": True})
        self.assertNotIn(RUN.encode(), resolve("run", [("--run-id", RUN)]).to_bytes())


HOSTILE = {
    "SV0COV_OUTPUT_DIR": "/tmp/evil", "SV0COV_REPORTS": "html", "SV0COV_EMPTY": "pass", "SV0COV_CONTEXT": "evil",
    "SV0COV_THRESHOLD_LINE": "0", "SV0COV_THRESHOLDS_LINE": "0", "SV0COV_SATURATION_POLICY": "allow-ordinary",
    "SV0COV_RAW_PROFILE_TIER": "large", "SV0COV_DIFF_BASE": "HEAD", "SV0COV_RATCHET_BASELINE": "x", "SV0COV_EXPECT_RUN": RUN,
    "SV0COV_RUN_ID": RUN, "SV0COV_PROFILE_DIR": "/tmp/evil", "SV0COV_REQUIRED": "0", "SV0COV_ALLOW_REJECTED_INPUTS": "1",
    "SV0COV_CONFIG": "/tmp/evil.toml", "SV0COV_": "", "SV0COV_é": "\xff", "sv0cov_threshold_line": "0",
    "TOOL_SV0COV_THRESHOLDS_LINE": "0", "COVERAGE_THRESHOLD_LINE": "0", "SV0_TOML": "/tmp/evil.toml", "PYTHONHASHSEED": "7",
}
POLICY = (HEAD + 'empty = "pass"\ncontext = "file"\n\n[tool.sv0cov.thresholds]\nline = 85\nbranch = 70\n\n'
          '[[tool.sv0cov.scopes]]\nname = "core"\ninclude = ["src/**"]\nline = 95\n\n'
          '[tool.sv0cov.diff]\nbase = "HEAD"\nline = 100\n\n[tool.sv0cov.ratchet]\nbaseline = "b.json"\nmetrics = ["line"]\n').encode()
POLICY_CLI = [("--threshold-line", "90"), ("--saturation-policy", "allow-ordinary"), ("--raw-profile-tier", "large"),
              ("--report", "json"), ("--run-id", RUN)]


class EnvironmentTest(unittest.TestCase):
    """COV-CFG-001, AC-098: the caller environment is not a configuration layer."""

    def test_a_hostile_environment_changes_nothing_in_process(self) -> None:
        want = resolve("run", POLICY_CLI, POLICY)
        with mock.patch.dict(os.environ, HOSTILE):
            got = resolve("run", POLICY_CLI, POLICY)
            defaults = resolve("run").to_bytes()
        self.assertEqual((got.to_bytes(), got.controls), (want.to_bytes(), want.controls))
        self.assertEqual(defaults, resolve("run").to_bytes())
        # Every nondefault value names the CLI or the file as its source.
        base = leaves(resolve("run").coverage)
        for key, leaf in leaves(want.coverage).items():
            unset = base[key].value if key in base else 0 if key.endswith("tolerance_basis_points") else None
            if leaf.value != unset:
                self.assertIn(leaf.source, ("cli", "sv0.toml"), key)
        self.assertEqual((want.source("thresholds.line"), want.source("thresholds.branch"), want.source("integrity.saturation")),
                         ("cli", "sv0.toml", "cli"))

    def test_a_hostile_environment_changes_nothing_in_a_fresh_interpreter(self) -> None:
        code = ("import sys, json; sys.path.insert(0, sys.argv[1])\n"
                "from sv0cov.config_resolve import resolve\n"
                "opts = [tuple(o) for o in json.loads(sys.argv[2])]\n"
                "sys.stdout.buffer.write(resolve('run', opts, sys.stdin.buffer.read()).to_bytes())\n")
        outs = []
        for extra in ({}, HOSTILE):
            env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SV0COV_")}
            env.update({k: v for k, v in extra.items() if "\xff" not in v and k.isascii()})
            p = subprocess.run([sys.executable, "-c", code, str(ROOT / "src"), json.dumps(POLICY_CLI)], input=POLICY, env=env,
                               capture_output=True, timeout=60)
            self.assertEqual(p.returncode, 0, p.stderr)
            outs.append(p.stdout)
        self.assertEqual(outs[0], outs[1])
        self.assertEqual(outs[0], resolve("run", POLICY_CLI, POLICY).to_bytes())

    def test_the_resolver_cannot_read_the_environment(self) -> None:
        for name in ("config.py", "config_resolve.py"):
            tree = ast.parse((ROOT / "src" / "sv0cov" / name).read_text())
            imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
                       {(n.module or "").split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
            self.assertFalse(imported & {"os", "sys", "posix", "subprocess", "pathlib", "io", "shutil", "socket"}, (name, imported))
            names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            self.assertFalse(names & {"environ", "getenv", "open", "__import__", "exec", "eval"}, name)


if __name__ == "__main__":
    unittest.main()
