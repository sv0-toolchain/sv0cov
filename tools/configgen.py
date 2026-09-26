#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Derive the coverage-configuration artifacts from ``sv0cov.config`` (CV-029).

Outputs (all canonical JSON):

- ``tests/fixtures/config/config.schema.json``: structural JSON Schema
  (Draft 2020-12) for the parsed ``coverage`` subtree, checked against the
  corpus with the jsonschema oracle. It is not in ``schemas/``: the R1
  artifact-schema profile requires every property of a closed object, and
  configuration keys are optional. Grammar and cross-field rules JSON Schema
  cannot express (threshold strings, paths, names, uniqueness, relations)
  stay in ``sv0cov.config``.
- ``tests/fixtures/config/inventory.json``: tables, keys, kinds, defaults,
  command applicability, and the CLI option table.
- ``tests/fixtures/config/defaults.json``: the default snapshot.
- ``tests/fixtures/config/file-cases.json``: the key-path corpus. Every case
  is TOML text plus either the resolved subtree or ``{code, path}``.
- ``tests/fixtures/config/cli-cases.json``: CLI values and the
  option x command applicability matrix.

The corpus is the frozen record: a change to the inventory or validator that
alters any outcome makes ``--check`` fail until the corpus is reviewed and
rewritten.

    python3 tools/configgen.py            # check (exit 1 if stale)
    python3 tools/configgen.py --write    # rewrite after review
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import config as C  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402

FIXTURES = ROOT / "tests" / "fixtures" / "config"
SCHEMA_FILE = FIXTURES / "config.schema.json"

# --- JSON Schema -------------------------------------------------------------


def _value_schema(kind: C.Kind) -> dict:
    if kind is C.THRESHOLD:
        return {"anyOf": [{"maximum": 100, "minimum": 0, "type": "integer"}, {"maxLength": 7, "minLength": 3, "type": "string"}]}
    if kind is C.SCHEMA:
        return {"const": C.SCHEMA_VERSION}
    if kind.toml == "integer":
        return {"maximum": kind.maximum, "minimum": kind.minimum, "type": "integer"}
    if kind.toml == "string":
        s: dict = {"type": "string"}
        if kind.values:
            s["enum"] = list(kind.values)
        elif kind in (C.ARTIFACT_PATH, C.NAME, C.SOURCE, C.QUALIFIED_NAME, C.DIFF_BASE):
            s["minLength"] = 1
        if kind is C.NAME:
            s["maxLength"] = 128
        return s
    item: dict = {"type": "string"}
    if kind.values:
        item = {"enum": list(kind.values), "type": "string"}
    elif kind in (C.PACKAGES, C.SOURCES, C.REASONS):
        item["minLength"] = 1
    s = {"items": item, "type": "array"}
    if kind not in (C.REASONS, C.FORBIDDEN_SOURCES):
        s["minItems"] = 1
    if kind.values:
        s["maxItems"] = len(kind.values)
    return s


def _table_schema(table: C.Table) -> dict:
    props = {k.name: {"$ref": f"#/$defs/{k.kind.name}"} for k in table.keys}
    for name in table.tables:
        props[name] = {"$ref": f"#/$defs/{_def_name(f'{table.path}.{name}')}"}
    obj: dict = {"additionalProperties": False, "properties": props, "type": "object"}
    required = [k.name for k in table.keys if k.required]
    if required:
        obj["required"] = required
    if table.array:
        return {"items": obj, "type": "array"}
    return obj


def _def_name(path: str) -> str:
    return "table-" + path.replace(".", "-").replace("_", "-")


def schema() -> dict:
    defs: dict = {}
    for t in C.TABLES:
        defs[_def_name(t.path)] = _table_schema(t)
        for k in t.keys:
            defs[k.kind.name] = _value_schema(k.kind)
    return {
        "$defs": dict(sorted(defs.items())),
        "$id": "https://github.com/sv0-toolchain/sv0cov/schemas/sv0cov.config-1.0.schema.json",
        "$ref": f"#/$defs/{_def_name('coverage')}",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "description": "Structural profile of the [coverage] subtree of sv0.toml (SPEC 18.2). Grammar and cross-field rules are in sv0cov.config.",
        "title": "sv0cov.config 1.0",
    }


# --- file corpus -------------------------------------------------------------

BOUNDARY = {  # kind -> (valid TOML literals, invalid TOML literals)
    C.ARTIFACT_PATH: (['"a"', '"out/cov"', '"a/"', '"é/x"'], ['""', '"/abs"', '"C:x"', '"a/../b"', '"./a"', '"a\\\\b"', '"a\\u0000b"', "1"]),
    C.REPORTS: (['["term"]', '["cobertura", "term", "lcov", "json", "html"]'], ["[]", '["term", "term"]', '["xml"]', '["TERM"]', '"term"', "[1]"]),
    C.EMPTY: (['"fail"', '"pass"'], ['"FAIL"', '""', "true"]),
    C.CONTEXT: (['""', '"ci"', '"' + "x" * 256 + '"', '"' + "é" * 128 + '"'], ['"' + "x" * 257 + '"', '"' + "é" * 128 + 'x"', "0"]),
    C.EPOCH: (["0", "9223372036854775807"], ["-1", "true", "1.0", '"0"', "1979-05-27T07:32:00Z"]),
    C.SATURATION: (['"fail"', '"allow-ordinary"'], ['"allow_ordinary"', '"allow"', "false"]),
    C.TIER: (['"standard"', '"large"'], ['"huge"', '"Standard"', "1"]),
    C.MAX_COUNTERS: (["1", "4294967295"], ["0", "4294967296", "1.5"]),
    C.MAX_BYTES: (["1", "68719476736"], ["0", "68719476737", '"1"']),
    C.THRESHOLD: (
        ["0", "85", "100", '"0bp"', '"8500bp"', '"10000bp"', '"1bp"'],
        ['"08500bp"', '"+85"', '"85%"', "85.0", "1e2", '" 85"', '"85 "', '"85"', "101", "-1", '"10001bp"', '"bp"', '"00bp"', '"85BP"', '"８５bp"', "true", "[85]"],
    ),
    C.NAME: (['"a"', '"core.v1_x-2"', '"' + "a" * 128 + '"'], ['""', '"-a"', '".a"', '"a b"', '"' + "a" * 129 + '"', '"é"', "1"]),
    C.PATTERNS: (['["src/**"]', '["", "#c", "!x", "\\\\#y", "a\\\\"]'], ["[]", '["a\\u0000"]', '["a\\nb"]', '["a\\rb"]', '"src/**"']),
    C.PACKAGES: (['["std"]', '["a", "b"]'], ["[]", '["a", "a"]', '[""]', '["a\\nb"]']),
    C.SOURCES: (['["src/a.sv0"]'], ["[]", '["src/a.sv0", "src/a.sv0"]', '["../a.sv0"]', '["/a.sv0"]', '["a//b.sv0"]']),
    C.SOURCE: (['"src/a.sv0"'], ['""', '"./a.sv0"', '"a\\\\b.sv0"']),
    C.QUALIFIED_NAME: (['"main"', '"m::f"'], ['""', '"a\\u0000"', "1"]),
    C.ENTITY_KIND: (['"function"'], ['"method"', '"Function"']),
    C.DIFF_BASE: (['"merge-base:origin/main"', '"HEAD~1"'], ['""', '"a\\u0000b"', "1"]),
    C.METRIC_SET: (['["line"]', '["contract", "branch", "line", "region", "function"]'], ["[]", '["line", "line"]', '["lines"]']),
    C.BASIS_POINTS: (["0", "10000"], ["-1", "10001", '"0bp"']),
    C.MAX_RECORDS: (["0", "4294967295"], ["-1", "4294967296"]),
    C.REASONS: (["[]", '["x"]', '["' + "r" * 256 + '"]'], ['[""]', '["x", "x"]', '["' + "r" * 257 + '"]', '"x"']),
    C.FORBIDDEN_SOURCES: (["[]", '["gen/**"]'], ['["a\\u0000"]', '"gen/**"']),
}

# Minimal bodies that make each table valid on its own, so one key can vary.
BASE = {
    "coverage": "",
    "coverage.integrity": "",
    "coverage.limits.raw_profile": 'tier = "custom"\nmax_counters = 1\nmax_bytes = 1\n',
    "coverage.thresholds": "",
    "coverage.scopes": 'name = "s"\ninclude = ["**"]\n',
    "coverage.entities": 'name = "e"\nsource = "src/a.sv0"\nqualified_name = "f"\nkind = "function"\n',
    "coverage.diff": 'base = "HEAD"\nline = 100\n',
    "coverage.ratchet": 'baseline = "b.json"\nmetrics = ["line"]\n',
    "coverage.exclusions": "",
}
KEY_BASE = {"coverage.limits.raw_profile.tier": ""}  # standard/large forbid max_*
HEAD = '[coverage]\nschema = "1.0"\n'


def _header(table: str) -> str:
    return f"[[{table}]]" if C.TABLE[table].array else f"[{table}]"


def _doc(table: str, body: str) -> str:
    if table == "coverage":
        return HEAD + body
    return HEAD + f"\n{_header(table)}\n{body}"


def _without(body: str, key: str) -> str:
    return "".join(line + "\n" for line in body.splitlines() if not line.startswith(f"{key} ="))


def _case(cases: list, cid: str, toml: str, note: str = "") -> None:
    try:
        resolved = C.validate_bytes(toml.encode("utf-8"))
        expect: dict = {"resolved": resolved}
    except C.ConfigError as exc:
        expect = {"code": exc.code, "path": exc.path}
    entry = {"expect": expect, "id": cid, "toml": toml}
    if note:
        entry["note"] = note
    cases.append(entry)


CANONICAL_EXAMPLE = """[coverage]
schema = "1.0"
output_dir = ".sv0cov"
reports = ["term", "html", "json", "lcov", "cobertura"]
empty = "fail"

[coverage.integrity]
saturation = "fail" # "fail" or explicit "allow-ordinary"

[coverage.limits.raw_profile]
tier = "standard"

[coverage.thresholds]
line = 85
region = 82
function = 90
branch = 75

[[coverage.scopes]]
name = "core"
include = ["src/core/**"]
line = 95
branch = 90

[coverage.diff]
base = "merge-base:origin/main"
line = 100
region = 100

[coverage.ratchet]
baseline = ".sv0cov-baseline.json"
metrics = ["function", "region", "line", "branch"]
tolerance_basis_points = 0
"""

EVERY_KEY = """[package]
name = "unrelated"
anything = [1, 2.5, true]

[coverage]
schema = "1.0"
output_dir = "build/cov"
reports = ["json", "term"]
empty = "pass"
context = ""
reproducible_epoch = 9223372036854775807

[coverage.integrity]
saturation = "allow-ordinary"

[coverage.limits.raw_profile]
tier = "custom"
max_counters = 4294967295
max_bytes = 68719476736

[coverage.thresholds]
function = "10000bp"
region = 0
line = 85
branch = "8500bp"
contract = "0bp"

[[coverage.scopes]]
name = "core"
include = ["src/core/**", "!src/core/gen/"]
packages = ["root"]
sources = ["src/main.sv0"]
function = 1
region = 2
line = 3
branch = 4
contract = 5

[[coverage.scopes]]
name = "Core"
sources = ["src/main.sv0"]

[[coverage.entities]]
name = "main"
source = "src/main.sv0"
qualified_name = "main"
kind = "function"
function = 100
region = 100
line = 100
branch = 100
contract = 100

[[coverage.entities]]
name = "main.requires"
source = "src/main.sv0"
qualified_name = "main"
kind = "contract"
contract = "5000bp"

[coverage.diff]
base = "merge-base:origin/main"
line = 100
region = "1bp"
branch = 0

[coverage.ratchet]
baseline = ".sv0cov-baseline.json"
metrics = ["function", "region", "line", "branch", "contract"]
tolerance_basis_points = 10000

[coverage.exclusions]
max_records = 4294967295
function_basis_points = 0
region_basis_points = 1
line_basis_points = 10000
branch_basis_points = 5000
contract_basis_points = 0
forbidden_reasons = ["todo", "later"]
forbidden_sources = ["src/core/**"]
"""


def file_cases() -> list:
    cases: list = []
    _case(cases, "no-coverage", '[package]\nname = "x"\n')
    _case(cases, "empty-document", "")
    _case(cases, "minimal", HEAD)
    _case(cases, "canonical-example", CANONICAL_EXAMPLE, "SPEC 18.2.4")
    _case(cases, "every-key", EVERY_KEY, "every table and key, boundary values; unrelated keys outside coverage are not examined")
    _case(cases, "threshold-85-vs-8500bp", HEAD + '\n[coverage.thresholds]\nline = 85\nbranch = "8500bp"\n', "AC-102: both resolve to 8500")
    _case(cases, "empty-exclusions", HEAD + "\n[coverage.exclusions]\n")
    _case(cases, "empty-limits", HEAD + "\n[coverage.limits]\n")

    # schema key
    _case(cases, "schema/missing", "[coverage]\n")
    _case(cases, "schema/missing-with-keys", '[coverage]\nempty = "pass"\n')
    for i, lit in enumerate(['"1.1"', '"1"', '"1.0 "', "1.0", "1", "true", '["1.0"]']):
        _case(cases, f"schema/invalid-{i}", f"[coverage]\nschema = {lit}\n")
    _case(cases, "coverage-not-a-table", "coverage = 1\n")
    _case(cases, "coverage-array-of-tables", '[[coverage]]\nschema = "1.0"\n')
    _case(cases, "toml/duplicate-key", HEAD + 'empty = "fail"\nempty = "pass"\n')
    _case(cases, "toml/syntax", HEAD + "empty = \n")
    _case(cases, "toml/not-utf8", "")  # replaced below
    cases[-1]["toml"] = None
    cases[-1]["toml_hex"] = (HEAD + 'context = "').encode().hex() + "ff" + '"\n'.encode().hex()
    cases[-1]["expect"] = _expect_bytes(bytes.fromhex(cases[-1]["toml_hex"]))

    for table in C.TABLES:
        base = BASE.get(table.path)
        if base is None:  # coverage.limits holds only the raw_profile subtable
            _case(cases, f"{table.path}/unknown-key", _doc(table.path, "bogus = 1\n"))
            continue
        _case(cases, f"{table.path}/unknown-key", _doc(table.path, base + "bogus = 1\n"))
        _case(cases, f"{table.path}/unknown-subtable", _doc(table.path, base + "bogus = {}\n"))
        if table.path != "coverage":
            wrong = f"{table.path.rpartition('.')[2]} = 1\n"
            parent = table.path.rpartition(".")[0]
            _case(cases, f"{table.path}/wrong-shape", _doc(parent, BASE.get(parent, "") + wrong) if parent != "coverage.limits" else HEAD + "\n[coverage.limits]\nraw_profile = 1\n")
        for key in table.keys:
            if key.kind is C.SCHEMA:
                continue
            valid, invalid = BOUNDARY[key.kind]
            rest = _without(KEY_BASE.get(f"{table.path}.{key.name}", base), key.name)
            for i, lit in enumerate(valid):
                _case(cases, f"{table.path}.{key.name}/valid-{i}", _doc(table.path, rest + f"{key.name} = {lit}\n"))
            for i, lit in enumerate(invalid):
                _case(cases, f"{table.path}.{key.name}/invalid-{i}", _doc(table.path, rest + f"{key.name} = {lit}\n"))
            if key.required:
                _case(cases, f"{table.path}.{key.name}/missing", _doc(table.path, rest))

    # relations and uniqueness
    rp = "coverage.limits.raw_profile"
    _case(cases, "relation/custom-without-limits", _doc(rp, 'tier = "custom"\n'))
    _case(cases, "relation/custom-without-max-bytes", _doc(rp, 'tier = "custom"\nmax_counters = 1\n'))
    _case(cases, "relation/custom-without-max-counters", _doc(rp, 'tier = "custom"\nmax_bytes = 1\n'))
    _case(cases, "relation/custom-with-limits", _doc(rp, 'tier = "custom"\nmax_counters = 1\nmax_bytes = 1\n'))
    _case(cases, "relation/standard-with-max-counters", _doc(rp, 'tier = "standard"\nmax_counters = 1\n'))
    _case(cases, "relation/large-with-max-bytes", _doc(rp, 'tier = "large"\nmax_bytes = 1\n'))
    _case(cases, "relation/default-tier-with-max-bytes", _doc(rp, "max_bytes = 1\n"))
    _case(cases, "relation/scope-without-selector", _doc("coverage.scopes", 'name = "s"\nline = 90\n'))
    for sel in ("include", "packages", "sources"):
        lit = {"include": '["**"]', "packages": '["p"]', "sources": '["a.sv0"]'}[sel]
        _case(cases, f"relation/scope-only-{sel}", _doc("coverage.scopes", f'name = "s"\n{sel} = {lit}\n'))
    ent = 'name = "e"\nsource = "src/a.sv0"\nqualified_name = "f"\nkind = "contract"\n'
    _case(cases, "relation/contract-entity-contract-metric", _doc("coverage.entities", ent + "contract = 90\n"))
    for m in ("function", "region", "line", "branch"):
        _case(cases, f"relation/contract-entity-{m}", _doc("coverage.entities", ent + f"{m} = 90\n"))
    _case(cases, "relation/diff-without-threshold", _doc("coverage.diff", 'base = "HEAD"\n'))
    for m in ("function", "contract"):
        _case(cases, f"relation/diff-{m}", _doc("coverage.diff", f'base = "HEAD"\nline = 1\n{m} = 1\n'))
    two = 'name = "s"\ninclude = ["**"]\n'
    two_upper = two.replace('"s"', '"S"')
    two_e = two.replace('"s"', '"e"')
    _case(cases, "unique/scope-names", HEAD + f"\n[[coverage.scopes]]\n{two}\n[[coverage.scopes]]\n{two}")
    _case(cases, "unique/scope-names-case-distinct", HEAD + f"\n[[coverage.scopes]]\n{two}\n[[coverage.scopes]]\n{two_upper}")
    e = BASE["coverage.entities"]
    _case(cases, "unique/entity-names", HEAD + f"\n[[coverage.entities]]\n{e}\n[[coverage.entities]]\n{e}")
    _case(cases, "unique/scope-and-entity-share-name", HEAD + f"\n[[coverage.scopes]]\n{two_e}\n[[coverage.entities]]\n{e}")
    _case(cases, "shape/scopes-as-table", HEAD + '\n[coverage.scopes]\nname = "s"\ninclude = ["**"]\n')
    _case(cases, "shape/thresholds-as-array", HEAD + "\n[[coverage.thresholds]]\nline = 1\n")
    _case(cases, "shape/cli-only-key", HEAD + 'run_id = "0123456789abcdef0123456789abcdef"\n')
    _case(cases, "shape/cli-spelling", HEAD + 'output-dir = "x"\n')
    _case(cases, "shape/percent-sign-key", HEAD + "\n[coverage.thresholds]\nlines = 1\n")
    return cases


def _expect_bytes(data: bytes) -> dict:
    try:
        return {"resolved": C.validate_bytes(data)}
    except C.ConfigError as exc:
        return {"code": exc.code, "path": exc.path}


# --- CLI corpus --------------------------------------------------------------

CLI_VALUES = {
    "--threshold-line": ["85", "8500bp", "0", "100", "0bp", "10000bp", "085", "+85", "85%", "85.0", "1e2", " 85", "101", "10001bp", "", "8500BP"],
    "--diff-branch": ["100", "1bp", "-1"],
    "--empty": ["fail", "pass", "FAIL", ""],
    "--report": ["term", "cobertura", "term,html", "xml"],
    "--ratchet-metric": ["line", "contract", "line,branch", "lines"],
    "--reproducible-epoch": ["0", "9223372036854775807", "9223372036854775808", "-1", "01", "+1", "1_000"],
    "--raw-profile-max-bytes": ["1", "68719476736", "0", "68719476737"],
    "--raw-profile-tier": ["standard", "custom", "huge"],
    "--output-dir": [".sv0cov", "/abs", "a/../b", ""],
    "--context": ["", "ci", "x" * 257],
    "--saturation-policy": ["fail", "allow-ordinary", "allow_ordinary"],
    "--ratchet-tolerance-basis-points": ["0", "10000", "10001"],
    "--run-id": ["0123456789abcdef0123456789abcdef", "0" * 32, "0123456789ABCDEF0123456789ABCDEF", "0123"],
    "--format": ["html", "term,html", "xml"],
    "--color": ["auto", "never", "Always"],
    "--diagnostic-format": ["human", "json-lines", "json"],
}


def cli_cases() -> dict:
    values = []
    for option, texts in CLI_VALUES.items():
        command = C.OPTION[option].commands[0]
        for text in texts:
            try:
                expect = {"value": C.check_cli_value(option, text, command)}
            except C.ConfigError as exc:
                expect = {"code": exc.code, "path": exc.path}
            values.append({"command": command, "expect": expect, "option": option, "text": text})
    matrix = {o.name: [c for c in C.COMMANDS if c in o.commands] for o in C.OPTIONS}
    return {"applicability": matrix, "schema": "sv0cov.config-cli-corpus", "values": values, "version": C.SCHEMA_VERSION}


# --- driver ------------------------------------------------------------------


def artifacts() -> dict[Path, bytes]:
    return {
        SCHEMA_FILE: encode(schema()),
        FIXTURES / "inventory.json": C.inventory_document(),
        FIXTURES / "defaults.json": C.default_snapshot(),
        FIXTURES / "file-cases.json": encode({"cases": file_cases(), "schema": "sv0cov.config-file-corpus", "version": C.SCHEMA_VERSION}),
        FIXTURES / "cli-cases.json": encode(cli_cases()),
    }


def main() -> int:
    write = "--write" in sys.argv
    stale = []
    for path, data in artifacts().items():
        if write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(str(path.relative_to(ROOT)))
    if stale:
        print("stale configuration artifacts: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("configuration artifacts: " + ("written" if write else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
