# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Coverage configuration schema 1.0 and its CLI mapping (SPEC 18.2).

The closed ``[coverage]`` inventory, its defaults, the threshold grammar, and
the CLI option table are data in this module. Everything else is derived
from them: the file validator, the default snapshot, the machine-readable
inventory document, the JSON Schema in ``schemas/``, and the frozen key-path
corpus in ``tests/fixtures/config``.

Resolution with provenance (CLI > file > default) is CV-224; semantic checks
that need a map or build graph (entity resolution, package existence) are
CV-310. This module validates one file and one CLI value at a time.

Interpretations recorded here:

- The spec gives command applicability only for the root, integrity, and
  raw-profile tables. Thresholds, scopes, entities, diff, ratchet, and
  exclusions are policy and apply to ``run`` and ``check``.
- A project-relative artifact path "uses ``/``", so a backslash is rejected
  along with the enumerated NUL, drive, absolute, ``.``, and ``..`` forms.
- A build-package identity has no grammar in the spec yet; it is checked as
  a nonempty logical string (UTF-8, no NUL/CR/LF) until the build graph
  defines one.
- On the CLI every value is text: an integer threshold is ASCII decimal
  with the same no-sign, no-leading-zero rules as ``bp``.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field

from sv0cov.formats.canonical_json import encode
from sv0cov.formats.runset import RunIdError, parse_run_id
from sv0cov.model.logical import LogicalValueError, check_logical_path

SCHEMA_VERSION = "1.0"
COMMANDS = ("run", "merge", "report", "check", "clean", "doctor", "version")
METRICS = ("function", "region", "line", "branch", "contract")
REPORT_FORMATS = ("term", "html", "json", "lcov", "cobertura")
DENOMINATOR = 10000
POLICY = ("run", "check")

RE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
RE_DECIMAL = re.compile(r"0|[1-9][0-9]*")
RE_DRIVE = re.compile(r"[A-Za-z]:")

# Diagnostic codes (registry revision 1).
TOML_ERROR = "COV0002"
BAD_SCHEMA = "COV0010"
UNKNOWN_KEY = "COV0011"
BAD_VALUE = "COV0012"
CONFLICT = "COV0013"
BAD_PATTERN = "COV0014"
BAD_THRESHOLD = "COV0015"


class ConfigError(ValueError):
    """A configuration failure: diagnostic code, dotted key path, detail."""

    def __init__(self, code: str, path: str, detail: str) -> None:
        super().__init__(f"{code} {path}: {detail}")
        self.code = code
        self.path = path
        self.detail = detail


# --- value kinds ------------------------------------------------------------


@dataclass(frozen=True)
class Kind:
    """A value grammar. ``toml`` is the TOML type; the rest bound the value."""

    name: str
    toml: str  # "string", "integer", "array", "threshold"
    values: tuple[str, ...] = ()
    minimum: int | None = None
    maximum: int | None = None
    max_bytes: int | None = None


SCHEMA = Kind("schema", "string", values=(SCHEMA_VERSION,))
ARTIFACT_PATH = Kind("artifact_path", "string")
REPORTS = Kind("report_formats", "array", values=REPORT_FORMATS)
EMPTY = Kind("empty_policy", "string", values=("fail", "pass"))
CONTEXT = Kind("context", "string", max_bytes=256)
EPOCH = Kind("epoch", "integer", minimum=0, maximum=2**63 - 1)
SATURATION = Kind("saturation_policy", "string", values=("fail", "allow-ordinary"))
TIER = Kind("raw_profile_tier", "string", values=("standard", "large", "custom"))
MAX_COUNTERS = Kind("max_counters", "integer", minimum=1, maximum=2**32 - 1)
MAX_BYTES = Kind("max_bytes", "integer", minimum=1, maximum=2**36)
THRESHOLD = Kind("threshold", "threshold")
NAME = Kind("assertion_name", "string")
PATTERNS = Kind("patterns", "array")
PACKAGES = Kind("packages", "array")
SOURCES = Kind("sources", "array")
SOURCE = Kind("source", "string")
QUALIFIED_NAME = Kind("qualified_name", "string")
ENTITY_KIND = Kind("entity_kind", "string", values=("function", "contract"))
DIFF_BASE = Kind("diff_base", "string")
METRIC_SET = Kind("metrics", "array", values=METRICS)
BASIS_POINTS = Kind("basis_points", "integer", minimum=0, maximum=DENOMINATOR)
MAX_RECORDS = Kind("max_records", "integer", minimum=0, maximum=2**32 - 1)
REASONS = Kind("reasons", "array", max_bytes=256)
FORBIDDEN_SOURCES = Kind("forbidden_sources", "array")


@dataclass(frozen=True)
class Key:
    name: str
    kind: Kind
    default: object = None  # None: absent unless configured
    required: bool = False
    commands: tuple[str, ...] = POLICY


@dataclass(frozen=True)
class Table:
    """One TOML table or array-table under ``coverage``."""

    path: str
    keys: tuple[Key, ...]
    array: bool = False
    tables: tuple[str, ...] = field(default=())  # child table names

    def key(self, name: str) -> Key | None:
        return next((k for k in self.keys if k.name == name), None)


def _thresholds(keys: tuple[str, ...] = METRICS) -> tuple[Key, ...]:
    return tuple(Key(m, THRESHOLD) for m in keys)


TABLES = (
    Table(
        "coverage",
        (
            Key("schema", SCHEMA, required=True, commands=COMMANDS),
            Key("output_dir", ARTIFACT_PATH, ".sv0cov", commands=("run", "merge", "report", "check", "clean")),
            Key("reports", REPORTS, ["term"], commands=("run",)),
            Key("empty", EMPTY, "fail", commands=("run", "check")),
            Key("context", CONTEXT, commands=("run",)),
            Key("reproducible_epoch", EPOCH, 0, commands=("run", "report")),
        ),
        tables=("integrity", "limits", "thresholds", "scopes", "entities", "diff", "ratchet", "exclusions"),
    ),
    Table("coverage.integrity", (Key("saturation", SATURATION, "fail", commands=("run", "merge", "report", "check")),)),
    Table("coverage.limits", (), tables=("raw_profile",)),
    Table(
        "coverage.limits.raw_profile",
        (
            Key("tier", TIER, "standard", commands=("run", "merge")),
            Key("max_counters", MAX_COUNTERS, commands=("run", "merge")),
            Key("max_bytes", MAX_BYTES, commands=("run", "merge")),
        ),
    ),
    Table("coverage.thresholds", _thresholds()),
    Table(
        "coverage.scopes",
        (Key("name", NAME, required=True), Key("include", PATTERNS), Key("packages", PACKAGES), Key("sources", SOURCES), *_thresholds()),
        array=True,
    ),
    Table(
        "coverage.entities",
        (
            Key("name", NAME, required=True),
            Key("source", SOURCE, required=True),
            Key("qualified_name", QUALIFIED_NAME, required=True),
            Key("kind", ENTITY_KIND, required=True),
            *_thresholds(),
        ),
        array=True,
    ),
    Table("coverage.diff", (Key("base", DIFF_BASE, required=True), *_thresholds(("line", "region", "branch")))),
    Table(
        "coverage.ratchet",
        (
            Key("baseline", ARTIFACT_PATH, required=True),
            Key("metrics", METRIC_SET, required=True),
            Key("tolerance_basis_points", BASIS_POINTS, 0),
        ),
    ),
    Table(
        "coverage.exclusions",
        (
            Key("max_records", MAX_RECORDS),
            *(Key(f"{m}_basis_points", BASIS_POINTS) for m in METRICS),
            Key("forbidden_reasons", REASONS, []),
            Key("forbidden_sources", FORBIDDEN_SOURCES, []),
        ),
    ),
)
TABLE = {t.path: t for t in TABLES}


# --- CLI mapping (SPEC 18.2.3) ----------------------------------------------


@dataclass(frozen=True)
class Option:
    """One CLI option. ``key`` is the dotted file key it overrides, if any."""

    name: str
    commands: tuple[str, ...]
    arity: str  # "scalar", "repeatable", or "flag"
    key: str | None = None
    kind: Kind | None = None
    conflicts: tuple[str, ...] = ()
    required: tuple[str, ...] = ()  # commands for which the option is required


def _mapped(name: str, key: str, arity: str = "scalar", conflicts: tuple[str, ...] = ()) -> Option:
    table, _, leaf = key.rpartition(".")
    k = TABLE[table].key(leaf)
    return Option(name, k.commands, arity, key, k.kind, conflicts)


RUN_ID = Kind("run_id", "string")
PATH_ARG = Kind("path", "string")
FORMAT = Kind("report_format", "string", values=REPORT_FORMATS)
COLOR = Kind("color", "string", values=("auto", "always", "never"))
DIAGNOSTIC_FORMAT = Kind("diagnostic_format", "string", values=("human", "json-lines"))

OPTIONS = (
    _mapped("--output-dir", "coverage.output_dir"),
    _mapped("--report", "coverage.reports", "repeatable"),
    _mapped("--empty", "coverage.empty"),
    _mapped("--context", "coverage.context", conflicts=("--no-context",)),
    Option("--no-context", ("run",), "flag", "coverage.context", conflicts=("--context",)),
    _mapped("--reproducible-epoch", "coverage.reproducible_epoch"),
    _mapped("--saturation-policy", "coverage.integrity.saturation"),
    *(_mapped(f"--threshold-{m}", f"coverage.thresholds.{m}") for m in METRICS),
    _mapped("--diff-base", "coverage.diff.base"),
    *(_mapped(f"--diff-{m}", f"coverage.diff.{m}") for m in ("line", "region", "branch")),
    _mapped("--ratchet-baseline", "coverage.ratchet.baseline"),
    _mapped("--ratchet-metric", "coverage.ratchet.metrics", "repeatable"),
    _mapped("--ratchet-tolerance-basis-points", "coverage.ratchet.tolerance_basis_points"),
    _mapped("--raw-profile-tier", "coverage.limits.raw_profile.tier"),
    _mapped("--raw-profile-max-counters", "coverage.limits.raw_profile.max_counters"),
    _mapped("--raw-profile-max-bytes", "coverage.limits.raw_profile.max_bytes"),
    Option("--run-id", ("run",), "scalar", kind=RUN_ID),
    Option("--expect-run", ("merge",), "repeatable", kind=RUN_ID, conflicts=("--run-manifest",)),
    Option("--run-manifest", ("merge",), "scalar", kind=PATH_ARG, conflicts=("--expect-run",)),
    Option("--output", ("merge", "report"), "scalar", kind=PATH_ARG),
    Option("--format", ("report",), "repeatable", kind=FORMAT, required=("report",)),
    Option("--quiet", ("run", "merge", "report", "check", "clean", "doctor"), "flag"),
    Option("--color", ("run", "merge", "report", "check", "doctor"), "scalar", kind=COLOR),
    Option("--diagnostic-format", COMMANDS, "scalar", kind=DIAGNOSTIC_FORMAT),
    Option("--json", ("doctor", "version"), "flag"),
    Option("--toolchain-root", ("doctor",), "scalar", kind=PATH_ARG),
    Option("--allow-source-mismatch", ("report",), "flag"),
    Option("--allow-rejected-inputs", ("merge",), "flag"),
    Option("--prefer-coverage-exit", ("run",), "flag"),
    Option("--allow-lossy-saturated-export", ("run", "report"), "flag"),
)
OPTION = {o.name: o for o in OPTIONS}


# --- scalar grammars --------------------------------------------------------


def parse_threshold(value: object, path: str) -> int:
    """A TOML threshold value → exact numerator over 10000 (SPEC 18.2.1)."""
    if type(value) is int:
        if not 0 <= value <= 100:
            raise ConfigError(BAD_THRESHOLD, path, f"percentage {value} outside 0..100")
        return value * 100
    if isinstance(value, str):
        digits = value.removesuffix("bp")
        if digits == value or not digits.isascii() or not RE_DECIMAL.fullmatch(digits):
            raise ConfigError(BAD_THRESHOLD, path, f"{value!r} is not an integer 0..100 or a canonical '<n>bp' string")
        n = int(digits)
        if n > DENOMINATOR:
            raise ConfigError(BAD_THRESHOLD, path, f"{n} basis points exceeds {DENOMINATOR}")
        return n
    raise ConfigError(BAD_THRESHOLD, path, f"must be an integer or a 'bp' string, not {_toml_type(value)}")


def parse_cli_threshold(text: str, path: str) -> int:
    """A CLI threshold: ASCII decimal percentage or canonical ``<n>bp``."""
    if text.isascii() and RE_DECIMAL.fullmatch(text) and len(text) <= 3:
        return parse_threshold(int(text), path)
    return parse_threshold(text, path)


def check_artifact_path(value: str, path: str) -> None:
    if value == "":
        raise ConfigError(BAD_VALUE, path, "must be a nonempty path")
    if "\x00" in value or "\\" in value:
        raise ConfigError(BAD_VALUE, path, "contains NUL or a backslash")
    if value.startswith("/") or RE_DRIVE.match(value):
        raise ConfigError(BAD_VALUE, path, "must be project-relative")
    if any(seg in (".", "..") for seg in value.split("/")):
        raise ConfigError(BAD_VALUE, path, "has a '.' or '..' component")


def _utf8_len(value: str, path: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeEncodeError:
        raise ConfigError(BAD_VALUE, path, "is not valid UTF-8") from None


def _toml_type(value: object) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "table"
    return "date-time"


def _unique(items: list, path: str) -> None:
    if len(set(items)) != len(items):
        raise ConfigError(BAD_VALUE, path, "contains a duplicate entry")


def _string_array(value: object, path: str, *, nonempty: bool) -> list[str]:
    if not isinstance(value, list) or any(not isinstance(v, str) for v in value):
        raise ConfigError(BAD_VALUE, path, "must be an array of strings")
    if nonempty and not value:
        raise ConfigError(BAD_VALUE, path, "must not be empty")
    return value


def check_value(kind: Kind, value: object, path: str) -> object:
    """Validate one value against its kind; returns the resolved value."""
    if kind.toml == "threshold":
        return parse_threshold(value, path)
    if kind is SCHEMA:
        if value != SCHEMA_VERSION or not isinstance(value, str):
            raise ConfigError(BAD_SCHEMA, path, f"must be exactly {SCHEMA_VERSION!r}")
        return value
    if kind.toml == "string" and not isinstance(value, str):
        raise ConfigError(BAD_VALUE, path, f"must be a string, not {_toml_type(value)}")
    if kind.toml == "integer":
        if type(value) is not int:
            raise ConfigError(BAD_VALUE, path, f"must be an integer, not {_toml_type(value)}")
        if not kind.minimum <= value <= kind.maximum:
            raise ConfigError(BAD_VALUE, path, f"{value} outside {kind.minimum}..{kind.maximum}")
        return value
    if kind.toml == "string":
        n = _utf8_len(value, path)
        if kind.values and value not in kind.values:
            raise ConfigError(BAD_VALUE, path, f"must be one of {', '.join(kind.values)}")
        if kind is ARTIFACT_PATH:
            check_artifact_path(value, path)
        elif kind is CONTEXT and n > kind.max_bytes:
            raise ConfigError(BAD_VALUE, path, f"exceeds {kind.max_bytes} bytes")
        elif kind is NAME and not (value.isascii() and RE_NAME.fullmatch(value)):
            raise ConfigError(BAD_VALUE, path, "is not an assertion name ([A-Za-z0-9][A-Za-z0-9._-]*, 1..128 bytes)")
        elif kind in (DIFF_BASE, QUALIFIED_NAME) and (n == 0 or "\x00" in value):
            raise ConfigError(BAD_VALUE, path, "must be nonempty with no NUL")
        elif kind is SOURCE:
            _logical(value, path)
        return value
    # arrays
    if kind in (REPORTS, METRIC_SET):
        items = _string_array(value, path, nonempty=True)
        bad = [v for v in items if v not in kind.values]
        if bad:
            raise ConfigError(BAD_VALUE, path, f"{bad[0]!r} is not one of {', '.join(kind.values)}")
        _unique(items, path)
        return list(items)
    if kind in (PATTERNS, FORBIDDEN_SOURCES):
        items = _string_array(value, path, nonempty=kind is PATTERNS)
        for i, p in enumerate(items):
            _utf8_len(p, f"{path}[{i}]")
            if any(c in p for c in "\x00\r\n"):
                raise ConfigError(BAD_PATTERN, f"{path}[{i}]", "contains NUL, CR, or LF")
        return list(items)
    if kind in (PACKAGES, SOURCES):
        items = _string_array(value, path, nonempty=True)
        for i, p in enumerate(items):
            _logical(p, f"{path}[{i}]", path_rules=kind is SOURCES)
        _unique(items, path)
        return list(items)
    if kind is REASONS:
        items = _string_array(value, path, nonempty=False)
        for i, r in enumerate(items):
            if not 0 < _utf8_len(r, f"{path}[{i}]") <= kind.max_bytes:
                raise ConfigError(BAD_VALUE, f"{path}[{i}]", f"must be 1..{kind.max_bytes} bytes")
        _unique(items, path)
        return list(items)
    raise AssertionError(kind.name)


def _logical(value: str, path: str, *, path_rules: bool = True) -> None:
    try:
        if path_rules:
            check_logical_path(value, path)
        elif not value or any(c in value for c in "\x00\r\n"):
            raise LogicalValueError(path, "must be nonempty with no NUL, CR, or LF")
        else:
            _utf8_len(value, path)
    except LogicalValueError as exc:
        raise ConfigError(BAD_VALUE, path, exc.detail) from None


# --- file validation --------------------------------------------------------


def parse_toml(data: bytes) -> dict:
    """Parse ``sv0.toml`` bytes; TOML errors (including duplicate keys) are COV0002."""
    try:
        return tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(TOML_ERROR, "sv0.toml", str(exc)) from None


def validate_document(doc: dict) -> dict | None:
    """Validate the ``coverage`` subtree of a parsed ``sv0.toml``.

    Returns the validated subtree with thresholds resolved to numerators, or
    ``None`` when there is no ``coverage`` key. Keys outside ``coverage`` are
    not examined.
    """
    if "coverage" not in doc:
        return None
    tree = doc["coverage"]
    if not isinstance(tree, dict):
        raise ConfigError(BAD_VALUE, "coverage", "must be a table")
    if "schema" not in tree:
        raise ConfigError(BAD_SCHEMA, "coverage.schema", "is required when [coverage] is present")
    check_value(SCHEMA, tree["schema"], "coverage.schema")
    return _table(TABLE["coverage"], tree, "coverage")


def validate_bytes(data: bytes) -> dict | None:
    return validate_document(parse_toml(data))


def _table(table: Table, tree: object, path: str) -> dict:
    if table.array:
        if not isinstance(tree, list) or any(not isinstance(t, dict) for t in tree):
            raise ConfigError(BAD_VALUE, path, "must be an array of tables")
        out = [_fields(table, t, f"{path}[{i}]") for i, t in enumerate(tree)]
        names = [t["name"] for t in out]
        if len(set(names)) != len(names):
            dup = next(n for n in names if names.count(n) > 1)
            raise ConfigError(CONFLICT, path, f"assertion name {dup!r} is not unique")
        return out
    if not isinstance(tree, dict):
        raise ConfigError(BAD_VALUE, path, "must be a table")
    return _fields(table, tree, path)


def _fields(table: Table, tree: dict, path: str) -> dict:
    out: dict = {}
    for name in tree:
        if table.key(name) is None and name not in table.tables:
            raise ConfigError(UNKNOWN_KEY, f"{path}.{name}", f"is not a key of [{table.path}]")
    for key in table.keys:
        if key.name in tree:
            out[key.name] = check_value(key.kind, tree[key.name], f"{path}.{key.name}")
        elif key.required:
            raise ConfigError(BAD_VALUE, f"{path}.{key.name}", "is required")
    for name in table.tables:
        if name in tree:
            out[name] = _table(TABLE[f"{table.path}.{name}"], tree[name], f"{path}.{name}")
    _relations(table.path, out, path)
    return out


def _relations(table: str, t: dict, path: str) -> None:
    """Cross-field rules decidable from the file alone (SPEC 18.2.2)."""
    if table == "coverage.limits.raw_profile":
        custom = t.get("tier", "standard") == "custom"
        for k in ("max_counters", "max_bytes"):
            if custom and k not in t:
                raise ConfigError(CONFLICT, f"{path}.{k}", "is required with tier = \"custom\"")
            if not custom and k in t:
                raise ConfigError(CONFLICT, f"{path}.{k}", "is allowed only with tier = \"custom\"")
    elif table == "coverage.scopes" and not {"include", "packages", "sources"} & t.keys():
        raise ConfigError(CONFLICT, path, "needs at least one of include, packages, or sources")
    elif table == "coverage.entities" and t["kind"] == "contract":
        extra = [m for m in METRICS if m != "contract" and m in t]
        if extra:
            raise ConfigError(CONFLICT, f"{path}.{extra[0]}", "is inapplicable to a contract entity")
    elif table == "coverage.diff" and not {"line", "region", "branch"} & t.keys():
        raise ConfigError(CONFLICT, path, "needs at least one of line, region, or branch")


# --- CLI values -------------------------------------------------------------


def check_cli_value(option: str, text: str, command: str) -> object:
    """Validate one CLI occurrence's value for ``command``.

    Applicability, arity, and comma lists are usage errors (COV0001). A
    mapped option's value uses its file key's grammar and diagnostic code,
    reported against the option name.
    """
    opt = OPTION.get(option)
    if opt is None:
        raise ConfigError("COV0001", option, "is not an sv0cov option")
    if command not in opt.commands:
        raise ConfigError("COV0001", option, f"does not apply to {command}")
    if opt.arity == "flag":
        raise ConfigError("COV0001", option, "takes no value")
    kind = opt.kind
    if kind in (FORMAT, COLOR, DIAGNOSTIC_FORMAT):
        if text not in kind.values:
            raise ConfigError("COV0001", option, f"must be one of {', '.join(kind.values)}")
        return text
    if kind is RUN_ID:
        try:
            parse_run_id(text)
        except RunIdError as exc:
            raise ConfigError("COV0001", option, str(exc)) from None
        return text
    if kind is PATH_ARG:
        if text == "" or "\x00" in text:
            raise ConfigError("COV0001", option, "must be a nonempty path")
        return text
    try:
        if kind is THRESHOLD:
            return parse_cli_threshold(text, option)
        if kind.toml == "array":
            if "," in text:
                raise ConfigError("COV0001", option, "takes one value per occurrence; comma lists are invalid")
            return check_value(Kind(kind.name, "string", values=kind.values), text, option)
        if kind.toml == "integer":
            if not (text.isascii() and RE_DECIMAL.fullmatch(text)):
                raise ConfigError(BAD_VALUE, option, f"{text!r} is not a decimal integer")
            return check_value(kind, int(text), option)
        return check_value(kind, text, option)
    except ConfigError as exc:
        raise ConfigError(exc.code, option, exc.detail) from None


# --- derived documents ------------------------------------------------------


def defaults() -> dict:
    """Every key with a built-in default, by dotted path (the default snapshot)."""
    return {f"{t.path}.{k.name}": k.default for t in TABLES if not t.array for k in t.keys if k.default is not None}


def default_snapshot() -> bytes:
    return encode({"defaults": defaults(), "schema": "sv0cov.config-defaults", "version": SCHEMA_VERSION})


def _kind_doc(kind: Kind) -> dict:
    d: dict = {"name": kind.name, "toml": kind.toml}
    if kind.values:
        d["values"] = list(kind.values)
    if kind.minimum is not None:
        d["minimum"] = kind.minimum
        d["maximum"] = kind.maximum
    if kind.max_bytes is not None:
        d["max_bytes"] = kind.max_bytes
    return d


def inventory_document() -> bytes:
    """The closed inventory, defaults, and CLI mapping as canonical JSON."""
    tables = []
    for t in TABLES:
        keys = []
        for k in t.keys:
            entry = {"commands": list(k.commands), "kind": _kind_doc(k.kind), "name": k.name, "required": k.required}
            if k.default is not None:
                entry["default"] = k.default
            keys.append(entry)
        tables.append({"array": t.array, "keys": keys, "path": t.path, "tables": list(t.tables)})
    options = []
    for o in OPTIONS:
        entry = {"arity": o.arity, "commands": list(o.commands), "conflicts": list(o.conflicts), "name": o.name, "required_for": list(o.required)}
        if o.key is not None:
            entry["key"] = o.key
        if o.kind is not None:
            entry["kind"] = _kind_doc(o.kind)
        options.append(entry)
    return encode(
        {"commands": list(COMMANDS), "metrics": list(METRICS), "options": options, "schema": "sv0cov.config-inventory", "tables": tables, "version": SCHEMA_VERSION}
    )
