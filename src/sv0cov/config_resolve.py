# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Configuration resolution (CV-224; SPEC 18.2, 21.3.7; COV-CFG-001..005,
AC-098).

:func:`resolve` takes a command, the CLI option occurrences in order, and
the bytes of ``sv0.toml`` (or ``None``), and returns the effective
configuration with the source of every leaf::

    explicit CLI option > sv0.toml > built-in default

There is no environment layer. This module and :mod:`sv0cov.config` read no
environment variable, so nothing a caller exports can change the result.

Everything is driven by the closed inventory in :mod:`sv0cov.config`
(``TABLES`` and ``OPTIONS``); no key or option is listed twice.

What fails, before anything runs:

- usage errors (``COV0001``): an unknown option, one that does not apply to
  the command, a repeated scalar or flag, a value on a flag or none on a
  valued option, a conflicting pair, a missing required option;
- every file error of :func:`sv0cov.config.validate_bytes`;
- every value error, with the CLI option as its path;
- relations that hold only on the effective values (``COV0013``): a custom
  tier needs both ceilings and other tiers forbid them; a ``diff`` table
  needs a base and a threshold; a ``ratchet`` table needs a baseline and
  metrics.

A CLI option can create the ``diff`` or ``ratchet`` table when the file has
none. A CLI option cannot remove a file key, except ``--no-context``; so
``--raw-profile-tier standard`` over a file that sets custom ceilings is a
conflict rather than a silent drop.

:meth:`Resolved.document` is the ``sv0cov.resolved-configuration`` 1.0
record of SPEC 21.3.7. Its schema and validator come with CV-228.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sv0cov import config as C
from sv0cov.formats.canonical_json import encode
from sv0cov.formats.rawprofile import Tier

ROOT = "tool.sv0cov"
CLI, FILE, DEFAULT = "cli", "sv0.toml", "default"
USAGE = "COV0001"
OPTIONAL_TABLES = ("diff", "ratchet")  # null in the resolved record when absent
SET_LIKE = (C.METRIC_SET, C.PACKAGES, C.SOURCES, C.REASONS)  # canonical bytewise order; the rest keep declaration order
REPORT_CONTROLS = ("--allow-lossy-saturated-export", "--allow-source-mismatch")


@dataclass(frozen=True)
class Leaf:
    value: object
    source: str

    def to_json(self) -> dict:
        return {"source": self.source, "value": self.value}


def _usage(option: str, detail: str) -> C.ConfigError:
    return C.ConfigError(USAGE, option, detail)


def _occurrences(command: str, options: Sequence[tuple[str, str | None]]) -> dict[str, list[str | None]]:
    """Group the occurrences by option after the usage checks."""
    if command not in C.COMMANDS:
        raise _usage(command, "is not an sv0cov command")
    seen: dict[str, list[str | None]] = {}
    for name, text in options:
        opt = C.OPTION.get(name)
        if opt is None:
            raise _usage(name, "is not an sv0cov option")
        if command not in opt.commands:
            raise _usage(name, f"does not apply to {command}")
        if opt.arity == "flag" and text is not None:
            raise _usage(name, "takes no value")
        if opt.arity != "flag" and text is None:
            raise _usage(name, "needs a value")
        if name in seen and opt.arity != "repeatable":
            raise _usage(name, "may be given only once")
        seen.setdefault(name, []).append(text)
    for name in seen:
        clash = next((c for c in C.OPTION[name].conflicts if c in seen), None)
        if clash is not None:
            raise _usage(name, f"conflicts with {clash}")
    for opt in C.OPTIONS:
        if command in opt.required and opt.name not in seen:
            raise _usage(opt.name, f"is required by {command}")
    return seen


def _cli_values(command: str, seen: dict[str, list[str | None]]) -> tuple[dict[str, Leaf], dict[str, object]]:
    """Mapped options as leaves by dotted key, and the CLI-only controls."""
    mapped: dict[str, Leaf] = {}
    controls: dict[str, object] = {}
    for name, texts in seen.items():
        opt = C.OPTION[name]
        if opt.arity == "flag":
            value: object = None if opt.key else True
        elif opt.arity == "repeatable":
            items = [C.check_cli_value(name, t, command) for t in texts]
            value = C.check_value(opt.kind, items, name) if opt.key else items
            if not opt.key and len(set(items)) != len(items):
                raise _usage(name, "repeats a value")
        else:
            value = C.check_cli_value(name, texts[0], command)
        if opt.key:
            mapped[opt.key] = Leaf(value, CLI)
        else:
            controls[name] = value
    return mapped, controls


def _normal(kind: C.Kind, value: object) -> object:
    return sorted(value, key=lambda s: s.encode("utf-8")) if kind in SET_LIKE and value is not None else value


def _relations(tree: dict, origin: dict[str, str]) -> None:
    """Relations on the effective values. ``origin`` names, per dotted key,
    what to blame: the CLI option or the key itself."""

    def fail(key: str, detail: str) -> None:
        raise C.ConfigError(C.CONFLICT, origin.get(key, key), detail)

    rp = tree["limits"]["raw_profile"]
    base = f"{ROOT}.limits.raw_profile"
    custom = rp["tier"].value == "custom"
    for k in ("max_counters", "max_bytes"):
        if custom and rp[k].value is None:
            fail(f"{base}.tier", f"tier custom needs {k}")
        if not custom and rp[k].value is not None:
            fail(f"{base}.{k}", f"is allowed only with tier custom (effective tier: {rp['tier'].value})")
    diff = tree["diff"]
    if diff is not None:
        if diff["base"].value is None:
            fail(f"{ROOT}.diff", "a diff check needs a base")
        if all(diff[m].value is None for m in ("line", "region", "branch")):
            fail(f"{ROOT}.diff", "a diff check needs at least one of line, region, or branch")
    ratchet = tree["ratchet"]
    if ratchet is not None:
        for k in ("baseline", "metrics"):
            if ratchet[k].value is None:
                fail(f"{ROOT}.ratchet", f"a ratchet needs {k}")


@dataclass(frozen=True)
class Resolved:
    """The effective configuration. ``coverage`` mirrors the inventory:
    tables are dicts, array-tables are lists, every scalar is a
    :class:`Leaf`; ``diff`` and ``ratchet`` are ``None`` when absent.
    ``controls`` holds the CLI-only options given (invocation transport,
    never serialized)."""

    command: str
    coverage: dict
    report: dict
    controls: dict

    def leaf(self, key: str) -> Leaf:
        """The leaf at a dotted key below ``tool.sv0cov``, such as
        ``thresholds.line``."""
        node: object = self.coverage
        for part in key.split("."):
            node = node[part]
        if not isinstance(node, Leaf):
            raise KeyError(key)
        return node

    def value(self, key: str) -> object:
        return self.leaf(key).value

    def source(self, key: str) -> str:
        return self.leaf(key).source

    def tier(self) -> Tier:
        rp = self.coverage["limits"]["raw_profile"]
        name = rp["tier"].value
        if name == "custom":
            return Tier.custom(rp["max_counters"].value, rp["max_bytes"].value)
        return Tier.large() if name == "large" else Tier.standard()

    def document(self) -> dict:
        """The ``sv0cov.resolved-configuration`` 1.0 record (SPEC 21.3.7)."""

        def plain(node: object) -> object:
            if isinstance(node, Leaf):
                return node.to_json()
            if isinstance(node, dict):
                return {k: plain(v) for k, v in node.items()}
            if isinstance(node, list):
                return [plain(v) for v in node]
            return node

        return {"coverage": plain(self.coverage), "report": plain(self.report), "schema": "sv0cov.resolved-configuration",
                "version": "1.0"}

    def to_bytes(self) -> bytes:
        return encode(self.document())


def resolve(command: str, options: Sequence[tuple[str, str | None]] = (), toml: bytes | None = None) -> Resolved:
    """Resolve the configuration for ``command``.

    ``options`` are the CLI occurrences in order: ``(name, text)``, with
    ``None`` as the text of a flag. ``toml`` is the bytes of the project's
    ``sv0.toml``, or ``None`` when there is none. Raises
    :class:`sv0cov.config.ConfigError`.
    """
    seen = _occurrences(command, options)
    file = (C.validate_bytes(toml) if toml is not None else None) or {}
    mapped, controls = _cli_values(command, seen)
    origin = {C.OPTION[name].key: name for name in seen if C.OPTION[name].key}

    def build(table: C.Table, tree: dict) -> dict:
        out: dict = {}
        for key in table.keys:
            dotted = f"{table.path}.{key.name}"
            if dotted in mapped:  # only keys of plain tables are mapped
                leaf = mapped[dotted]
            elif key.name in tree:
                leaf = Leaf(tree[key.name], FILE)
            else:
                leaf = Leaf(key.default, DEFAULT)
            out[key.name] = Leaf(_normal(key.kind, leaf.value), leaf.source)
        for name in table.tables:
            child = C.TABLE[f"{table.path}.{name}"]
            if child.array:
                rows = [build(child, row) for row in tree.get(name, [])]
                out[name] = sorted(rows, key=lambda r: r["name"].value.encode("utf-8"))
            elif name in OPTIONAL_TABLES and name not in tree and not any(k.startswith(f"{child.path}.") for k in mapped):
                out[name] = None
            else:
                out[name] = build(child, tree.get(name, {}))
        return out

    coverage = build(C.TABLE[ROOT], file)
    coverage["schema"] = Leaf(C.SCHEMA_VERSION, FILE if file else DEFAULT)
    _relations(coverage, origin)
    report = {name[2:].replace("-", "_"): Leaf(name in controls, CLI if name in controls else DEFAULT) for name in REPORT_CONTROLS}
    return Resolved(command, coverage, report, controls)
