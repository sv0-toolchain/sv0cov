# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Diagnostic registry and structured diagnostics (SPEC 20.5).

- :func:`load_registry` / :func:`validate_registry`: the closed
  ``sv0cov.diagnostic-registry`` 1.0 object, its self-digest, code ranges,
  and entry ordering.
- :class:`Diagnostic`: one closed ``sv0cov.diagnostic`` 1.0 record, built only
  from codes in the registry (message and severity come from the registry).
- :func:`order_events`: the deterministic phase / code / location order with
  duplicates removed.
- :func:`render_human` and :func:`render_json_line`: the two stderr forms.

Validation runs in the frozen order of SPEC 25.2.2: canonical bytes, then
the generated structural validator, then these semantic checks.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Iterable

from sv0cov._generated.validators import sv0cov_diagnostic_1_0 as _diag_schema
from sv0cov._generated.validators import sv0cov_diagnostic_registry_1_0 as _reg_schema
from sv0cov.formats.canonical_json import decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model.logical import LogicalValueError, check_logical_path, check_logical_string

RE_CODE = re.compile(r"COV[0-9]{4}")
RE_FACT = re.compile(r"[a-z][a-z0-9_]{0,63}")
RE_DIGEST = re.compile(r"[0-9a-f]{64}")
DOMAINS = (
    (1, 999, "invocation"),
    (1000, 1999, "planning"),
    (2000, 2999, "collection"),
    (3000, 3999, "merge"),
    (4000, 4999, "reporting"),
    (5000, 5999, "distribution"),
    (6000, 6999, "security"),
    (7000, 7999, "evidence"),
    (8000, 8999, "internal"),
    (9000, 9999, "reserved"),
)
PHASES = (
    "invocation",
    "configuration",
    "build",
    "execution",
    "collection",
    "merge",
    "report",
    "policy",
    "publication",
    "internal",
)
I64_MIN, I64_MAX = -(2**63), 2**63 - 1
REGISTRY_FILE = "diagnostics-v1.json"


class RegistryError(ValueError):
    """The registry itself is invalid (reported as COV8002 by callers)."""


class DiagnosticError(ValueError):
    """A diagnostic record is invalid or uses a code outside the registry."""


def domain_of(code: str) -> str:
    n = int(code[3:])
    for lo, hi, name in DOMAINS:
        if lo <= n <= hi:
            return name
    raise RegistryError(f"{code}: outside every registry range")


# ── registry ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Entry:
    code: str
    default_severity: str
    domain: str
    title: str


@dataclass(frozen=True)
class Registry:
    revision: int
    sha256: str
    entries: dict[str, Entry]

    def entry(self, code: str) -> Entry:
        try:
            return self.entries[code]
        except KeyError:
            raise DiagnosticError(f"{code} is not in registry revision {self.revision}") from None


def registry_digest(obj: dict) -> str:
    body = {k: v for k, v in obj.items() if k != "registry_sha256"}
    return hashlib.sha256(encode(body)).hexdigest()


def validate_registry(data: bytes) -> Registry:
    """Canonical bytes → structural schema → semantic rules."""
    try:
        obj = decode_canonical(data)
        _reg_schema.validate(obj)
    except (ValueError, StructuralError) as exc:
        raise RegistryError(str(exc)) from exc
    if not RE_DIGEST.fullmatch(obj["registry_sha256"]):
        raise RegistryError("registry_sha256 is not lowercase hexadecimal")
    if registry_digest(obj) != obj["registry_sha256"]:
        raise RegistryError("registry_sha256 does not match the registry contents")
    entries: dict[str, Entry] = {}
    previous = ""
    for raw in obj["entries"]:
        code = raw["code"]
        if not RE_CODE.fullmatch(code) or code == "COV0000":
            raise RegistryError(f"invalid code {code!r}")
        if code <= previous:
            raise RegistryError(f"{code}: entries must be strictly ordered by code")
        previous = code
        if domain_of(code) == "reserved":
            raise RegistryError(f"{code}: the COV9000-COV9999 range is reserved")
        if raw["domain"] != domain_of(code):
            raise RegistryError(f"{code}: domain {raw['domain']!r} does not match its range")
        try:
            check_logical_string(raw["title"], "title", min_bytes=1, max_bytes=128)
        except LogicalValueError as exc:
            raise RegistryError(f"{code}: {exc}") from exc
        entries[code] = Entry(code, raw["default_severity"], raw["domain"], raw["title"])
    return Registry(obj["revision"], obj["registry_sha256"], entries)


def check_append_only(old: Registry, new: Registry) -> None:
    """``new`` is a valid successor of ``old`` (SPEC 20.5.1).

    Every published entry stays byte-identical; a changed registry has
    revision exactly ``old.revision + 1``; an unchanged one keeps its identity.
    """
    for code, entry in old.entries.items():
        if new.entries.get(code) != entry:
            raise RegistryError(f"{code}: a published entry was removed or changed")
    if new.entries == old.entries:
        if (new.revision, new.sha256) != (old.revision, old.sha256):
            raise RegistryError("unchanged entries must keep the same revision and digest")
    elif new.revision != old.revision + 1:
        raise RegistryError(f"revision must be {old.revision + 1}, got {new.revision}")


def registry_bytes() -> bytes:
    """The installed registry: package resource in a wheel, else the checkout."""
    packaged = resources.files("sv0cov").joinpath("_resources", "registries", REGISTRY_FILE)
    if packaged.is_file():
        return packaged.read_bytes()
    return (Path(__file__).resolve().parents[2] / "registries" / REGISTRY_FILE).read_bytes()


_REGISTRY: Registry | None = None


def load_registry() -> Registry:
    global _REGISTRY
    if _REGISTRY is None:
        _REGISTRY = validate_registry(registry_bytes())
    return _REGISTRY


# ── records ─────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Span:
    start_byte: int
    end_byte: int
    start_line: int
    start_column: int
    end_line: int
    end_column: int

    def as_json(self) -> dict:
        return {
            "end_byte": self.end_byte,
            "end_column": self.end_column,
            "end_line": self.end_line,
            "start_byte": self.start_byte,
            "start_column": self.start_column,
            "start_line": self.start_line,
        }


@dataclass(frozen=True)
class Location:
    path: str
    span: Span


@dataclass(frozen=True)
class Related:
    label: str
    path: str
    span: Span


Fact = tuple[str, None | bool | int | str]


@dataclass(frozen=True)
class Diagnostic:
    code: str
    phase: str
    facts: tuple[Fact, ...] = ()
    primary_location: Location | None = None
    related_locations: tuple[Related, ...] = ()

    def to_json(self, registry: Registry | None = None) -> dict:
        reg = registry or load_registry()
        entry = reg.entry(self.code)
        obj = {
            "code": self.code,
            "facts": [{"name": n, "value": v} for n, v in sorted(self.facts, key=lambda f: f[0].encode())],
            "message": entry.title,
            "phase": self.phase,
            "primary_location": None
            if self.primary_location is None
            else {"path": self.primary_location.path, "span": self.primary_location.span.as_json()},
            "registry_revision": reg.revision,
            "registry_sha256": reg.sha256,
            "related_locations": [
                {"label": r.label, "path": r.path, "span": r.span.as_json()}
                for r in sorted(self.related_locations, key=_related_key)
            ],
            "schema": "sv0cov.diagnostic",
            "severity": entry.default_severity,
            "version": "1.0",
        }
        validate_record(obj, reg)
        return obj


def _related_key(r: Related) -> tuple:
    s = r.span
    return (r.path.encode(), s.start_byte, s.end_byte, r.label.encode())


def _check_span(span: dict, where: str) -> None:
    if span["end_byte"] < span["start_byte"]:
        raise DiagnosticError(f"{where}: span ends before it starts")
    if (span["end_line"], span["end_column"]) < (span["start_line"], span["start_column"]):
        raise DiagnosticError(f"{where}: span end line/column precedes its start")


def validate_record(obj: object, registry: Registry | None = None) -> None:
    """Structural schema, then semantic checks, for one diagnostic record."""
    reg = registry or load_registry()
    try:
        _diag_schema.validate(obj)
    except StructuralError as exc:
        raise DiagnosticError(str(exc)) from exc
    assert isinstance(obj, dict)
    if obj["registry_revision"] != reg.revision or obj["registry_sha256"] != reg.sha256:
        raise DiagnosticError("record names a different registry")
    entry = reg.entry(obj["code"])
    if obj["severity"] != entry.default_severity:
        raise DiagnosticError(f"{entry.code}: severity must be {entry.default_severity!r}")
    if obj["message"] != entry.title:
        raise DiagnosticError(f"{entry.code}: message must equal the registry title")
    names = [f["name"] for f in obj["facts"]]
    for name in names:
        if not RE_FACT.fullmatch(name):
            raise DiagnosticError(f"invalid fact name {name!r}")
    if names != sorted(set(names), key=str.encode) or len(set(names)) != len(names):
        raise DiagnosticError("fact names must be unique and bytewise sorted")
    try:
        for f in obj["facts"]:
            v = f["value"]
            if isinstance(v, str):
                check_logical_string(v, f"fact {f['name']}", max_bytes=4096)
            elif isinstance(v, int) and not isinstance(v, bool) and not I64_MIN <= v <= I64_MAX:
                raise DiagnosticError(f"fact {f['name']}: integer out of range")
        loc = obj["primary_location"]
        if loc is not None:
            check_logical_path(loc["path"], "primary_location.path")
            _check_span(loc["span"], "primary_location")
        keys = []
        for r in obj["related_locations"]:
            check_logical_path(r["path"], "related_locations.path")
            check_logical_string(r["label"], "related_locations.label", min_bytes=1, max_bytes=256)
            _check_span(r["span"], "related_locations")
            s = r["span"]
            keys.append((r["path"].encode(), s["start_byte"], s["end_byte"], r["label"].encode()))
    except LogicalValueError as exc:
        raise DiagnosticError(str(exc)) from exc
    if keys != sorted(set(keys)) or len(set(keys)) != len(keys):
        raise DiagnosticError("related locations must be unique and ordered by path, span, label")


# ── ordering and rendering ──────────────────────────────────────────────────


def _event_key(obj: dict) -> tuple:
    loc = obj["primary_location"]
    loc_key = (0,) if loc is None else (1, loc["path"].encode(), loc["span"]["start_byte"], loc["span"]["end_byte"])
    return (
        PHASES.index(obj["phase"]),
        obj["code"],
        loc_key,
        encode(obj["facts"]),
        encode(obj["related_locations"]),
        obj["message"].encode(),
    )


def order_events(events: Iterable[Diagnostic], registry: Registry | None = None) -> list[dict]:
    """Records in phase order, then code, location, facts, related, message; deduplicated."""
    unique = {encode(e.to_json(registry)): e.to_json(registry) for e in events}
    return sorted(unique.values(), key=_event_key)


def render_json_line(obj: dict) -> bytes:
    """One canonical record with its own LF (JSON Lines on stderr)."""
    return encode(obj)


def _escape(text: str) -> str:
    """Make untrusted text inert on a terminal: escape C0 controls, DEL, and C1."""
    return "".join(
        f"\\x{ord(c):02x}" if (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F) else c for c in text
    )


def _render_value(v: object) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    return _escape(str(v))


def render_human(obj: dict) -> str:
    """Human stderr form, as in SPEC Appendix B. Not an automation interface."""
    lines = [f"{obj['code']} {obj['severity']}: {obj['message']}"]
    loc = obj["primary_location"]
    if loc is not None:
        s = loc["span"]
        lines.append(f"  at: {_escape(loc['path'])}:{s['start_line']}:{s['start_column']}")
    for r in obj["related_locations"]:
        s = r["span"]
        lines.append(f"  {_escape(r['label'])}: {_escape(r['path'])}:{s['start_line']}:{s['start_column']}")
    for f in obj["facts"]:
        lines.append(f"  {f['name']}: {_render_value(f['value'])}")
    return "\n".join(lines) + "\n"
