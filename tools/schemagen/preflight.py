# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Schema authoring preflight (CV-010, SPEC 25.2.3).

Every canonical sv0cov schema must pass this check before validators are
generated from it. The check is stricter than JSON Schema itself: a keyword
outside the closed R1 profile is an error rather than a silently ignored
annotation.

Checks, in order:

1. canonical JSON bytes (SPEC 16.2) within resource limits;
2. exact root ``$schema`` (Draft 2020-12), present only at the root;
3. recursive keyword allowlist and per-keyword shape and bounds;
4. local ``$ref`` forms, reference resolution within the bundle, and an
   acyclic definition graph;
5. optionally, offline Draft 2020-12 meta-schema validation through the
   development-only oracle (``jsonschema``), when it is installed.

Standard library plus sv0cov's own canonical JSON codec. Development tool:
never imported by production code.
"""

from __future__ import annotations

import hashlib
import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical  # noqa: E402

DIALECT = "https://json-schema.org/draft/2020-12/schema"
TYPES = ("null", "boolean", "object", "array", "number", "integer", "string")
ANNOTATIONS = {"$comment": 1024, "title": 4096, "description": 4096}
ALLOWED = {
    "$schema",
    "$defs",
    "$ref",
    "type",
    "const",
    "enum",
    "properties",
    "required",
    "additionalProperties",
    "prefixItems",
    "items",
    "minItems",
    "maxItems",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "anyOf",
    "oneOf",
    "not",
    *ANNOTATIONS,
}
OBJECT_KEYWORDS = ("properties", "required", "additionalProperties")
SIZE_MAX = 16777216
NUM_MIN = -(2**63)
NUM_MAX = 2**64 - 1

RE_DEF_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}")
RE_FILE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.schema\.json")
RE_REF = re.compile(r"(?:(?P<file>[^#]*))?#/\$defs/(?P<name>[^/]*)")
RE_SCHEMA_FILE = re.compile(r"(?P<name>[A-Za-z0-9][A-Za-z0-9._-]*)-(?P<version>[0-9]+\.[0-9]+)\.schema\.json")


@dataclass(frozen=True)
class Finding:
    file: str
    pointer: str
    message: str

    def __str__(self) -> str:
        return f"{self.file}#{self.pointer or '/'}: {self.message}"


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _is_int(v: object) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_scalar(v: object) -> bool:
    return v is None or isinstance(v, (bool, int, str))


def _json_key(v: object) -> tuple:
    """Instance-equality key for canonical scalars (true != 1)."""
    return (type(v).__name__, v)


class _Checker:
    def __init__(self, file: str) -> None:
        self.file = file
        self.findings: list[Finding] = []
        self.refs: list[tuple[str, str, str]] = []  # (pointer, target file, def name)
        self.def_refs: dict[str, set[tuple[str, str]]] = {}  # def -> referenced (file, def)

    def err(self, pointer: str, message: str) -> None:
        self.findings.append(Finding(self.file, pointer, message))

    def check_root(self, doc: object) -> None:
        if not isinstance(doc, dict):
            self.err("", "schema root must be an object")
            return
        if doc.get("$schema") != DIALECT:
            self.err("/$schema", f"root $schema must be exactly {DIALECT!r}")
        defs = doc.get("$defs", {})
        if not isinstance(defs, dict):
            self.err("/$defs", "$defs must be an object")
            defs = {}
        for name, sub in defs.items():
            if not RE_DEF_NAME.fullmatch(name):
                self.err(f"/$defs/{_escape(name)}", "invalid definition name")
            self.check_schema(sub, f"/$defs/{_escape(name)}", owner=name)
        self.check_schema(doc, "", owner=None, root=True)

    def check_schema(self, s: object, ptr: str, owner: str | None, root: bool = False) -> None:
        if not isinstance(s, dict):
            self.err(ptr, "schema must be an object")
            return
        for key in s:
            if key not in ALLOWED:
                self.err(f"{ptr}/{_escape(key)}", f"keyword {key!r} is outside the R1 profile")
        if "$schema" in s and not root:
            self.err(f"{ptr}/$schema", "$schema is allowed only at the root")
        if "$defs" in s and not root:
            self.err(f"{ptr}/$defs", "$defs is allowed only at the root")
        for key, limit in ANNOTATIONS.items():
            if key in s and (not isinstance(s[key], str) or len(s[key].encode("utf-8")) > limit):
                self.err(f"{ptr}/{_escape(key)}", f"{key} must be a string of at most {limit} bytes")

        if "$ref" in s:
            extra = set(s) - {"$ref", *ANNOTATIONS}
            if extra:
                self.err(ptr, f"$ref object has non-annotation siblings {sorted(extra)}")
            self.check_ref(s["$ref"], f"{ptr}/$ref", owner)

        if "type" in s and s["type"] not in TYPES:
            self.err(f"{ptr}/type", "type must be one exact type string (use anyOf for unions)")
        if "const" in s and not _is_scalar(s["const"]):
            self.err(f"{ptr}/const", "const must be a scalar")
        if "enum" in s:
            e = s["enum"]
            if not isinstance(e, list) or not e or not all(_is_scalar(v) for v in e):
                self.err(f"{ptr}/enum", "enum must be a nonempty array of scalars")
            elif len({_json_key(v) for v in e}) != len(e):
                self.err(f"{ptr}/enum", "enum values must be distinct")

        self.check_object(s, ptr, owner)
        self.check_array(s, ptr, owner)
        self.check_bounds(s, ptr, "minLength", "maxLength", 0, SIZE_MAX)
        self.check_bounds(s, ptr, "minItems", "maxItems", 0, SIZE_MAX)
        self.check_bounds(s, ptr, "minimum", "maximum", NUM_MIN, NUM_MAX)
        if s.get("type") in ("number", "integer") and not ("minimum" in s and "maximum" in s):
            self.err(ptr, f"{s['type']} schema must declare both minimum and maximum")

        for key in ("anyOf", "oneOf"):
            if key in s:
                subs = s[key]
                if not isinstance(subs, list) or not 2 <= len(subs) <= 16:
                    self.err(f"{ptr}/{key}", f"{key} must list 2..16 schemas")
                    continue
                for i, sub in enumerate(subs):
                    self.check_schema(sub, f"{ptr}/{key}/{i}", owner)
        if "not" in s:
            self.check_schema(s["not"], f"{ptr}/not", owner)

    def check_object(self, s: dict, ptr: str, owner: str | None) -> None:
        present = [k for k in OBJECT_KEYWORDS if k in s]
        if not present and s.get("type") != "object":
            return
        if len(present) != 3:
            self.err(ptr, "object schemas must declare properties, required, and additionalProperties")
            return
        if s.get("type") != "object":
            self.err(ptr, "object keywords require type 'object'")
        props = s["properties"]
        if not isinstance(props, dict):
            self.err(f"{ptr}/properties", "properties must be an object")
            return
        req = s["required"]
        want = sorted(props, key=lambda k: k.encode("utf-8"))
        if req != want:
            self.err(f"{ptr}/required", "required must list every property exactly once in UTF-8 byte order")
        if s["additionalProperties"] is not False:
            self.err(f"{ptr}/additionalProperties", "additionalProperties must be false")
        for name, sub in props.items():
            self.check_schema(sub, f"{ptr}/properties/{_escape(name)}", owner)

    def check_array(self, s: dict, ptr: str, owner: str | None) -> None:
        if "prefixItems" in s:
            prefix = s["prefixItems"]
            if not isinstance(prefix, list) or not prefix:
                self.err(f"{ptr}/prefixItems", "prefixItems must be a nonempty array")
                return
            if s.get("items") is not False:
                self.err(f"{ptr}/items", "a tuple must set items to false")
            if s.get("minItems") != len(prefix) or s.get("maxItems") != len(prefix):
                self.err(ptr, "a tuple must set minItems and maxItems to its length")
            for i, sub in enumerate(prefix):
                self.check_schema(sub, f"{ptr}/prefixItems/{i}", owner)
        elif "items" in s:
            if s["items"] is False:
                self.err(f"{ptr}/items", "items: false is allowed only in a tuple")
            else:
                self.check_schema(s["items"], f"{ptr}/items", owner)

    def check_bounds(self, s: dict, ptr: str, lo_key: str, hi_key: str, floor: int, ceil: int) -> None:
        lo, hi = s.get(lo_key), s.get(hi_key)
        for key, v in ((lo_key, lo), (hi_key, hi)):
            if key in s and (not _is_int(v) or not floor <= v <= ceil):
                self.err(f"{ptr}/{key}", f"{key} must be an integer in {floor}..{ceil}")
        if _is_int(lo) and _is_int(hi) and lo > hi:
            self.err(ptr, f"{lo_key} exceeds {hi_key}")

    def check_ref(self, ref: object, ptr: str, owner: str | None) -> None:
        m = RE_REF.fullmatch(ref) if isinstance(ref, str) else None
        if not m or "~" in ref or "%" in ref:
            self.err(ptr, f"unsupported $ref form {ref!r}")
            return
        target = m.group("file") or self.file
        if m.group("file") and not RE_FILE.fullmatch(m.group("file")):
            self.err(ptr, f"invalid sibling schema file name {m.group('file')!r}")
            return
        if not RE_DEF_NAME.fullmatch(m.group("name")):
            self.err(ptr, f"invalid definition name in {ref!r}")
            return
        self.refs.append((ptr, target, m.group("name")))
        if owner is not None:
            self.def_refs.setdefault(owner, set()).add((target, m.group("name")))


def check_bundle(files: dict[str, bytes], *, metaschema: bool = True) -> list[Finding]:
    """Preflight a bundle of schema files given as ``{basename: bytes}``."""
    findings: list[Finding] = []
    docs: dict[str, dict] = {}
    checkers: dict[str, _Checker] = {}
    for name in sorted(files):
        if not RE_FILE.fullmatch(name) or not RE_SCHEMA_FILE.fullmatch(name):
            findings.append(Finding(name, "", "schema file must be named <name>-<major>.<minor>.schema.json"))
        try:
            doc = decode_canonical(files[name])
        except CanonicalJsonError as exc:
            findings.append(Finding(name, "", f"not canonical JSON ({exc.reason})"))
            continue
        c = _Checker(name)
        c.check_root(doc)
        findings += c.findings
        if isinstance(doc, dict):
            docs[name] = doc
            checkers[name] = c

    # Reference resolution and cycles over (file, def) nodes.
    edges: dict[tuple[str, str], set[tuple[str, str]]] = {}
    for name, c in checkers.items():
        for ptr, target, def_name in c.refs:
            defs = docs.get(target, {}).get("$defs", {})
            if target not in files:
                findings.append(Finding(name, ptr, f"reference to {target!r} outside the schema bundle"))
            elif def_name not in defs:
                findings.append(Finding(name, ptr, f"unresolved reference to {target}#/$defs/{def_name}"))
        for owner, targets in c.def_refs.items():
            edges[(name, owner)] = targets
    findings += _cycles(edges)

    if metaschema and not findings:
        findings += _metaschema(docs)
    return findings


def _cycles(edges: dict[tuple[str, str], set[tuple[str, str]]]) -> list[Finding]:
    state: dict[tuple[str, str], int] = {}  # 1 visiting, 2 done
    found: list[Finding] = []

    def visit(node: tuple[str, str], stack: list[tuple[str, str]]) -> None:
        state[node] = 1
        for nxt in sorted(edges.get(node, ())):
            if state.get(nxt) == 1:
                cycle = " -> ".join(f"{f}#{d}" for f, d in stack[stack.index(nxt):] + [nxt])
                found.append(Finding(node[0], f"/$defs/{node[1]}", f"reference cycle {cycle}"))
            elif nxt not in state:
                visit(nxt, stack + [nxt])
        state[node] = 2

    for node in sorted(edges):
        if node not in state:
            visit(node, [node])
    return found


def _metaschema(docs: dict[str, dict]) -> list[Finding]:
    try:
        from jsonschema import Draft202012Validator
        from jsonschema.exceptions import SchemaError
    except ImportError:
        return []
    findings = []
    for name, doc in sorted(docs.items()):
        try:
            Draft202012Validator.check_schema(doc)
        except SchemaError as exc:
            findings.append(Finding(name, "", f"fails the Draft 2020-12 meta-schema: {exc.message}"))
    return findings


def metaschema_available() -> bool:
    try:
        import jsonschema  # noqa: F401
    except ImportError:
        return False
    return True


def load_bundle(directory: Path) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in sorted(directory.glob("*.schema.json"))}


def inventory(files: dict[str, bytes]) -> list[tuple[str, str]]:
    """Sorted ``(basename, sha256)`` inventory of a bundle."""
    return [(name, hashlib.sha256(files[name]).hexdigest()) for name in sorted(files)]


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="sv0cov schema authoring preflight")
    ap.add_argument("directory", type=Path, nargs="?", default=Path(__file__).resolve().parents[2] / "schemas")
    ap.add_argument("--require-metaschema", action="store_true", help="fail if the oracle is not installed")
    args = ap.parse_args(argv)
    if args.require_metaschema and not metaschema_available():
        print("preflight: jsonschema oracle not installed (sync the 'oracle' group)", file=sys.stderr)
        return 1
    files = load_bundle(args.directory)
    findings = check_bundle(files)
    for f in findings:
        print(f"preflight: {f}", file=sys.stderr)
    if findings:
        return 1
    print(f"preflight: {len(files)} schema(s) OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
