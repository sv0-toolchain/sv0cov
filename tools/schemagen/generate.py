# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Generate structural validators from canonical schemas (CV-011, SPEC 25.2.2).

Each ``schemas/<name>-<version>.schema.json`` becomes one checked-in module
in ``src/sv0cov/_generated/validators/``. Generated code:

- uses only the standard library and ``sv0cov.formats.structural``;
- never reads, evaluates, or interprets schema text at run time;
- checks keywords in one frozen order and raises ``StructuralError`` at the
  first failure (JSON pointer + keyword), so diagnostics are deterministic;
- carries a non-time-varying header naming the schema, its version, its
  SHA-256, and the generator format version.

Output depends only on the schema bytes and this generator. ``--check``
regenerates into a temporary directory and fails on any byte difference,
missing module, or orphaned module.

Per-node keyword order: $ref, type, const, enum, minimum/maximum,
minLength/maxLength, minItems/maxItems, prefixItems, items, required,
additionalProperties, properties, anyOf, oneOf, not. Checks that no
instance can trigger (a zero minLength or minItems, or a tuple's items: false
already enforced by maxItems) are not emitted.
"""

from __future__ import annotations

import argparse
import filecmp
import hashlib
import re
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import preflight  # noqa: E402

from sv0cov.formats.canonical_json import decode_canonical  # noqa: E402  (path set by preflight)

GENERATOR_FORMAT = "2"
ROOT = Path(__file__).resolve().parents[2]
DEFAULT_SCHEMAS = ROOT / "schemas"
DEFAULT_OUT = ROOT / "src" / "sv0cov" / "_generated" / "validators"
HEADER = "# SPDX-License-Identifier: MIT OR Apache-2.0\n# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla\n"


def module_name(schema_file: str) -> str:
    stem = schema_file.removesuffix(".schema.json")
    return re.sub(r"[^A-Za-z0-9]", "_", stem)


class _ModuleWriter:
    """Emits one function per schema node, numbered in traversal order."""

    def __init__(self, file: str, doc: dict, siblings: dict[str, str]) -> None:
        self.file = file
        self.doc = doc
        self.siblings = siblings  # schema file -> module name
        self.functions: list[str] = []
        self.count = 0
        self.imports: set[str] = set()

    def def_function(self, file: str, name: str) -> str:
        fn = f"_def_{re.sub(r'[^A-Za-z0-9]', '_', name)}"
        if file == self.file:
            return fn
        mod = self.siblings[file]
        self.imports.add(mod)
        return f"_m_{mod}.{fn}"

    def node(self, s: dict) -> str:
        """Emit a function for schema node ``s``; return its name."""
        name = f"_s{self.count}"
        self.count += 1
        body: list[str] = []
        emit = body.append

        if "$ref" in s:
            m = preflight.RE_REF.fullmatch(s["$ref"])
            target = m.group("file") or self.file
            emit(f"    {self.def_function(target, m.group('name'))}(v, p)")
        if "type" in s:
            t = s["type"]
            emit(f"    if not is_type(v, {t!r}):")
            emit(f"        fail(p, 'type', {('expected ' + t)!r})")
        if "const" in s:
            emit(f"    if not json_equal(v, {s['const']!r}):")
            emit("        fail(p, 'const', 'value differs from the constant')")
        if "enum" in s:
            emit(f"    if not any(json_equal(v, e) for e in {tuple(s['enum'])!r}):")
            emit("        fail(p, 'enum', 'value is not in the enumeration')")
        if "minimum" in s or "maximum" in s:
            emit("    if is_number(v):")
            if "minimum" in s:
                emit(f"        if v < {s['minimum']!r}:")
                emit(f"            fail(p, 'minimum', {('below ' + str(s['minimum']))!r})")
            if "maximum" in s:
                emit(f"        if v > {s['maximum']!r}:")
                emit(f"            fail(p, 'maximum', {('above ' + str(s['maximum']))!r})")
        # A zero lower bound can never fail, so no check is emitted for it
        # (the mutation gate rejects checks that no input can trigger).
        min_length = s.get("minLength", 0)
        if min_length or "maxLength" in s:
            emit("    if isinstance(v, str):")
            if min_length:
                emit(f"        if len(v) < {s['minLength']!r}:")
                emit("            fail(p, 'minLength', 'string too short')")
            if "maxLength" in s:
                emit(f"        if len(v) > {s['maxLength']!r}:")
                emit("            fail(p, 'maxLength', 'string too long')")
        min_items = s.get("minItems", 0)
        if min_items or any(k in s for k in ("maxItems", "prefixItems", "items")):
            emit("    if isinstance(v, list):")
            if min_items:
                emit(f"        if len(v) < {s['minItems']!r}:")
                emit("            fail(p, 'minItems', 'array too short')")
            if "maxItems" in s:
                emit(f"        if len(v) > {s['maxItems']!r}:")
                emit("            fail(p, 'maxItems', 'array too long')")
            start = 0
            if "prefixItems" in s:
                for i, sub in enumerate(s["prefixItems"]):
                    fn = self.node(sub)
                    emit(f"        if len(v) > {i}:")
                    emit(f"            {fn}(v[{i}], child(p, {i}))")
                start = len(s["prefixItems"])
            # In a tuple, maxItems == len(prefixItems) is checked first, so a
            # separate items: false check would be unreachable; emit it only
            # when maxItems does not already enforce it.
            if s.get("items") is False and s.get("maxItems", start + 1) > start:
                emit(f"        if len(v) > {start}:")
                emit(f"            fail(child(p, {start}), 'items', 'no items are allowed here')")
            elif isinstance(s.get("items"), dict):
                fn = self.node(s["items"])
                emit(f"        for i in range({start}, len(v)):")
                emit(f"            {fn}(v[i], child(p, i))")
        if "properties" in s:
            props = s["properties"]
            emit("    if isinstance(v, dict):")
            for key in s.get("required", []):
                emit(f"        if {key!r} not in v:")
                emit(f"            fail(p, 'required', {('missing property ' + key)!r})")
            if s.get("additionalProperties") is False:
                allowed = tuple(sorted(props, key=_utf8_key))
                emit("        for k in sorted(v, key=_utf8):")
                emit(f"            if k not in {allowed!r}:")
                emit("                fail(child(p, k), 'additionalProperties', 'unknown property')")
            for key, sub in props.items():
                fn = self.node(sub)
                emit(f"        if {key!r} in v:")
                emit(f"            {fn}(v[{key!r}], child(p, {key!r}))")
        for key in ("anyOf", "oneOf"):
            if key in s:
                fns = [self.node(sub) for sub in s[key]]
                emit(f"    passed = sum(_ok(f, v, p) for f in ({', '.join(fns)},))")
                if key == "anyOf":
                    emit("    if passed == 0:")
                    emit("        fail(p, 'anyOf', 'no alternative matches')")
                else:
                    emit("    if passed != 1:")
                    emit("        fail(p, 'oneOf', f'{passed} alternatives match; exactly one is required')")
        if "not" in s:
            fn = self.node(s["not"])
            emit(f"    if _ok({fn}, v, p):")
            emit("        fail(p, 'not', 'value matches a forbidden schema')")

        if not body:
            body.append("    del v, p")
        self.functions.append(f"def {name}(v: object, p: str) -> None:\n" + "\n".join(body) + "\n")
        return name

    def render(self, schema_name: str, version: str, digest: str) -> str:
        defs = self.doc.get("$defs", {})
        aliases = []
        for def_name in defs:  # canonical JSON keeps these in byte order
            fn = self.node(defs[def_name])
            aliases.append(f"{self.def_function(self.file, def_name)} = {fn}\n")
        root_fn = self.node({k: v for k, v in self.doc.items() if k not in ("$defs", "$schema")})
        imports = "".join(
            f"from . import {m} as _m_{m}\n" for m in sorted(self.imports)
        )
        parts = [
            HEADER,
            "# Generated by tools/schemagen/generate.py. DO NOT EDIT: change the schema\n",
            "# or the generator and regenerate.\n",
            f"# schema-file: {self.file}\n",
            f"# schema-sha256: {digest}\n",
            f"# generator-format: {GENERATOR_FORMAT}\n",
            f'"""Structural validator for {schema_name} {version}."""\n\n',
            "from __future__ import annotations\n\n",
            "from sv0cov.formats.structural import (\n",
            "    StructuralError,\n    child,\n    fail,\n    is_number,\n    is_type,\n    json_equal,\n)\n",
            imports,
            "\n",
            f"SCHEMA_NAME = {schema_name!r}\n",
            f"SCHEMA_VERSION = {version!r}\n",
            f"SCHEMA_SHA256 = {digest!r}\n",
            f"GENERATOR_FORMAT = {GENERATOR_FORMAT!r}\n\n\n",
            "def _utf8(k: str) -> bytes:\n    return k.encode('utf-8', 'surrogatepass')\n\n\n",
            "def _ok(fn, v: object, p: str) -> bool:\n",
            "    try:\n        fn(v, p)\n    except StructuralError:\n        return False\n    return True\n\n\n",
            "\n\n".join(self.functions),
            "\n\n",
            "".join(aliases),
            "\n\n",
            "def validate(value: object) -> None:\n",
            '    """Raise ``StructuralError`` at the first structural failure."""\n',
            f"    {root_fn}(value, '')\n",
        ]
        return "".join(parts)


def _utf8_key(k: str) -> bytes:
    return k.encode("utf-8")


def generate(schema_dir: Path) -> dict[str, str]:
    """Return ``{output filename: source}`` for every schema in ``schema_dir``."""
    files = preflight.load_bundle(schema_dir)
    findings = preflight.check_bundle(files, metaschema=False)
    if findings:
        raise SystemExit("schema preflight failed:\n" + "\n".join(f"  {f}" for f in findings))
    siblings = {name: module_name(name) for name in files}
    out: dict[str, str] = {}
    inventory = []
    for name in sorted(files):
        m = preflight.RE_SCHEMA_FILE.fullmatch(name)
        digest = hashlib.sha256(files[name]).hexdigest()
        writer = _ModuleWriter(name, decode_canonical(files[name]), siblings)
        out[f"{siblings[name]}.py"] = writer.render(m.group("name"), m.group("version"), digest)
        inventory.append((siblings[name], name, digest))
    init = [
        HEADER,
        "# Generated by tools/schemagen/generate.py. DO NOT EDIT.\n",
        '"""Generated structural validators: module -> (schema file, schema SHA-256)."""\n\n',
        f"GENERATOR_FORMAT = {GENERATOR_FORMAT!r}\n\n",
        "SCHEMAS = {\n",
        *(f"    {mod!r}: ({name!r}, {digest!r}),\n" for mod, name, digest in inventory),
        "}\n",
    ]
    out["__init__.py"] = "".join(init)
    return out


def write(outputs: dict[str, str], out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    for stale in out_dir.glob("*.py"):
        if stale.name not in outputs:
            stale.unlink()
    for name, text in outputs.items():
        (out_dir / name).write_text(text, encoding="utf-8", newline="\n")


def check(outputs: dict[str, str], out_dir: Path) -> list[str]:
    problems = []
    with tempfile.TemporaryDirectory() as tmp:
        write(outputs, Path(tmp))
        cmp = filecmp.dircmp(tmp, out_dir, ignore=["__pycache__", ".gitignore"])
        problems += [f"missing generated module {n}" for n in cmp.left_only]
        problems += [f"orphaned module {n}" for n in cmp.right_only]
        _, mismatch, errors = filecmp.cmpfiles(tmp, out_dir, cmp.common_files, shallow=False)
        problems += [f"stale generated module {n}" for n in mismatch + errors]
    return problems


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="generate sv0cov structural validators")
    ap.add_argument("--schemas", type=Path, default=DEFAULT_SCHEMAS)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    ap.add_argument("--check", action="store_true", help="fail if checked-in output differs")
    args = ap.parse_args(argv)
    outputs = generate(args.schemas)
    if args.check:
        problems = check(outputs, args.out)
        for p in problems:
            print(f"generate --check: {p}", file=sys.stderr)
        if problems:
            return 1
        print(f"generate --check: {len(outputs) - 1} validator module(s) current")
        return 0
    write(outputs, args.out)
    print(f"generate: wrote {len(outputs)} file(s) to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
