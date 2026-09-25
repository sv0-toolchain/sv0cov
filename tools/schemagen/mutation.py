# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Mutation gate for generated structural validators (CV-013, SPEC 25.2.2).

Every ``fail(...)`` call in a generated module is one check. For each check,
a mutant module is built with that call deleted (replaced by ``pass``). The
gate requires every mutant to change the outcome of at least one fixture,
where an outcome is "accepted" or the first failure's (JSON pointer,
keyword). A surviving mutant means some check is not exercised by any
fixture, or is redundant.

Fixtures are synthesized deterministically from the schema: a minimal base
instance, plus one targeted violation per constraint (wrong type, bound
minus or plus one, off-by-one lengths and item counts, missing and unknown
properties, constants and enum misses), applied at every location reachable
from the base instance, including inside every combinator branch.
Callers may add checked-in fixtures on top.
"""

from __future__ import annotations

import copy
import importlib
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Iterator

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from sv0cov.formats.structural import StructuralError  # noqa: E402

WRONG_TYPES: tuple = (None, True, 0, 1.5, "x", [], {})
RE_REF = re.compile(r"(?P<file>[^#]*)#/\$defs/(?P<name>.+)")


class Synth:
    """Fixture synthesis over one schema bundle ``{file: decoded schema}``."""

    def __init__(self, bundle: dict[str, dict]) -> None:
        self.bundle = bundle

    def resolve(self, node: dict, file: str) -> tuple[dict, str]:
        seen = 0
        while "$ref" in node:
            m = RE_REF.fullmatch(node["$ref"])
            file = m.group("file") or file
            node = self.bundle[file]["$defs"][m.group("name")]
            seen += 1
            if seen > 64:
                raise ValueError("reference chain too deep")
        return node, file

    def minimal(self, node: dict, file: str, depth: int = 0) -> object:
        node, file = self.resolve(node, file)
        if depth > 32:
            return None
        if "const" in node:
            return copy.deepcopy(node["const"])
        if "enum" in node:
            return copy.deepcopy(node["enum"][0])
        for key in ("anyOf", "oneOf"):
            if key in node:
                return self.minimal(node[key][0], file, depth + 1)
        t = node.get("type")
        if t in ("integer", "number"):
            lo, hi = node.get("minimum", 0), node.get("maximum", 0)
            return 0 if lo <= 0 <= hi else lo
        if t == "string":
            n = node.get("minLength", 0) or min(1, node.get("maxLength", 1))
            return "a" * n
        if t == "boolean":
            return False
        if t == "array":
            if "prefixItems" in node:
                return [self.minimal(sub, file, depth + 1) for sub in node["prefixItems"]]
            if isinstance(node.get("items"), dict):
                return [self.minimal(node["items"], file, depth + 1) for _ in range(node.get("minItems", 1))]
            return []
        if t == "object":
            return {k: self.minimal(node["properties"][k], file, depth + 1) for k in node.get("required", [])}
        return None

    def variants(self, node: dict, file: str, value: object, depth: int = 0) -> Iterator[object]:
        """Replacement values for ``value`` at this node, each violating one rule."""
        node, file = self.resolve(node, file)
        if depth > 32:
            return
        yield from WRONG_TYPES
        if "const" in node or "enum" in node:
            yield "\x00not-a-member"
        for key in ("anyOf", "oneOf"):
            for sub in node.get(key, []):
                base = self.minimal(sub, file, depth + 1)
                yield base
                yield from self.variants(sub, file, base, depth + 1)
        if "not" in node:
            base = self.minimal(node["not"], file, depth + 1)
            yield base
            yield from self.variants(node["not"], file, base, depth + 1)
        t = node.get("type")
        if t in ("integer", "number"):
            if "minimum" in node:
                yield node["minimum"] - 1
                yield node["minimum"]
            if "maximum" in node:
                yield node["maximum"] + 1
                yield node["maximum"]
            if t == "integer":
                yield 0.5
        if t == "string":
            if node.get("minLength", 0) > 0:
                yield "a" * (node["minLength"] - 1)
            if "maxLength" in node:
                yield "a" * (node["maxLength"] + 1)
                yield "é" * node["maxLength"]
        if t == "array" and isinstance(value, list):
            filler = value[-1] if value else None
            if node.get("minItems", 0) > 0:
                yield value[: node["minItems"] - 1]
            if "maxItems" in node:
                yield (value + [filler] * (node["maxItems"] + 1))[: node["maxItems"] + 1]
            if "prefixItems" in node:
                yield value + [None]
                for i, sub in enumerate(node["prefixItems"]):
                    for v in self.variants(sub, file, value[i], depth + 1):
                        yield value[:i] + [v] + value[i + 1 :]
            elif isinstance(node.get("items"), dict):
                item = value[0] if value else self.minimal(node["items"], file, depth + 1)
                for v in self.variants(node["items"], file, item, depth + 1):
                    yield [v]
        if t == "object" and isinstance(value, dict):
            for k in node.get("required", []):
                yield {kk: vv for kk, vv in value.items() if kk != k}
            if node.get("additionalProperties") is False:
                yield {**value, "zz-unknown": None}
            for k, sub in node.get("properties", {}).items():
                current = value.get(k, self.minimal(sub, file, depth + 1))
                for v in self.variants(sub, file, current, depth + 1):
                    yield {**value, k: v}

    def fixtures(self, file: str) -> list[object]:
        root = {k: v for k, v in self.bundle[file].items() if k not in ("$defs", "$schema")}
        base = self.minimal(root, file)
        out = [base]
        seen = {repr(base)}
        for v in self.variants(root, file, base):
            key = repr(v)
            if key not in seen:
                seen.add(key)
                out.append(v)
        return out


def outcome(module, instance: object) -> tuple | None:
    try:
        module.validate(instance)
    except StructuralError as exc:
        return (exc.pointer, exc.keyword)
    return None


def check_sites(source: str) -> list[int]:
    return [i for i, line in enumerate(source.splitlines()) if line.lstrip().startswith("fail(")]


def run_gate(package_dir: Path, fixtures: dict[str, list[object]]) -> tuple[int, list[str]]:
    """Mutate every check in every module named in ``fixtures``.

    ``package_dir`` holds a generated validator package. Returns the number of
    mutants and a list of surviving mutants (empty = every check is killed).
    """
    survivors: list[str] = []
    total = 0
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        original_pkg = "gate_original"
        shutil.copytree(package_dir, tmp_path / original_pkg)
        sys.path.insert(0, tmp)
        try:
            originals = {m: importlib.import_module(f"{original_pkg}.{m}") for m in fixtures}
            expected = {m: [outcome(originals[m], x) for x in xs] for m, xs in fixtures.items()}
            for m, xs in fixtures.items():
                source = (package_dir / f"{m}.py").read_text(encoding="utf-8")
                lines = source.splitlines(keepends=True)
                for n, line_no in enumerate(check_sites(source)):
                    total += 1
                    pkg = f"gate_{m}_{n}"
                    shutil.copytree(package_dir, tmp_path / pkg)
                    mutated = list(lines)
                    indent = line_no and lines[line_no][: len(lines[line_no]) - len(lines[line_no].lstrip())]
                    mutated[line_no] = f"{indent}pass  # mutant: check deleted\n"
                    (tmp_path / pkg / f"{m}.py").write_text("".join(mutated), encoding="utf-8")
                    mutant = importlib.import_module(f"{pkg}.{m}")
                    if all(outcome(mutant, x) == e for x, e in zip(xs, expected[m])):
                        survivors.append(f"{m}.py line {line_no + 1}: {lines[line_no].strip()}")
        finally:
            sys.path.remove(tmp)
            for name in list(sys.modules):
                if name.startswith("gate_"):
                    del sys.modules[name]
    return total, survivors
