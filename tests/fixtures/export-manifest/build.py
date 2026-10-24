# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``sv0cov.export-manifest`` 1.0 fixtures (CV-403): one manifest per
format and layout for the ``f0`` fixture, and ``mutations.json``, the
single-change corpus every reader of the schema must agree with: each entry
is a manifest text and whether it is ``valid`` or ``COV4402``. `--write`
regenerates them; without it, any difference fails."""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_report import fixture_report  # noqa: E402

from sv0cov.formats.canonical_json import CanonicalJsonError, encode  # noqa: E402
from sv0cov.formats.cobertura import render_cobertura  # noqa: E402
from sv0cov.formats.export_manifest import FORMATS, ManifestError, build_manifest, decode_manifest  # noqa: E402
from sv0cov.formats.lcov import render_lcov  # noqa: E402

#: name -> (format, primary basename or None for stdout, native basename)
LAYOUTS = {
    "lcov-bundle": ("lcov", "lcov.info", "coverage.json"),
    "lcov-file": ("lcov", "out.info", "out.info.sv0cov.json"),
    "lcov-stdout": ("lcov", None, "coverage.json"),
    "cobertura-bundle": ("cobertura", "cobertura.xml", "coverage.json"),
    "cobertura-file": ("cobertura", "out.xml", "out.xml.sv0cov.json"),
    "cobertura-stdout": ("cobertura", None, "coverage.json"),
}


def manifests() -> dict[str, bytes]:
    report, _ = fixture_report("f0")
    native = encode(report)
    primary = {"lcov": render_lcov(report), "cobertura": render_cobertura(report)}
    return {name: build_manifest(fmt, report, primary=primary[fmt], primary_name=p, native=native, native_name=n)
            for name, (fmt, p, n) in LAYOUTS.items()}


def _mutations(base: dict) -> list[tuple[str, object]]:
    """(what, manifest object or raw text) single changes of ``base``."""
    out: list[tuple[str, object]] = []

    def put(what: str, change) -> None:
        m = copy.deepcopy(base)
        change(m)
        out.append((what, m))

    for key in sorted(base):
        put(f"no {key}", lambda m, k=key: m.pop(k))
        for kind, value in (("null", None), ("integer", 0), ("string", "x"), ("array", []), ("object", {})):
            if type(base[key]) is not type(value) or base[key] is None and value is not None:
                put(f"{key} as {kind}", lambda m, k=key, v=value: m.__setitem__(k, v))
    put("an unknown member", lambda m: m.__setitem__("signature", "x"))
    for n in (0, 1):
        for key in sorted(base["artifacts"][n]):
            put(f"artifacts/{n} without {key}", lambda m, n=n, k=key: m["artifacts"][n].pop(k))
            put(f"artifacts/{n}/{key} as an object", lambda m, n=n, k=key: m["artifacts"][n].__setitem__(k, {}))
        put(f"artifacts/{n} with an unknown member", lambda m, n=n: m["artifacts"][n].__setitem__("mode", 384))
    s = lambda path, value: (lambda m: _set(m, path, value))  # noqa: E731
    other = "cobertura" if base["format"] == "lcov" else "lcov"
    for what, path, value in [
        ("another schema", ["schema"], "sv0cov.report"), ("another version", ["version"], "1.1"),
        ("the other format", ["format"], other), ("the other profile", ["profile"], FORMATS[other]["profile"]),
        ("the other compatibility reference", ["compatibility_reference"], FORMATS[other]["compatibility_reference"]),
        ("the other omissions", ["omissions"], FORMATS[other]["omissions"]),
        ("the other placeholders", ["placeholders"], FORMATS[other]["placeholders"] or ["complexity_unavailable_as_0.0"]),
        ("the other projections", ["projections"], FORMATS[other]["projections"]),
        ("omissions reordered", ["omissions"], list(reversed(base["omissions"]))),
        ("an omission dropped", ["omissions"], base["omissions"][1:]),
        ("an omission repeated", ["omissions"], [base["omissions"][0], *base["omissions"]]),
        ("a projection case-folded", ["projections"], [p.upper() for p in base["projections"]]),
        ("named contexts", ["context_projection"], "named"),
        ("another saturation disposition", ["saturation_disposition"], "lossy"),
        ("another producer", ["producer", "name"], "lcov"),
        ("an empty producer version", ["producer", "version"], ""),
        ("a producer version with a space", ["producer", "version"], "1.0 beta"),
        ("a producer version of 129 bytes", ["producer", "version"], "1" * 129),
        ("an uppercase indexed digest", ["indexed_input_sha256"], base["indexed_input_sha256"].upper()),
        ("a short configuration digest", ["report_configuration_sha256"], base["report_configuration_sha256"][:63]),
        ("a non-hex artifact digest", ["artifacts", 0, "sha256"], "g" * 64),
        ("a negative length", ["artifacts", 0, "byte_length"], -1),
        ("a length past int64", ["artifacts", 0, "byte_length"], 2**63),
        ("a fractional length", ["artifacts", 1, "byte_length"], 1.5),
        ("a boolean length", ["artifacts", 1, "byte_length"], True),
        ("the roles swapped", ["artifacts", 0, "role"], "native"),
        ("the primary's media type on the native", ["artifacts", 1, "media_type"], FORMATS[base["format"]]["media_type"]),
        ("the other format's media type", ["artifacts", 0, "media_type"], FORMATS[other]["media_type"]),
        ("a native on stdout", ["artifacts", 1, "destination"], "stdout"),
        ("a path in a name", ["artifacts", 1, "name"], "reports/coverage.json"),
        ("a backslash in a name", ["artifacts", 1, "name"], "a\\coverage.json"),
        ("a parent name", ["artifacts", 1, "name"], ".."),
        ("a NUL in a name", ["artifacts", 1, "name"], "a\x00b"),
        ("a 256-byte name", ["artifacts", 1, "name"], "a" * 256),
        ("an empty name", ["artifacts", 1, "name"], ""),
        ("the native named like the primary", ["artifacts", 1, "name"], base["artifacts"][0]["name"] or "x"),
        ("a named native as null", ["artifacts", 1, "name"], None),
        ("an unknown destination", ["artifacts", 0, "destination"], "pipe"),
    ]:
        put(what, s(path, value))
    if base["artifacts"][0]["destination"] == "file":
        put("a file primary with no name", s(["artifacts", 0, "name"], None))
        put("a named stdout primary", s(["artifacts", 0, "destination"], "stdout"))
        put("a stdout primary (valid)", lambda m: (m["artifacts"][0].__setitem__("destination", "stdout"),
                                                   m["artifacts"][0].__setitem__("name", None)))
    put("a native on stdout with no name", lambda m: (m["artifacts"][1].__setitem__("destination", "stdout"),
                                                      m["artifacts"][1].__setitem__("name", None)))
    put("artifacts reversed", lambda m: m["artifacts"].reverse())
    put("one artifact", lambda m: m["artifacts"].pop())
    put("three artifacts", lambda m: m["artifacts"].append(copy.deepcopy(m["artifacts"][1])))
    put("lossy_hit_only (valid)", s(["saturation_disposition"], "lossy_hit_only"))
    put("a 255-byte native name (valid)", s(["artifacts", 1, "name"], "a" * 250 + ".json"))
    put("a non-ASCII native name (valid)", s(["artifacts", 1, "name"], "covérage.json"))
    text = encode(base).decode("utf-8")
    out += [("a byte-order mark", "﻿" + text), ("no final line feed", text[:-1]), ("a trailing byte", text + " "),
            ("whitespace", text.replace(",", ", ", 1)), ("keys out of order", '{"version":"1.0",' + text[1:].replace(',"version":"1.0"', "")),
            ("a duplicate key", text[:-2] + ',"version":"1.0"}\n'), ("an escaped slash", text.replace("/", "\\/", 1))]
    return out


def _set(m, path, value) -> None:
    for p in path[:-1]:
        m = m[p]
    m[path[-1]] = value


def _text(m: dict) -> str:
    """Canonical text, or the same layout for what canonical JSON cannot hold (a fraction, past int64)."""
    try:
        return encode(m).decode("utf-8")
    except CanonicalJsonError:
        return json.dumps(m, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n"


def corpus() -> list[dict]:
    rows = []
    for name, data in manifests().items():
        if not name.endswith("-bundle"):
            continue
        base = json.loads(data)
        for what, m in _mutations(base):
            text = m if isinstance(m, str) else _text(m)
            try:
                decode_manifest(text.encode("utf-8", "surrogatepass"))
                result = "valid"
            except ManifestError:
                result = "COV4402"
            expect = "valid" if what.endswith("(valid)") else "COV4402"
            if result != expect:
                raise SystemExit(f"{name}: {what}: the reader says {result}, the corpus expects {expect}")
            rows.append({"base": name, "manifest": text, "result": expect, "what": what})
    return rows


def artifacts() -> dict[Path, bytes]:
    out = {HERE / f"{name}.manifest.json": data for name, data in manifests().items()}
    out[HERE / "mutations.json"] = (json.dumps(corpus(), ensure_ascii=True, indent=1, sort_keys=True) + "\n").encode()
    return out


def main() -> int:
    stale = []
    for path, data in artifacts().items():
        if "--write" in sys.argv:
            path.write_bytes(data)
        elif not path.is_file() or path.read_bytes() != data:
            stale.append(path.name)
    if stale:
        print(f"export-manifest fixtures: stale: {', '.join(stale)} (run with --write)", file=sys.stderr)
        return 1
    print("export-manifest fixtures: " + ("written" if "--write" in sys.argv else "current"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
