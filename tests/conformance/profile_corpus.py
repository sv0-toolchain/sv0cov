# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Project-owned structural corpus for the closed R1 schema profile (CV-012).

The upstream suite is a dialect-wide suite, not a profile-completeness proof
(SPEC 25.2.4), so this corpus covers every permitted keyword and shape, the
exact numeric and length boundaries, closed objects, tuples, local references,
and combinator overlap. Each entry is ``(name, schema, instances)``; the
schema is the complete root schema of a single-file bundle. Only Boolean
validity is compared between the generated validator and the oracle.
"""

from __future__ import annotations

DIALECT = "https://json-schema.org/draft/2020-12/schema"
U64 = 2**64 - 1
I64 = -(2**63)


def s(**kw: object) -> dict:
    return {"$schema": DIALECT, **kw}


def closed(props: dict, **kw: object) -> dict:
    return {
        "additionalProperties": False,
        "properties": props,
        "required": sorted(props, key=lambda k: k.encode()),
        "type": "object",
        **kw,
    }


ANY = [None, True, False, 0, -1, 1, 1.0, 1.5, U64, U64 + 1, I64, I64 - 1, "", "a", "é", "😀", [], [1], {}, {"a": 1}]

CORPUS = [
    ("type-null", s(type="null"), ANY),
    ("type-boolean", s(type="boolean"), ANY),
    ("type-object", s(**closed({})), ANY),
    ("type-array", s(type="array", items={"type": "integer", "minimum": I64, "maximum": U64}), ANY + [[1, 2.0, U64], [1.5]]),
    ("type-string", s(type="string"), ANY),
    ("type-integer-u64", s(type="integer", minimum=0, maximum=U64), ANY + [2.0, -0.0, 1e20, float(U64)]),
    ("type-integer-i64", s(type="integer", minimum=I64, maximum=2**63 - 1), ANY),
    ("type-number", s(type="number", minimum=-10, maximum=10), ANY + [9.999, 10.0, 10.5, -10.0]),
    ("integer-exact-bounds", s(type="integer", minimum=5, maximum=5), [4, 5, 6, 5.0, "5"]),
    ("const-string", s(const="demo"), ANY + ["demo", "Demo", "demo "]),
    ("const-int", s(const=1), ANY + [1.0, True]),
    ("const-null", s(const=None), ANY),
    ("const-false", s(const=False), ANY + [0, 0.0]),
    ("enum-mixed", s(enum=["a", 0, None, True]), ANY + [0.0, False, "A"]),
    ("string-bounds", s(type="string", minLength=2, maxLength=3), ["", "a", "ab", "abc", "abcd", "éé", "😀😀", "😀😀😀😀", 12]),
    ("string-zero-length", s(type="string", minLength=0, maxLength=0), ["", "a", None]),
    ("array-bounds", s(type="array", items={"type": "null"}, minItems=1, maxItems=2), [[], [None], [None, None], [None, None, None], [1], "x"]),
    ("tuple", s(type="array", prefixItems=[{"type": "string"}, {"type": "integer", "minimum": 0, "maximum": 9}], items=False, minItems=2, maxItems=2),
     [["a", 1], ["a"], ["a", 1, 2], [1, 1], ["a", 10], ["a", 1.0], [], "a"]),
    ("closed-object", s(**closed({"a": {"type": "string"}, "b": {"type": "integer", "minimum": 0, "maximum": 1}})),
     [{"a": "x", "b": 0}, {"a": "x"}, {"a": "x", "b": 0, "c": 1}, {"a": 1, "b": 0}, {"a": "x", "b": 2}, {}, [], None]),
    ("object-keys-unicode", s(**closed({"é": {"type": "null"}, "z": {"type": "null"}})), [{"é": None, "z": None}, {"e": None, "z": None}, {"é": None, "z": None, "é́": None}]),
    ("nested-closed", s(**closed({"inner": closed({"n": {"type": "integer", "minimum": 0, "maximum": 3}})})),
     [{"inner": {"n": 1}}, {"inner": {"n": 4}}, {"inner": {}}, {"inner": {"n": 1, "x": 1}}, {"inner": 1}]),
    ("anyOf-overlap", s(anyOf=[{"type": "integer", "minimum": 0, "maximum": 10}, {"type": "integer", "minimum": 5, "maximum": 20}]), [-1, 0, 5, 10, 15, 20, 21, "5", 7.0]),
    ("oneOf-overlap", s(oneOf=[{"type": "integer", "minimum": 0, "maximum": 10}, {"type": "integer", "minimum": 5, "maximum": 20}]), [-1, 0, 5, 10, 15, 20, 21, "5", 7.0]),
    ("oneOf-nullable-ref", s(**{"$defs": {"name": {"type": "string", "minLength": 1, "maxLength": 4}}}, oneOf=[{"type": "null"}, {"$ref": "#/$defs/name"}]),
     [None, "", "a", "abcde", 1]),
    ("not", s(**{"not": {"type": "string"}}), ANY),
    ("not-not", s(**{"not": {"not": {"const": 3}}}), [3, 3.0, 4, "3"]),
    ("anyOf-nested-ref", s(**{"$defs": {"a": {"type": "integer", "minimum": 0, "maximum": 1}, "b": {"$ref": "#/$defs/a", "title": "alias"}}}, anyOf=[{"$ref": "#/$defs/b"}, {"type": "null"}]),
     [0, 1, 2, None, "0"]),
    ("annotations-inert", s(type="string", title="t", description="d", **{"$comment": "c"}), ["x", 1]),
    ("empty-schema", s(), ANY),
    ("ref-to-closed", s(**{"$defs": {"pt": closed({"x": {"type": "integer", "minimum": 0, "maximum": 9}})}}, type="array", items={"$ref": "#/$defs/pt"}, maxItems=3),
     [[], [{"x": 1}], [{"x": 1}, {"x": 10}], [{"x": 1, "y": 2}], [{"x": 1}] * 4]),
]
