# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Canonical JSON codec (CV-007, SPEC 16.2, COV-FMT-003)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import (  # noqa: E402
    INT_MAX,
    INT_MIN,
    CanonicalJsonError,
    Limits,
    decode,
    decode_canonical,
    encode,
)

# (value, exact canonical bytes). Expected bytes are written by hand from the
# SPEC 16.2 rules, not produced by the implementation.
GOLDEN = [
    (None, b"null\n"),
    (True, b"true\n"),
    (0, b"0\n"),
    (-1, b"-1\n"),
    (INT_MAX, b"18446744073709551615\n"),
    (INT_MIN, b"-9223372036854775808\n"),
    ("", b'""\n'),
    ([], b"[]\n"),
    ({}, b"{}\n"),
    ({"b": 1, "a": [1, 2, {"d": None, "c": False}]}, b'{"a":[1,2,{"c":false,"d":null}],"b":1}\n'),
    # Short escapes and lowercase \u00xx for other control characters.
    ('"\\\b\t\n\f\r', b'"\\"\\\\\\b\\t\\n\\f\\r"\n'),
    ("\x00\x1f", b'"\\u0000\\u001f"\n'),
    # DEL, '/', non-ASCII, and U+2028 are written raw.
    ("\x7f/é\u2028𝄞", '"\x7f/é\u2028𝄞"\n'.encode("utf-8")),
    # Keys sort by UTF-8 bytes: "Z" (5a) < "a" (61) < "é" (c3 a9) < "𝄞" (f0 ...).
    ({"𝄞": 4, "é": 3, "a": 2, "Z": 1}, '{"Z":1,"a":2,"é":3,"𝄞":4}\n'.encode("utf-8")),
]


class EncodeTest(unittest.TestCase):
    def test_golden_bytes(self) -> None:
        for value, expected in GOLDEN:
            with self.subTest(value=value):
                self.assertEqual(encode(value), expected)
                self.assertEqual(decode_canonical(expected), value)

    def test_rejects_non_json_values(self) -> None:
        for bad in (1.0, float("nan"), b"x", {1: 2}, {"k": object()}, INT_MAX + 1, INT_MIN - 1, "\ud800"):
            with self.subTest(value=bad):
                with self.assertRaises(CanonicalJsonError):
                    encode(bad)

    def test_bool_is_not_an_integer(self) -> None:
        self.assertEqual(encode([True, 1]), b"[true,1]\n")


class DecodeRejectionTest(unittest.TestCase):
    CASES = {
        "bom": b'\xef\xbb\xbf{}\n',
        "final_newline": b"{}",
        "final_newline_double": b"{}\n\n",
        "invalid_utf8": b'"\xff"\n',
        "duplicate_key": b'{"a":1,"a":1}\n',
        "duplicate_key_nested": b'{"x":{"a":1,"a":2}}\n',
        "float": b"1.0\n",
        "exponent": b"1e3\n",
        "nan": b"NaN\n",
        "infinity": b"-Infinity\n",
        "integer_range_high": b"18446744073709551616\n",
        "integer_range_low": b"-9223372036854775809\n",
        "integer_huge": b"1" + b"0" * 5000 + b"\n",
        "lone_surrogate": b'"\\ud800"\n',
        "trailing_data": b"{} {}\n",
        "syntax": b"{\n",
    }

    def test_rejections(self) -> None:
        for name, data in self.CASES.items():
            with self.subTest(case=name):
                with self.assertRaises(CanonicalJsonError):
                    decode(data)

    def test_rejection_reasons_are_stable(self) -> None:
        expected = {
            "bom": "bom",
            "duplicate_key": "duplicate_key",
            "float": "non_integer_number",
            "nan": "non_integer_number",
            "integer_range_high": "integer_range",
            "lone_surrogate": "invalid_unicode",
        }
        for name, reason in expected.items():
            with self.subTest(case=name):
                with self.assertRaises(CanonicalJsonError) as ctx:
                    decode(self.CASES[name])
                self.assertEqual(ctx.exception.reason, reason)


class CanonicalityTest(unittest.TestCase):
    NONCANONICAL = [
        b'{"b":1,"a":2}\n',  # unsorted keys
        b'{"a": 1}\n',  # insignificant whitespace
        b" {}\n",
        b"-0\n",  # decodes to 0, canonical form is "0"
        b'"\\u0041"\n',  # unnecessary escape
        b'"\\/"\n',
        b'"\\u001F"\n',  # uppercase hex escape
        b'"\\u00e9"\n',  # non-ASCII must be raw UTF-8
        b"[1,\n2]\n",
    ]

    def test_semantically_valid_but_noncanonical(self) -> None:
        for data in self.NONCANONICAL:
            with self.subTest(data=data):
                decode(data)  # accepted by the plain decoder
                with self.assertRaises(CanonicalJsonError) as ctx:
                    decode_canonical(data)
                self.assertEqual(ctx.exception.reason, "noncanonical")

    def test_round_trip_is_stable(self) -> None:
        for value, _ in GOLDEN:
            once = encode(value)
            self.assertEqual(encode(decode(once)), once)


class LimitsTest(unittest.TestCase):
    def test_size_limit_checked_first(self) -> None:
        with self.assertRaises(CanonicalJsonError) as ctx:
            decode(b"[" * 100, Limits(max_bytes=10))
        self.assertEqual(ctx.exception.reason, "size_limit")

    def test_depth_limit(self) -> None:
        deep = b"[" * 65 + b"]" * 65 + b"\n"
        with self.assertRaises(CanonicalJsonError) as ctx:
            decode(deep)
        self.assertEqual(ctx.exception.reason, "depth_limit")
        ok = b"[" * 64 + b"]" * 64 + b"\n"
        decode(ok)

    def test_depth_scan_ignores_brackets_in_strings(self) -> None:
        decode(b'["' + b"[" * 1000 + b'"]\n')

    def test_hostile_deep_nesting_does_not_recurse(self) -> None:
        with self.assertRaises(CanonicalJsonError):
            decode(b"[" * 1_000_000 + b"\n")

    def test_string_and_container_limits(self) -> None:
        with self.assertRaises(CanonicalJsonError) as ctx:
            decode(b'"abcdef"\n', Limits(max_string_bytes=5))
        self.assertEqual(ctx.exception.reason, "string_limit")
        with self.assertRaises(CanonicalJsonError) as ctx:
            decode(b"[1,2,3]\n", Limits(max_container_items=2))
        self.assertEqual(ctx.exception.reason, "container_limit")
        with self.assertRaises(CanonicalJsonError) as ctx:
            decode(b'{"ab":1}\n', Limits(max_string_bytes=1))
        self.assertEqual(ctx.exception.reason, "string_limit")


if __name__ == "__main__":
    unittest.main()
