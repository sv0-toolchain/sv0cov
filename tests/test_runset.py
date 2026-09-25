# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Run IDs and the run-set manifest 1.0 (CV-019, SPEC 14.3/17.2, COV-FMT-035/036)."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from sv0cov.formats.runset import RunIdError, decode_run_set, encode_run_set, new_run_id, parse_run_id  # noqa: E402

A = "0123456789abcdef0123456789abcdef"
B = "fedcba9876543210fedcba9876543210"


class RunIdTest(unittest.TestCase):
    def test_valid(self) -> None:
        self.assertEqual(parse_run_id(A), bytes.fromhex(A))

    def test_invalid_spellings(self) -> None:
        for bad in (A.upper(), A[:-1], A + "0", "0" * 32, "g" * 32, " " + A[1:], A[:31] + "\n", "", 5, None):
            with self.subTest(value=bad):
                with self.assertRaises(RunIdError):
                    parse_run_id(bad)

    def test_new_run_id(self) -> None:
        rid = new_run_id()
        self.assertEqual(parse_run_id(rid).hex(), rid)
        self.assertNotEqual(new_run_id(), new_run_id())

    def test_entropy_failures_are_errors(self) -> None:
        with self.assertRaises(RunIdError):
            new_run_id(lambda n: bytes(n))
        with self.assertRaises(RunIdError):
            new_run_id(lambda n: b"\x01" * (n - 1))

        def broken(n: int) -> bytes:
            raise OSError("no entropy")

        with self.assertRaises(OSError):
            new_run_id(broken)


class RunSetTest(unittest.TestCase):
    GOLDEN = b'{"run_ids":["0123456789abcdef0123456789abcdef","fedcba9876543210fedcba9876543210"],"schema":"sv0cov.run-set","version":"1.0"}\n'

    def test_golden_bytes(self) -> None:
        self.assertEqual(encode_run_set([B, A]), self.GOLDEN)
        self.assertEqual(decode_run_set(self.GOLDEN), [A, B])

    def test_encode_rejects(self) -> None:
        for ids in ([], [A, A], [A.upper()], ["0" * 32]):
            with self.subTest(ids=ids):
                with self.assertRaises(RunIdError):
                    encode_run_set(ids)

    def test_decode_rejects(self) -> None:
        g = self.GOLDEN
        bad = {
            "unsorted": g.replace(A.encode(), b"TMP").replace(B.encode(), A.encode()).replace(b"TMP", B.encode()),
            "duplicate": g.replace(B.encode(), A.encode()),
            "empty": b'{"run_ids":[],"schema":"sv0cov.run-set","version":"1.0"}\n',
            "uppercase": g.replace(A.encode(), A.upper().encode()),
            "zero": g.replace(A.encode(), b"0" * 32),
            "unknown property": g.replace(b'"version"', b'"x":1,"version"'),
            "missing property": b'{"run_ids":["' + A.encode() + b'"],"schema":"sv0cov.run-set"}\n',
            "wrong schema": g.replace(b"sv0cov.run-set", b"sv0cov.runset"),
            "wrong version": g.replace(b'"1.0"', b'"1.1"'),
            "whitespace": g.replace(b",", b", "),
            "bom": b"\xef\xbb\xbf" + g,
            "no final LF": g[:-1],
            "trailing byte": g + b" ",
            "duplicate key": g.replace(b'"version":"1.0"', b'"version":"1.0","version":"1.0"'),
        }
        for name, data in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(RunIdError):
                    decode_run_set(data)


if __name__ == "__main__":
    unittest.main()
