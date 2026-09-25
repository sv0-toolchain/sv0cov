# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Point identity 1.0 (CV-008, SPEC 10.3, COV-MAP-017, AC-110)."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.model.identity import (  # noqa: E402
    NO_ORDINAL,
    EntityKind,
    PointIdentity,
    PointKind,
    point_id,
    preimage,
)
from sv0cov.model.logical import LogicalValueError  # noqa: E402

VECTORS = json.loads((ROOT / "tests/fixtures/point-id/vectors.json").read_text(encoding="utf-8"))

ENTITY = {"none": EntityKind.NONE, "function": EntityKind.FUNCTION, "contract": EntityKind.CONTRACT}
KIND = {
    "function_entry": PointKind.FUNCTION_ENTRY,
    "region": PointKind.REGION,
    "branch_outcome": PointKind.BRANCH_OUTCOME,
    "contract_true": PointKind.CONTRACT_TRUE,
    "contract_false": PointKind.CONTRACT_FALSE,
}


def identity(v: dict) -> PointIdentity:
    return PointIdentity(
        source_path=v["source_path"],
        source_digest=v["source_digest"],
        entity_kind=ENTITY[v["entity_kind"]],
        entity_name=v["entity_name"],
        point_kind=KIND[v["point_kind"]],
        start_byte=v["start_byte"],
        end_byte=v["end_byte"],
        # Maps store null for a non-branch point; the preimage uses the sentinel.
        outcome_ordinal=NO_ORDINAL if v["outcome_ordinal"] is None else v["outcome_ordinal"],
        discriminator=v["discriminator"],
    )


BASE = PointIdentity(
    source_path="src/main.sv0",
    source_digest="0123456789abcdef" * 4,
    entity_kind=EntityKind.FUNCTION,
    entity_name="main",
    point_kind=PointKind.REGION,
    start_byte=1,
    end_byte=2,
    outcome_ordinal=NO_ORDINAL,
    discriminator="d",
)


class GoldenVectorTest(unittest.TestCase):
    def test_vector_file_is_self_consistent(self) -> None:
        self.assertEqual(VECTORS["point_identity_version"], "1.0")
        for v in VECTORS["vectors"]:
            with self.subTest(vector=v["name"]):
                whole = b""
                for seg in v["segments"]:
                    self.assertEqual(seg["offset"], len(whole))
                    whole += bytes.fromhex(seg["hex"])
                self.assertEqual(len(whole), v["preimage_length"])
                self.assertEqual(hashlib.sha256(whole).hexdigest(), v["point_id"])

    def test_vector_file_regenerates_exactly(self) -> None:
        gen = ROOT / "tests/fixtures/point-id/generate_vectors.py"
        out = subprocess.run([sys.executable, str(gen)], check=True, capture_output=True).stdout
        self.assertEqual(out, (ROOT / "tests/fixtures/point-id/vectors.json").read_bytes())

    def test_implementation_reproduces_every_vector(self) -> None:
        for v in VECTORS["vectors"]:
            with self.subTest(vector=v["name"]):
                expected = b"".join(bytes.fromhex(s["hex"]) for s in v["segments"])
                self.assertEqual(preimage(identity(v)), expected)
                self.assertEqual(point_id(identity(v)), v["point_id"])

    def test_every_point_and_entity_kind_is_covered(self) -> None:
        self.assertEqual({v["point_kind"] for v in VECTORS["vectors"]}, set(KIND))
        self.assertEqual({v["entity_kind"] for v in VECTORS["vectors"]}, set(ENTITY))

    def test_one_preimage_written_by_hand(self) -> None:
        p = PointIdentity("a", "00" * 32, EntityKind.FUNCTION, "b", PointKind.FUNCTION_ENTRY, 0, 0, NO_ORDINAL, "c")
        expected = (
            b"sv0cov.point.v1\x00"  # 16-byte domain separator
            + b"\x01\x00\x00\x00"  # identity 1.0
            + b"\x01\x00\x00\x00a"  # path
            + b"\x00" * 32  # source digest
            + b"\x01"  # entity kind: function
            + b"\x01\x00\x00\x00b"  # entity name
            + b"\x01"  # point kind: function entry
            + b"\x00" * 16  # start, end
            + b"\xff\xff\xff\xff"  # no ordinal
            + b"\x01\x00\x00\x00c"  # discriminator
        )
        self.assertEqual(preimage(p), expected)


class FieldSensitivityTest(unittest.TestCase):
    """Every preimage field changes the ID; nothing outside it can."""

    def test_each_field_changes_the_id(self) -> None:
        base = point_id(BASE)
        changes = {
            "source_path": "src/main2.sv0",
            "source_digest": "f" * 64,
            "entity_name": "main2",
            "start_byte": 0,
            "end_byte": 3,
            "discriminator": "e",
        }
        for field, value in changes.items():
            with self.subTest(field=field):
                self.assertNotEqual(point_id(dataclasses.replace(BASE, **field_value(field, value))), base)
        unowned = dataclasses.replace(BASE, entity_kind=EntityKind.NONE, entity_name="")
        self.assertNotEqual(point_id(unowned), base)
        branch = dataclasses.replace(BASE, point_kind=PointKind.BRANCH_OUTCOME, outcome_ordinal=0)
        self.assertNotEqual(point_id(branch), point_id(dataclasses.replace(branch, outcome_ordinal=1)))

    def test_case_is_not_folded(self) -> None:
        self.assertNotEqual(point_id(BASE), point_id(dataclasses.replace(BASE, source_path="src/Main.sv0")))

    def test_unicode_is_not_normalized(self) -> None:
        nfc = dataclasses.replace(BASE, entity_name="caf\u00e9")
        nfd = dataclasses.replace(BASE, entity_name="cafe\u0301")
        self.assertNotEqual(point_id(nfc), point_id(nfd))


def field_value(field: str, value: object) -> dict:
    return {field: value}


class RejectionTest(unittest.TestCase):
    INVALID = {
        "absolute path": {"source_path": "/src/main.sv0"},
        "drive path": {"source_path": "C:/src/main.sv0"},
        "backslash path": {"source_path": "src\\main.sv0"},
        "dot component": {"source_path": "src/./main.sv0"},
        "dotdot component": {"source_path": "../main.sv0"},
        "empty component": {"source_path": "src//main.sv0"},
        "trailing slash": {"source_path": "src/"},
        "empty path": {"source_path": ""},
        "long path": {"source_path": "p" * 4097},
        "newline in path": {"source_path": "src/a\nb.sv0"},
        "uppercase digest": {"source_digest": "0123456789ABCDEF" * 4},
        "short digest": {"source_digest": "ab"},
        "empty entity name": {"entity_name": ""},
        "long entity name": {"entity_name": "n" * 4097},
        "name without entity": {"entity_kind": EntityKind.NONE},
        "entity kind 3": {"entity_kind": 3},
        "point kind 0": {"point_kind": 0},
        "point kind 6": {"point_kind": 6},
        "end before start": {"start_byte": 5, "end_byte": 4},
        "negative start": {"start_byte": -1},
        "u64 overflow": {"end_byte": 2**64},
        "bool offset": {"start_byte": True},
        "ordinal on region": {"outcome_ordinal": 0},
        "empty discriminator": {"discriminator": ""},
        "long discriminator": {"discriminator": "x" * 257},
        "NUL discriminator": {"discriminator": "a\x00b"},
        "surrogate discriminator": {"discriminator": "\ud800"},
        "function entry without function": {
            "point_kind": PointKind.FUNCTION_ENTRY,
            "entity_kind": EntityKind.CONTRACT,
        },
        "contract point on function": {"point_kind": PointKind.CONTRACT_TRUE},
        "region owned by contract": {"entity_kind": EntityKind.CONTRACT},
        "branch sentinel ordinal": {"point_kind": PointKind.BRANCH_OUTCOME, "outcome_ordinal": NO_ORDINAL},
    }

    def test_invalid_inputs_rejected(self) -> None:
        for name, changes in self.INVALID.items():
            with self.subTest(case=name):
                with self.assertRaises(LogicalValueError):
                    preimage(dataclasses.replace(BASE, **changes))

    def test_boundaries_accepted(self) -> None:
        ok = [
            {"source_path": "p" * 4096},
            {"entity_name": "n" * 4096},
            {"discriminator": "x" * 256},
            {"start_byte": 0, "end_byte": 0},
            {"start_byte": 2**64 - 1, "end_byte": 2**64 - 1},
            {"entity_kind": EntityKind.NONE, "entity_name": ""},
            {"point_kind": PointKind.BRANCH_OUTCOME, "outcome_ordinal": 0xFFFFFFFE},
            {"source_path": ".hidden/x.sv0"},
        ]
        for changes in ok:
            with self.subTest(changes=list(changes)):
                self.assertEqual(len(point_id(dataclasses.replace(BASE, **changes))), 64)


if __name__ == "__main__":
    unittest.main()
