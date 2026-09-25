# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Diagnostic registry revision 1 and diagnostic records (CV-009).

SPEC 20.5, COV-FMT-042, COV-CLI-009 (renderers), AC-113.
"""

from __future__ import annotations

import copy
import dataclasses
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import diagnostics as d  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402

REGISTRY_PATH = ROOT / "registries" / "diagnostics-v1.json"
SPEC = Path.home() / "Documents" / "project-specs" / "sv0cov" / "SPEC.md"

# Revision 1 is F0 golden evidence (SPEC 20.5.1): these digests freeze it.
REVISION_1_REGISTRY_SHA256 = "440aad98c48e372d526d4aefb7c3e8cba8a0d4fc07b31797115a55044b06e3b1"
REVISION_1_FILE_SHA256 = "10174e49ffa3628a0ddcc6863af286fd0c9204bb334dc94e8adf07ed8e846093"

SPAN = d.Span(start_byte=10, end_byte=20, start_line=2, start_column=3, end_line=2, end_column=13)


def registry_obj() -> dict:
    return decode_canonical(REGISTRY_PATH.read_bytes())


def reencode(obj: dict) -> bytes:
    """Recompute the self-digest so only the intended mutation differs."""
    obj = copy.deepcopy(obj)
    obj["registry_sha256"] = d.registry_digest(obj)
    return encode(obj)


class RegistryTest(unittest.TestCase):
    def test_revision_1_is_frozen(self) -> None:
        reg = d.load_registry()
        self.assertEqual(reg.revision, 1)
        self.assertEqual(reg.sha256, REVISION_1_REGISTRY_SHA256)
        self.assertEqual(len(reg.entries), 71)
        self.assertEqual(hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest(), REVISION_1_FILE_SHA256)

    def test_file_is_canonical_and_self_consistent(self) -> None:
        obj = registry_obj()
        self.assertEqual(d.registry_digest(obj), obj["registry_sha256"])
        self.assertEqual(encode(obj), REGISTRY_PATH.read_bytes())

    @unittest.skipUnless(SPEC.is_file(), "sv0cov SPEC.md not available on this host")
    def test_entries_match_the_spec_table(self) -> None:
        text = SPEC.read_text(encoding="utf-8")
        section = text[text.index("Registry revision 1 reserves") : text.index("An entry is immutable after")]
        rows = re.findall(r"^\| `(COV\d{4})` \| (error|warning|note) \| (.+?) \|$", section, re.M)
        got = [(e.code, e.default_severity, e.title) for e in d.load_registry().entries.values()]
        self.assertEqual(got, rows)

    def test_every_domain_matches_its_range(self) -> None:
        for entry in d.load_registry().entries.values():
            self.assertEqual(entry.domain, d.domain_of(entry.code))

    def test_mutations_are_rejected(self) -> None:
        def entries(o: dict) -> list:
            return o["entries"]

        cases = {
            "wrong domain": lambda o: entries(o)[0].__setitem__("domain", "merge"),
            "reserved range": lambda o: entries(o).append(
                {"code": "COV9001", "default_severity": "error", "domain": "reserved", "title": "x"}
            ),
            "COV0000": lambda o: entries(o).insert(
                0, {"code": "COV0000", "default_severity": "error", "domain": "invocation", "title": "x"}
            ),
            "lowercase code": lambda o: entries(o)[0].__setitem__("code", "cov0001"),
            "unordered": lambda o: entries(o).reverse(),
            "duplicate": lambda o: entries(o).insert(1, dict(entries(o)[0])),
            "unknown severity": lambda o: entries(o)[0].__setitem__("default_severity", "fatal"),
            "empty title": lambda o: entries(o)[0].__setitem__("title", ""),
            "title over 128 bytes": lambda o: entries(o)[0].__setitem__("title", "é" * 65),
            "unknown entry field": lambda o: entries(o)[0].__setitem__("url", "x"),
            "unknown top-level field": lambda o: o.__setitem__("notes", "x"),
            "missing field": lambda o: o.pop("revision"),
            "revision zero": lambda o: o.__setitem__("revision", 0),
            "wrong schema": lambda o: o.__setitem__("schema", "sv0cov.registry"),
            "wrong version": lambda o: o.__setitem__("version", "1.1"),
        }
        for name, fn in cases.items():
            with self.subTest(case=name):
                obj = registry_obj()
                fn(obj)
                with self.assertRaises(d.RegistryError):
                    d.validate_registry(reencode(obj))

    def test_stale_digest_rejected(self) -> None:
        obj = registry_obj()
        obj["entries"][0]["title"] = "Edited title"
        with self.assertRaises(d.RegistryError):
            d.validate_registry(encode(obj))

    def test_noncanonical_bytes_rejected(self) -> None:
        pretty = json.dumps(registry_obj(), indent=1).encode() + b"\n"
        with self.assertRaises(d.RegistryError):
            d.validate_registry(pretty)


class AppendOnlyTest(unittest.TestCase):
    def successor(self, fn, revision: int = 2) -> d.Registry:
        obj = registry_obj()
        fn(obj)
        obj["revision"] = revision
        return d.validate_registry(reencode(obj))

    def test_append_is_allowed(self) -> None:
        new = self.successor(
            lambda o: o["entries"].append(
                {"code": "COV8004", "default_severity": "error", "domain": "internal", "title": "New invariant"}
            )
        )
        d.check_append_only(d.load_registry(), new)

    def test_changes_are_rejected(self) -> None:
        old = d.load_registry()
        cases = {
            "removed": lambda o: o["entries"].pop(),
            "retitled": lambda o: o["entries"][0].__setitem__("title", "Renamed"),
            "reseverity": lambda o: o["entries"][0].__setitem__("default_severity", "warning"),
        }
        for name, fn in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(d.RegistryError):
                    d.check_append_only(old, self.successor(fn))

    def test_revision_must_increase_by_one(self) -> None:
        add = lambda o: o["entries"].append(  # noqa: E731
            {"code": "COV8004", "default_severity": "error", "domain": "internal", "title": "x"}
        )
        with self.assertRaises(d.RegistryError):
            d.check_append_only(d.load_registry(), self.successor(add, revision=3))


class RecordTest(unittest.TestCase):
    def test_record_takes_severity_and_message_from_registry(self) -> None:
        obj = d.Diagnostic("COV4021", "report").to_json()
        self.assertEqual((obj["severity"], obj["message"]), ("warning", "Lossy saturated export requested"))
        self.assertEqual(obj["registry_sha256"], REVISION_1_REGISTRY_SHA256)

    def test_unknown_code_rejected(self) -> None:
        for code in ("COV9999", "COV0000", "COV1234"):
            with self.subTest(code=code):
                with self.assertRaises(d.DiagnosticError):
                    d.Diagnostic(code, "report").to_json()

    def test_facts_are_sorted_and_validated(self) -> None:
        obj = d.Diagnostic("COV2103", "collection", facts=(("supported_version", "1.0"), ("observed_version", "2.0"))).to_json()
        self.assertEqual([f["name"] for f in obj["facts"]], ["observed_version", "supported_version"])
        bad = {
            "uppercase fact name": (("Observed", 1),),
            "duplicate fact": (("a", 1), ("a", 2)),
            "newline in value": (("a", "x\ny"),),
            "i64 overflow": (("a", 2**63),),
            "long value": (("a", "x" * 4097),),
        }
        for name, facts in bad.items():
            with self.subTest(case=name):
                with self.assertRaises(d.DiagnosticError):
                    d.Diagnostic("COV2103", "collection", facts=facts).to_json()

    def test_record_validation_rejects_tampering(self) -> None:
        good = d.Diagnostic("COV1004", "report", primary_location=d.Location("src/a.sv0", SPAN)).to_json()
        d.validate_record(good)
        cases = {
            "severity": ("severity", "warning"),
            "message": ("message", "Something else"),
            "revision": ("registry_revision", 2),
            "digest": ("registry_sha256", "0" * 64),
            "phase": ("phase", "linking"),
            "extra key": ("extra", 1),
        }
        for name, (key, value) in cases.items():
            with self.subTest(case=name):
                obj = copy.deepcopy(good)
                obj[key] = value
                with self.assertRaises(d.DiagnosticError):
                    d.validate_record(obj)

    def test_locations_are_validated(self) -> None:
        bad_spans = [
            dataclasses.replace(SPAN, end_byte=5),
            dataclasses.replace(SPAN, end_line=1),
        ]
        for span in bad_spans:
            with self.assertRaises(d.DiagnosticError):
                d.Diagnostic("COV1004", "report", primary_location=d.Location("src/a.sv0", span)).to_json()
        for path in ("/abs/a.sv0", "../a.sv0", "a//b.sv0"):
            with self.subTest(path=path), self.assertRaises(d.DiagnosticError):
                d.Diagnostic("COV1004", "report", primary_location=d.Location(path, SPAN)).to_json()

    def test_related_locations_are_ordered(self) -> None:
        related = (d.Related("second", "b.sv0", SPAN), d.Related("first", "a.sv0", SPAN))
        obj = d.Diagnostic("COV3202", "merge", related_locations=related).to_json()
        self.assertEqual([r["path"] for r in obj["related_locations"]], ["a.sv0", "b.sv0"])


class OrderingAndRenderingTest(unittest.TestCase):
    def test_phase_code_location_order_and_dedupe(self) -> None:
        loc = d.Location("src/a.sv0", SPAN)
        events = [
            d.Diagnostic("COV4101", "policy"),
            d.Diagnostic("COV1004", "report", primary_location=loc),
            d.Diagnostic("COV1004", "report"),
            d.Diagnostic("COV0002", "configuration"),
            d.Diagnostic("COV0001", "invocation"),
            d.Diagnostic("COV0001", "invocation"),
        ]
        ordered = d.order_events(events)
        got = [(o["phase"], o["code"], o["primary_location"] is None) for o in ordered]
        self.assertEqual(
            got,
            [
                ("invocation", "COV0001", True),
                ("configuration", "COV0002", True),
                ("report", "COV1004", True),
                ("report", "COV1004", False),
                ("policy", "COV4101", True),
            ],
        )

    def test_json_line_is_one_canonical_record(self) -> None:
        line = d.render_json_line(d.Diagnostic("COV3001", "merge").to_json())
        self.assertEqual(line.count(b"\n"), 1)
        self.assertTrue(line.endswith(b"\n"))
        self.assertEqual(encode(decode_canonical(line)), line)

    def test_human_rendering_matches_appendix_b_shape(self) -> None:
        obj = d.Diagnostic(
            "COV2103", "collection", facts=(("observed_version", "2.0"), ("supported_version", "1.0"))
        ).to_json()
        self.assertEqual(
            d.render_human(obj),
            "COV2103 error: Unsupported raw-profile version\n"
            "  observed_version: 2.0\n"
            "  supported_version: 1.0\n",
        )

    def test_human_rendering_neutralizes_terminal_controls(self) -> None:
        obj = d.Diagnostic("COV3002", "merge", facts=(("name", "evil\x1b[31mred\x9b"),)).to_json()
        text = d.render_human(obj)
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x9b", text)
        self.assertIn("\\x1b[31mred\\x9b", text)


if __name__ == "__main__":
    unittest.main()
