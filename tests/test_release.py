# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Release identity, SHA256SUMS, and release manifest 1.0 (CV-034; SPEC 25.4)."""

from __future__ import annotations

import copy
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HERE = ROOT / "tests" / "fixtures" / "release"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(HERE))

import build as B  # noqa: E402

from sv0cov.formats import release as R  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402

MANIFEST = (HERE / "sv0cov-1.0.0.release.json").read_bytes()
SUMS = (HERE / "SHA256SUMS").read_bytes()


class VersionTest(unittest.TestCase):
    def test_grammar(self) -> None:
        for good in ("0.0.0", "1.0.0", "10.20.30", "1.0.123456789"):
            R.version_key(good)
        for bad in ("v1.0.0", "1.0", "1.0.0.0", "01.0.0", "1.00.0", "1.0.0-rc1", "1.0.0+local", "1.0.0.post1", "1.0.0.dev0",
                    " 1.0.0", "1.0.0\n", "１.0.0", "0!1.0.0", "1.0.0" + "0" * 124):
            with self.subTest(bad=bad), self.assertRaises(R.ReleaseError):
                R.version_key(bad)

    def test_numeric_precedence(self) -> None:
        self.assertLess(R.version_key("1.9.0"), R.version_key("1.10.0"))
        self.assertLess(R.version_key("9.0.0"), R.version_key("10.0.0"))

    def test_successor_rules(self) -> None:
        ok = [
            (None, "0.1.0", "MAJOR"), ("0.1.0", "0.1.1", "PATCH"), ("0.1.1", "0.2.0", "MINOR"),
            ("0.2.0", "0.3.0", "MAJOR"), ("0.9.3", "1.0.0", "MAJOR"), ("1.0.0", "1.0.1", "PATCH"),
            ("1.0.1", "1.1.0", "MINOR"), ("1.1.0", "1.2.0", "PATCH"), ("1.2.0", "2.0.0", "MAJOR"),
            ("1.9.0", "1.10.0", "MINOR"), ("1.0.0", "1.0.2", "PATCH"),
        ]
        for prev, new, impact in ok:
            with self.subTest(prev=prev, new=new, impact=impact):
                R.check_successor(prev, new, impact)
        bad = [
            ("1.0.0", "1.0.0", "PATCH"), ("1.1.0", "1.0.9", "PATCH"), ("1.0.0", "1.0.1", "MINOR"),
            ("1.0.0", "1.1.0", "MAJOR"), ("1.0.0", "1.1.1", "MINOR"), ("1.0.0", "2.1.0", "MAJOR"),
            ("1.0.0", "2.0.1", "MAJOR"), ("0.9.0", "1.0.1", "MAJOR"), ("1.10.0", "1.9.0", "MINOR"),
            ("1.0.0", "1.0.1", "BREAKING"),
        ]
        for prev, new, impact in bad:
            with self.subTest(prev=prev, new=new, impact=impact), self.assertRaises(R.ReleaseError):
                R.check_successor(prev, new, impact)

    def test_asset_names(self) -> None:
        self.assertEqual(R.sdist_name("1.2.3"), "sv0cov-1.2.3.tar.gz")
        self.assertEqual(R.wheel_name("1.2.3"), "sv0cov-1.2.3-py3-none-any.whl")
        self.assertEqual(R.tag_version("v1.2.3"), "1.2.3")
        for bad in ("1.2.3", "V1.2.3", "vv1.2.3", "v1.2"):
            with self.assertRaises(R.ReleaseError):
                R.tag_version(bad)


class SumsTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        self.assertEqual(R.encode_sums(R.parse_sums(SUMS)), SUMS)

    def test_negative_corpus(self) -> None:
        d = "a" * 64
        cases = {
            "empty": b"",
            "no-final-lf": f"{d}  a".encode(),
            "one-space": f"{d} a\n".encode(),
            "binary-marker": f"{d} *a\n".encode(),
            "uppercase-hex": f"{d.upper()}  a\n".encode(),
            "short-digest": f"{d[:63]}  a\n".encode(),
            "path": f"{d}  dir/a\n".encode(),
            "leading-dot": f"{d}  .a\n".encode(),
            "space-in-name": f"{d}  a b\n".encode(),
            "crlf": f"{d}  a\r\n".encode(),
            "blank-line": f"{d}  a\n\n".encode(),
            "comment": f"# sums\n{d}  a\n".encode(),
            "bom": b"\xef\xbb\xbf" + f"{d}  a\n".encode(),
            "unsorted": f"{d}  b\n{d}  a\n".encode(),
            "duplicate": f"{d}  a\n{d}  a\n".encode(),
            "self-reference": f"{d}  SHA256SUMS\n".encode(),
            "non-ascii": f"{d}  é\n".encode(),
            "trailing-space": f"{d}  a \n".encode(),
            "long-name": f"{d}  {'a' * 256}\n".encode(),
        }
        for name, data in cases.items():
            with self.subTest(case=name), self.assertRaises(R.ReleaseError):
                R.parse_sums(data)

    def test_byte_order_not_case_order(self) -> None:
        d = "b" * 64
        R.parse_sums(f"{d}  B\n{d}  a\n".encode())
        with self.assertRaises(R.ReleaseError):
            R.parse_sums(f"{d}  a\n{d}  B\n".encode())


class ManifestTest(unittest.TestCase):
    def test_fixtures_are_current(self) -> None:
        r = subprocess.run([sys.executable, str(HERE / "build.py")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_fixture_reconciles(self) -> None:
        obj = R.validate_manifest(MANIFEST)
        self.assertEqual(len(obj), 14)
        R.reconcile(MANIFEST, SUMS)

    def mutate(self, fn) -> bytes:
        obj = json.loads(MANIFEST)
        fn(obj)
        body = {k: v for k, v in obj.items() if k != "release_manifest_sha256"}
        obj["release_manifest_sha256"] = R.manifest_digest(body)
        return encode(obj)

    def test_mutation_corpus(self) -> None:
        def drop_sbom(o):
            o["artifacts"] = [a for a in o["artifacts"] if a["role"] != "sbom"]

        def rename_wheel(o):
            next(a for a in o["artifacts"] if a["filename"].endswith(".whl"))["filename"] = "sv0cov-1.0.1-py3-none-any.whl"
            o["artifacts"].sort(key=lambda a: a["filename"].encode())

        cases = {
            "unknown-property": lambda o: o.update(extra=1),
            "missing-property": lambda o: o.pop("sbom_sha256"),
            "schema": lambda o: o.update(schema="sv0cov.release"),
            "version": lambda o: o.update(version="1.1"),
            "product": lambda o: o.update(product="sv0"),
            "tag-without-v": lambda o: o.update(release_tag="1.0.0"),
            "tag-prerelease": lambda o: o.update(release_tag="v1.0.0-rc1"),
            "tag-other-version": lambda o: o.update(release_tag="v1.0.1"),
            "commit-uppercase": lambda o: o.update(release_commit=o["release_commit"].upper()),
            "negative-epoch": lambda o: o.update(source_date_epoch=-1),
            "sbom-digest": lambda o: o.update(sbom_sha256="0" * 64),
            "unsorted-artifacts": lambda o: o["artifacts"].reverse(),
            "duplicate-artifact": lambda o: o["artifacts"].insert(0, copy.deepcopy(o["artifacts"][0])),
            "no-sbom": drop_sbom,
            "wheel-version": rename_wheel,
            "bad-role": lambda o: o["artifacts"][0].update(role="binary"),
            "artifact-extra-key": lambda o: o["artifacts"][0].update(url="x"),
            "self-listed": lambda o: o["artifacts"].append({**o["artifacts"][0], "filename": "sv0cov-1.0.0.release.json"}),
            "sums-listed": lambda o: o["artifacts"].insert(0, {**o["artifacts"][0], "filename": "SHA256SUMS"}),
            "issuer": lambda o: o["attestation_policy"].update(expected_issuer="https://example.invalid"),
            "offline-optional": lambda o: o["attestation_policy"].update(offline_bundle_retention=False),
            "fork-repository": lambda o: o["attestation_policy"].update(repository="someone/sv0cov"),
        }
        for name, fn in cases.items():
            with self.subTest(case=name), self.assertRaises(R.ReleaseError):
                R.validate_manifest(self.mutate(fn))
        with self.assertRaises(R.ReleaseError):
            R.validate_manifest(MANIFEST.replace(b'"product":"sv0cov"', b'"product":"sv0cov" '))
        stale = json.loads(MANIFEST)
        stale["source_date_epoch"] += 1
        with self.assertRaises(R.ReleaseError):
            R.validate_manifest(encode(stale))

    def test_reconcile_detects_disagreement(self) -> None:
        sums = R.parse_sums(SUMS)
        for name, change in {
            "missing": lambda s: s.pop("INSTALL.md"),
            "extra": lambda s: s.update({"extra.txt": "c" * 64}),
            "digest": lambda s: s.update({"INSTALL.md": "c" * 64}),
            "manifest-digest": lambda s: s.update({"sv0cov-1.0.0.release.json": "c" * 64}),
        }.items():
            with self.subTest(case=name):
                s = dict(sums)
                change(s)
                with self.assertRaises(R.ReleaseError):
                    R.reconcile(MANIFEST, R.encode_sums(s))


if __name__ == "__main__":
    unittest.main()
