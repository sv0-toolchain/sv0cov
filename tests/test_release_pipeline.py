# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The release dry run (CV-243; SPEC 25.2.7, 25.2.7.1, 25.4; R0-G8,
COV-REL-001, COV-PKG-001, COV-PKG-007, COV-PKG-028).

Unit tests of ``tools/release.py`` and the build-info resource run
everywhere. ``DryRunTest`` checks a real dry-run directory: CI makes one with
``python tools/release.py dry-run "$RUNNER_TEMP/release"`` (it needs the
locked ``build`` group) and names it in ``SV0COV_RELEASE_DRY_RUN``; without
that variable those tests are skipped. Each test copies the directory, makes
one change, keeps ``SHA256SUMS`` and the release manifest consistent with it
where that matters, and requires ``verify`` to refuse the result.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import release as tool  # noqa: E402

from sv0cov import capabilities  # noqa: E402
from sv0cov.formats import compatibility, release as R  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.version_manifest import ManifestError  # noqa: E402

COMMIT = "0123456789abcdef0123456789abcdef01234567"
FACTS = {"commit": COMMIT, "version": "0.4.0", "tag": "v0.4.0", "tagged": False, "epoch": 1790000000}


class BuildInfoTest(unittest.TestCase):
    """SPEC 25.2.7.1 / COV-PKG-028."""

    def test_round_trip(self) -> None:
        data = capabilities.build_info(COMMIT)
        self.assertEqual(data, b'{"revision":"' + COMMIT.encode() + b'","schema":"sv0cov.build-info","version":"1.0"}\n')
        self.assertEqual(capabilities.read_build_info(data), COMMIT)

    def test_rejections(self) -> None:
        with self.assertRaises(ManifestError):
            capabilities.build_info("abc")
        good = decode_canonical(capabilities.build_info(COMMIT))
        for label, data in (("not canonical", b'{ "revision": "x" }\n'), ("extra key", encode({**good, "built": 1})),
                            ("other schema", encode({**good, "schema": "sv0cov.version"})), ("other version", encode({**good, "version": "2.0"})),
                            ("short revision", encode({**good, "revision": "abc"})), ("uppercase", encode({**good, "revision": COMMIT.upper()}))):
            with self.subTest(case=label), self.assertRaises(ManifestError):
                capabilities.read_build_info(data)

    def test_an_installed_distribution_reads_its_build_info(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "sv0cov"
            pkg.mkdir()
            with mock.patch.object(capabilities, "_is_checkout", lambda: False), \
                    mock.patch.object(capabilities, "__file__", str(pkg / "capabilities.py")):
                with self.assertRaises(ManifestError) as ctx:
                    capabilities.revision()  # a build without the release script is not a release
                self.assertIn("no release build-info", str(ctx.exception))
                (pkg / capabilities.BUILD_INFO).write_bytes(capabilities.build_info(COMMIT))
                self.assertEqual(capabilities.revision(), COMMIT)

    def test_it_is_never_tracked(self) -> None:
        ignored = (ROOT / "src" / ".gitignore").read_text()
        self.assertIn("sv0cov/_build_info.json", ignored.splitlines())
        self.assertFalse((ROOT / "src" / "sv0cov" / capabilities.BUILD_INFO).exists())


class ArchiveTest(unittest.TestCase):
    def test_reproducible_tar_gz(self) -> None:
        entries = {"b.txt": (0o644, b"b"), "a/run": (0o755, b"#!/bin/sh\n"), "tests/vendor/x/latest": (tool.LINK, b"../y")}
        one = tool.targz(entries, "p", 1790000000)
        self.assertEqual(one, tool.targz(dict(reversed(list(entries.items()))), "p", 1790000000))
        self.assertNotEqual(one, tool.targz(entries, "p", 1790000001))
        self.assertEqual(one[4:8], b"\0\0\0\0")  # gzip header carries no time
        with tarfile.open(fileobj=io.BytesIO(one)) as tf:
            members = tf.getmembers()
            self.assertEqual([m.name for m in members], ["p/a/run", "p/b.txt", "p/tests/vendor/x/latest"])
            self.assertTrue(all((m.mtime, m.uid, m.gid, m.uname, m.gname) == (1790000000, 0, 0, "", "") for m in members))
            self.assertEqual([m.mode for m in members[:2]], [0o755, 0o644])
            self.assertTrue(members[2].issym() and members[2].linkname == "../y")


class AttachmentTest(unittest.TestCase):
    manifest = {
        "artifact_versions": {f: ["1.0"] for f in sorted(tool.inv.ARTIFACT_FAMILIES)}, "backends": [], "bytecode_profiles": [],
        "commands": ["version"], "diagnostic_registry": {"revision": 2, "sha256": "a" * 64}, "features": [],
        "host": {"architecture": "arm64", "operating_system": "macos"},
        "implementation": {"language": "python", "revision": COMMIT, "runtime": {"name": "cpython", "version": "3.14.0"}},
        "supported_hosts": list(tool.inv.HOSTS), "supported_python_versions": ["3.13", "3.14"], "version": "1.0",
    }

    def test_the_proposed_policy_selects_the_release(self) -> None:
        policy = compatibility.validate_policy(tool.proposed_policy(self.manifest, FACTS))
        self.assertEqual((policy["expected_revision"], policy["expected_tool"]["version"]), (COMMIT, "0.4.0"))
        self.assertEqual((policy["required_commands"], policy["required_hosts"]), (["version"], list(tool.inv.HOSTS)))

    def test_the_matrix_names_no_host_or_runtime(self) -> None:
        data = tool.matrix(self.manifest, "0.4.0")
        self.assertNotIn(b"macos-arm64", data.replace(b'"macos-arm64",', b""))  # only in supported_hosts
        self.assertNotIn(b"3.14.0", data)
        self.assertNotIn(b"host", data.replace(b"supported_hosts", b""))

    def test_the_sbom_is_checked(self) -> None:
        sdist, wheel = b"sdist", b"wheel"
        data = tool.sbom(FACTS, sdist, wheel)
        tool.check_sbom(data, FACTS, sdist, wheel)
        doc = decode_canonical(data)
        self.assertEqual((doc["spdxVersion"], doc["creationInfo"]["created"]), ("SPDX-2.3", "2026-09-21T14:13:20Z"))
        for label, args in (("another sdist", (FACTS, b"other", wheel)), ("another version", ({**FACTS, "version": "0.4.1"}, sdist, wheel))):
            with self.subTest(case=label), self.assertRaises(tool.ReleaseFailure):
                tool.check_sbom(data, *args)
        broken = {**doc, "relationships": doc["relationships"] + [{"relatedSpdxElement": "SPDXRef-Nothing", "relationshipType": "CONTAINS",
                                                                     "spdxElementId": "SPDXRef-Package-sdist"}]}
        with self.assertRaises(tool.ReleaseFailure):
            tool.check_sbom(encode(broken), FACTS, sdist, wheel)

    def test_media_types(self) -> None:
        self.assertEqual([tool.media_type(n) for n in ("a.whl", "a.tar.gz", "CHANGELOG.md", "a.json", "a.spdx.json")],
                         ["application/zip", "application/gzip", "text/markdown", "application/json", "application/spdx+json"])


class ChannelLintTest(unittest.TestCase):
    """COV-PKG-001 / COV-PKG-007: no document sends users to another channel."""

    FORBIDDEN = re.compile(r"pip3? install|pipx (install|run)|uv (tool )?(add|install|run --with|pip install)|brew install|pypi\.org|"
                           r"test\.pypi|docker (pull|run)|apt(-get)? install|curl [^|\n]*\| *(ba)?sh", re.I)

    def test_documents(self) -> None:
        docs = [ROOT / "README.md", ROOT / "CHANGELOG.md", *sorted((ROOT / "docs").rglob("*.md"))]
        found = [f"{p.relative_to(ROOT)}:{n}: {line.strip()}" for p in docs for n, line in enumerate(p.read_text().splitlines(), 1)
                 if self.FORBIDDEN.search(line)]
        self.assertEqual(found, [])

    def test_the_pattern_catches_the_usual_spellings(self) -> None:
        for line in ("pip install sv0cov", "uv tool install sv0cov", "uv add sv0cov", "brew install sv0cov", "see https://pypi.org/project/sv0cov",
                     "curl -fsSL https://x/install.sh | sh"):
            self.assertRegex(line, self.FORBIDDEN)


@unittest.skipUnless(os.environ.get("SV0COV_RELEASE_DRY_RUN"), "set SV0COV_RELEASE_DRY_RUN to a dry-run directory (CI does)")
class DryRunTest(unittest.TestCase):
    def setUp(self) -> None:
        source = Path(os.environ["SV0COV_RELEASE_DRY_RUN"])
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.out = Path(tmp.name) / "out"
        shutil.copytree(source, self.out)
        man = R.validate_manifest(next(self.out.glob("*.release.json")).read_bytes())
        self.commit, self.version = man["release_commit"], R.tag_version(man["release_tag"])

    def verify(self) -> None:
        tool.verify(self.out, self.commit)

    def reseal(self, **digests: str) -> None:
        """Make SHA256SUMS and the manifest describe the files as they now are."""
        path = self.out / R.manifest_name(self.version)
        man = decode_canonical(path.read_bytes())
        for a in man["artifacts"]:
            data = (self.out / a["filename"]).read_bytes()
            a.update(sha256=hashlib.sha256(data).hexdigest(), size=len(data))
        by_name = {a["filename"]: a["sha256"] for a in man["artifacts"]}
        man["sbom_sha256"] = by_name[R.sbom_name(self.version)]
        man["compatibility_policy_sha256"] = by_name[f"sv0cov-{self.version}.compatibility-policy.json"]
        man["license_inventory_sha256"] = by_name[f"sv0cov-{self.version}.licenses.json"]
        man["evidence_manifest_sha256"] = by_name[f"sv0cov-{self.version}.evidence.json"]
        man.update(digests)
        data = R.seal_manifest(man)
        path.write_bytes(data)
        sums = {**by_name, path.name: hashlib.sha256(data).hexdigest()}
        (self.out / R.SUMS_NAME).write_bytes(R.encode_sums(sums))

    def assert_refused(self, change) -> None:
        change()
        with self.assertRaises((tool.ReleaseFailure, R.ReleaseError, compatibility.PolicyError)):
            self.verify()

    def test_the_dry_run_verifies(self) -> None:
        self.verify()
        names = sorted(p.name for p in self.out.iterdir())
        v = self.version
        self.assertEqual(names, sorted(["CHANGELOG.md", "SHA256SUMS", f"sv0cov-{v}-protocol.tar.gz", R.wheel_name(v), f"sv0cov-{v}-source.tar.gz",
                                        f"sv0cov-{v}.compatibility-matrix.json", f"sv0cov-{v}.compatibility-policy.json",
                                        f"sv0cov-{v}.evidence.json", f"sv0cov-{v}.licenses.json", R.manifest_name(v), R.sbom_name(v),
                                        R.sdist_name(v)]))
        with zipfile.ZipFile(self.out / R.wheel_name(v)) as zf:
            self.assertEqual(capabilities.read_build_info(zf.read("sv0cov/_build_info.json")), self.commit)

    def test_the_file_set(self) -> None:
        with self.subTest(case="an extra file"):
            self.assert_refused(lambda: (self.out / "extra.txt").write_text("x"))
            (self.out / "extra.txt").unlink()
        with self.subTest(case="a missing file"):
            self.assert_refused(lambda: (self.out / "CHANGELOG.md").unlink())

    def test_digests(self) -> None:
        wheel = self.out / R.wheel_name(self.version)
        self.assert_refused(lambda: wheel.write_bytes(wheel.read_bytes() + b"\0"))

    def test_resealed_changes(self) -> None:
        v = self.version
        cases = {
            "changelog": lambda: (self.out / "CHANGELOG.md").write_text("rewritten\n"),
            "policy for another commit": lambda: (self.out / f"sv0cov-{v}.compatibility-policy.json").write_bytes(compatibility.seal(
                {**compatibility.validate_policy((self.out / f"sv0cov-{v}.compatibility-policy.json").read_bytes()), "expected_revision": "f" * 40})),
            "license inventory": lambda: (self.out / f"sv0cov-{v}.licenses.json").write_bytes(encode({"files": []})),
            "sbom namespace": lambda: (self.out / R.sbom_name(v)).write_bytes(encode(
                {**decode_canonical((self.out / R.sbom_name(v)).read_bytes()), "documentNamespace": "https://example.invalid/spdx"})),
            "sbom comment": lambda: (self.out / R.sbom_name(v)).write_bytes(encode(
                {**decode_canonical((self.out / R.sbom_name(v)).read_bytes()), "comment": "edited"})),
            "matrix": lambda: (self.out / f"sv0cov-{v}.compatibility-matrix.json").write_bytes(encode({"product": "sv0cov"})),
            "source archive": lambda: (self.out / f"sv0cov-{v}-source.tar.gz").write_bytes(tool.targz({"x": (0o644, b"x")}, f"sv0cov-{v}", 0)),
            "protocol bundle": lambda: (self.out / f"sv0cov-{v}-protocol.tar.gz").write_bytes(tool.targz({}, f"sv0cov-{v}-protocol", 0)),
        }
        for label, change in cases.items():
            with self.subTest(case=label):
                self.setUp()
                change()
                self.reseal()
                with self.assertRaises((tool.ReleaseFailure, R.ReleaseError, compatibility.PolicyError)):
                    self.verify()

    def test_a_manifest_for_another_commit_or_epoch(self) -> None:
        for change in ({"release_commit": "f" * 40}, {"source_date_epoch": 1}):
            with self.subTest(change=change):
                self.setUp()
                self.reseal(**change)
                with self.assertRaises(tool.ReleaseFailure):
                    self.verify()

    def test_a_wheel_with_another_build_info(self) -> None:
        wheel = self.out / R.wheel_name(self.version)
        with zipfile.ZipFile(wheel) as zf:
            members = {n: zf.read(n) for n in zf.namelist()}
        members["sv0cov/_build_info.json"] = capabilities.build_info("f" * 40)
        with zipfile.ZipFile(wheel, "w") as zf:
            for n, data in members.items():
                zf.writestr(n, data)
        self.reseal()
        with self.assertRaises(tool.ReleaseFailure):
            self.verify()

    def test_sha256sums_grammar(self) -> None:
        sums = self.out / R.SUMS_NAME
        lines = sums.read_bytes().splitlines(keepends=True)
        self.assert_refused(lambda: sums.write_bytes(b"".join(reversed(lines))))


if __name__ == "__main__":
    unittest.main()
