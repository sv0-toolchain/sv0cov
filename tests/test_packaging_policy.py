# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Packaging and dependency-source policy (CV-004, CV-005).

COV-PKG-016/018/019/020: the checked-in configuration passes, and each
single mutation that the SPEC forbids is rejected.
"""

from __future__ import annotations

import copy
import sys
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_packaging as cp  # noqa: E402

PYPROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
LOCK = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))


def mutated(fn) -> dict:
    py = copy.deepcopy(PYPROJECT)
    fn(py)
    return py


class PyprojectPolicyTest(unittest.TestCase):
    def test_checked_in_configuration_passes(self) -> None:
        self.assertEqual(cp.check_pyproject(PYPROJECT), [])
        self.assertEqual(cp.check_lock(LOCK), [])
        self.assertEqual(cp.check_tree(ROOT), [])

    def assert_rejected(self, fn) -> None:
        self.assertNotEqual(cp.check_pyproject(mutated(fn)), [])

    def test_runtime_dependency_rejected(self) -> None:
        self.assert_rejected(lambda p: p["project"].__setitem__("dependencies", ["attrs==25.1.0"]))

    def test_optional_extra_rejected(self) -> None:
        self.assert_rejected(lambda p: p["project"].__setitem__("optional-dependencies", {"x": []}))

    def test_dynamic_metadata_rejected(self) -> None:
        self.assert_rejected(lambda p: p["project"].__setitem__("dynamic", ["version"]))

    def test_missing_group_rejected(self) -> None:
        self.assert_rejected(lambda p: p["dependency-groups"].pop("fuzz"))

    def test_extra_dev_group_rejected(self) -> None:
        self.assert_rejected(lambda p: p["dependency-groups"].__setitem__("dev", []))

    def test_requirement_in_two_groups_rejected(self) -> None:
        self.assert_rejected(lambda p: p["dependency-groups"]["docs"].append("pytest==9.1.1"))

    def test_unpinned_requirement_rejected(self) -> None:
        self.assert_rejected(lambda p: p["dependency-groups"]["docs"].append("sphinx>=8"))

    def test_direct_reference_rejected(self) -> None:
        self.assert_rejected(
            lambda p: p["dependency-groups"]["docs"].append("sphinx @ https://example.invalid/sphinx.whl")
        )

    def test_second_index_rejected(self) -> None:
        self.assert_rejected(
            lambda p: p["tool"]["uv"]["index"].append({"name": "mirror", "url": "https://example.invalid/simple"})
        )

    def test_extra_index_url_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["uv"].__setitem__("extra-index-url", ["https://example.invalid"]))

    def test_uv_sources_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["uv"].__setitem__("sources", {"x": {"path": "../x"}}))

    def test_default_groups_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["uv"].__setitem__("default-groups", ["test"]))

    def test_index_strategy_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["uv"].__setitem__("index-strategy", "unsafe-best-match"))

    def test_other_backend_rejected(self) -> None:
        self.assert_rejected(lambda p: p["build-system"].__setitem__("build-backend", "setuptools.build_meta"))

    def test_unpinned_backend_rejected(self) -> None:
        self.assert_rejected(lambda p: p["build-system"].__setitem__("requires", ["hatchling>=1.30"]))

    def test_backend_group_mismatch_rejected(self) -> None:
        self.assert_rejected(lambda p: p["build-system"].__setitem__("requires", ["hatchling==1.30.0"]))

    def test_hatch_envs_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["hatch"].__setitem__("envs", {"default": {}}))

    def test_hatch_hooks_rejected(self) -> None:
        self.assert_rejected(lambda p: p["tool"]["hatch"]["build"].__setitem__("hooks", {"custom": {}}))

    def test_non_reproducible_target_rejected(self) -> None:
        self.assert_rejected(
            lambda p: p["tool"]["hatch"]["build"]["targets"]["wheel"].__setitem__("reproducible", False)
        )


class LockPolicyTest(unittest.TestCase):
    def test_non_registry_source_rejected(self) -> None:
        lock = copy.deepcopy(LOCK)
        pkg = next(p for p in lock["package"] if p["name"] == "pytest")
        pkg["source"] = {"git": "https://example.invalid/pytest.git"}
        self.assertNotEqual(cp.check_lock(lock), [])

    def test_missing_platform_wheels_rejected(self) -> None:
        lock = copy.deepcopy(LOCK)
        pkg = next(p for p in lock["package"] if p["name"] == "rpds-py")
        pkg["wheels"] = [w for w in pkg["wheels"] if "manylinux" in w["url"]]
        errors = cp.check_lock(lock)
        self.assertTrue(any("macos" in e for e in errors), errors)

    def test_unhashed_wheel_does_not_count(self) -> None:
        wheels = [{"url": "https://x/pytest-9.1.1-py3-none-any.whl", "hash": ""}]
        self.assertEqual(cp.wheel_cells(wheels), set())

    def test_ambient_override_rejected(self) -> None:
        self.assertNotEqual(cp.check_environment({"UV_EXTRA_INDEX_URL": "https://example.invalid"}), [])
        self.assertEqual(cp.check_environment({"HOME": "/x"}), [])


class WheelMetadataTest(unittest.TestCase):
    META = "Metadata-Version: 2.4\nName: sv0cov\nVersion: 0.0.0\nLicense-Expression: MIT OR Apache-2.0\n"
    WHEEL = "Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n"
    EP = "[console_scripts]\nsv0cov = sv0cov.cli:main\n"

    def test_valid(self) -> None:
        self.assertEqual(cp.check_wheel_metadata(self.META, self.WHEEL, self.EP), [])

    def test_requires_dist_rejected(self) -> None:
        self.assertNotEqual(cp.check_wheel_metadata(self.META + "Requires-Dist: attrs\n", self.WHEEL, self.EP), [])

    def test_extra_rejected(self) -> None:
        self.assertNotEqual(cp.check_wheel_metadata(self.META + "Provides-Extra: x\n", self.WHEEL, self.EP), [])

    def test_platform_tag_rejected(self) -> None:
        wheel = self.WHEEL.replace("py3-none-any", "cp313-cp313-macosx_14_0_arm64")
        self.assertNotEqual(cp.check_wheel_metadata(self.META, wheel, self.EP), [])

    def test_missing_entry_point_rejected(self) -> None:
        self.assertNotEqual(cp.check_wheel_metadata(self.META, self.WHEEL, "[console_scripts]\n"), [])


if __name__ == "__main__":
    unittest.main()
