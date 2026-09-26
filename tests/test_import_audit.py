# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Production import-boundary audit (CV-033; COV-PKG-016, F0-G20, AC-121).

The audit must pass on this checkout and must fail whenever a third-party
import, dynamic loader, vendored tree, binary member, or poisoned site
module enters the production closure.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import import_audit as A  # noqa: E402

PYTHON = os.path.realpath(sys.executable)


class ImportAuditTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.src = self.tmp / "src"
        shutil.copytree(ROOT / "src", self.src, ignore=shutil.ignore_patterns("__pycache__"))
        shutil.copytree(ROOT / "registries", self.tmp / "registries")
        shutil.copy2(ROOT / "pyproject.toml", self.tmp / "pyproject.toml")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def append(self, rel: str, text: str) -> None:
        with open(self.src / "sv0cov" / rel, "a", encoding="utf-8") as f:
            f.write("\n" + text + "\n")

    def audit(self, **kw) -> list[str]:
        return A.audit(self.src, PYTHON, no_site=kw.pop("no_site", True), **kw)

    def test_checkout_is_clean(self) -> None:
        violations, modules = A.static_audit(ROOT / "src")
        self.assertEqual(violations, [])
        self.assertLessEqual({"sv0cov", "sv0cov.cli", "sv0cov.config", "sv0cov.formats.map"}, modules)
        self.assertEqual(A.audit(ROOT / "src", PYTHON, no_site=True), [])

    def test_third_party_import_is_caught_statically_and_at_runtime(self) -> None:
        pkg = self.src / "thirdparty_evil"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("VALUE = 1\n")
        self.append("config.py", "import thirdparty_evil")
        violations = self.audit()
        self.assertTrue(any("third-party import 'thirdparty_evil'" in v for v in violations), violations)
        self.assertTrue(any(v.startswith("runtime:") and "thirdparty_evil" in v for v in violations), violations)

    def test_missing_third_party_import_is_caught(self) -> None:
        self.append("formats/map.py", "try:\n    import yaml\nexcept ImportError:\n    yaml = None")
        self.assertTrue(any("'yaml'" in v for v in self.audit()))

    def test_dynamic_loading_is_caught(self) -> None:
        self.append("cli.py", 'import importlib.util\n_m = __import__("json")\nfrom importlib import import_module\nimport_module("json")')
        violations = self.audit()
        for needle in ("importlib.util", "__import__()", "import_module()"):
            self.assertTrue(any(needle in v for v in violations), (needle, violations))

    def test_installer_modules_are_caught(self) -> None:
        self.append("cli.py", "import ensurepip\nimport venv")
        violations = self.audit()
        self.assertTrue(any("'ensurepip'" in v for v in violations))
        self.assertTrue(any("'venv'" in v for v in violations))

    def test_vendored_tree_and_binary_member_are_caught(self) -> None:
        vendor = self.src / "sv0cov" / "_vendor"
        vendor.mkdir()
        (vendor / "six.py").write_text("X = 1\n")
        (self.src / "sv0cov" / "speedups.so").write_bytes(b"\x7fELF")
        violations = A.static_audit(self.src)[0]
        self.assertTrue(any("_vendor: vendored" in v for v in violations), violations)
        self.assertTrue(any("speedups.so: non-Python member" in v for v in violations), violations)

    def test_escaping_relative_import_is_caught(self) -> None:
        self.append("cli.py", "from .. import elsewhere")
        self.assertTrue(any("escapes the package" in v for v in A.static_audit(self.src)[0]))

    def test_poisoned_site_is_caught(self) -> None:
        site = self.tmp / "site"
        site.mkdir()
        (site / "evil_site.py").write_text("X = 1\n")
        (site / "zz-evil.pth").write_text("import evil_site\n")
        shadow = site / "sv0cov"
        shadow.mkdir()
        (shadow / "__init__.py").write_text("raise SystemExit('shadowed')\n")
        violations = self.audit(poison=site)
        self.assertTrue(any("evil_site" in v for v in violations), violations)
        self.assertFalse(any("loaded from outside the checkout" in v for v in violations), violations)

    def test_ambient_python_variables_are_ignored(self) -> None:
        shadow = self.tmp / "shadow"
        shadow.mkdir()
        (shadow / "json.py").write_text("raise SystemExit('shadowed json')\n")
        (shadow / "sitecustomize.py").write_text("import evil_site\n")
        env = {**os.environ, "PYTHONPATH": str(shadow), "PYTHONSTARTUP": str(shadow / "json.py")}
        r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "import_audit.py"), "--src", str(self.src), "--python", PYTHON, "--no-site"],
                           env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
