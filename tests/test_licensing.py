# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""License-map lint (SPEC COV-LIC-001..004, F0-G14).

Every project-owned file must declare its license, either with an in-file
SPDX-License-Identifier line near the top or with a REUSE.toml annotation. The
license texts themselves are pinned by SHA-256 so an edit is caught.
"""

from __future__ import annotations

import hashlib
import os
import subprocess
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SOFTWARE = "MIT OR Apache-2.0"
DOCUMENTATION = "CC-BY-4.0"

# Exact, unmodified license texts (COV-LIC-003).
LICENSE_TEXTS = {
    "LICENSE-MIT": "932f3d9186d95c5b0faeefcc48e20ebe99de0d67b1c860557224579edc0e8ab9",
    "LICENSE-APACHE": "406afd225f45ca38ffb02af11af08eba1e3b4ffb54e1a1316ba25178cbc331ea",
    "LICENSES/CC-BY-4.0.txt": "9e5f1b3c610b9c2da5c313bf81d577a7d1acec686bdb0384edefa6df0f90cd94",
}

# The expected license class per file suffix. A file whose suffix is absent
# here may use either class but must still declare one.
CLASS_BY_SUFFIX = {
    ".md": DOCUMENTATION,
    ".py": SOFTWARE,
    ".toml": SOFTWARE,
    ".c": SOFTWARE,
    ".h": SOFTWARE,
}

HEADER_LINES = 5


def project_files() -> list[str]:
    """Tracked plus untracked-but-not-ignored files, as POSIX relative paths."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        ).stdout
        names = [n for n in out.decode("utf-8").split("\0") if n]
    except (OSError, subprocess.CalledProcessError):
        names = []
        for dirpath, dirnames, filenames in os.walk(ROOT):
            dirnames[:] = [d for d in dirnames if d not in (".git", "__pycache__")]
            for f in filenames:
                names.append(Path(dirpath, f).relative_to(ROOT).as_posix())
    return sorted(n for n in names if (ROOT / n).is_file())


def reuse_annotations() -> dict[str, str]:
    data = tomllib.loads((ROOT / "REUSE.toml").read_text(encoding="utf-8"))
    result: dict[str, str] = {}
    for ann in data.get("annotations", []):
        paths = ann["path"]
        if isinstance(paths, str):
            paths = [paths]
        for p in paths:
            result[p] = ann["SPDX-License-Identifier"]
    return result


def header_license(path: Path) -> str | None:
    try:
        with path.open(encoding="utf-8") as f:
            head = [next(f, "") for _ in range(HEADER_LINES)]
    except UnicodeDecodeError:
        return None
    for line in head:
        marker = "SPDX-License-Identifier:"
        if marker in line:
            value = line.split(marker, 1)[1].strip()
            return value.removesuffix("-->").strip()
    return None


class LicensingTest(unittest.TestCase):
    def test_license_texts_are_exact(self) -> None:
        for rel, digest in LICENSE_TEXTS.items():
            with self.subTest(file=rel):
                data = (ROOT / rel).read_bytes()
                self.assertEqual(hashlib.sha256(data).hexdigest(), digest)

    def test_license_map_names_every_text(self) -> None:
        text = (ROOT / "LICENSE").read_text(encoding="utf-8")
        for rel in LICENSE_TEXTS:
            self.assertIn(rel, text)
        self.assertIn(SOFTWARE, text)
        self.assertIn(DOCUMENTATION, text)

    def test_every_file_declares_a_license(self) -> None:
        annotations = reuse_annotations()
        for rel in project_files():
            if rel in LICENSE_TEXTS:
                continue
            with self.subTest(file=rel):
                in_file = header_license(ROOT / rel)
                annotated = annotations.get(rel)
                self.assertFalse(
                    in_file and annotated,
                    "declared both in-file and in REUSE.toml",
                )
                declared = in_file or annotated
                self.assertIn(declared, (SOFTWARE, DOCUMENTATION))
                expected = CLASS_BY_SUFFIX.get(Path(rel).suffix)
                if expected is not None and annotated is None:
                    self.assertEqual(declared, expected)

    def test_annotations_name_existing_files(self) -> None:
        for rel in reuse_annotations():
            with self.subTest(file=rel):
                self.assertTrue((ROOT / rel).is_file())


if __name__ == "__main__":
    unittest.main()
