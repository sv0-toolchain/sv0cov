#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Generate the launchers' bootstrap diagnostic block (CV-031; SPEC 20.6.4).

The block in ``scripts/sv0cov-python`` between the BEGIN/END GENERATED
markers carries the registry identity and the title and severity of the five
bootstrap codes, taken from the installed registry. ``scripts/sv0cov`` is a
byte-identical copy. The launcher's rendering is byte-compared with the
Python renderer in ``tests/test_launcher.py``.

    python3 tools/launchergen.py            # check (exit 1 if stale)
    python3 tools/launchergen.py --write
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.diagnostics import load_registry  # noqa: E402

CODES = ("COV0016", "COV5001", "COV6001", "COV6002", "COV8001")
SOURCE = ROOT / "scripts" / "sv0cov-python"
COPY = ROOT / "scripts" / "sv0cov"
BEGIN = "# BEGIN GENERATED BOOTSTRAP DIAGNOSTICS (tools/launchergen.py; do not edit)\n"
END = "# END GENERATED BOOTSTRAP DIAGNOSTICS\n"
SAFE = re.compile(r"[A-Za-z0-9 ,.()-]+")


def block() -> str:
    reg = load_registry()
    lines = [f"REGISTRY_REVISION={reg.revision}\n", f"REGISTRY_SHA256={reg.sha256}\n"]
    for code in CODES:
        entry = reg.entry(code)
        for value in (entry.title, entry.default_severity):
            if not SAFE.fullmatch(value):  # must need no JSON or shell escaping
                raise SystemExit(f"launchergen: {code} text {value!r} needs escaping")
        lines += [f"TITLE_{code}='{entry.title}'\n", f"SEVERITY_{code}='{entry.default_severity}'\n"]
    return "".join(lines)


def render() -> bytes:
    text = SOURCE.read_text(encoding="utf-8")
    head, rest = text.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    return (head + BEGIN + block() + END + tail).encode("utf-8")


def main() -> int:
    data = render()
    if "--write" in sys.argv:
        for path in (SOURCE, COPY):
            path.write_bytes(data)
            path.chmod(0o755)
        print("launchers: written")
        return 0
    stale = [str(p.relative_to(ROOT)) for p in (SOURCE, COPY) if not p.is_file() or p.read_bytes() != data]
    if stale:
        print("stale launchers: " + ", ".join(stale), file=sys.stderr)
        return 1
    print("launchers: current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
