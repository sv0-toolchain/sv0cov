# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Console entry point.

No command is implemented yet. Every invocation is an invocation error
(exit 2, SPEC 20.3) until the command slices land.
"""

from __future__ import annotations

import sys


def main(argv: list[str] | None = None) -> int:
    del argv
    sys.stderr.write("sv0cov: no commands are implemented yet (pre-F0)\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
