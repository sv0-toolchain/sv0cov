#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The sv0cov CLI from this checkout, for the merge/report-scale fixtures'
timed commands (CV-427): ``python -I -B bench/sv0cov_cmd.py <command> ...``."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sv0cov.cli import main  # noqa: E402

sys.exit(main(sys.argv[1:]))
