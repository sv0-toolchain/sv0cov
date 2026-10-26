#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Record this host's 64-bit atomics probe (CV-422; SPEC 14.2;
COV-INS-010): whether the native runtime's counters are lock-free, at
build time and at run time, never assumed.

    python3 tools/atomics_probe.py [--out FILE]

Builds runtime/c/sv0cov_rt.c with the test driver (the same build the
runtime tests use) with the host C compiler ($CC, else cc, clang, gcc), runs
its ``probe`` scenario, and writes one ``sv0cov-atomics-probe`` record:

- ``host``: platform system and machine;
- ``compiler``: the command and the first line of its ``--version``;
- ``runtime_sha256``: the runtime source the answer is for;
- ``lock_free_build``: ``ATOMIC_LLONG_LOCK_FREE`` (0 never, 1 sometimes,
  2 always);
- ``lock_free_runtime``: ``atomic_is_lock_free`` on the counter type
  (1 or 0);
- ``counter_size``: bytes per counter; ``storage_aligned``: the counter and
  overflow arrays are aligned for their atomic type.

CI runs it on every host class and keeps the record as a build artifact;
``docs/generated-c-protocol.md`` carries the table, which the tests check
against this host's record. Coverage means the same whatever the answer.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RT = ROOT / "runtime" / "c"
RUN_ID = "0123456789abcdef0123456789abcdef"
PROBE = re.compile(r"^probe lock_free_build=(\d) lock_free_runtime=(\d) counter_size=(\d+) storage_aligned=(\d)$", re.M)


def compiler() -> str | None:
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


def probe() -> dict:
    cc = compiler()
    if cc is None:
        raise SystemExit("atomics probe: no C compiler on this host")
    version = subprocess.run([cc, "--version"], capture_output=True, text=True).stdout.splitlines()
    with tempfile.TemporaryDirectory() as t:
        driver = Path(t, "rt_driver")
        subprocess.run([cc, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-DSV0COV_RT_TESTING", "-pthread",
                        "-o", str(driver), str(RT / "sv0cov_rt.c"), str(RT / "tests" / "rt_driver.c")], check=True)
        os.mkdir(Path(t, "profiles"))
        env = {k: v for k, v in os.environ.items() if not k.startswith("SV0COV")}
        env.update({"SV0COV_PROFILE_DIR": str(Path(t, "profiles")), "SV0COV_RUN_ID": RUN_ID, "SV0COV_REQUIRED": "1"})
        p = subprocess.run([str(driver), "probe"], capture_output=True, text=True, env=env, timeout=60)
    m = PROBE.search(p.stdout)
    if p.returncode != 0 or m is None:
        raise SystemExit(f"atomics probe: the probe did not run (exit {p.returncode}): {p.stderr.strip()[-300:]}")
    build, run, size, aligned = map(int, m.groups())
    return {
        "record": "sv0cov-atomics-probe",
        "version": 1,
        "host": {"system": platform.system(), "machine": platform.machine()},
        "compiler": {"command": os.path.basename(cc), "version": version[0] if version else "unknown"},
        "runtime_sha256": hashlib.sha256((RT / "sv0cov_rt.c").read_bytes()).hexdigest(),
        "lock_free_build": build,
        "lock_free_runtime": run,
        "counter_size": size,
        "storage_aligned": aligned == 1,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="write the record here instead of standard output")
    args = ap.parse_args(argv)
    text = json.dumps(probe(), indent=1, sort_keys=True) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
