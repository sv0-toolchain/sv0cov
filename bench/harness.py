#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Benchmark harness (CV-035; SPEC 24, COV-PERF-001/005/007).

Runs paired coverage-off/coverage-on measurements under the frozen
``bench/protocol.json`` and writes one canonical raw-result bundle
(``sv0cov.benchmark-results`` 1.0). The protocol's SHA-256 is pinned here;
the harness refuses to run against any other protocol bytes, so warmup,
sample count, ordering, retries, and invalidation cannot drift after results
are seen.

A run plan is JSON: ``{"corpus": {...}, "fixtures": [fixture, ...]}`` where a
fixture is::

    {"id": "...", "category": "...", "cwd": "<dir>",
     "arms": {"off": {"argv": [...], "expect": {"exit_code": 0, "stdout_sha256": "..."}},
              "on": {...} | null}}

``stdout_sha256`` may be null when a fixture validates only its exit code.
The plan is produced by ``bench/corpus.py plan``; the harness never invents
commands.

    python3 bench/harness.py run --plan plan.json --stage managed-ci-provisional --out results.json
    python3 bench/harness.py host --stage managed-ci-provisional
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402

PROTOCOL_FILE = ROOT / "bench" / "protocol.json"
PROTOCOL_SHA256 = "e630003f16f609f08fb5a7f3cdb4ec9ac982cf6d608599855457b302b0bdb67e"
STAGES = ("managed-ci-provisional", "reference-dedicated", "local-development")
UNKNOWN = "unknown"
DESCRIPTOR_KEYS = (
    "architecture", "clock_source", "c_compiler", "cpu_model", "filesystem", "installed_memory_bytes", "isolation",
    "kernel", "libc", "logical_cpus", "os_build", "os_name", "os_version", "physical_cpus", "power_mode",
    "provider", "python", "runner_image", "runner_label", "stage", "storage_class", "throttling_check",
    "toolchain_revision", "virtualization",
)


class HarnessError(Exception):
    pass


# --- protocol ---------------------------------------------------------------


def load_protocol(path: Path = PROTOCOL_FILE) -> dict:
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != PROTOCOL_SHA256:
        raise HarnessError("bench/protocol.json does not match the frozen protocol digest")
    return decode_canonical(data)


def slot_order(slot: int, arms: list[str]) -> list[str]:
    """Counterbalanced ABBA: even slots run off then on, odd slots on then off."""
    if arms == ["off"]:
        return ["off"]
    return ["off", "on"] if slot % 2 == 0 else ["on", "off"]


# --- host descriptor --------------------------------------------------------


def _run_text(argv: list[str]) -> str:
    exe = argv[0]
    if not os.path.isabs(exe) or not os.access(exe, os.X_OK):
        return UNKNOWN
    try:
        out = subprocess.run(argv, capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return UNKNOWN
    return out.splitlines()[0].strip() if out else UNKNOWN


def _cpu_model() -> str:
    if sys.platform == "darwin":
        return _run_text(["/usr/sbin/sysctl", "-n", "machdep.cpu.brand_string"])
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith(("model name", "cpu model")):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return UNKNOWN


def _memory_bytes() -> int | str:
    if sys.platform == "darwin":
        text = _run_text(["/usr/sbin/sysctl", "-n", "hw.memsize"])
        return int(text) if text.isdigit() else UNKNOWN
    try:
        for line in Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1]) * 1024
    except (OSError, ValueError):
        pass
    return UNKNOWN


def _physical_cpus() -> int | str:
    if sys.platform == "darwin":
        text = _run_text(["/usr/sbin/sysctl", "-n", "hw.physicalcpu"])
        return int(text) if text.isdigit() else UNKNOWN
    return UNKNOWN


def _os_version() -> str:
    if sys.platform == "darwin":
        return platform.mac_ver()[0] or UNKNOWN
    try:
        return platform.freedesktop_os_release().get("PRETTY_NAME", UNKNOWN)
    except OSError:
        return UNKNOWN


def host_descriptor(stage: str, toolchain_revision: str = UNKNOWN) -> dict:
    """Observed host facts; anything not observable is the string ``unknown``.

    Contains no absolute path, user name, or host name: the interpreter is
    identified by version, implementation, and executable digest.
    """
    if stage not in STAGES:
        raise HarnessError(f"stage must be one of {', '.join(STAGES)}")
    exe = os.path.realpath(sys.executable)
    with open(exe, "rb") as f:
        exe_digest = hashlib.file_digest(f, "sha256").hexdigest()
    uname = platform.uname()
    github = os.environ.get("GITHUB_ACTIONS") == "true"
    libc = platform.libc_ver()
    d = {
        "architecture": uname.machine or UNKNOWN,
        "clock_source": "time.perf_counter_ns",
        "c_compiler": _run_text(["/usr/bin/cc", "--version"]),
        "cpu_model": _cpu_model(),
        "filesystem": UNKNOWN,
        "installed_memory_bytes": _memory_bytes(),
        "isolation": "shared managed runner" if github else UNKNOWN,
        "kernel": uname.release or UNKNOWN,
        "libc": f"{libc[0]} {libc[1]}".strip() if libc[0] else ("darwin libSystem" if sys.platform == "darwin" else UNKNOWN),
        "logical_cpus": os.cpu_count() or UNKNOWN,
        "os_build": uname.version or UNKNOWN,
        "os_name": {"darwin": "macos", "linux": "linux"}.get(sys.platform, sys.platform),
        "os_version": _os_version(),
        "physical_cpus": _physical_cpus(),
        "power_mode": UNKNOWN,
        "provider": "github-actions" if github else UNKNOWN,
        "python": {"executable_sha256": exe_digest, "implementation": sys.implementation.name, "version": platform.python_version()},
        "runner_image": f"{os.environ.get('ImageOS', UNKNOWN)} {os.environ.get('ImageVersion', '')}".strip() if github else UNKNOWN,
        "runner_label": os.environ.get("SV0COV_RUNNER_LABEL", UNKNOWN),
        "stage": stage,
        "storage_class": UNKNOWN,
        "throttling_check": UNKNOWN,
        "toolchain_revision": toolchain_revision,
        "virtualization": "virtual machine" if github else UNKNOWN,
    }
    check_descriptor(d)
    return d


def check_descriptor(d: dict) -> None:
    if sorted(d) != sorted(DESCRIPTOR_KEYS):
        raise HarnessError("host descriptor must have exactly the descriptor keys")
    if d["stage"] not in STAGES:
        raise HarnessError("host descriptor has an unknown stage")
    for key, value in d.items():
        if key == "python":
            if sorted(value) != ["executable_sha256", "implementation", "version"]:
                raise HarnessError("python descriptor must have executable_sha256, implementation, version")
            continue
        if not (isinstance(value, str) and value) and not (isinstance(value, int) and not isinstance(value, bool) and value > 0):
            raise HarnessError(f"descriptor {key} must be a nonempty string or positive integer")
        if isinstance(value, str) and ("/Users/" in value or "/home/" in value):
            raise HarnessError(f"descriptor {key} contains a user path")


def series_key(d: dict) -> str:
    """Results join one trend series only when provider, label, image, and CPU agree."""
    return "|".join(str(d[k]) for k in ("provider", "runner_label", "os_name", "architecture", "cpu_model"))


# --- execution --------------------------------------------------------------


def _maxrss_bytes(ru_maxrss: int) -> int:
    return ru_maxrss if sys.platform == "darwin" else ru_maxrss * 1024


def run_once(argv: list[str], cwd: str, expect: dict, timeout: int) -> dict:
    """One measured process: wall time and its own max RSS (wait4), then validation."""
    with tempfile.TemporaryFile() as out:
        fired = threading.Event()
        try:
            start = time.perf_counter_ns()
            proc = subprocess.Popen(argv, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.DEVNULL)
        except OSError as exc:
            return {"detail": type(exc).__name__, "invalid": "spawn-failure"}

        def kill() -> None:
            fired.set()
            proc.kill()

        timer = threading.Timer(timeout, kill)
        timer.start()
        try:
            _, status, rusage = os.wait4(proc.pid, 0)
        finally:
            timer.cancel()
        elapsed = time.perf_counter_ns() - start
        proc.returncode = os.waitstatus_to_exitcode(status)
        if fired.is_set():
            return {"invalid": "timeout"}
        out.seek(0)
        data = out.read()
    result = {"exit_code": proc.returncode, "rss_bytes": _maxrss_bytes(rusage.ru_maxrss), "wall_ns": elapsed}
    if proc.returncode != expect["exit_code"]:
        result["invalid"] = "nonzero-or-unexpected-exit"
    elif expect.get("stdout_sha256") is not None and hashlib.sha256(data).hexdigest() != expect["stdout_sha256"]:
        result["invalid"] = "output-validation-failure"
    return result


def run_fixture(fixture: dict, protocol: dict) -> dict:
    arms = ["off"] if fixture["arms"].get("on") is None else ["off", "on"]
    warmup = protocol["samples"]["warmup_slots"]
    measured = protocol["samples"]["measured_slots"]
    attempts_max = protocol["retry"]["max_attempts_per_slot"]
    timeout = protocol["timeout_seconds"]
    slots = []
    invalid_slots = 0
    for slot in range(warmup + measured):
        attempts = []
        for _ in range(attempts_max):
            runs = {}
            for arm in slot_order(slot, arms):
                spec = fixture["arms"][arm]
                runs[arm] = run_once(spec["argv"], fixture["cwd"], spec["expect"], timeout)
            attempts.append({"order": slot_order(slot, arms), "runs": runs})
            if not any("invalid" in r for r in runs.values()):
                break
        valid = not any("invalid" in r for r in attempts[-1]["runs"].values())
        if not valid and slot >= warmup:
            invalid_slots += 1
        slots.append({"attempts": attempts, "slot": slot, "valid": valid, "warmup": slot < warmup})
    budget = protocol["retry"]["max_invalid_slots_basis_points"]
    fixture_valid = invalid_slots * 10000 <= measured * budget
    stats = {arm: statistics([s["attempts"][-1]["runs"][arm] for s in slots if s["valid"] and not s["warmup"]]) for arm in arms}
    result = {
        "arms": arms,
        "category": fixture["category"],
        "id": fixture["id"],
        "invalid_slots": invalid_slots,
        "slots": slots,
        "statistics": stats,
        "valid": fixture_valid,
    }
    if not fixture_valid:
        result["invalid"] = "invalid-slots-over-budget"
    if arms == ["off", "on"] and fixture_valid and stats["off"]["wall_ns"]["p95"]:
        result["overhead_p95_ratio_ppm"] = stats["on"]["wall_ns"]["p95"] * 1_000_000 // stats["off"]["wall_ns"]["p95"]
    return result


def nearest_rank(sorted_values: list[int], q_num: int, q_den: int) -> int:
    """Nearest-rank quantile q = q_num/q_den over sorted values (no interpolation)."""
    rank = max(1, -(-len(sorted_values) * q_num // q_den))
    return sorted_values[rank - 1]


def statistics(runs: list[dict]) -> dict:
    out = {}
    for key in ("wall_ns", "rss_bytes"):
        values = sorted(r[key] for r in runs)
        if not values:
            out[key] = {"count": 0}
            continue
        n = len(values)
        mean_num = sum(values)
        var = sum((v * n - mean_num) ** 2 for v in values) // (n * n * (n - 1)) if n > 1 else 0
        q1, q3 = nearest_rank(values, 1, 4), nearest_rank(values, 3, 4)
        iqr = q3 - q1
        out[key] = {
            "count": n,
            "iqr": iqr,
            "max": values[-1],
            "mean": mean_num // n,
            "median": nearest_rank(values, 1, 2),
            "min": values[0],
            "outliers": sum(1 for v in values if v < q1 - 3 * iqr or v > q3 + 3 * iqr),
            "p95": nearest_rank(values, 95, 100),
            "variance": var,
        }
    return out


# --- bundle -----------------------------------------------------------------


def run_plan(plan: dict, stage: str, toolchain_revision: str = UNKNOWN) -> bytes:
    protocol = load_protocol()
    host = host_descriptor(stage, toolchain_revision)
    results = [run_fixture(f, protocol) for f in plan["fixtures"]]
    if host_descriptor(stage, toolchain_revision) != host:
        raise HarnessError("host descriptor drifted during the campaign; results are invalid")
    bundle = {
        "conformance": stage == "reference-dedicated",
        "corpus": plan["corpus"],
        "fixtures": results,
        "host": host,
        "label": "provisional trend evidence; not performance conformance" if stage != "reference-dedicated" else "reference-dedicated evidence",
        "protocol_sha256": PROTOCOL_SHA256,
        "schema": "sv0cov.benchmark-results",
        "series": series_key(host),
        "version": "1.0",
    }
    data = encode(bundle)
    validate_bundle(data)
    return data


def validate_bundle(data: bytes) -> dict:
    b = decode_canonical(data)
    keys = ["conformance", "corpus", "fixtures", "host", "label", "protocol_sha256", "schema", "series", "version"]
    if sorted(b) != keys or b["schema"] != "sv0cov.benchmark-results" or b["version"] != "1.0":
        raise HarnessError("not an sv0cov.benchmark-results 1.0 bundle")
    if b["protocol_sha256"] != PROTOCOL_SHA256:
        raise HarnessError("bundle was produced under a different protocol")
    check_descriptor(b["host"])
    if b["conformance"] != (b["host"]["stage"] == "reference-dedicated"):
        raise HarnessError("only reference-dedicated bundles may claim conformance")
    if b["series"] != series_key(b["host"]):
        raise HarnessError("series key does not match the host descriptor")
    ids = [f["id"] for f in b["fixtures"]]
    if len(set(ids)) != len(ids):
        raise HarnessError("fixture ids must be unique")
    return b


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--plan", type=Path, required=True)
    r.add_argument("--stage", required=True, choices=STAGES)
    r.add_argument("--toolchain-revision", default=UNKNOWN)
    r.add_argument("--out", type=Path, required=True)
    h = sub.add_parser("host")
    h.add_argument("--stage", required=True, choices=STAGES)
    args = ap.parse_args()
    if args.cmd == "host":
        sys.stdout.buffer.write(encode(host_descriptor(args.stage)))
        return 0
    plan = json.loads(args.plan.read_bytes())
    data = run_plan(plan, args.stage, args.toolchain_revision)
    args.out.write_bytes(data)
    bad = [f["id"] for f in json.loads(data)["fixtures"] if not f["valid"]]
    print(f"harness: {len(json.loads(data)['fixtures'])} fixture(s), invalid: {bad or 'none'}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
