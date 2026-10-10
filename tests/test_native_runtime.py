# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Native coverage runtime: arena, transport, flush, publication (CV-114,
CV-115; SPEC 14.1-14.3, 16.4, 23.4).

Builds runtime/c/sv0cov_rt.c twice with the host C compiler: strictly as a
production object (C11, -Wall -Wextra -Werror -pedantic, no test hooks),
and with -DSV0COV_RT_TESTING linked into runtime/c/tests/rt_driver.c. Each
driver run is one process with its own environment: it registers a 70-counter
fixture program, prints "user-code" where a generated main would enter the
user program, and reports the runtime state.

COV-INS-005 (saturation), COV-INS-006/009 (relaxed atomic saturating CAS and
overflow bitmap, under contention), COV-C-005/006 (registration matrix,
zero-counter program), COV-FMT-031 (nonzero OS-entropy profile ID, no
fallback), COV-FMT-035 (exact run-ID decoding), SPEC 14.3 (the four
transport names, required mode, no values in diagnostics); CV-115:
COV-INS-007 (normal exit and exit(1) flush one complete profile, decoded
by sv0cov.formats.rawprofile), COV-INS-008 (SIGKILL and _exit publish
nothing and leave no temporary), SPEC 23.4 (mode 0600, <run>-<profile>
name, no-replace commit: a collision is COV2112 and leaves the existing
file alone), and a forked child never publishing inherited counters;
CV-116 (F0-G8, COV-FMT-007): with fixture-supplied IDs the C writer's bytes
equal every CV-024 golden (the VM goldens through a test-only backend-flag
override) and sv0cov.formats.rawprofile.encode for 40 seeded random native
profiles (sizes, sparse and saturated counts, absent/empty/UTF-8 context).
"""

from __future__ import annotations

import json
import itertools
import os
import random
import re
import stat
import sys
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RT = ROOT / "runtime" / "c"
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.rawprofile import RawProfile, decode, encode  # noqa: E402

GOLDEN_DIR = ROOT / "tests" / "fixtures" / "rawprofile"

MAP_ID = bytes.fromhex("4f5da9345b6f601cba7b19e442e4b26352c18a1fb2044e8141685a2915b81b6c")
RUN_ID = "0123456789abcdef0123456789abcdef"
MAX = 2**64 - 1
REPORT = re.compile(
    r"^state=(\d) required=(\d) run_id=([0-9a-f]{32}) profile_id=([0-9a-f]{32}) "
    r"context=(absent|len:\d+:[0-9a-f]*) counts=([0-9,]*) overflow=([01,]*)$"
)


def cc() -> str | None:
    return os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")


class NativeRuntimeTest(unittest.TestCase):
    tmp: tempfile.TemporaryDirectory
    driver: Path
    profile_dir: str

    @classmethod
    def setUpClass(cls) -> None:
        compiler = cc()
        if compiler is None:
            raise unittest.SkipTest("no C compiler on this host")
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        strict = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic"]
        subprocess.run([*strict, "-c", str(RT / "sv0cov_rt.c"), "-o", str(t / "rt.o")], check=True)
        cls.driver = t / "rt_driver"
        subprocess.run([*strict, "-DSV0COV_RT_TESTING", "-pthread", "-o", str(cls.driver),
                        str(RT / "sv0cov_rt.c"), str(RT / "tests" / "rt_driver.c")], check=True)
        cls.profile_dir = str(t / "profiles")
        os.mkdir(cls.profile_dir)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def fresh_dir(self) -> str:
        return tempfile.mkdtemp(dir=self.tmp.name)

    def profiles(self, d: str) -> list[str]:
        return sorted(os.listdir(d))

    def run_driver(self, *args: str, env: dict | None = None, **transport) -> subprocess.CompletedProcess:
        """Run the driver with a clean SV0COV_* environment plus `transport`
        (None deletes a default: profile dir, run ID, required=1)."""
        base = {k: v for k, v in os.environ.items() if not k.startswith("SV0COV")}
        values = {"SV0COV_PROFILE_DIR": self.profile_dir, "SV0COV_RUN_ID": RUN_ID, "SV0COV_REQUIRED": "1"}
        values.update(transport)
        base.update({k: v for k, v in values.items() if v is not None})
        if env:
            base.update(env)
        return subprocess.run([str(self.driver), *args], capture_output=True, env=base, timeout=120)

    def report(self, p: subprocess.CompletedProcess) -> dict:
        lines = p.stdout.decode().splitlines()
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        m = REPORT.match(lines[-1])
        self.assertIsNotNone(m, lines)
        state, required, run_id, profile_id, context, counts, overflow = m.groups()
        return {
            "user_code": "user-code" in lines,
            "state": int(state), "required": int(required), "run_id": run_id, "profile_id": profile_id,
            "context": context,
            "counts": [int(x) for x in counts.split(",") if x],
            "overflow": [int(x) for x in overflow.split(",") if x],
            "stderr": p.stderr.decode(),
        }

    def assert_refused(self, p: subprocess.CompletedProcess, code: str, secret: str | None = None) -> None:
        """Required mode: one diagnostic with `code`, exit 1, user code never reached."""
        err = p.stderr.decode()
        self.assertEqual(p.returncode, 1, err)
        self.assertIn(f"error[{code}]", err)
        self.assertNotIn(b"user-code", p.stdout)
        if secret:
            self.assertNotIn(secret, err)

    # ── collection ─────────────────────────────────────────────────────────

    def test_counts_and_identity(self) -> None:
        r = self.report(self.run_driver("ok"))
        self.assertEqual((r["state"], r["required"], r["run_id"]), (1, 1, RUN_ID))
        self.assertEqual(r["counts"], [i % 5 + 1 for i in range(70)])
        self.assertEqual(r["overflow"], [0] * 70)
        self.assertEqual(r["context"], "absent")
        self.assertEqual(r["stderr"], "")
        self.assertNotEqual(r["profile_id"], "0" * 32)

    def test_profile_ids_are_fresh(self) -> None:
        ids = {self.report(self.run_driver("ok"))["profile_id"] for _ in range(5)}
        self.assertEqual(len(ids), 5)

    def test_saturation(self) -> None:
        r = self.report(self.run_driver("saturate"))
        self.assertEqual(r["counts"][3], MAX)
        self.assertEqual(r["counts"][65], MAX)
        self.assertEqual(r["counts"][66], MAX)
        # 3 overflowed after reaching MAX; 65 was hit at MAX (second bitmap
        # word); 66 reached MAX exactly but was never hit beyond it.
        self.assertEqual([i for i, o in enumerate(r["overflow"]) if o], [3, 65])
        self.assertEqual(r["state"], 1)

    def test_contended_counts_and_saturation(self) -> None:
        r = self.report(self.run_driver("threads"))
        self.assertEqual(r["counts"][0], 8 * 100000)
        self.assertEqual(r["counts"][1], MAX)
        self.assertEqual([i for i, o in enumerate(r["overflow"]) if o], [1])

    # ── CV-210: contention, saturation races, probes ───────────────────────

    def test_stress_counts_are_exact_and_repeatable(self) -> None:
        """AC-035: joined threads hitting one counter give the exact total;
        one counter per thread gives exact per-counter totals; every run
        gives the same counts."""
        runs = []
        for _ in range(3):
            r = self.report(self.run_driver("stress", "8", "100000"))
            self.assertEqual(r["state"], 1)
            runs.append(r["counts"])
        want = [0] * 70
        want[0] = 8 * 100000
        want[10:18] = [100000] * 8
        self.assertEqual(runs, [want] * 3)

    def test_saturation_race(self) -> None:
        """AC-036: two threads hitting a counter at UINT64_MAX - 1 always
        leave it at UINT64_MAX (never wrapped) with its overflow bit set, in
        every one of 2000 rounds; eight threads crossing the limit together
        do too; and the published profile reports both as saturated."""
        d = self.fresh_dir()
        p = self.run_driver("race-saturate", "2000", SV0COV_PROFILE_DIR=d)
        r = self.report(p)
        self.assertIn("race two_thread_failures=0 eight_thread_failures=0 trials=2000", p.stdout.decode())
        self.assertEqual((r["counts"][5], r["counts"][64]), (MAX, MAX))
        self.assertEqual([i for i, o in enumerate(r["overflow"]) if o], [5, 64])
        (name,) = self.profiles(d)
        prof = decode(Path(d, name).read_bytes(), map_counter_count=70, expected_map_id=MAP_ID)
        self.assertEqual(prof.counts, ((5, MAX), (64, MAX)))
        self.assertEqual(prof.saturated(), [5, 64])

    def test_lock_free_probe_and_alignment(self) -> None:
        """COV-INS-010: lock-freedom is probed and recorded, never assumed.
        The compile-time and run-time answers agree, and the counter and
        overflow storage is aligned for its atomic type. Coverage works the
        same whatever the answer (every other test runs on this host)."""
        out = self.run_driver("probe").stdout.decode()
        m = re.search(r"^probe lock_free_build=(\d) lock_free_runtime=(\d) counter_size=(\d+) storage_aligned=(\d)$",
                      out, re.M)
        self.assertIsNotNone(m, out)
        build, run, size, aligned = map(int, m.groups())
        self.assertIn(build, (0, 1, 2))  # ATOMIC_LLONG_LOCK_FREE: never, sometimes, always
        self.assertIn(run, (0, 1))
        if build == 2:
            self.assertEqual(run, 1)
        if build == 0:
            self.assertEqual(run, 0)
        self.assertEqual(aligned, 1)
        self.assertGreaterEqual(size, 8)
        import platform
        print(f"\nsv0cov atomics probe: {platform.system()} {platform.machine()} cc={cc()} "
              f"lock_free_build={build} lock_free_runtime={run} counter_size={size}", file=sys.stderr)

    def test_unjoined_worker_never_tears_the_profile(self) -> None:
        """COV-INS-012: with a worker still hitting at exit, the run either
        publishes one valid profile or refuses with COV2011; never a torn or
        partial file."""
        for _ in range(5):
            d = self.fresh_dir()
            p = self.run_driver("unjoined", SV0COV_PROFILE_DIR=d)
            names = self.profiles(d)
            self.assertEqual([n for n in os.listdir(d) if n not in names], [])  # no temporary file left
            if names:
                (name,) = names
                decode(Path(d, name).read_bytes(), map_counter_count=70, expected_map_id=MAP_ID)
                self.assertEqual(p.returncode, 0, p.stderr.decode())
            else:
                # Required mode: a refused profile fails the process.
                self.assertIn("COV2011", p.stderr.decode())
                self.assertEqual(p.returncode, 1)

    def test_zero_counter_program(self) -> None:
        r = self.report(self.run_driver("zero"))
        self.assertEqual((r["state"], r["counts"], r["overflow"]), (1, [], []))

    def test_two_modules(self) -> None:
        r = self.report(self.run_driver("two-modules"))
        want = [0] * 70
        want[0], want[39], want[40], want[69] = 1, 1, 1, 2
        self.assertEqual((r["state"], r["counts"]), (1, want))

    def test_per_fragment_modules_in_every_order(self) -> None:
        """CV-206: one module per fragment (as sv0c emits), registered in all
        24 orders, initializes and counts module-local hits identically."""
        want = [0] * 70
        want[0] = want[39] = want[40] = want[69] = 1
        for perm in itertools.permutations("0123"):
            order = "".join(perm)
            with self.subTest(order):
                r = self.report(self.run_driver("per-fragment", order))
                self.assertEqual((r["state"], r["counts"]), (1, want))

    def test_per_fragment_registration_rejections(self) -> None:
        """CV-206 / COV-C-005: a later module with a wrong map, count, target,
        identity, or protocol; a cross-module overlap, gap, missing module, or
        out-of-range slice; a duplicated (also empty) fragment; a misplaced
        empty fragment; a module registered twice or missing: all fail before
        user code (required) or leave collection off (not required)."""
        kinds = ("map-id", "total", "target", "identity", "protocol", "overlap", "gap", "missing", "out-of-range",
                 "dup-fragment", "dup-empty-fragment", "empty-misplaced", "dup-module", "null-module")
        for kind in kinds:
            with self.subTest(kind):
                self.assert_refused(self.run_driver("bad-modules", kind), "COV1015")
                r = self.report(self.run_driver("bad-modules", kind, SV0COV_REQUIRED="0"))
                self.assertEqual(r["state"], 2)

    def test_hit_before_start_is_ignored(self) -> None:
        r = self.report(self.run_driver("hit-before-start"))
        self.assertEqual((r["state"], r["counts"]), (0, []))

    def test_bad_hits_make_the_run_incomplete(self) -> None:
        for scenario in ("bad-hit", "foreign-hit"):
            with self.subTest(scenario):
                d = self.fresh_dir()
                p = self.run_driver(scenario, SV0COV_PROFILE_DIR=d)
                # Required: the exit-time flush refuses and fails the process.
                self.assertEqual(p.returncode, 1)
                self.assertIn("error[COV2011]", p.stderr.decode())
                self.assertEqual(os.listdir(d), [])
                r = self.report(self.run_driver(scenario, SV0COV_REQUIRED="0", SV0COV_PROFILE_DIR=d))
                self.assertEqual(r["state"], 2)
                self.assertIn("error[COV2011]", r["stderr"])
                self.assertEqual(os.listdir(d), [])

    def test_second_start_is_refused(self) -> None:
        p = self.run_driver("twice")
        self.assertEqual(p.returncode, 1)
        self.assertIn("error[COV1015]", p.stderr.decode())
        self.assertNotIn(b"after-second-start", p.stdout)
        r = self.report(self.run_driver("twice", SV0COV_REQUIRED="0"))
        self.assertEqual(r["state"], 2)

    # ── transport ──────────────────────────────────────────────────────────

    def test_transport_rejections(self) -> None:
        cases = {
            "unknown name": {"SV0COV_TRESHOLD": "90"},
            "profile dir unset": {"SV0COV_PROFILE_DIR": None},
            "profile dir relative": {"SV0COV_PROFILE_DIR": "profiles"},
            "profile dir missing": {"SV0COV_PROFILE_DIR": self.profile_dir + "/nope"},
            "profile dir is a file": {"SV0COV_PROFILE_DIR": str(RT / "sv0cov_rt.c")},
            "run id unset": {"SV0COV_RUN_ID": None},
            "run id uppercase": {"SV0COV_RUN_ID": RUN_ID.upper()},
            "run id short": {"SV0COV_RUN_ID": RUN_ID[:31]},
            "run id long": {"SV0COV_RUN_ID": RUN_ID + "0"},
            "run id non-hex": {"SV0COV_RUN_ID": "g" + RUN_ID[1:]},
            "run id all zero": {"SV0COV_RUN_ID": "0" * 32},
            "run id spaced": {"SV0COV_RUN_ID": " " + RUN_ID[1:]},
            "required malformed": {"SV0COV_REQUIRED": "true"},
            "required empty": {"SV0COV_REQUIRED": ""},
            "context too long": {"SV0COV_CONTEXT": "x" * 257},
        }
        for name, transport in cases.items():
            with self.subTest(name):
                secret = next((v for v in transport.values() if v and len(v) > 3), None)
                env = {k: v for k, v in transport.items() if k == "SV0COV_TRESHOLD"}
                over = {k: v for k, v in transport.items() if k != "SV0COV_TRESHOLD"}
                self.assert_refused(self.run_driver("ok", env=env, **over), "COV2001",
                                    secret if name != "profile dir is a file" else None)

    def test_duplicate_name_is_rejected(self) -> None:
        self.assert_refused(self.run_driver("dup-env"), "COV2001")

    def test_invalid_utf8_context_is_rejected(self) -> None:
        for raw in (b"\xc0\xaf", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\xff"):
            with self.subTest(raw=raw):
                env = {k: v for k, v in os.environ.items() if not k.startswith("SV0COV")}
                envb = {k.encode(): v.encode() for k, v in env.items()}
                envb.update({b"SV0COV_PROFILE_DIR": self.profile_dir.encode(), b"SV0COV_RUN_ID": RUN_ID.encode(),
                             b"SV0COV_REQUIRED": b"1", b"SV0COV_CONTEXT": raw})
                p = subprocess.run([str(self.driver), "ok"], capture_output=True, env=envb, timeout=60)
                self.assert_refused(p, "COV2001")

    def test_context(self) -> None:
        self.assertEqual(self.report(self.run_driver("ok", SV0COV_CONTEXT=""))["context"], "len:0:")
        text = "shard é😀"
        r = self.report(self.run_driver("ok", SV0COV_CONTEXT=text))
        self.assertEqual(r["context"], f"len:{len(text.encode())}:{text.encode().hex()}")
        r = self.report(self.run_driver("ok", SV0COV_CONTEXT="y" * 256))
        self.assertEqual(r["context"], "len:256:" + "79" * 256)

    def test_not_required_continues_without_collecting(self) -> None:
        r = self.report(self.run_driver("ok", SV0COV_REQUIRED="0", SV0COV_RUN_ID="0" * 32))
        self.assertTrue(r["user_code"])
        self.assertEqual((r["state"], r["required"]), (2, 0))
        self.assertEqual(r["counts"], [])
        self.assertIn("error[COV2001]", r["stderr"])
        # Absent SV0COV_REQUIRED is not required either.
        r = self.report(self.run_driver("ok", SV0COV_REQUIRED=None, SV0COV_RUN_ID=None))
        self.assertEqual((r["state"], r["required"]), (2, 0))

    def test_no_transport_at_all(self) -> None:
        r = self.report(self.run_driver("ok", SV0COV_REQUIRED=None, SV0COV_RUN_ID=None, SV0COV_PROFILE_DIR=None))
        self.assertEqual(r["state"], 2)
        self.assertIn("SV0COV_PROFILE_DIR is not set", r["stderr"])

    # ── flush and publication (CV-115) ─────────────────────────────────────

    def published(self, d: str, report: dict) -> object:
        """The one complete profile in `d`, decoded against the fixture map."""
        names = self.profiles(d)
        self.assertEqual(names, [f"{RUN_ID}-{report['profile_id']}.sv0profraw"])
        path = os.path.join(d, names[0])
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        with open(path, "rb") as f:
            prof = decode(f.read(), map_counter_count=70, expected_map_id=MAP_ID)
        self.assertEqual((prof.run_id.hex(), prof.profile_id.hex(), prof.backend),
                         (RUN_ID, report["profile_id"], "native"))
        return prof

    def test_normal_exit_publishes_one_profile(self) -> None:
        d = self.fresh_dir()
        r = self.report(self.run_driver("ok", SV0COV_PROFILE_DIR=d, SV0COV_CONTEXT="shard-1"))
        prof = self.published(d, r)
        self.assertEqual(prof.context, "shard-1")
        self.assertEqual(list(prof.counts), [(i, i % 5 + 1) for i in range(70)])
        self.assertEqual(prof.saturated(), [])

    def test_sparse_counts_and_absent_context(self) -> None:
        d = self.fresh_dir()
        r = self.report(self.run_driver("two-modules", SV0COV_PROFILE_DIR=d))
        prof = self.published(d, r)
        self.assertIsNone(prof.context)
        self.assertEqual(list(prof.counts), [(0, 1), (39, 1), (40, 1), (69, 2)])

    def test_saturated_counts_carry_the_overflow_bitmap(self) -> None:
        d = self.fresh_dir()
        prof = self.published(d, self.report(self.run_driver("saturate", SV0COV_PROFILE_DIR=d)))
        # 66 reached UINT64_MAX exactly: the format marks every count at the
        # maximum, since the value is only a lower bound from then on.
        self.assertEqual(prof.saturated(), [3, 65, 66])

    def test_zero_counter_program_publishes_an_empty_profile(self) -> None:
        d = self.fresh_dir()
        r = self.report(self.run_driver("zero", SV0COV_PROFILE_DIR=d))
        with open(os.path.join(d, self.profiles(d)[0]), "rb") as f:
            prof = decode(f.read(), map_counter_count=0, expected_map_id=MAP_ID)
        self.assertEqual((prof.counts, prof.profile_id.hex()), ((), r["profile_id"]))

    def test_exit_1_path_publishes(self) -> None:
        # The sv0 runtime's panic and contract failures end with exit(1).
        d = self.fresh_dir()
        p = self.run_driver("exit1", SV0COV_PROFILE_DIR=d)
        self.assertEqual(p.returncode, 1)
        self.assertEqual(p.stderr, b"")
        report = REPORT.match(p.stdout.decode().splitlines()[-1])
        self.assertEqual(len(self.published(d, {"profile_id": report.group(4)}).counts), 70)

    def test_killed_or_underscore_exit_publishes_nothing(self) -> None:
        for scenario, want in (("kill", -9), ("underscore-exit", 0)):
            with self.subTest(scenario):
                d = self.fresh_dir()
                p = self.run_driver(scenario, SV0COV_PROFILE_DIR=d)
                self.assertEqual(p.returncode, want)
                self.assertIn(b"user-code", p.stdout)
                self.assertEqual(self.profiles(d), [])  # no profile, no temporary

    def test_collision_is_refused_and_keeps_the_existing_file(self) -> None:
        d = self.fresh_dir()
        p = self.run_driver("collide", SV0COV_PROFILE_DIR=d)
        self.assertEqual(p.returncode, 1)
        self.assertIn("error[COV2112]", p.stderr.decode())
        names = self.profiles(d)
        self.assertEqual(len(names), 1)
        with open(os.path.join(d, names[0]), "rb") as f:
            self.assertEqual(f.read(), b"occupied")
        p = self.run_driver("collide", SV0COV_PROFILE_DIR=self.fresh_dir(), SV0COV_REQUIRED="0")
        self.assertEqual(p.returncode, 0)
        self.assertIn("error[COV2112]", p.stderr.decode())

    def test_missing_directory_at_exit(self) -> None:
        for required, rc in (("1", 1), ("0", 0)):
            with self.subTest(required=required):
                d = self.fresh_dir()
                p = self.run_driver("rmdir", SV0COV_PROFILE_DIR=d, SV0COV_REQUIRED=required)
                self.assertEqual(p.returncode, rc)
                self.assertIn("error[COV2010]", p.stderr.decode())
                self.assertFalse(os.path.exists(d))

    def test_forked_child_does_not_publish(self) -> None:
        for required, child in (("1", 1), ("0", 0)):
            with self.subTest(required=required):
                d = self.fresh_dir()
                p = self.run_driver("fork", SV0COV_PROFILE_DIR=d, SV0COV_REQUIRED=required)
                self.assertEqual(p.returncode, 0, p.stderr.decode())
                self.assertIn(f"child-status={child}".encode(), p.stdout)
                self.assertIn("error[COV2120]", p.stderr.decode())
                report = REPORT.match([x for x in p.stdout.decode().splitlines() if x.startswith("state=")][0])
                self.published(d, {"profile_id": report.group(4)})  # the parent's, exactly one

    # ── writer byte parity (CV-116) ───────────────────────────────────────

    def write_profile(self, map_id: str, n: int, counts: list[tuple[int, int]], run_id: str, profile_id: str,
                      context: str | None, backend: str | None = None) -> bytes:
        """Run the driver's `write` scenario; return the one published profile's bytes."""
        d = self.fresh_dir()
        env = {"SV0COVRT_TEST_PROFILE_ID": profile_id}
        if backend is not None:
            env["SV0COVRT_TEST_BACKEND"] = backend
        p = self.run_driver("write", map_id, str(n), *(f"{i}={c}" for i, c in counts), env=env,
                            SV0COV_PROFILE_DIR=d, SV0COV_RUN_ID=run_id, SV0COV_CONTEXT=context)
        self.assertEqual((p.returncode, p.stderr), (0, b""))
        self.assertEqual(self.profiles(d), [f"{run_id}-{profile_id}.sv0profraw"])
        with open(os.path.join(d, self.profiles(d)[0]), "rb") as f:
            return f.read()

    def test_goldens_byte_parity(self) -> None:
        goldens = json.loads((GOLDEN_DIR / "goldens.json").read_text(encoding="utf-8"))["goldens"]
        self.assertEqual(len(goldens), 5)
        for g in goldens:
            with self.subTest(g["file"]):
                got = self.write_profile(g["map_id"], g["map_counter_count"], [tuple(c) for c in g["counts"]],
                                         g["run_id"], g["profile_id"], g["context"],
                                         None if g["backend"] == "native" else g["backend"])
                self.assertEqual(got, (GOLDEN_DIR / g["file"]).read_bytes())

    def test_random_profiles_match_the_python_writer(self) -> None:
        rng = random.Random(116)
        alphabet = "abcXYZ019 -_/.é€😀"
        for case in range(40):
            with self.subTest(case=case):
                n = rng.choice([0, 1, 2, 63, 64, 65, 127, 128, 129, rng.randrange(1, 300)])
                counts = []
                for i in range(n):
                    roll = rng.random()
                    if roll < 0.55:
                        continue
                    if roll < 0.9:
                        c = rng.randrange(1, 40)
                    elif roll < 0.95:
                        c = rng.randrange(1000, 2**64 - 1)
                    else:
                        c = 2**64 - 1
                    counts.append((i, c))
                ctx_roll = rng.random()
                if ctx_roll < 0.3:
                    context = None
                elif ctx_roll < 0.4:
                    context = ""
                else:
                    context = "".join(rng.choice(alphabet) for _ in range(rng.randrange(1, 60)))
                    while len(context.encode()) > 256:
                        context = context[:-1]
                map_id = rng.randbytes(32).hex()
                run_id = (b"\x01" + rng.randbytes(15)).hex()
                profile_id = (b"\x02" + rng.randbytes(15)).hex()
                want = encode(RawProfile(bytes.fromhex(map_id), bytes.fromhex(run_id), bytes.fromhex(profile_id),
                                         "native", context, tuple(counts)), n)
                self.assertEqual(self.write_profile(map_id, n, counts, run_id, profile_id, context), want)

    def test_production_build_ignores_the_parity_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "rt.o"
            subprocess.run([cc(), "-std=c11", "-c", str(RT / "sv0cov_rt.c"), "-o", str(obj)], check=True)
            data = obj.read_bytes()
        self.assertNotIn(b"SV0COVRT_TEST_PROFILE_ID", data)
        self.assertNotIn(b"SV0COVRT_TEST_BACKEND", data)

    # ── registration ───────────────────────────────────────────────────────

    def test_registration_rejections(self) -> None:
        kinds = ("protocol", "map-id", "gap", "overlap", "short", "total", "dup-fragment", "fragment-id",
                 "identity", "no-fragments", "dup-module", "none")
        for kind in kinds:
            with self.subTest(kind):
                self.assert_refused(self.run_driver("bad-registration", kind), "COV1015")
                r = self.report(self.run_driver("bad-registration", kind, SV0COV_REQUIRED="0"))
                self.assertEqual(r["state"], 2)

    # ── entropy ────────────────────────────────────────────────────────────

    def test_entropy_failure_and_zero_id(self) -> None:
        for mode in ("fail", "zero"):
            with self.subTest(mode):
                p = self.run_driver("ok", env={"SV0COVRT_TEST_ENTROPY": mode})
                self.assert_refused(p, "COV2002")
                r = self.report(self.run_driver("ok", SV0COV_REQUIRED="0", env={"SV0COVRT_TEST_ENTROPY": mode}))
                self.assertEqual(r["state"], 2)

    def test_production_build_has_no_test_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            obj = Path(td) / "rt.o"
            subprocess.run([cc(), "-std=c11", "-c", str(RT / "sv0cov_rt.c"), "-o", str(obj)], check=True)
            data = obj.read_bytes()
        self.assertNotIn(b"SV0COVRT_TEST_ENTROPY", data)
        self.assertNotIn(b"sv0cov_rt_test_", data)



STANDARD = (4194304, 67108864)
LARGE = (16777216, 268435456)
PROTOCOL_MAX = (4294967295, 68719476736)


class TierTest(unittest.TestCase):
    """CV-211 (SPEC 16.4; COV-FMT-019, COV-FMT-020, COV-FMT-023): the runtime
    is compiled for one raw-profile tier (standard unless the build defines
    the ceilings) and refuses a map over its counter ceiling before user
    code and a profile over its byte ceiling before any file exists, both
    with COV6001, at the exact limits."""

    tmp: tempfile.TemporaryDirectory
    built: dict[tuple, Path]

    @classmethod
    def setUpClass(cls) -> None:
        if cc() is None:
            raise unittest.SkipTest("no C compiler on this host")
        cls.tmp = tempfile.TemporaryDirectory()
        cls.built = {}

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    def compile(self, tier: tuple[int, int] | None) -> subprocess.CompletedProcess:
        out = Path(self.tmp.name) / f"drv-{len(self.built)}-{tier}"
        defs = [] if tier is None else [f"-DSV0COV_TIER_MAX_COUNTERS={tier[0]}", f"-DSV0COV_TIER_MAX_BYTES={tier[1]}"]
        p = subprocess.run([cc(), "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", *defs, "-DSV0COV_RT_TESTING",
                            "-pthread", "-o", str(out), str(RT / "sv0cov_rt.c"), str(RT / "tests" / "rt_driver.c")],
                           capture_output=True, text=True)
        if p.returncode == 0:
            self.built[tier] = out
        return p

    def driver(self, tier: tuple[int, int] | None) -> Path:
        if tier not in self.built:
            p = self.compile(tier)
            self.assertEqual(p.returncode, 0, p.stderr[-600:])
        return self.built[tier]

    def run_tier(self, tier, *args: str, **over: str | None) -> tuple[subprocess.CompletedProcess, str]:
        d = tempfile.mkdtemp(dir=self.tmp.name)
        env = {k: v for k, v in os.environ.items() if not k.startswith("SV0COV")}
        values = {"SV0COV_PROFILE_DIR": d, "SV0COV_RUN_ID": RUN_ID, "SV0COV_REQUIRED": "1",
                  "SV0COVRT_TEST_PROFILE_ID": "00112233445566778899aabbccddeeff"}
        values.update(over)
        env.update({k: v for k, v in values.items() if v is not None})
        return subprocess.run([str(self.driver(tier)), *args], capture_output=True, env=env, timeout=600), d

    def accepted(self, tier, counters: int, *counts: str, **over) -> bytes:
        p, d = self.run_tier(tier, "write", MAP_ID.hex(), str(counters), *counts, **over)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        (name,) = os.listdir(d)
        self.assertTrue(name.endswith(".sv0profraw"))
        return Path(d, name).read_bytes()

    def refused(self, tier, counters: int, *counts: str, needle: str, **over) -> None:
        p, d = self.run_tier(tier, "write", MAP_ID.hex(), str(counters), *counts, **over)
        err = p.stderr.decode()
        self.assertEqual(p.returncode, 1, err)
        self.assertIn("error[COV6001]", err)
        self.assertIn(needle, err)
        self.assertEqual(os.listdir(d), [])  # no profile and no temporary file

    def test_standard_counter_boundary(self) -> None:
        data = self.accepted(None, STANDARD[0])
        self.assertEqual(decode(data, map_counter_count=STANDARD[0]).counts, ())
        self.refused(None, STANDARD[0] + 1, needle="the standard raw-profile tier this program was built for allows 4194304")
        # Defining the standard values explicitly is the same tier.
        self.refused(STANDARD, STANDARD[0] + 1, needle="the standard raw-profile tier")

    def test_large_counter_boundary_and_explicitness(self) -> None:
        """COV-FMT-019 / AC-055: only a build made for `large` takes more than
        the standard counters, up to exactly 16,777,216."""
        self.accepted(LARGE, STANDARD[0] + 1)
        self.accepted(LARGE, LARGE[0])
        self.refused(LARGE, LARGE[0] + 1, needle="the large raw-profile tier this program was built for allows 16777216")

    def test_tier_does_not_change_the_profile(self) -> None:
        """The same counts give the same bytes under every tier that admits them."""
        counts = ("0=3", "5=1", "69=18446744073709551615")
        want = self.accepted(None, 70, *counts, SV0COV_CONTEXT="shard é")
        for tier in (LARGE, (70, 4096), PROTOCOL_MAX):
            with self.subTest(tier=tier):
                self.assertEqual(self.accepted(tier, 70, *counts, SV0COV_CONTEXT="shard é"), want)

    def test_custom_counter_boundary(self) -> None:
        self.accepted((70, 4096), 70)
        self.refused((69, 4096), 70, needle="the custom raw-profile tier this program was built for allows 69")
        self.accepted((1, 4096), 1, "0=1")
        self.refused((1, 4096), 2, needle="allows 1")

    def test_custom_byte_boundary(self) -> None:
        """An encoded profile of exactly max_bytes is published; one byte more
        is refused before any file is created. 104 bytes of fixed fields, 12
        per nonzero counter, the context, and 8 per overflow word all count."""
        three = ("0=1", "1=1", "2=1")
        data = self.accepted((70, 140), 70, *three)          # 104 + 3 * 12
        self.assertEqual(len(data), 140)
        self.refused((70, 139), 70, *three, needle="the profile would be 140 bytes; the custom raw-profile tier allows 139")
        self.refused((70, 140), 70, *three, "3=1", needle="would be 152 bytes")
        self.refused((70, 140), 70, *three, needle="would be 142 bytes", SV0COV_CONTEXT="ab")
        self.assertEqual(len(self.accepted((70, 142), 70, *three, SV0COV_CONTEXT="ab")), 142)
        # A saturated counter adds the two-word overflow bitmap (70 counters).
        sat = ("0=18446744073709551615",)
        self.assertEqual(len(self.accepted((70, 132), 70, *sat)), 132)   # 104 + 12 + 16
        self.refused((70, 131), 70, *sat, needle="would be 132 bytes")
        # An empty profile is 104 bytes.
        self.assertEqual(len(self.accepted((70, 104), 70)), 104)
        self.refused((70, 103), 70, needle="would be 104 bytes")

    def test_not_required_refusal_publishes_nothing(self) -> None:
        p, d = self.run_tier((70, 139), "write", MAP_ID.hex(), "70", "0=1", "1=1", "2=1", SV0COV_REQUIRED="0")
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        self.assertIn("error[COV6001]", p.stderr.decode())
        self.assertEqual(os.listdir(d), [])

    def test_ceilings_must_be_explicit_positive_and_inside_the_protocol(self) -> None:
        """COV-FMT-020: a runtime cannot be built with a zero, negative, or
        over-protocol ceiling; the protocol maxima themselves are accepted."""
        for tier, needle in (((0, 4096), "SV0COV_TIER_MAX_COUNTERS must be"), ((PROTOCOL_MAX[0] + 1, 4096), "SV0COV_TIER_MAX_COUNTERS must be"),
                             ((70, 0), "SV0COV_TIER_MAX_BYTES must be"), ((70, PROTOCOL_MAX[1] + 1), "SV0COV_TIER_MAX_BYTES must be"),
                             ((-1, 4096), "SV0COV_TIER_MAX_COUNTERS must be")):
            with self.subTest(tier=tier):
                p = self.compile(tier)
                self.assertNotEqual(p.returncode, 0)
                self.assertIn(needle, p.stderr)
        self.accepted(PROTOCOL_MAX, 70, "0=1")


SANITIZERS = {
    "thread": (["-fsanitize=thread"], {"TSAN_OPTIONS": "halt_on_error=1:exitcode=66"}, "ThreadSanitizer"),
    "address+undefined": (["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"],
                          {"ASAN_OPTIONS": "exitcode=67", "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=1"},
                          "AddressSanitizer"),
}


class SanitizerTest(unittest.TestCase):
    """CV-210 (COV-INS-006, AC-035): the runtime under ThreadSanitizer and
    under AddressSanitizer + UndefinedBehaviorSanitizer. Every scenario must
    behave as in the plain build and the sanitizer must report nothing.

    A host whose compiler cannot build or run a sanitizer skips it, unless
    SV0COV_REQUIRE_SANITIZERS=1 (set in CI), which makes that a failure."""

    tmp: tempfile.TemporaryDirectory
    drivers: dict[str, Path]
    missing: dict[str, str]

    @classmethod
    def setUpClass(cls) -> None:
        compiler = cc()
        if compiler is None:
            raise unittest.SkipTest("no C compiler on this host")
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        cls.drivers, cls.missing = {}, {}
        for name, (flags, env, _) in SANITIZERS.items():
            out = t / ("drv-" + name.replace("+", "-"))
            argv = [compiler, "-std=c11", "-Wall", "-Wextra", "-Werror", "-pedantic", "-g", "-O1", *flags,
                    "-DSV0COV_RT_TESTING", "-pthread", "-o", str(out),
                    str(RT / "sv0cov_rt.c"), str(RT / "tests" / "rt_driver.c")]
            b = subprocess.run(argv, capture_output=True, text=True)
            if b.returncode != 0:
                cls.missing[name] = f"build failed: {b.stderr.strip()[-300:]}"
                continue
            d = tempfile.mkdtemp(dir=t)
            probe = subprocess.run([str(out), "ok"], capture_output=True, text=True, env=cls.env_for(name, d))
            if probe.returncode != 0 or "state=1" not in probe.stdout:
                cls.missing[name] = f"does not run: exit {probe.returncode} {probe.stderr.strip()[-300:]}"
                continue
            cls.drivers[name] = out

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    @classmethod
    def env_for(cls, name: str, profile_dir: str, **over: str) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items() if not k.startswith("SV0COV")}
        env.update({"SV0COV_PROFILE_DIR": profile_dir, "SV0COV_RUN_ID": RUN_ID, "SV0COV_REQUIRED": "1"})
        env.update(SANITIZERS[name][1])
        env.update(over)
        return env

    def driver(self, name: str) -> Path:
        if name in self.missing:
            if os.environ.get("SV0COV_REQUIRE_SANITIZERS") == "1":
                self.fail(f"{name} sanitizer is required here but unavailable: {self.missing[name]}")
            self.skipTest(f"{name} sanitizer unavailable: {self.missing[name]}")
        return self.drivers[name]

    def run_clean(self, name: str, *args: str, want_rc: int = 0, **over: str) -> subprocess.CompletedProcess:
        d = tempfile.mkdtemp(dir=self.tmp.name)
        p = subprocess.run([str(self.driver(name)), *args], capture_output=True, text=True,
                           env=self.env_for(name, d, **over), timeout=600)
        err = p.stderr
        for marker in ("ThreadSanitizer", "AddressSanitizer", "LeakSanitizer", "runtime error:", "UndefinedBehaviorSanitizer"):
            self.assertNotIn(marker, err, f"{name} {args}: {err[-1500:]}")
        self.assertEqual(p.returncode, want_rc, f"{name} {args}: {err[-800:]}")
        return p

    def scenarios(self, name: str) -> None:
        p = self.run_clean(name, "stress", "8", "20000")
        counts = REPORT.match(p.stdout.splitlines()[-1]).group(6).split(",")
        self.assertEqual((counts[0], counts[10], counts[17]), (str(8 * 20000), "20000", "20000"))
        p = self.run_clean(name, "race-saturate", "200")
        self.assertIn("race two_thread_failures=0 eight_thread_failures=0", p.stdout)
        self.run_clean(name, "threads")
        self.run_clean(name, "saturate")
        self.run_clean(name, "two-modules")
        self.run_clean(name, "per-fragment", "3120")
        self.run_clean(name, "zero")
        self.run_clean(name, "probe")
        self.run_clean(name, "exit1", want_rc=1)
        self.run_clean(name, "bad-hit", want_rc=1)  # required: the refused profile fails the process
        self.run_clean(name, "ok", SV0COV_CONTEXT="shard é")
        # Refusals before user code: registration and transport.
        self.run_clean(name, "bad-registration", "gap", want_rc=1)
        self.run_clean(name, "bad-modules", "overlap", want_rc=1)
        self.run_clean(name, "ok", want_rc=1, SV0COV_RUN_ID="not-hex")

    def caught(self, name: str, kind: str, *markers: str) -> None:
        """The sanitizer build really is instrumented: it stops a deliberate
        fault, reporting it with one of `markers` (which sanitizer catches a
        fault first differs between GCC and Clang)."""
        d = tempfile.mkdtemp(dir=self.tmp.name)
        p = subprocess.run([str(self.driver(name)), "selfcheck", kind], capture_output=True, text=True,
                           env=self.env_for(name, d), timeout=600)
        self.assertNotEqual(p.returncode, 0, f"{name} did not stop a deliberate {kind} fault")
        self.assertTrue(any(m in p.stderr for m in markers), p.stderr[-800:])

    def test_thread_sanitizer(self) -> None:
        self.caught("thread", "race", "ThreadSanitizer: data race")
        self.scenarios("thread")
        # A worker still hitting during the exit-time flush is not a data
        # race: the profile is published whole or refused (not required here).
        self.run_clean("thread", "unjoined", SV0COV_REQUIRED="0")

    def test_address_and_undefined_sanitizers(self) -> None:
        self.caught("address+undefined", "heap", "AddressSanitizer: heap-buffer-overflow",
                    "insufficient space for an object")  # GCC's UBSan bounds check fires first
        self.caught("address+undefined", "overflow", "signed integer overflow")
        self.scenarios("address+undefined")


if __name__ == "__main__":
    unittest.main()
