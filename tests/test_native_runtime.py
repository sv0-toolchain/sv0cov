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


if __name__ == "__main__":
    unittest.main()
