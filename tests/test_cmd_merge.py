# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``merge`` command end to end (CV-227; SPEC 17, 20.1, 20.2;
COV-CLI-002, COV-CLI-006).

Real files in real directories go through the console entry point: input
discovery, destinations (default, explicit, stdout), collisions, run
selection, rejected inputs with and without the override, limits, and
streams.
"""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from test_cli import records  # noqa: E402
from test_indexed_reader import RUN_A, RUN_B, fixture_inputs, raw  # noqa: E402

from sv0cov import cli, cmd_merge  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.rawprofile import decode  # noqa: E402
from sv0cov.formats.runset import encode_run_set  # noqa: E402
from sv0cov.model.indexed import read_indexed  # noqa: E402
from sv0cov.model.merge import Artifact, merge  # noqa: E402

DEFAULT = ".sv0cov/coverage.sv0covdata.json"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.cwd = Path(tmp.name).resolve()
        self.map_bytes, self.m, self.counts = fixture_inputs("f0")
        self.inputs = self.cwd / "in"
        self.inputs.mkdir()

    def put(self, rel: str, data: bytes) -> Path:
        path = self.cwd / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        return path

    def profile(self, n: int, **kw) -> bytes:
        return raw(self.m, self.counts, n, **kw)

    def name(self, data: bytes) -> str:
        p = decode(data)
        return f"{p.run_id.hex()}-{p.profile_id.hex()}.sv0profraw"

    def seed(self, *profiles: bytes, where: str = "in") -> None:
        self.put(f"{where}/f0.sv0covmap.json", self.map_bytes)
        for data in profiles:
            self.put(f"{where}/{self.name(data)}", data)

    def run_merge(self, *args: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["merge", "--diagnostic-format=json-lines", *args], stdout=out, stderr=err, cwd=self.cwd)
        return code, out.getvalue(), err.getvalue()

    def tree(self) -> list[str]:
        return sorted(str(p.relative_to(self.cwd)) for p in self.cwd.rglob("*") if not str(p.relative_to(self.cwd)).startswith("in"))

    def codes(self, err: str) -> list[tuple[str, str | None]]:
        got = [(r["code"], next((f["value"] for f in r["facts"] if f["name"] == "name"), None)) for r in records(err)]
        return sorted(got, key=lambda x: (x[0], x[1] or ""))


class HappyPathTest(Base):
    def test_a_directory_merges_to_the_default_destination(self) -> None:
        one, two = self.profile(1), self.profile(2, context="shard-2", backend="vm-v1")
        self.seed(one, two)
        code, out, err = self.run_merge("in")
        self.assertEqual((code, err), (0, ""))
        final = self.cwd / DEFAULT
        data = final.read_bytes()
        obj = read_indexed(data)
        self.assertTrue(obj["semantic"]["complete"])
        self.assertEqual([r["name"] for r in obj["profile_inputs"]], sorted([self.name(one), self.name(two)],
                                                                            key=lambda n: hashlib.sha256((one if n == self.name(one) else two)).hexdigest()))
        self.assertEqual(obj["map_inputs"][0]["name"], "f0.sv0covmap.json")
        self.assertEqual(obj["execution"], {"exit_code": None, "signal": None, "status": "not_applicable"})
        # The command publishes exactly what the engine produces from those bytes.
        want = merge([Artifact("f0.sv0covmap.json", self.map_bytes)], [Artifact(self.name(one), one), Artifact(self.name(two), two)])
        self.assertEqual(data, want.data)
        self.assertEqual((stat.S_IMODE(final.stat().st_mode), stat.S_IMODE((self.cwd / ".sv0cov").stat().st_mode)), (0o600, 0o700))
        self.assertEqual(self.tree(), [".sv0cov", DEFAULT])
        self.assertEqual(out, f"merged 2 of 2 profiles over 1 maps: complete\nwrote {DEFAULT}\n")
        self.assertNotIn(str(self.cwd), data.decode())  # no absolute path is serialized

    def test_files_and_directories_mix_and_order_does_not_matter(self) -> None:
        one, two, three = self.profile(1), self.profile(2), self.profile(3)
        self.seed(one)
        self.put("more/f0.sv0covmap.json", self.map_bytes)
        self.put(f"more/{self.name(two)}", two)
        loose = self.put("loose/renamed.bin", three)  # a named file needs no suffix
        self.assertEqual(self.run_merge("in", "more", str(loose), "--output", "a.json")[0], 0)
        self.assertEqual(self.run_merge(str(loose), "more/f0.sv0covmap.json", f"more/{self.name(two)}", "in", "--output", "b.json")[0], 0)
        a, b = (self.cwd / "a.json").read_bytes(), (self.cwd / "b.json").read_bytes()
        self.assertEqual(a, b)
        obj = read_indexed(a)
        self.assertEqual((len(obj["profile_inputs"]), len(obj["map_inputs"])), (3, 1))
        self.assertIn("renamed.bin", [r["name"] for r in obj["profile_inputs"]])

    def test_a_named_symlink_is_read_and_the_map_ceiling_is_not_the_profile_ceiling(self) -> None:
        one = self.profile(1)
        self.seed(one)
        os.symlink(self.inputs / self.name(one), self.cwd / "alias.sv0profraw")
        os.symlink(self.inputs / "f0.sv0covmap.json", self.cwd / "alias.sv0covmap.json")
        self.assertEqual(self.run_merge("alias.sv0profraw", "alias.sv0covmap.json", "--output", "a.json")[0], 0)
        # A custom raw-profile ceiling far below the map's size does not reject the map (SPEC 16.3.9).
        self.assertLess(len(one), len(self.map_bytes))
        code, _, err = self.run_merge("in", "--output", "b.json", "--raw-profile-tier", "custom", "--raw-profile-max-counters",
                                      str(self.m["program_counter_count"]), "--raw-profile-max-bytes", str(len(one)))
        self.assertEqual((code, err), (0, ""))

    def test_the_same_path_twice_counts_once_and_is_reported(self) -> None:
        """AC-013."""
        self.seed(self.profile(1))
        code, out, err = self.run_merge("in", "in", f"in/{self.name(self.profile(1))}", "--output", "dup.json")
        self.assertEqual((code, err), (0, ""))
        self.assertIn("3 duplicate copies counted once", out)
        self.run_merge("in", "--output", "once.json")
        self.assertEqual((self.cwd / "dup.json").read_bytes(), (self.cwd / "once.json").read_bytes())

    def test_configuration_reaches_the_evidence(self) -> None:
        self.seed(self.profile(1))
        self.put("sv0.toml", b'[tool.sv0cov]\nschema = "1.0"\noutput_dir = "build/cov"\n[tool.sv0cov.limits.raw_profile]\ntier = "large"\n')
        self.assertEqual(self.run_merge("in")[0], 0)
        obj = read_indexed((self.cwd / "build/cov/coverage.sv0covdata.json").read_bytes(), tier="large")
        self.assertEqual(obj["merge"]["limits"]["tier"], "large")
        self.assertEqual(self.run_merge("in", "--output-dir", "other", "--raw-profile-tier", "standard", "--saturation-policy", "allow-ordinary")[0], 0)
        obj = read_indexed((self.cwd / "other/coverage.sv0covdata.json").read_bytes())
        self.assertEqual((obj["merge"]["limits"]["tier"], obj["semantic"]["saturation"]["policy"]), ("standard", "allow-ordinary"))

    def test_quiet_removes_the_summary_only(self) -> None:
        self.seed(self.profile(1))
        self.assertEqual(self.run_merge("in", "--quiet"), (0, "", ""))
        self.assertTrue((self.cwd / DEFAULT).is_file())


class StdoutTest(Base):
    def test_output_dash_writes_only_the_canonical_artifact(self) -> None:
        self.seed(self.profile(1))
        code, out, err = self.run_merge("in", "--output", "-")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(read_indexed(out.encode())["semantic"]["complete"], True)
        self.assertEqual(out.encode(), encode(read_indexed(out.encode())))
        self.assertEqual(self.tree(), [])  # nothing is written to disk
        self.run_merge("in", "--output", "file.json")
        self.assertEqual(out.encode(), (self.cwd / "file.json").read_bytes())

    def test_a_failed_merge_writes_nothing_to_stdout(self) -> None:
        self.seed(self.profile(1), self.profile(2, run=RUN_B))
        code, out, err = self.run_merge("in", "--output=-")
        self.assertEqual((code, out, self.codes(err)), (5, "", [("COV3003", None)]))

    def test_a_real_process_and_a_closed_stdout(self) -> None:
        self.seed(self.profile(1))
        boot = "import sys; sys.path.insert(0, sys.argv.pop(1)); from sv0cov.cli import main; sys.exit(main())"
        base = [sys.executable, "-I", "-B", "-c", boot, str(ROOT / "src"), "merge", "in", "--output", "-"]
        p = subprocess.run(base, cwd=self.cwd, capture_output=True, timeout=60)
        self.assertEqual((p.returncode, p.stderr), (0, b""))
        self.assertEqual(read_indexed(p.stdout)["semantic"]["complete"], True)
        r, w = os.pipe()
        os.close(r)
        try:
            p = subprocess.run(base, cwd=self.cwd, stdout=w, stderr=subprocess.PIPE, timeout=60)
        finally:
            os.close(w)
        self.assertEqual(p.returncode, 5)
        self.assertTrue(p.stderr.startswith(b"COV4011 "), p.stderr)


class DestinationTest(Base):
    def test_an_existing_destination_is_never_replaced(self) -> None:
        self.seed(self.profile(1))
        for dest, args in ((DEFAULT, []), ("out.json", ["--output", "out.json"])):
            with self.subTest(dest=dest):
                existing = self.put(dest, b"precious")
                inode = existing.stat().st_ino
                with mock.patch.object(cmd_merge, "collect", side_effect=AssertionError("inputs were read before the destination check")):
                    code, out, err = self.run_merge("in", *args)
                (rec,) = records(err)
                self.assertEqual((code, out, rec["code"], rec["phase"]), (5, "", "COV4010", "publication"))
                self.assertEqual((existing.read_bytes(), existing.stat().st_ino), (b"precious", inode))
        os.symlink("nowhere", self.cwd / "dangling.json")
        self.assertEqual(self.run_merge("in", "--output", "dangling.json")[0], 5)
        self.assertFalse((self.cwd / "nowhere").exists())

    def test_a_destination_that_appears_during_the_merge_is_still_a_collision(self) -> None:
        self.seed(self.profile(1))
        real = cmd_merge.merge

        def racing(*a, **k):
            self.put("late.json", b"theirs")
            return real(*a, **k)

        with mock.patch.object(cmd_merge, "merge", racing):
            code, _, err = self.run_merge("in", "--output", "late.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV4010", None)]))
        self.assertEqual((self.cwd / "late.json").read_bytes(), b"theirs")

    def test_explicit_parents_are_not_created_and_managed_symlinks_are_refused(self) -> None:
        self.seed(self.profile(1))
        code, _, err = self.run_merge("in", "--output", "missing/dir/out.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV4011", None)]))
        self.assertFalse((self.cwd / "missing").exists())
        elsewhere = self.cwd / "elsewhere"
        elsewhere.mkdir()
        os.symlink(elsewhere, self.cwd / ".sv0cov")
        code, _, err = self.run_merge("in")
        self.assertEqual((code, self.codes(err)), (5, [("COV6002", None)]))
        self.assertEqual(os.listdir(elsewhere), [])
        # An absolute explicit path is allowed.
        self.assertEqual(self.run_merge("in", "--output", str(elsewhere / "abs.json"))[0], 0)
        self.assertTrue((elsewhere / "abs.json").is_file())

    def test_a_failed_merge_leaves_no_directory_behind(self) -> None:
        self.put("in/f0.sv0covmap.json", self.map_bytes)
        self.assertEqual(self.run_merge("in")[0], 5)
        self.assertEqual(self.tree(), [])


class RejectionTest(Base):
    def test_one_bad_input_fails_the_merge_and_names_it(self) -> None:
        """AC-012, COV-MRG-001."""
        good, bad = self.profile(1), bytearray(self.profile(2))
        bad[-1] ^= 1
        self.seed(good)
        self.put("in/bad.sv0profraw", bytes(bad))
        code, out, err = self.run_merge("in")
        self.assertEqual((code, out), (5, ""))
        self.assertEqual(self.codes(err), [("COV2012", "bad.sv0profraw"), ("COV3002", None)])
        self.assertEqual({r["phase"] for r in records(err)}, {"merge"})
        self.assertEqual(self.tree(), [])

    def test_the_override_publishes_incomplete_evidence(self) -> None:
        good = self.profile(1)
        self.seed(good)
        self.put("in/cut.sv0profraw", self.profile(2)[:-9])
        code, out, err = self.run_merge("in", "--allow-rejected-inputs")
        self.assertEqual(code, 0)
        self.assertEqual(self.codes(err), [("COV2011", "cut.sv0profraw"), ("COV3002", None)])
        obj = read_indexed((self.cwd / DEFAULT).read_bytes())
        self.assertEqual((obj["semantic"]["complete"], obj["merge"]["allow_rejected_inputs"]), (False, True))
        self.assertEqual(sorted(r["status"] for r in obj["profile_inputs"]), ["accepted", "incomplete"])
        self.assertIn("merged 1 of 2 profiles over 1 maps: INCOMPLETE (diagnostic only)", out)

    def test_what_a_directory_contributes(self) -> None:
        good = self.profile(1)
        self.seed(good)
        d = self.inputs
        (d / "notes.txt").write_bytes(b"ignored")
        (d / ".hidden.sv0profraw").write_bytes(b"ignored: a dot file that is not a runtime temporary")
        (d / "nested").mkdir()
        self.put(f"in/nested/{self.name(self.profile(5))}", self.profile(5))  # not searched
        code, _, err = self.run_merge("in", "--output", "ok.json")
        self.assertEqual((code, err), (0, ""))
        self.assertEqual(len(read_indexed((self.cwd / "ok.json").read_bytes())["profile_inputs"]), 1)
        # A runtime's uncommitted temporary means a process did not finish: incomplete, never replayed.
        temp = f".{self.name(self.profile(6))}.tmp-Ab12Cd"
        (d / temp).write_bytes(self.profile(6))  # even complete bytes are not replayed
        code, _, err = self.run_merge("in", "--output", "t.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV2011", temp), ("COV3002", None)]))
        code, _, _ = self.run_merge("in", "--output", "t.json", "--allow-rejected-inputs")
        obj = read_indexed((self.cwd / "t.json").read_bytes())
        self.assertEqual(code, 0)
        self.assertEqual([(r["status"], r["run_id"]) for r in obj["profile_inputs"] if r["name"] == temp], [("incomplete", RUN_A)])
        self.assertEqual(sum(p["count"]["value"] for p in obj["semantic"]["points"]), sum(self.counts.values()))
        (d / temp).unlink()
        # Entries with an artifact name that are not regular files are rejected inputs, not skipped.
        os.symlink(d / self.name(good), d / "link.sv0profraw")
        (d / "dir.sv0covmap.json").mkdir()
        code, _, err = self.run_merge("in", "--output", "s.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV3002", None), ("COV6002", "dir.sv0covmap.json"), ("COV6002", "link.sv0profraw")]))

    def test_missing_unreadable_and_oversized_inputs(self) -> None:
        self.seed(self.profile(1))
        code, _, err = self.run_merge("in", "gone.sv0profraw", "gone.sv0covmap.json", "--output", "x.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV1010", "gone.sv0covmap.json"), ("COV2010", "gone.sv0profraw"), ("COV3002", None)]))
        big = self.put("big.sv0profraw", self.profile(2))
        size = big.stat().st_size
        with mock.patch.object(cmd_merge.os, "read", side_effect=AssertionError("an oversized file was read")):
            code, _, err = self.run_merge(str(big), "--raw-profile-tier", "custom", "--raw-profile-max-counters", "100",
                                          "--raw-profile-max-bytes", str(size - 1), "--output", "x.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV3001", None), ("COV3002", None), ("COV3003", None), ("COV6001", "big.sv0profraw")]))
        with mock.patch.dict(cmd_merge.map_limits.__globals__["MAP_CEILINGS"], {"standard": len(self.map_bytes) - 1}):
            code, _, err = self.run_merge("in", "--output", "x.json")
        self.assertIn(("COV6001", "f0.sv0covmap.json"), self.codes(err))
        self.assertEqual(code, 5)
        os.mkfifo(self.cwd / "pipe.sv0profraw")  # must not block
        code, _, err = self.run_merge("in", "pipe.sv0profraw", "--output", "x.json")
        self.assertIn(("COV6002", "pipe.sv0profraw"), self.codes(err))
        self.assertFalse((self.cwd / "x.json").exists())

    def test_an_input_name_that_cannot_be_inventoried_stops_the_command(self) -> None:
        self.seed(self.profile(1))
        self.put("in/back\\slash.sv0profraw", self.profile(2))
        code, out, err = self.run_merge("in")
        self.assertEqual((code, out, self.codes(err)), (5, "", [("COV6002", None)]))
        self.assertNotIn("slash", err)


class MapTierTest(Base):
    """SPEC 16.3.9, COV-FMT-048: map-scale artifacts are bounded by the reader's tier."""

    def test_the_ceilings_are_the_specified_ones(self) -> None:
        from sv0cov.formats.map import MAP_CEILINGS, map_limits
        self.assertEqual(MAP_CEILINGS, {"standard": 536870912, "large": 2147483648, "custom": 2147483648})
        self.assertEqual((map_limits().max_bytes, map_limits("large").max_bytes), (2**29, 2**31))

    def test_a_map_or_indexed_artifact_over_the_ceiling_is_refused_before_parsing(self) -> None:
        from sv0cov.formats.canonical_json import Limits
        from sv0cov.formats.indexed import IndexedError
        from sv0cov.formats.map import MAP_CEILINGS, MapError, validate_map
        n = len(self.map_bytes)
        self.assertEqual(validate_map(self.map_bytes, limits=Limits(max_bytes=n))["map_id"], self.m["map_id"])
        with self.assertRaises(MapError) as ctx:
            validate_map(self.map_bytes, limits=Limits(max_bytes=n - 1))
        self.assertEqual(ctx.exception.code, "COV6001")
        with self.assertRaises(MapError) as ctx:  # an oversized non-map is still only "too big": nothing was parsed
            validate_map(b"x" * 100, limits=Limits(max_bytes=99))
        self.assertEqual(ctx.exception.code, "COV6001")
        data = merge([Artifact("m", self.map_bytes)], [Artifact("p", self.profile(1))]).data
        with mock.patch.dict(MAP_CEILINGS, {"standard": len(data) - 1, "large": len(data)}):
            with self.assertRaises(IndexedError) as ctx:
                read_indexed(data)
            self.assertEqual(ctx.exception.code, "COV6001")
            self.assertTrue(read_indexed(data, tier="large")["semantic"]["complete"])


class RunSelectionTest(Base):
    """COV-CLI-006, AC-097."""

    def setUp(self) -> None:
        super().setUp()
        self.seed(self.profile(1, run=RUN_A), self.profile(2, run=RUN_B))

    def test_two_runs_need_a_declaration(self) -> None:
        code, _, err = self.run_merge("in")
        self.assertEqual((code, self.codes(err), self.tree()), (5, [("COV3003", None)], []))

    def test_expect_run_in_either_order_and_a_manifest_agree(self) -> None:
        self.assertEqual(self.run_merge("in", "--expect-run", RUN_A, "--expect-run", RUN_B, "--output", "a.json")[0], 0)
        self.assertEqual(self.run_merge("in", "--expect-run", RUN_B, "--expect-run=" + RUN_A, "--output", "b.json")[0], 0)
        a, b = (self.cwd / "a.json").read_bytes(), (self.cwd / "b.json").read_bytes()
        self.assertEqual(a, b)
        manifest = encode_run_set([RUN_A, RUN_B])
        self.put("runs.json", manifest)
        self.assertEqual(self.run_merge("in", "--run-manifest", "runs.json", "--output", "c.json")[0], 0)
        ja, jc = read_indexed(a), read_indexed((self.cwd / "c.json").read_bytes())
        self.assertEqual(ja["run_selection"], {"manifest_sha256": None, "mode": "explicit-list", "requested_run_ids": sorted([RUN_A, RUN_B]),
                                               "selected_run_ids": sorted([RUN_A, RUN_B])})
        self.assertEqual(jc["run_selection"], {**ja["run_selection"], "mode": "manifest", "manifest_sha256": hashlib.sha256(manifest).hexdigest()})
        self.assertEqual(ja["semantic"], jc["semantic"])

    def test_the_declared_set_must_match(self) -> None:
        other = "00000000000000000000000000000009"
        for args in (["--expect-run", RUN_A], ["--expect-run", RUN_A, "--expect-run", RUN_B, "--expect-run", other]):
            code, _, err = self.run_merge("in", *args)
            self.assertEqual((code, self.codes(err)), (5, [("COV3003", None)]), args)
        # The override exposes the state and still cannot make it complete.
        code, _, _ = self.run_merge("in", "--expect-run", RUN_A, "--allow-rejected-inputs", "--output", "d.json")
        self.assertEqual((code, read_indexed((self.cwd / "d.json").read_bytes())["semantic"]["complete"]), (0, False))

    def test_malformed_selection(self) -> None:
        usage = [["--expect-run", RUN_A.upper()], ["--expect-run", "0" * 32], ["--expect-run", RUN_A, "--expect-run", RUN_A],
                 ["--expect-run", RUN_A, "--run-manifest", "runs.json"], ["--run-manifest", "a", "--run-manifest", "b"]]
        for args in usage:
            code, _, err = self.run_merge("in", *args)
            self.assertEqual((code, [c for c, _ in self.codes(err)]), (2, ["COV0001"]), args)
        self.put("bad.json", encode_run_set([RUN_A])[:-1])
        (self.cwd / "adir").mkdir()
        for path in ("bad.json", "absent.json", "adir"):
            code, out, err = self.run_merge("in", "--run-manifest", path)
            self.assertEqual((code, out, self.codes(err)), (5, "", [("COV3003", None)]), path)
        # An unreadable manifest fails even when the implicit rule would have held.
        self.put("single/f0.sv0covmap.json", self.map_bytes)
        self.put("single/p.sv0profraw", self.profile(7))
        self.assertEqual(self.run_merge("single", "--output", "s.json")[0], 0)
        code, _, err = self.run_merge("single", "--run-manifest", "absent.json", "--output", "s2.json")
        self.assertEqual((code, self.codes(err)), (5, [("COV3003", None)]))
        self.assertEqual(self.tree(), ["adir", "bad.json", "s.json", "single", "single/f0.sv0covmap.json", "single/p.sv0profraw"])

    def test_the_environment_selects_nothing(self) -> None:
        hostile = {"SV0COV_RUN_ID": RUN_A, "SV0COV_EXPECT_RUN": f"{RUN_A},{RUN_B}", "SV0COV_RUN_MANIFEST": "runs.json",
                   "SV0COV_ALLOW_REJECTED_INPUTS": "1", "SV0COV_OUTPUT": "-", "SV0COV_OUTPUT_DIR": "evil"}
        self.put("runs.json", encode_run_set([RUN_A, RUN_B]))
        with mock.patch.dict(os.environ, hostile):
            code, out, err = self.run_merge("in")
            self.assertEqual((code, out, self.codes(err)), (5, "", [("COV3003", None)]))
            self.assertEqual(self.run_merge("in", "--expect-run", RUN_A, "--expect-run", RUN_B)[0], 0)
        self.assertEqual(self.tree(), [".sv0cov", DEFAULT, "runs.json"])


if __name__ == "__main__":
    unittest.main()
