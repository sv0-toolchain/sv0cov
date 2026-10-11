# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""No-replace publication (CV-226; SPEC 20.2.2, 20.2.3; COV-SEC-007).

Collisions of every kind leave the existing destination untouched; a race
between the check and the commit is still a collision; every injected fault
leaves no destination and no temporary; modes are 0600 / 0700 and a umask
only removes permissions; nothing falls back to a replacing rename or a
cross-filesystem copy.
"""

from __future__ import annotations

import errno
import io
import multiprocessing
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import publish as P  # noqa: E402
from sv0cov.publish import PublishError, check_destination, publish_bundle, publish_file, publish_stdout  # noqa: E402

DATA = b'{"artifact":1}\n'
FILES = {"coverage.json": b"{}\n", "lcov.info": b"TN:\n", "index.html": b"<!doctype html>\n"}


def mode(path: Path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def snapshot(path: Path) -> tuple:
    st = os.lstat(path)
    content = os.readlink(path) if stat.S_ISLNK(st.st_mode) else path.read_bytes() if stat.S_ISREG(st.st_mode) \
        else sorted(os.listdir(path)) if stat.S_ISDIR(st.st_mode) else None
    return (st.st_ino, st.st_mode, content)


def _race(args: tuple[str, int]) -> str:
    final, n = args
    sys.path.insert(0, str(ROOT / "src"))
    from sv0cov.publish import PublishError, publish_bundle, publish_file
    body = (f"writer {n}\n" * 2000).encode()
    try:
        if final.endswith(".d"):
            publish_bundle(final, {"a": body, "b": body})
        else:
            publish_file(final, body)
    except PublishError as exc:
        return exc.reason
    return f"won {n}"


class Base(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name).resolve()

    def assert_clean(self, *names: str) -> None:
        """The directory holds exactly ``names``: no temporary is left behind."""
        self.assertEqual(sorted(os.listdir(self.dir)), sorted(names))

    def reason(self, fn, *args, **kw) -> str:
        with self.assertRaises(PublishError) as ctx:
            fn(*args, **kw)
        self.assertEqual(ctx.exception.code, P.CODES[ctx.exception.reason])
        return ctx.exception.reason

    def obstacles(self) -> dict[str, Path]:
        """Every kind of thing that may already sit at a destination."""
        made = {}
        (self.dir / "o-file").write_bytes(b"old")
        (self.dir / "o-empty").write_bytes(b"")
        (self.dir / "o-dir").mkdir()
        (self.dir / "o-full").mkdir()
        (self.dir / "o-full" / "x").write_bytes(b"keep")
        (self.dir / "target").write_bytes(b"target")
        os.symlink("target", self.dir / "o-link")
        os.symlink("nowhere", self.dir / "o-dangling")
        os.symlink("o-dir", self.dir / "o-dirlink")
        os.mkfifo(self.dir / "o-fifo")
        for p in self.dir.iterdir():
            if p.name.startswith("o-"):
                made[p.name] = p
        return made


class FileTest(Base):
    def test_a_file_is_published_complete_and_private(self) -> None:
        final = self.dir / "coverage.sv0covdata.json"
        seen = []
        publish_file(str(final), DATA, validate=seen.append)
        self.assertEqual((final.read_bytes(), seen, mode(final), os.lstat(final).st_nlink), (DATA, [DATA], 0o600, 1))
        self.assert_clean("coverage.sv0covdata.json")
        publish_file(str(self.dir / "empty"), b"")
        self.assertEqual((self.dir / "empty").read_bytes(), b"")
        big = os.urandom(3 << 20)
        publish_file(str(self.dir / "big"), big)
        self.assertEqual((self.dir / "big").read_bytes(), big)

    def test_a_relative_destination_is_resolved_from_the_working_directory(self) -> None:
        old = os.getcwd()
        os.chdir(self.dir)
        try:
            publish_file("out.json", DATA)
            (self.dir / "sub").mkdir()
            publish_file("sub/out.json", DATA)
        finally:
            os.chdir(old)
        self.assertEqual(((self.dir / "out.json").read_bytes(), (self.dir / "sub" / "out.json").read_bytes()), (DATA, DATA))

    def test_every_existing_destination_is_a_collision_and_is_left_alone(self) -> None:
        for name, path in self.obstacles().items():
            with self.subTest(obstacle=name):
                before = snapshot(path)
                everything = sorted(os.listdir(self.dir))
                self.assertEqual(self.reason(check_destination, str(path)), "collision")
                self.assertEqual(self.reason(publish_file, str(path), DATA), "collision")
                self.assertEqual(self.reason(publish_bundle, str(path), FILES), "collision")
                self.assertEqual((snapshot(path), sorted(os.listdir(self.dir))), (before, everything))
        self.assertEqual((self.dir / "target").read_bytes(), b"target")  # nothing was written through the link
        self.assertFalse((self.dir / "nowhere").exists())

    def test_the_commit_itself_refuses_a_destination_that_appears_after_the_check(self) -> None:
        """Correctness does not depend on the check (SPEC 20.2.3)."""
        real = P._commit
        for kind in ("file", "empty directory", "symlink", "dangling symlink"):
            for bundle in (False, True):
                final = self.dir / f"late-{kind[:4]}-{bundle}"

                def racing(parent, temp, name, *, directory, final=final, kind=kind):
                    if kind == "file":
                        final.write_bytes(b"theirs")
                    elif kind == "empty directory":
                        final.mkdir()
                    else:
                        os.symlink("target" if kind == "symlink" else "nowhere", final)
                    return real(parent, temp, name, directory=directory)

                with self.subTest(kind=kind, bundle=bundle), mock.patch.object(P, "_commit", racing):
                    got = self.reason(publish_bundle, str(final), FILES) if bundle else self.reason(publish_file, str(final), DATA)
                    self.assertEqual(got, "collision")
                    self.assertEqual([n for n in os.listdir(self.dir) if n.startswith(P.TEMP_PREFIX)], [])
                    if kind == "file":
                        self.assertEqual(final.read_bytes(), b"theirs")
                    elif kind == "empty directory":
                        self.assertEqual(os.listdir(final), [])  # an empty directory is not replaced either
                    else:
                        self.assertTrue(final.is_symlink())

    def test_the_link_fallback_cannot_replace_either(self) -> None:
        with mock.patch.object(P, "_rename_noreplace", side_effect=P._NoPrimitive("refused")):
            publish_file(str(self.dir / "a"), DATA)
            self.assertEqual(((self.dir / "a").read_bytes(), mode(self.dir / "a"), os.lstat(self.dir / "a").st_nlink), (DATA, 0o600, 1))
            self.assert_clean("a")
            real = os.link

            def racing(src, dst, **kw):
                (self.dir / "b").write_bytes(b"theirs")
                return real(src, dst, **kw)

            with mock.patch.object(os, "link", racing):
                self.assertEqual(self.reason(publish_file, str(self.dir / "b"), DATA), "collision")
            self.assertEqual((self.dir / "b").read_bytes(), b"theirs")
            os.symlink("a", self.dir / "c")
            with mock.patch.object(P, "_absent"):
                self.assertEqual(self.reason(publish_file, str(self.dir / "c"), b"new"), "collision")
            self.assertEqual((self.dir / "a").read_bytes(), DATA)
            self.assert_clean("a", "b", "c")

    def test_the_parent_of_an_explicit_destination_must_exist(self) -> None:
        self.assertEqual(self.reason(publish_file, str(self.dir / "missing" / "x"), DATA), "failed")
        self.assertEqual(self.reason(publish_bundle, str(self.dir / "missing" / "x"), FILES), "failed")
        self.assertEqual(self.reason(check_destination, str(self.dir / "missing" / "x")), "failed")
        (self.dir / "file").write_bytes(b"f")
        self.assertEqual(self.reason(publish_file, str(self.dir / "file" / "x"), DATA), "unsafe")
        self.assert_clean("file")
        for bad in ("", str(self.dir) + "/", str(self.dir) + "/.", str(self.dir) + "/..", str(self.dir / ("n" * 256))):
            self.assertEqual(self.reason(publish_file, bad, DATA), "unsafe", bad)
        self.assert_clean("file")


class BundleTest(Base):
    def test_a_bundle_appears_whole_and_private(self) -> None:
        final = self.dir / "reports"
        seen = {}
        publish_bundle(str(final), FILES, validate={"lcov.info": lambda b: seen.setdefault("lcov", b)})
        self.assertEqual({p.name: p.read_bytes() for p in final.iterdir()}, FILES)
        self.assertEqual((mode(final), {mode(p) for p in final.iterdir()}, seen), (0o700, {0o600}, {"lcov": FILES["lcov.info"]}))
        self.assert_clean("reports")

    def test_member_names_are_single_components(self) -> None:
        for bad in ("", ".", "..", "a/b", "/abs", "a\x00b", P.TEMP_PREFIX + "x", "n" * 256):
            self.assertEqual(self.reason(publish_bundle, str(self.dir / "r"), {bad: b"x"}), "unsafe", bad)
        self.assertEqual(self.reason(publish_bundle, str(self.dir / "r"), {}), "failed")
        self.assert_clean()

    def test_without_the_primitive_a_bundle_is_not_published_at_all(self) -> None:
        with mock.patch.object(P, "_rename_noreplace", side_effect=P._NoPrimitive("refused")), \
                mock.patch.object(os, "rename", side_effect=AssertionError("a replacing rename was used")), \
                mock.patch.object(os, "replace", side_effect=AssertionError("replace was used")):
            with self.assertRaises(PublishError) as ctx:
                publish_bundle(str(self.dir / "r"), FILES)
            self.assertEqual(ctx.exception.reason, "failed")
            self.assertIn("no atomic no-replace rename for a directory", ctx.exception.detail)
        self.assert_clean()

    def test_the_host_primitive_is_real_and_refuses_existing_names(self) -> None:
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            (self.dir / "src").mkdir()
            P._rename_noreplace(fd, "src", fd, "dst")
            self.assertTrue((self.dir / "dst").is_dir() and not (self.dir / "src").exists())
            for obstacle in ("dir", "file", "link"):
                (self.dir / "src").mkdir()
                target = self.dir / f"o-{obstacle}"
                target.mkdir() if obstacle == "dir" else target.write_bytes(b"x") if obstacle == "file" else os.symlink("dst", target)
                with self.assertRaises(FileExistsError):
                    P._rename_noreplace(fd, "src", fd, target.name)
                os.rmdir(self.dir / "src")
            (self.dir / "f").write_bytes(b"1")
            (self.dir / "g").write_bytes(b"2")
            with self.assertRaises(FileExistsError):
                P._rename_noreplace(fd, "f", fd, "g")
            self.assertEqual(((self.dir / "f").read_bytes(), (self.dir / "g").read_bytes()), (b"1", b"2"))
        finally:
            os.close(fd)


    @unittest.skipUnless(sys.platform.startswith("linux"), "the raw system call is the Linux fallback")
    def test_the_raw_system_call_is_used_when_the_c_library_has_no_wrapper(self) -> None:
        real = P._libc()

        class NoWrapper:
            syscall = real.syscall

        (self.dir / "src").mkdir()
        (self.dir / "taken").mkdir()
        fd = os.open(self.dir, os.O_RDONLY)
        try:
            with mock.patch.object(P, "_libc", return_value=NoWrapper()):
                with self.assertRaises(FileExistsError):
                    P._rename_noreplace(fd, "src", fd, "taken")
                P._rename_noreplace(fd, "src", fd, "dst")
                with mock.patch.object(os, "uname", return_value=mock.Mock(machine="mips")), self.assertRaises(P._NoPrimitive):
                    P._rename_noreplace(fd, "dst", fd, "other")
        finally:
            os.close(fd)
        self.assertEqual(sorted(os.listdir(self.dir)), ["dst", "taken"])

    def test_an_unknown_host_has_no_primitive(self) -> None:
        with mock.patch.object(sys, "platform", "sunos5"), self.assertRaises(P._NoPrimitive):
            P._rename_noreplace(0, "a", 0, "b")
        with mock.patch.object(P, "_libc", side_effect=OSError("no libc")), self.assertRaises(P._NoPrimitive):
            P._rename_noreplace(0, "a", 0, "b")


class ManagedTest(Base):
    def test_missing_managed_directories_are_created_private(self) -> None:
        publish_file(".sv0cov/runs/abc/coverage.sv0covdata.json", DATA, anchor=str(self.dir))
        publish_bundle(".sv0cov/runs/abc/reports", FILES, anchor=str(self.dir))
        self.assertEqual((self.dir / ".sv0cov/runs/abc/coverage.sv0covdata.json").read_bytes(), DATA)
        for d in (".sv0cov", ".sv0cov/runs", ".sv0cov/runs/abc", ".sv0cov/runs/abc/reports"):
            self.assertEqual(mode(self.dir / d), 0o700, d)
        # Existing real directories are reused; an existing artifact is a collision.
        self.assertEqual(self.reason(publish_file, ".sv0cov/runs/abc/coverage.sv0covdata.json", b"new", anchor=str(self.dir)), "collision")
        self.assertEqual(self.reason(publish_bundle, ".sv0cov/runs/abc/reports", FILES, anchor=str(self.dir)), "collision")
        self.assertEqual(sorted(os.listdir(self.dir / ".sv0cov/runs/abc")), ["coverage.sv0covdata.json", "reports"])

    def test_no_component_below_the_root_may_be_a_symlink_or_a_file(self) -> None:
        outside = self.dir / "outside"
        outside.mkdir()
        root = self.dir / "project"
        (root / "real").mkdir(parents=True)
        os.symlink(outside, root / "link")
        os.symlink("real", root / "inner")
        os.symlink("nowhere", root / "dangling")
        (root / "file").write_bytes(b"f")
        os.symlink(outside, root / "real" / "deep")
        for dest in ("link/x", "inner/x", "dangling/x", "file/x", "real/deep/x", "link/a/b/x"):
            with self.subTest(dest=dest):
                self.assertEqual(self.reason(publish_file, dest, DATA, anchor=str(root)), "unsafe")
                self.assertEqual(self.reason(publish_bundle, dest, FILES, anchor=str(root)), "unsafe")
                self.assertEqual(self.reason(check_destination, dest, anchor=str(root)), "unsafe")
        self.assertEqual((os.listdir(outside), os.listdir(root / "real")), ([], ["deep"]))
        for dest in ("/abs/x", "../x", "a/../x", "a//x", "./x", ""):
            self.assertEqual(self.reason(publish_file, dest, DATA, anchor=str(root)), "unsafe", dest)
        self.assertEqual(self.reason(publish_file, "x", DATA, anchor=str(self.dir / "no-root")), "failed")
        self.assertFalse((self.dir / "x").exists() or (root / "a").exists())


class PermissionTest(Base):
    def test_a_umask_removes_permissions_and_never_adds_any(self) -> None:
        for umask, file_mode, dir_mode in ((0o000, 0o600, 0o700), (0o022, 0o600, 0o700), (0o077, 0o600, 0o700), (0o177, 0o600, 0o600)):
            old = os.umask(umask)
            try:
                tag = f"{umask:o}"
                publish_file(str(self.dir / f"f{tag}"), DATA)
                if dir_mode & 0o100:
                    publish_bundle(str(self.dir / f"b{tag}"), FILES)
                    publish_file(f"m{tag}/x", DATA, anchor=str(self.dir))
            finally:
                os.umask(old)
            self.assertEqual(mode(self.dir / f"f{tag}"), file_mode)
            if dir_mode & 0o100:
                self.assertEqual((mode(self.dir / f"b{tag}"), mode(self.dir / f"m{tag}")), (0o700, 0o700))
                self.assertEqual({mode(p) for p in (self.dir / f"b{tag}").iterdir()}, {0o600})

    def test_the_temporary_is_private_and_unpredictable(self) -> None:
        seen = []

        def spy(data: bytes) -> None:
            (temp,) = [n for n in os.listdir(self.dir) if n.startswith(P.TEMP_PREFIX)]
            seen.append((temp, mode(self.dir / temp)))

        publish_file(str(self.dir / "a"), DATA, validate=spy)
        publish_file(str(self.dir / "b"), DATA, validate=spy)
        self.assertEqual({m for _, m in seen}, {0o600})
        self.assertEqual(len({t for t, _ in seen}), 2)
        self.assertTrue(all(len(t) == len(P.TEMP_PREFIX) + 32 for t, _ in seen))
        with mock.patch.object(os, "urandom", return_value=bytes(16)) as entropy:
            publish_file(str(self.dir / "c"), DATA)
            entropy.assert_called_once_with(16)
        # A squatter on the temporary name is not written through.
        (self.dir / (P.TEMP_PREFIX + "00" * 16)).write_bytes(b"squat")
        with mock.patch.object(os, "urandom", return_value=bytes(16)):
            self.assertEqual(self.reason(publish_file, str(self.dir / "d"), DATA), "collision")
        self.assertFalse((self.dir / "d").exists())


class FaultTest(Base):
    """Every failure leaves no destination and no temporary."""

    def test_faults_at_every_step(self) -> None:
        faults = {
            "create": ("os.open", lambda real: lambda *a, **k: (_ for _ in ()).throw(OSError(errno.EACCES, "denied"))
                       if len(a) > 1 and a[1] & os.O_CREAT else real(*a, **k)),
            "write": ("os.write", lambda real: lambda *a, **k: (_ for _ in ()).throw(OSError(errno.ENOSPC, "full"))),
            "short write": ("os.write", lambda real: lambda *a, **k: 0),
            "fsync": ("os.fsync", lambda real: lambda fd: (_ for _ in ()).throw(OSError(errno.EIO, "io"))
                      if stat.S_ISREG(os.fstat(fd).st_mode) else real(fd)),
            "read back": ("os.read", lambda real: lambda fd, n: b""),
            "commit": ("P._rename_noreplace", lambda real: lambda *a: (_ for _ in ()).throw(OSError(errno.EIO, "io"))),
            "cross filesystem": ("P._rename_noreplace", lambda real: lambda *a: (_ for _ in ()).throw(OSError(errno.EXDEV, "xdev"))),
        }
        for label, (target, make) in faults.items():
            module, attr = (P, target[2:]) if target.startswith("P.") else (os, target[3:])
            for bundle in (False, True):
                with self.subTest(fault=label, bundle=bundle):
                    with mock.patch.object(module, attr, make(getattr(module, attr))), \
                            mock.patch.object(os, "rename", side_effect=AssertionError("a replacing rename was used")):
                        got = self.reason(publish_bundle, str(self.dir / "out"), FILES) if bundle else \
                            self.reason(publish_file, str(self.dir / "out"), DATA)
                    self.assertEqual(got, "failed")
                    self.assert_clean()
        with mock.patch.object(P, "_rename_noreplace", side_effect=OSError(errno.EXDEV, "xdev")), self.assertRaises(PublishError) as ctx:
            publish_file(str(self.dir / "out"), DATA)
        self.assertIn("different filesystems", ctx.exception.detail)
        self.assert_clean()

    def test_a_failing_validator_publishes_nothing(self) -> None:
        def bad(data: bytes) -> None:
            raise ValueError("secret detail")

        with self.assertRaises(PublishError) as ctx:
            publish_file(str(self.dir / "out"), DATA, validate=bad)
        self.assertEqual((ctx.exception.reason, "secret" in str(ctx.exception), "ValueError" in str(ctx.exception)), ("failed", False, True))
        self.assertEqual(self.reason(publish_bundle, str(self.dir / "out"), FILES, validate={"index.html": bad}), "failed")
        self.assert_clean()

    def test_an_interrupt_cleans_up_and_propagates(self) -> None:
        def interrupt(data: bytes) -> None:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            publish_file(str(self.dir / "out"), DATA, validate=interrupt)
        with self.assertRaises(KeyboardInterrupt):
            publish_bundle(str(self.dir / "out"), FILES, validate={"lcov.info": interrupt})
        self.assert_clean()

    def test_something_slipped_into_the_temporary_bundle_stops_the_commit(self) -> None:
        def intrude(data: bytes) -> None:
            (temp,) = [n for n in os.listdir(self.dir) if n.startswith(P.TEMP_PREFIX)]
            (self.dir / temp / "intruder").write_bytes(b"x")

        self.assertEqual(self.reason(publish_bundle, str(self.dir / "out"), FILES, validate={"lcov.info": intrude}), "unsafe")
        self.assert_clean()


class RaceTest(Base):
    def test_concurrent_publishers_of_one_name_have_exactly_one_winner(self) -> None:
        ctx = multiprocessing.get_context("spawn")
        for final in ("race.json", "race.d"):
            with ctx.Pool(6) as pool:
                results = pool.map(_race, [(str(self.dir / final), n) for n in range(12)])
            winners = [r for r in results if r.startswith("won")]
            self.assertEqual((len(winners), set(results) - set(winners)), (1, {"collision"}), results)
            n = winners[0].split()[1]
            body = (f"writer {n}\n" * 2000).encode()
            target = self.dir / final
            got = target.read_bytes() if target.is_file() else {p.name: p.read_bytes() for p in target.iterdir()}
            self.assertEqual(got, body if target.is_file() else {"a": body, "b": body})
        self.assert_clean("race.json", "race.d")


class StdoutTest(unittest.TestCase):
    def test_the_whole_artifact_is_written_after_validation(self) -> None:
        out, order = io.BytesIO(), []
        publish_stdout(out, DATA, validate=lambda b: order.append(out.getvalue()))
        self.assertEqual((out.getvalue(), order), (DATA, [b""]))

    def test_a_failed_validation_writes_nothing(self) -> None:
        out = io.BytesIO()

        def bad(data: bytes) -> None:
            raise ValueError("no")

        with self.assertRaises(PublishError):
            publish_stdout(out, DATA, validate=bad)
        self.assertEqual(out.getvalue(), b"")

    def test_short_and_failed_writes_are_errors(self) -> None:
        class Chunky(io.RawIOBase):
            def __init__(self, behaviour):
                self.behaviour, self.got = behaviour, b""

            def writable(self) -> bool:
                return True

            def write(self, b):
                step = self.behaviour(len(self.got))
                if isinstance(step, BaseException):
                    raise step
                self.got += bytes(b[:step])
                return step

        partial = Chunky(lambda n: 3)
        publish_stdout(partial, DATA)
        self.assertEqual(partial.got, DATA)  # partial writes are continued
        for label, behaviour in (("stalls", lambda n: 0 if n else 4), ("pipe closed", lambda n: BrokenPipeError()),
                                 ("device error", lambda n: OSError(errno.EIO, "io") if n else 2)):
            with self.subTest(case=label), self.assertRaises(PublishError) as ctx:
                publish_stdout(Chunky(behaviour), DATA)
            self.assertEqual(ctx.exception.reason, "failed")
        closed = io.BytesIO()
        closed.close()
        with self.assertRaises(PublishError):
            publish_stdout(closed, DATA)
        r, w = os.pipe()
        os.close(r)
        with os.fdopen(w, "wb", buffering=0) as pipe, self.assertRaises(PublishError):
            publish_stdout(pipe, DATA)


if __name__ == "__main__":
    unittest.main()
