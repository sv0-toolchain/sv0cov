# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""No-replace publication of output artifacts (CV-226; SPEC 20.2.2, 20.2.3;
COV-SEC-007, BL-034).

sv0cov never overwrites, with one explicit exception: :func:`replace_file`,
which only the ratchet-baseline update uses. An artifact is written to an unpredictable sibling
temporary, synchronized, read back and validated, and then committed to its
absent final name by one atomic operation that cannot replace anything. A
check for an existing destination is made first, to fail early and say why,
but correctness rests only on the commit.

Three shapes:

- :func:`publish_file`: one file, mode ``0600``.
- :func:`publish_bundle`: a directory of files, built in a sibling temporary
  directory of mode ``0700`` and committed by one rename.
- :func:`publish_stdout`: the explicit non-atomic exception. The bytes are
  complete and validated before the first write, and a short or failed
  write is an error.

Where a destination may be:

- An **explicit** destination (``anchor=None``): the parent must already be
  a directory; no ancestor is created. The final name must not exist in any
  form, a dangling symlink included.
- A **managed** destination (``anchor`` is the project root, ``final`` is
  relative to it): missing directories are created with mode ``0700``, and
  no component below the anchor may be a symlink or a non-directory.

Every step after the parent is opened works relative to that open
directory, so renaming or replacing an ancestor meanwhile cannot redirect
the write.

The commit primitive, per host:

==========  ==================================  =============================
Host        Files and directories               Files only, as a fallback
==========  ==================================  =============================
macOS       ``renameatx_np(RENAME_EXCL)``       ``linkat`` + ``unlinkat``
Linux       ``renameat2(RENAME_NOREPLACE)``     ``linkat`` + ``unlinkat``
==========  ==================================  =============================

``link`` never replaces a name, so it is a sound fallback for a file when
the rename primitive is missing or the filesystem refuses its flag. A
directory cannot be hard-linked: when the primitive is unavailable a bundle
is not published at all. Nothing ever falls back to a plain ``rename``
(which replaces) or to copying across filesystems.

The modes are requested from the kernel at creation, so the process umask
can remove permissions and never add any.

Failures raise :class:`PublishError`. ``reason`` is ``collision`` (the
destination exists; ``COV4010``), ``unsafe`` (a symlink or non-directory on
the way, or a bad name; ``COV6002``), or ``failed`` (everything else;
``COV4011``). Whatever the reason, a pre-existing destination is untouched
and the temporary is removed.
"""

from __future__ import annotations

import ctypes
import errno
import os
import stat
import sys
from typing import BinaryIO, Callable, Mapping

TEMP_PREFIX = ".sv0cov-tmp-"
FILE_MODE, DIR_MODE = 0o600, 0o700
CODES = {"collision": "COV4010", "unsafe": "COV6002", "failed": "COV4011"}
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
_FILE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_UNSUPPORTED = (errno.ENOSYS, errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP)
_RENAMEAT2_SYSCALL = {"x86_64": 316, "aarch64": 276}

Validator = Callable[[bytes], None]


class PublishError(Exception):
    """``reason`` is ``collision``, ``unsafe`` or ``failed``; ``code`` is the
    matching diagnostic code."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(f"{reason}: {detail}")
        self.reason = reason
        self.detail = detail
        self.code = CODES[reason]


class _NoPrimitive(Exception):
    """The host or the filesystem has no rename that cannot replace."""


# ── the commit primitive ────────────────────────────────────────────────────


def _libc() -> ctypes.CDLL:
    return ctypes.CDLL(None, use_errno=True)


def _rename_noreplace(src_fd: int, src: str, dst_fd: int, dst: str) -> None:
    """Atomically rename ``src`` to the absent name ``dst``. Raises
    ``FileExistsError`` when ``dst`` exists, :class:`_NoPrimitive` when no
    such operation is available here, ``OSError`` otherwise."""
    a, b = os.fsencode(src), os.fsencode(dst)
    try:
        libc = _libc()
        if sys.platform == "darwin":
            rc = libc.renameatx_np(ctypes.c_int(src_fd), a, ctypes.c_int(dst_fd), b, ctypes.c_uint(0x4))  # RENAME_EXCL
        elif sys.platform.startswith("linux"):
            if hasattr(libc, "renameat2"):
                rc = libc.renameat2(ctypes.c_int(src_fd), a, ctypes.c_int(dst_fd), b, ctypes.c_uint(0x1))  # RENAME_NOREPLACE
            else:
                number = _RENAMEAT2_SYSCALL.get(os.uname().machine)
                if number is None:
                    raise _NoPrimitive("renameat2 is not reachable on this host")
                rc = libc.syscall(ctypes.c_long(number), ctypes.c_int(src_fd), a, ctypes.c_int(dst_fd), b, ctypes.c_uint(0x1))
        else:
            raise _NoPrimitive(f"no no-replace rename is known for {sys.platform}")
    except (OSError, AttributeError) as exc:  # the C library or the symbol is missing
        raise _NoPrimitive(str(exc)) from None
    if rc == 0:
        return
    err = ctypes.get_errno()
    if err in _UNSUPPORTED:
        raise _NoPrimitive(os.strerror(err))
    raise OSError(err, os.strerror(err))


def _commit(parent: int, temp: str, final: str, *, directory: bool) -> None:
    try:
        _rename_noreplace(parent, temp, parent, final)
        return
    except _NoPrimitive as exc:
        if directory:
            raise PublishError("failed", f"this host or filesystem has no atomic no-replace rename for a directory ({exc})") from None
    # A file: link never replaces an existing name.
    os.link(temp, final, src_dir_fd=parent, dst_dir_fd=parent, follow_symlinks=False)
    try:
        os.unlink(temp, dir_fd=parent)
    except OSError:
        pass  # the artifact is published; a leftover temporary is only litter


# ── destinations ────────────────────────────────────────────────────────────


def _check_name(name: str, what: str) -> None:
    if not name or name in (".", "..") or "/" in name or "\x00" in name or len(os.fsencode(name)) > 255:
        raise PublishError("unsafe", f"{what} {name!r} is not a single path component")


class _Missing(Exception):
    """A managed directory on the way does not exist yet (and was not to be created)."""


def _open_parent(final: str, anchor: str | None, *, create: bool = True) -> tuple[int, str]:
    """An open directory to publish into and the final name inside it."""
    final = os.fspath(final)
    if anchor is None:
        parent, name = os.path.split(final)
        _check_name(name, "the destination name")
        try:
            return os.open(parent or ".", _DIR_FLAGS), name
        except FileNotFoundError:
            raise PublishError("failed", "the parent directory of an explicit destination must already exist") from None
        except NotADirectoryError:
            raise PublishError("unsafe", "an ancestor of the destination is not a directory") from None
        except OSError as exc:
            raise PublishError("failed", f"the parent directory cannot be opened ({os.strerror(exc.errno)})") from None
    parts = final.split("/")  # an absolute path has an empty first component and is refused below
    for part in parts:
        _check_name(part, "the path component")
    try:
        fd = os.open(anchor, _DIR_FLAGS)
    except OSError as exc:
        raise PublishError("failed", f"the project root cannot be opened ({os.strerror(exc.errno)})") from None
    try:
        for part in parts[:-1]:
            if create:
                try:
                    os.mkdir(part, DIR_MODE, dir_fd=fd)
                except FileExistsError:
                    pass
            try:
                nxt = os.open(part, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=fd)
            except FileNotFoundError:
                if create:
                    raise
                raise _Missing(part) from None
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR, errno.EMLINK):
                    raise PublishError("unsafe", f"{part!r} is a symlink or not a directory") from None
                raise PublishError("failed", f"{part!r} cannot be opened ({os.strerror(exc.errno)})") from None
            os.close(fd)
            fd = nxt
    except OSError as exc:
        os.close(fd)
        raise PublishError("failed", f"a managed directory cannot be created ({os.strerror(exc.errno)})") from None
    except BaseException:
        os.close(fd)
        raise
    return fd, parts[-1]


def _absent(parent: int, name: str) -> None:
    try:
        os.lstat(name, dir_fd=parent)
    except FileNotFoundError:
        return
    except OSError as exc:
        raise PublishError("failed", f"the destination cannot be examined ({os.strerror(exc.errno)})") from None
    raise PublishError("collision", f"{name!r} already exists")


def check_destination(final: str, *, anchor: str | None = None) -> None:
    """Fail early when ``final`` cannot be published to. It creates nothing:
    a managed directory that does not exist yet is simply not an obstacle.
    It is a diagnostic aid: :func:`publish_file` and :func:`publish_bundle`
    repeat it and do not depend on it."""
    try:
        parent, name = _open_parent(final, anchor, create=False)
    except _Missing:
        return
    try:
        _absent(parent, name)
    finally:
        os.close(parent)


# ── writing ─────────────────────────────────────────────────────────────────


def _temp_name() -> str:
    return TEMP_PREFIX + os.urandom(16).hex()


def _write_file(parent: int, name: str, data: bytes) -> None:
    """Create ``name`` exclusively with mode 0600, write, synchronize, close."""
    fd = os.open(name, _FILE_FLAGS, FILE_MODE, dir_fd=parent)
    try:
        view = memoryview(data)
        while view:
            n = os.write(fd, view)
            if n <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[n:]
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_back(parent: int, name: str, data: bytes, validate: Validator | None) -> None:
    """The temporary holds exactly ``data`` as a regular file, and ``data`` is valid."""
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise PublishError("unsafe", "the temporary is not a regular file")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                break
            chunks.append(chunk)
    finally:
        os.close(fd)
    if b"".join(chunks) != data:
        raise PublishError("failed", "the written bytes do not read back")
    if validate is not None:
        validate(data)


def _sync_dir(fd: int) -> None:
    try:
        os.fsync(fd)
    except OSError:
        pass  # not every filesystem can synchronize a directory (SPEC 20.2.3)


def _remove_file(parent: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent)
    except OSError:
        pass


def _remove_tree(parent: int, name: str) -> None:
    try:
        fd = os.open(name, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=parent)
    except OSError:
        return
    try:
        for entry in os.listdir(fd):
            try:
                os.unlink(entry, dir_fd=fd)
            except OSError:
                pass
    finally:
        os.close(fd)
    try:
        os.rmdir(name, dir_fd=parent)
    except OSError:
        pass


def _failure(exc: BaseException, final: str) -> PublishError:
    if isinstance(exc, PublishError):
        return exc
    if isinstance(exc, FileExistsError):
        return PublishError("collision", f"{final!r} already exists")
    if isinstance(exc, OSError):
        if exc.errno == errno.EXDEV:
            return PublishError("failed", "the temporary and the destination are on different filesystems")
        return PublishError("failed", os.strerror(exc.errno) if exc.errno else type(exc).__name__)
    return PublishError("failed", f"validation failed ({type(exc).__name__})")


def publish_file(final: str, data: bytes, *, anchor: str | None = None, validate: Validator | None = None) -> None:
    """Publish ``data`` as the new file ``final``. Raises :class:`PublishError`."""
    parent, name = _open_parent(final, anchor)
    temp = _temp_name()
    try:
        _absent(parent, name)
        try:
            _write_file(parent, temp, data)
            _read_back(parent, temp, data, validate)
            _commit(parent, temp, name, directory=False)
        except BaseException as exc:
            _remove_file(parent, temp)
            if isinstance(exc, Exception):
                raise _failure(exc, name) from None
            raise  # an interrupt: the temporary is gone, the destination untouched
        _sync_dir(parent)
    finally:
        os.close(parent)


def replace_file(final: str, data: bytes, *, anchor: str | None = None, validate: Validator | None = None) -> None:
    """The one publication that may replace: a ratchet baseline, which an
    explicit command updates (CV-313; SPEC 22.4). ``data`` is written,
    synchronized, read back and validated in a sibling temporary exactly as
    for :func:`publish_file`, then renamed over ``final`` in one atomic step,
    so a reader sees the old file or the new one, never a mixture. What is
    replaced must be a regular file: a symlink, a directory or anything else
    there is ``unsafe`` and left alone. Raises :class:`PublishError`."""
    parent, name = _open_parent(final, anchor)
    temp = _temp_name()
    try:
        try:
            st = os.lstat(name, dir_fd=parent)
        except FileNotFoundError:
            st = None
        except OSError as exc:
            raise PublishError("failed", f"the destination cannot be examined ({os.strerror(exc.errno)})") from None
        if st is not None and not stat.S_ISREG(st.st_mode):
            raise PublishError("unsafe", f"{name!r} exists and is not a regular file; it is not replaced")
        try:
            _write_file(parent, temp, data)
            _read_back(parent, temp, data, validate)
            os.rename(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
        except BaseException as exc:
            _remove_file(parent, temp)
            if isinstance(exc, Exception):
                raise _failure(exc, name) from None
            raise
        _sync_dir(parent)
    finally:
        os.close(parent)


def publish_bundle(final: str, files: Mapping[str, bytes], *, anchor: str | None = None,
                   validate: Mapping[str, Validator] | None = None) -> None:
    """Publish ``files`` (name -> bytes) as the new directory ``final`` in
    one commit. ``validate`` may give a validator per file name."""
    if not files:
        raise PublishError("failed", "a bundle needs at least one file")
    for member in files:
        _check_name(member, "the bundle member")
        if member.startswith(TEMP_PREFIX):
            raise PublishError("unsafe", f"{member!r} uses the reserved temporary prefix")
    parent, name = _open_parent(final, anchor)
    temp = _temp_name()
    try:
        _absent(parent, name)
        try:
            os.mkdir(temp, DIR_MODE, dir_fd=parent)
            inner = os.open(temp, _DIR_FLAGS | os.O_NOFOLLOW, dir_fd=parent)
            try:
                for member in sorted(files, key=os.fsencode):
                    _write_file(inner, member, files[member])
                    _read_back(inner, member, files[member], (validate or {}).get(member))
                if sorted(os.listdir(inner)) != sorted(files):
                    raise PublishError("unsafe", "the temporary bundle holds something that was not written")
                _sync_dir(inner)
            finally:
                os.close(inner)
            _commit(parent, temp, name, directory=True)
        except BaseException as exc:
            _remove_tree(parent, temp)
            if isinstance(exc, Exception):
                raise _failure(exc, name) from None
            raise
        _sync_dir(parent)
    finally:
        os.close(parent)


def publish_stdout(stream: BinaryIO, data: bytes, *, validate: Validator | None = None) -> None:
    """Write a complete, validated artifact to a binary stdout stream. This
    is not atomic and does not claim to be; a short or failed write raises
    :class:`PublishError` so the caller publishes no commit record."""
    try:
        if validate is not None:
            validate(data)
    except Exception as exc:  # noqa: BLE001 - any validator failure means nothing is written
        raise _failure(exc, "stdout") from None
    try:
        view = memoryview(data)
        while view:
            n = stream.write(view)
            if n is None:  # a blocking raw stream wrote everything or raised
                n = len(view)
            if n <= 0:
                raise OSError(errno.EIO, "short write")
            view = view[n:]
        stream.flush()
    except (OSError, ValueError) as exc:
        raise PublishError("failed", f"stdout could not take the artifact ({type(exc).__name__})") from None
