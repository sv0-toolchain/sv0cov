# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Gitignore-compatible scope patterns (CV-310; SPEC 18.3; COV-SCP-007,
COV-SCP-008).

A scope's ``include`` array is read as a virtual root-level ``.gitignore``
under the Git 2.55.0 pattern contract, and a logical source path is
selected exactly when Git would call it ignored by that file:

- blank lines and lines starting with an unescaped ``#`` match nothing;
  trailing spaces are dropped unless escaped with ``\\``;
- a leading ``!`` negates (``\\!`` and ``\\#`` are literal);
- a trailing ``/`` matches directories only; a pattern with no other ``/``
  matches the last path component at any depth, otherwise it is anchored at
  the root (a leading ``/`` only anchors);
- ``*``, ``?``, ``[...]`` (ranges, ``!``/``^`` negation, ``[:class:]``) and
  ``\\`` escapes follow Git's ``wildmatch``, with ``**`` special only as a
  whole component;
- the last matching pattern decides, and a path inside a directory that is
  excluded cannot be re-included: each leading directory of a path is
  checked first, as Git does.

Matching is on the exact UTF-8 bytes, case-sensitively, with no Unicode
normalization. Nothing but the given patterns is consulted: no ``.gitignore``
file, ``.git/info/exclude``, ``core.excludesFile``, environment or index,
and Git is never run (SPEC 18.3, COV-SCP-008).

:func:`wildmatch` is a port of Git's ``wildmatch.c`` (``dowild``) whose
recursion is memoized on (pattern position, text position), so a pattern of
length *m* against a path of length *n* does at most *m* x *n* steps of work
per state and cannot backtrack without bound. The conformance corpus in
``tests/fixtures/gitignore`` was produced by Git 2.55.0 ``check-ignore
--no-index``; this module must reproduce it exactly.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

MATCH, NOMATCH, ABORT_ALL, ABORT_TO_STARSTAR = 0, 1, -1, -2
_GLOB_SPECIAL = frozenset(b"*?[\\")


def _is_upper(c: int) -> bool:
    return 0x41 <= c <= 0x5A


def _is_lower(c: int) -> bool:
    return 0x61 <= c <= 0x7A


def _is_digit(c: int) -> bool:
    return 0x30 <= c <= 0x39


def _is_alpha(c: int) -> bool:
    return _is_upper(c) or _is_lower(c)


def _is_space(c: int) -> bool:  # Git's sane ctype: \t \n \r and space
    return c in (0x09, 0x0A, 0x0D, 0x20)


def _is_xdigit(c: int) -> bool:
    return _is_digit(c) or 0x41 <= c <= 0x46 or 0x61 <= c <= 0x66


def _is_print(c: int) -> bool:
    return 0x20 <= c <= 0x7E


def _is_cntrl(c: int) -> bool:
    return c < 0x20 or c == 0x7F


def _is_punct(c: int) -> bool:
    return _is_print(c) and not _is_alpha(c) and not _is_digit(c) and c != 0x20


_CLASSES = {
    b"alnum": lambda c: _is_alpha(c) or _is_digit(c),
    b"alpha": _is_alpha,
    b"blank": lambda c: c in (0x20, 0x09),
    b"cntrl": _is_cntrl,
    b"digit": _is_digit,
    b"graph": lambda c: _is_print(c) and c != 0x20,
    b"lower": _is_lower,
    b"print": _is_print,
    b"punct": _is_punct,
    b"space": _is_space,
    b"upper": _is_upper,
    b"xdigit": _is_xdigit,
}


class _Wild:
    """One ``wildmatch`` call: pattern and text bytes, PATHNAME flag."""

    def __init__(self, pattern: bytes, text: bytes, pathname: bool) -> None:
        self.p = pattern + b"\0"
        self.t = text + b"\0"
        self.pathname = pathname
        self.memo: dict[tuple[int, int], int] = {}

    def run(self, pi: int, ti: int) -> int:
        key = (pi, ti)
        hit = self.memo.get(key)
        if hit is None:
            hit = self._dowild(pi, ti)
            self.memo[key] = hit
        return hit

    def _dowild(self, pi: int, ti: int) -> int:  # noqa: C901 - a faithful port
        p, t, pathname = self.p, self.t, self.pathname
        start = pi
        while p[pi] != 0:
            p_ch = p[pi]
            t_ch = t[ti]
            if t_ch == 0 and p_ch != 0x2A:  # '*'
                return ABORT_ALL
            if p_ch == 0x5C:  # '\\': literal next byte
                pi += 1
                p_ch = p[pi]
                if t_ch != p_ch:
                    return NOMATCH
            elif p_ch == 0x3F:  # '?'
                if pathname and t_ch == 0x2F:
                    return NOMATCH
            elif p_ch == 0x2A:  # '*'
                pi += 1
                if p[pi] == 0x2A:
                    prev = pi - 2
                    while p[pi + 1] == 0x2A:
                        pi += 1
                    pi += 1
                    if (prev < start or p[prev] == 0x2F) and (p[pi] == 0 or p[pi] == 0x2F or (p[pi] == 0x5C and p[pi + 1] == 0x2F)):
                        if p[pi] == 0x2F and self.run(pi + 1, ti) == MATCH:
                            return MATCH
                        match_slash = True
                    else:
                        match_slash = False
                else:
                    match_slash = not pathname
                if p[pi] == 0:
                    # Trailing "**" matches everything; trailing "*" only
                    # when no slash is left.
                    if not match_slash and 0x2F in t[ti:-1]:
                        return ABORT_TO_STARSTAR
                    return MATCH
                if not match_slash and p[pi] == 0x2F:
                    # One "*" then "/" with PATHNAME matches up to the next slash.
                    slash = t.find(b"/", ti, len(t) - 1)
                    if slash < 0:
                        return ABORT_ALL
                    # the "/" of both is consumed here, as by Git's loop step
                    pi, ti = pi + 1, slash + 1
                    continue
                while True:
                    t_ch = t[ti]
                    if t_ch == 0:
                        break
                    if p[pi] not in _GLOB_SPECIAL:
                        want = p[pi]
                        while True:
                            t_ch = t[ti]
                            if t_ch == 0 or (not match_slash and t_ch == 0x2F):
                                break
                            if t_ch == want:
                                break
                            ti += 1
                        if t_ch != want:
                            if match_slash:
                                return ABORT_ALL
                            # Stopped at a slash it cannot cross: let an
                            # enclosing "**" try further on (Git 2.55.0).
                            return ABORT_TO_STARSTAR if t_ch == 0x2F else ABORT_ALL
                    matched = self.run(pi, ti)
                    if matched != NOMATCH:
                        if not match_slash or matched != ABORT_TO_STARSTAR:
                            return matched
                    elif not match_slash and t_ch == 0x2F:
                        return ABORT_TO_STARSTAR
                    ti += 1
                return ABORT_ALL
            elif p_ch == 0x5B:  # '['
                pi += 1
                p_ch = p[pi]
                if p_ch == 0x5E:  # '^' is '!' here
                    p_ch = 0x21
                negated = p_ch == 0x21
                if negated:
                    pi += 1
                    p_ch = p[pi]
                prev_ch = 0
                matched_class = False
                while True:
                    if p_ch == 0:
                        return ABORT_ALL
                    if p_ch == 0x5C:
                        pi += 1
                        p_ch = p[pi]
                        if p_ch == 0:
                            return ABORT_ALL
                        if t_ch == p_ch:
                            matched_class = True
                    elif p_ch == 0x2D and prev_ch and p[pi + 1] and p[pi + 1] != 0x5D:  # '-'
                        pi += 1
                        p_ch = p[pi]
                        if p_ch == 0x5C:
                            pi += 1
                            p_ch = p[pi]
                            if p_ch == 0:
                                return ABORT_ALL
                        if prev_ch <= t_ch <= p_ch:
                            matched_class = True
                        p_ch = 0
                    elif p_ch == 0x5B and p[pi + 1] == 0x3A:  # "[:"
                        s = pi + 2
                        pi = s
                        while p[pi] != 0 and p[pi] != 0x5D:
                            pi += 1
                        p_ch = p[pi]
                        if p_ch == 0:
                            return ABORT_ALL
                        i = pi - s - 1
                        if i < 0 or p[pi - 1] != 0x3A:
                            # No ":]": an ordinary "[" in the set, and the
                            # scan goes on after its ":" (Git 2.55.0).
                            pi = s - 1
                            p_ch = 0x5B
                            if t_ch == p_ch:
                                matched_class = True
                            prev_ch = p_ch
                            pi += 1
                            p_ch = p[pi]
                            if p_ch == 0x5D:
                                break
                            continue
                        test = _CLASSES.get(p[s:s + i])
                        if test is None:
                            return ABORT_ALL
                        if test(t_ch):
                            matched_class = True
                        p_ch = 0
                    elif t_ch == p_ch:
                        matched_class = True
                    prev_ch = p_ch
                    pi += 1
                    p_ch = p[pi]
                    if p_ch == 0x5D:  # ']'
                        break
                if matched_class == negated or (pathname and t_ch == 0x2F):
                    return NOMATCH
            else:
                if t_ch != p_ch:
                    return NOMATCH
            pi += 1
            ti += 1
        return NOMATCH if t[ti] != 0 else MATCH


def wildmatch(pattern: bytes, text: bytes, *, pathname: bool) -> bool:
    """Git's ``wildmatch(pattern, text, pathname ? WM_PATHNAME : 0) == WM_MATCH``."""
    return _Wild(pattern, text, pathname).run(0, 0) == MATCH


@dataclass(frozen=True)
class Pattern:
    """One parsed pattern line (Git ``parse_path_pattern``)."""

    text: bytes
    negative: bool
    must_be_dir: bool
    no_dir: bool  # no slash: matches the last component at any depth
    line: int = 0  # 1-based line in the pattern file
    head: bytes = b""  # literal bytes every match starts with (path patterns)
    tail: bytes | None = None  # what the last path component must match, when that is decidable alone
    words: frozenset = frozenset()  # literal components that must each equal some path component


def _trim_trailing_spaces(line: bytes) -> bytes:
    """Git ``trim_trailing_spaces``: drop unescaped trailing spaces."""
    end = len(line)
    last_space = None
    i = 0
    while i < end:
        c = line[i]
        if c == 0x20:
            if last_space is None:
                last_space = i
        elif c == 0x5C:
            i += 1
            if i >= end:
                return line
            last_space = None
        else:
            last_space = None
        i += 1
    return line if last_space is None else line[:last_space]


def _filters(raw: bytes, no_dir: bool) -> tuple[bytes, bytes | None, frozenset]:
    """Cheap necessary conditions for a path pattern, checked before
    ``wildmatch`` (deep paths are matched once per leading directory):

    - ``head``: the literal bytes before the first special character; Git
      compares this prefix first too.
    - ``tail``: the pattern's last component. With ``WM_PATHNAME`` a single
      ``*`` cannot cross ``/`` and only a component that is exactly ``**``
      can span components, so unless the last component is ``**`` it must
      match the path's last component on its own.
    - ``words``: the components with no special character. Nothing in one
      can consume a ``/``, so each must equal a whole path component.

    ``tail`` and ``words`` are left out when the pattern has a backslash (an
    escaped ``/`` is not a separator)."""
    if no_dir:
        return b"", None, frozenset()
    n = 0
    while n < len(raw) and raw[n] not in _GLOB_SPECIAL:
        n += 1
    if b"\\" in raw:
        return raw[:n], None, frozenset()
    parts = raw.split(b"/")
    words = frozenset(c for c in parts if c and not any(b in _GLOB_SPECIAL for b in c))
    return raw[:n], None if parts[-1] == b"**" else parts[-1], words


def parse(lines: Iterable[str]) -> list[Pattern]:
    """The patterns of an ordered pattern file; comments and blanks dropped."""
    out = []
    for number, line in enumerate(lines, 1):
        raw = _trim_trailing_spaces(line.encode("utf-8"))
        if not raw or raw[:1] == b"#":
            continue
        negative = raw[:1] == b"!"
        if negative:
            raw = raw[1:]
        must_be_dir = raw.endswith(b"/")
        if must_be_dir:
            raw = raw[:-1]
        no_dir = b"/" not in raw
        if raw.startswith(b"/"):
            raw = raw[1:]
        out.append(Pattern(raw, negative, must_be_dir, no_dir, number, *_filters(raw, no_dir)))
    return out


def _matches(pat: Pattern, path: bytes, is_dir: bool) -> bool:
    if pat.must_be_dir and not is_dir:
        return False
    if pat.no_dir:
        base = path[path.rfind(b"/") + 1:]
        return wildmatch(pat.text, base, pathname=False)
    if not path.startswith(pat.head):
        return False
    if pat.tail is not None and not wildmatch(pat.tail, path[path.rfind(b"/") + 1:], pathname=True):
        return False
    if pat.words and not pat.words <= set(path.split(b"/")):
        return False
    return wildmatch(pat.text, path, pathname=True)


def _last_match(patterns: Sequence[Pattern], path: bytes, is_dir: bool) -> Pattern | None:
    for pat in reversed(patterns):
        if _matches(pat, path, is_dir):
            return pat
    return None


class Matcher:
    """A compiled pattern file over logical paths."""

    def __init__(self, lines: Iterable[str]) -> None:
        self.patterns = parse(lines)
        self._dirs: dict[bytes, bool] = {}

    def _excluded(self, path: bytes, is_dir: bool) -> bool:
        hit = _last_match(self.patterns, path, is_dir)
        return hit is not None and not hit.negative

    def _dir_excluded(self, path: bytes) -> bool:
        """Whether the directory ``path`` or one above it is excluded,
        deciding each leading directory from the root down (iteratively: a
        logical path may have thousands of components)."""
        known = self._dirs.get(path)
        if known is not None:
            return known
        parts = path.split(b"/")
        excluded = False
        for n in range(1, len(parts) + 1):
            prefix = b"/".join(parts[:n])
            hit = self._dirs.get(prefix)
            if hit is None:
                hit = excluded or self._excluded(prefix, True)
                self._dirs[prefix] = hit
            excluded = hit
        return excluded

    def explain(self, path: str, is_dir: bool = False) -> tuple[int | None, bool]:
        """(line of the deciding pattern or None, selected) for ``path``, as
        Git ``check-ignore -v -n`` reports it: an excluded leading directory
        decides with its own pattern; otherwise the path's last match does."""
        raw = path.encode("utf-8")
        parts = raw.split(b"/")
        for n in range(1, len(parts)):
            hit = _last_match(self.patterns, b"/".join(parts[:n]), True)
            if hit is not None and not hit.negative:
                return hit.line, True
        hit = _last_match(self.patterns, raw, is_dir)
        return (None, False) if hit is None else (hit.line, not hit.negative)

    def selects(self, path: str) -> bool:
        """Whether Git would call the file ``path`` ignored by these patterns."""
        raw = path.encode("utf-8")
        if b"/" in raw and self._dir_excluded(raw.rsplit(b"/", 1)[0]):
            return True
        return self._excluded(raw, False)


def select(lines: Sequence[str], paths: Iterable[str]) -> list[str]:
    """The paths (files) the pattern file selects, in the order given."""
    m = Matcher(lines)
    return [p for p in paths if m.selects(p)]
