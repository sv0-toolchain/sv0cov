# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The LCOV export profile ``sv0cov-lcov-r1-core`` (CV-401; SPEC 21.4;
COV-REP-004, COV-REP-008, COV-REP-010, BL-053, BL-078).

:func:`render_lcov` writes one tracefile from a validated native report.
:func:`parse_lcov` reads a tracefile back under the exact profile grammar,
and :func:`check_lcov` additionally requires its totals to equal the
report's.

What is exported:

- **Sources.** One record per root-project (``user``) source, in source
  order: the totals add up to the native project summary (SPEC 18.1;
  owner decision, CV-401). Dependency sources are omitted, and the export
  manifest (CV-403) says so.
- **Functions.** ``FN`` and then ``FNDA`` for every function the native
  function metric counts, in entity order: the first executable line of
  its span, its canonical qualified name, its exact entry count.
- **Lines.** ``DA`` for every executable line, ascending: ``1`` for a line
  that executed (native status ``covered`` or ``partial``), ``0`` for
  ``uncovered``. LCOV's own meaning of a hit line; LCOV 2.5 refuses a
  ``DA`` of ``0`` on a line with a taken branch (owner decision, CV-418;
  the native report keeps ``partial`` apart).
- **Branches.** ``BRDA`` for every eligible outcome (``covered`` or
  ``uncovered``), on the first executable line of its branch's span (a
  ``loop`` header is not executable; LCOV 2.5 places branch data only on
  ``DA`` lines). Within a line,
  decisions are numbered from zero in canonical branch order and outcomes
  from zero in ordinal order; a decision with no eligible outcome has no
  number. Counts are exact.
- **Not exported:** regions, contracts, contexts (all contexts are
  aggregated; ``TN:`` is always empty), excluded and statically unreachable
  units, and every LCOV extension (``VER``, checksums, ``FNL``, ``FNA``,
  end lines, comments). Native JSON stays authoritative.

The summaries (``FNF``/``FNH``, ``LF``/``LH``, ``BRF``/``BRH``) equal the
native per-source function and branch metrics and the line metric's
executed lines (covered plus partial); a zero denominator is written ``0``.
Every golden is accepted by LCOV 1.16 and 2.5 ``lcov --summary`` and
``genhtml`` with no ignored error (``tools/lcov_conformance.py``).

A count that is saturated or only a lower bound has no exact value, so a
report holding one in an exported unit is refused (``COV4020``) unless the
caller asks for the explicit diagnostic-only lossy export (``lossy=True``;
CV-420, SPEC 14.2.1), which writes each such count as the hit count ``1``.
:func:`has_inexact` says whether an export would need it. A malformed tracefile, or one that does not
match its report, is ``COV4401``.
"""

from __future__ import annotations

import bisect
import re

PROFILE = "sv0cov-lcov-r1-core"
SATURATED, INVALID = "COV4020", "COV4401"
ELIGIBLE = ("covered", "uncovered")
EXECUTABLE = ("covered", "partial", "uncovered")
RE_NAME = re.compile(r"[^\x00-\x1f\x7f,]+")


class LcovError(ValueError):
    """``code``: COV4020 a count with no exact value, COV4401 an invalid tracefile."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _exact(count: dict, what: str, lossy: bool) -> int:
    if count["saturated"] or count["lower_bound"]:
        if lossy:
            return 1  # the lossy hit-only projection: executed, magnitude unknown
        raise LcovError(SATURATED, f"{what} has no exact count (it saturated); LCOV needs exact counts")
    return count["value"]


def _records(r: dict, lossy: bool = False) -> list[dict]:
    """Per root-project source: its functions, lines and decisions as LCOV sees them."""
    entry = {p["entity_index"]: p for p in r["points"] if p["kind"] == "function_entry"}
    out = []
    for s in r["sources"]:
        if s["ownership"] != "user":
            continue
        n = s["source_index"]
        functions = []
        for e in r["entities"]:
            p = entry.get(e["entity_index"])
            if e["kind"] != "function" or e["source_index"] != n or p is None or p["classification"] != "user":
                continue
            name = e["qualified_name"]
            if not RE_NAME.fullmatch(name):
                raise LcovError(INVALID, f"function name {name!r} cannot be written as an LCOV record")
            functions.append((e["span"], name, _exact(p["count"], f"function {name}", lossy)))
        # DA is 1 for a line that executed at all, partial included (owner decision, CV-418): LCOV 2.5 refuses
        # a DA 0 line holding a taken branch, and a partial line nearly always holds one.
        lines = sorted((x["line"], int(x["status"] != "uncovered")) for x in r["lines"] if x["source_index"] == n and x["status"] in EXECUTABLE)
        numbers = [k for k, _ in lines]

        def first_line(span: dict, what: str) -> int:
            """The first executable line inside ``span``: LCOV 2.5 places function and
            branch data only on lines that have DA (owner decision, CV-418)."""
            at = bisect.bisect_left(numbers, span["start_line"])
            if at == len(numbers) or numbers[at] > span["end_line"]:
                raise LcovError(INVALID, f"{what} in {s['path']} has no executable line to carry it")
            return numbers[at]

        functions = [(first_line(span, f"function {name}"), name, count) for span, name, count in functions]
        decisions: dict[int, list[list[int]]] = {}
        for b in sorted((b for b in r["branches"] if b["source_index"] == n), key=lambda b: (b["span"]["start_line"], b["branch_index"])):
            outcomes = sorted((o for o in b["outcomes"] if o["status"] in ELIGIBLE), key=lambda o: o["ordinal"])
            if outcomes:
                where = f"branch {b['branch_index']} in {s['path']}"
                decisions.setdefault(first_line(b["span"], where), []).append([_exact(o["count"], where, lossy) for o in outcomes])
        out.append({"path": s["path"], "functions": functions, "lines": lines, "decisions": decisions})
    return out


def has_inexact(report: dict) -> bool:
    """Whether some exported count is saturated or a lower bound."""
    try:
        _records(report)
    except LcovError as exc:
        if exc.code == SATURATED:
            return True
        raise
    return False


def render_lcov(report: dict, *, lossy: bool = False) -> bytes:
    """The ``sv0cov-lcov-r1-core`` tracefile of a validated native report;
    ``lossy`` writes an inexact count as ``1`` instead of refusing it."""
    text = []
    for rec in _records(report, lossy):
        text += ["TN:", f"SF:{rec['path']}"]
        text += [f"FN:{line},{name}" for line, name, _ in rec["functions"]]
        text += [f"FNDA:{count},{name}" for _, name, count in rec["functions"]]
        text += [f"FNF:{len(rec['functions'])}", f"FNH:{sum(c > 0 for _, _, c in rec['functions'])}"]
        text += [f"DA:{line},{hit}" for line, hit in rec["lines"]]
        text += [f"LF:{len(rec['lines'])}", f"LH:{sum(h for _, h in rec['lines'])}"]
        brf = brh = 0
        for line in sorted(rec["decisions"]):
            for d, counts in enumerate(rec["decisions"][line]):
                for o, count in enumerate(counts):
                    text.append(f"BRDA:{line},{d},{o},{count}")
                    brf += 1
                    brh += count > 0
        text += [f"BRF:{brf}", f"BRH:{brh}", "end_of_record"]
    return ("\n".join(text) + "\n").encode("ascii") if text else b""


# ── reading ─────────────────────────────────────────────────────────────────


_INT = r"(0|[1-9][0-9]*)"
_LINE = r"([1-9][0-9]*)"
_PATTERNS = {
    "FN": re.compile(rf"FN:{_LINE},(.+)"),
    "FNDA": re.compile(rf"FNDA:{_INT},(.+)"),
    "DA": re.compile(rf"DA:{_LINE},([01])"),
    "BRDA": re.compile(rf"BRDA:{_LINE},{_INT},{_INT},{_INT}"),
}
_SUMMARY = {k: re.compile(rf"{k}:{_INT}") for k in ("FNF", "FNH", "LF", "LH", "BRF", "BRH")}


def _bad(n: int, detail: str) -> None:
    raise LcovError(INVALID, f"line {n}: {detail}")


def parse_lcov(data: bytes) -> list[dict]:
    """The records of a ``sv0cov-lcov-r1-core`` tracefile, each with its
    path and function/line/branch totals; raises :class:`LcovError` for
    anything outside the profile or inconsistent within a record."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise LcovError(INVALID, "not UTF-8") from None
    if text and not text.endswith("\n"):
        raise LcovError(INVALID, "the tracefile does not end with a line feed")
    lines = text.split("\n")[:-1] if text else []
    out, i, seen = [], 0, set()
    order = ("FN", "FNDA", "FNF", "FNH", "DA", "LF", "LH", "BRDA", "BRF", "BRH")

    def take(prefix: str) -> list[tuple[int, re.Match]]:
        nonlocal i
        got = []
        while i < len(lines) and lines[i].startswith(prefix + ":"):
            m = (_PATTERNS.get(prefix) or _SUMMARY[prefix]).fullmatch(lines[i])
            if not m:
                _bad(i + 1, f"malformed {prefix} record")
            got.append((i + 1, m))
            i += 1
        return got

    while i < len(lines):
        if lines[i] != "TN:":
            _bad(i + 1, "a record begins with an empty TN:")
        i += 1
        if i >= len(lines) or not lines[i].startswith("SF:") or len(lines[i]) == 3:
            _bad(i + 1, "SF: with a path follows TN:")
        path = lines[i][3:]
        if path in seen:
            _bad(i + 1, f"source {path} appears twice")
        seen.add(path)
        i += 1
        got = {k: take(k) for k in order}
        for k in ("FNF", "FNH", "LF", "LH", "BRF", "BRH"):
            if len(got[k]) != 1:
                _bad(i + 1, f"exactly one {k} record per source")
        if i >= len(lines) or lines[i] != "end_of_record":
            _bad(i + 1, f"unexpected record {lines[i].split(':', 1)[0] if i < len(lines) else 'end of file'!r}")
        i += 1
        num = {k: int(got[k][0][1].group(1)) for k in ("FNF", "FNH", "LF", "LH", "BRF", "BRH")}
        fn = [(m.group(2), int(m.group(1))) for _, m in got["FN"]]
        fnda = {m.group(2): int(m.group(1)) for _, m in got["FNDA"]}
        names = [name for name, _ in fn]
        if len(set(names)) != len(names) or sorted(fnda) != sorted(names) or len(got["FNDA"]) != len(fnda):
            _bad(i, f"{path}: every function has one FN and one FNDA")
        da = [(int(m.group(1)), int(m.group(2))) for _, m in got["DA"]]
        if any(a >= b for (a, _), (b, _) in zip(da, da[1:])):
            _bad(i, f"{path}: DA lines are strictly ascending")
        brda = [tuple(int(x) for x in m.groups()) for _, m in got["BRDA"]]
        if [x[0] for x in brda] != sorted(x[0] for x in brda):
            _bad(i, f"{path}: BRDA lines are ascending")
        last: tuple[int, int, int] | None = None  # (line, decision, outcome)
        for line, d, o, _ in brda:
            if last is None or last[0] != line:
                ok = (d, o) == (0, 0)
            else:
                ok = (d, o) in ((last[1], last[2] + 1), (last[1] + 1, 0))
            if not ok:
                _bad(i, f"{path}: decision and outcome indexes are contiguous from zero within a line")
            last = (line, d, o)
        totals = {"FNF": len(fn), "FNH": sum(fnda[n] > 0 for n in names), "LF": len(da), "LH": sum(h for _, h in da),
                  "BRF": len(brda), "BRH": sum(c > 0 for *_, c in brda)}
        for k, v in totals.items():
            if num[k] != v:
                _bad(i, f"{path}: {k} is {num[k]}, its records give {v}")
        out.append({"path": path, "function": (totals["FNH"], totals["FNF"]), "line": (totals["LH"], totals["LF"]),
                    "branch": (totals["BRH"], totals["BRF"])})
    return out


def check_lcov(data: bytes, report: dict) -> None:
    """``data`` is a valid tracefile whose records are exactly the report's
    root-project sources, in order, with the report's own function, line
    and branch fractions."""
    got = parse_lcov(data)
    want = [s for s in report["sources"] if s["ownership"] == "user"]
    if [g["path"] for g in got] != [s["path"] for s in want]:
        raise LcovError(INVALID, "the tracefile's sources are not the report's root-project sources")
    for g, s in zip(got, want):
        for metric in ("function", "line", "branch"):
            m = s["summary"][metric]
            hit = m["covered"] + (m["partial"] or 0) if metric == "line" else m["covered"]  # DA 1 = executed
            if g[metric] != (hit, m["total"]):
                raise LcovError(INVALID, f"{s['path']}: the {metric} fraction {g[metric][0]}/{g[metric][1]} is not the "
                                         f"report's {hit}/{m['total']}")


__all__ = ["LcovError", "PROFILE", "check_lcov", "has_inexact", "parse_lcov", "render_lcov"]
