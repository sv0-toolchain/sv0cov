# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The terminal report (CV-230; SPEC 11.6, 20.2, 21.1; COV-REP-001,
COV-MET-011, COV-SEC-003).

:func:`render_terminal` is a pure view of one validated native report (the
dictionary :func:`sv0cov.model.report.read_report` returns). It computes no
coverage fact of its own: every number is a number the report holds.

- A metric is shown as the exact ``covered/total`` pair and a percentage.
  The percentage is the report's own ``ratio`` with the decimal point moved
  two places, so nothing is rounded a second time. A zero total shows
  ``N/A``.
- A saturated or lower-bound count is written ``>=N``.
- Every status is a word. Color, when asked for, only repeats it: removing
  the color sequences gives exactly the colorless text.
- Text that came from a source file, a path or a configuration is escaped,
  so it cannot move the cursor, change color, or reorder the line.
- The layout does not depend on the terminal's width, the locale, or the
  clock. The same report gives the same bytes.
"""

from __future__ import annotations

from typing import Iterable

from sv0cov.diagnostics import escape_text

TITLE = "sv0cov coverage report"
METRICS = (("function", "functions"), ("region", "regions"), ("line", "lines"), ("branch", "branches"))
CONTRACT = ("contract", "contracts")
ELIGIBILITY = {"passing": "PASSING", "policy_failed": "POLICY FAILED", "incomplete": "INCOMPLETE",
               "diagnostic_only": "DIAGNOSTIC ONLY"}
RESULT = {"pass": "PASS", "fail": "FAIL", "ineligible": "INELIGIBLE", "not_applicable": "N/A"}
COMPARISON = {"at_least": ">=", "at_most": "<=", "equal": "=="}
MEMBERS = (("source_indices", "source"), ("entity_indices", "entity", "entities"), ("region_indices", "region"),
           ("line_indices", "line"), ("branch_indices", "branch", "branches"), ("clause_indices", "clause"))
SGR_GOOD, SGR_BAD, SGR_WARN, SGR_BOLD, SGR_RESET = "\x1b[32m", "\x1b[1;31m", "\x1b[33m", "\x1b[1m", "\x1b[0m"
GOOD_WORDS = frozenset({"PASS", "PASSING", "passed"})
BAD_WORDS = frozenset({"FAIL", "POLICY FAILED", "failed"})


def percent(ratio: str | None) -> str:
    """``0.848485`` as ``84.8485%``; a null ratio as ``N/A`` (SPEC 11.6)."""
    if ratio is None:
        return "N/A"
    whole, fraction = ratio.split(".")
    return f"{int(whole + fraction[:2])}.{fraction[2:]}%"


def count_text(count: dict) -> str:
    """A count, in lower-bound notation when it is not exact."""
    bound = count["saturated"] or count["lower_bound"]
    return f"{'>=' if bound else ''}{count['value']}"


def ranges(numbers: Iterable[int]) -> str:
    """Sorted integers as ``3, 5-7, 9``; a range joins adjacent numbers only."""
    out: list[str] = []
    start = last = None
    for n in sorted(set(numbers)):
        if last is not None and n == last + 1:
            last = n
            continue
        if start is not None:
            out.append(str(start) if start == last else f"{start}-{last}")
        start = last = n
    if start is not None:
        out.append(str(start) if start == last else f"{start}-{last}")
    return ", ".join(out)


def _quoted(text: str) -> str:
    r"""Text between double quotes. A backslash is doubled before anything is
    escaped, so neither an escape sequence nor a closing quote can be forged:
    the text ``a\`` reads ``"a\\"``, the ESC character reads ``"\x1b"`` and
    the four characters backslash, x, 1, b read ``"\\x1b"``."""
    return '"' + escape_text(text.replace("\\", "\\\\")).replace('"', '\\"') + '"'


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def _table(rows: list[list[str]], right: frozenset[int] = frozenset()) -> list[str]:
    """Columns padded to their widest cell; no trailing spaces."""
    widths = [max(len(r[i]) for r in rows if i < len(r)) for i in range(max(len(r) for r in rows))]
    out = []
    for r in rows:
        cells = [c.rjust(widths[i]) if i in right else c.ljust(widths[i]) for i, c in enumerate(r)]
        out.append("  ".join(cells).rstrip())
    return out


def _sgr(word: str) -> str:
    return SGR_GOOD if word in GOOD_WORDS else SGR_BAD if word in BAD_WORDS else SGR_WARN


def change_line(c: dict) -> str:
    """The changed-region base in one line (SPEC 22.3): the merge base, how
    it was named, and whether ``HEAD`` alone reproduces the result."""
    b = c["base"]
    lines = sum(len(x["changed_lines"]) for x in c["sources"])
    files = sum(1 for x in c["sources"] if x["changed_lines"])
    state = "clean" if c["clean"] else "dirty, not reproducible from HEAD alone"
    return (f"since {b['merge_base'][:12]} (merge base of {_quoted(b['spelling'])} and HEAD {b['head'][:12]}); "
            f"{_plural(lines, 'changed line')} in {_plural(files, 'source')}; {state}")


RATCHET_STATE = {"ok": "baseline", "missing": "no baseline", "invalid": "invalid baseline", "incompatible": "incompatible baseline",
                 "stale": "stale baseline (its commit is not HEAD or an ancestor)"}


def ratchet_line(t: dict) -> str:
    """The ratchet's baseline in one line (SPEC 22.4): its state and digest,
    the commit it was made at, the source-set change, and every metric
    outcome."""
    parts = [RATCHET_STATE[t["state"]]]
    if t["baseline_sha256"] is not None:
        parts[0] += f" sha256 {t['baseline_sha256'][:12]}"
    b = t["baseline"]
    if b is not None:
        parts.append("made outside Git" if b["commit"] is None else f"made at {b['commit'][:12]}")
    if t["sources_added"] or t["sources_removed"]:
        parts.append(f"sources {len(t['sources_added'])} added, {len(t['sources_removed'])} removed")
    found = [f"{c['metric']} {o.replace('_', ' ')}" for c in t["comparisons"] for o in c["outcomes"]]
    if found:
        parts.append(", ".join(found))
    return "; ".join(parts)


class _View:
    def __init__(self, report: dict, color: bool) -> None:
        self.r = report
        self.color = color
        self.lines: list[str] = []
        # line number -> (where, length, sequence): the only color there is.
        self.marks: dict[int, tuple[str, int, str]] = {}
        self.raw_path = {s["source_index"]: s["path"].encode("utf-8") for s in report["sources"]}
        self.path = {i: escape_text(p.decode("utf-8")) for i, p in self.raw_path.items()}
        self.entity = {e["entity_index"]: e for e in report["entities"]}
        self.context = {c["context_index"]: c["value"] for c in report["contexts"]}

    # -- helpers --------------------------------------------------------------

    def section(self, title: str) -> None:
        self.lines.append("")
        self.put(title, "head", len(title), SGR_BOLD)
        self.lines.append("-" * len(title))

    def put(self, line: str, where: str, length: int, sgr: str) -> None:
        """One line whose first (``head``) or last (``tail``) ``length``
        characters are colored when color is on."""
        self.marks[len(self.lines)] = (where, length, sgr)
        self.lines.append(line)

    def status_line(self, prefix: str, word: str) -> None:
        self.put(prefix + word, "tail", len(word), _sgr(word))

    def where(self, record: dict) -> str:
        span = record["span"]
        return f"{self.path[record['source_index']]}:{span['start_line']}:{span['start_column']}"

    def context_name(self, index: int) -> str:
        value = self.context[index]
        return "(default)" if value is None else _quoted(value)

    @staticmethod
    def pair(metric: dict | None) -> list[str]:
        if metric is None:
            return ["-", ""]
        return [f"{metric['covered']}/{metric['total']}", percent(metric["ratio"])]

    # -- sections -------------------------------------------------------------

    def header(self) -> None:
        r, p = self.r, self.r["provenance"]
        self.put(TITLE, "head", len(TITLE), SGR_BOLD)
        self.lines.append("=" * len(TITLE))
        status = p["execution_status"].replace("_", " ")
        if p["execution_exit_code"] is not None:
            status += f" (exit {p['execution_exit_code']})"
        if p["execution_signal"] is not None:
            status += f" (signal {p['execution_signal']})"
        by_status: dict[str, int] = {}
        for i in r["inputs"]:
            by_status[i["status"]] = by_status.get(i["status"], 0) + 1
        inputs = ", ".join(f"{by_status[s]} {s}" for s in ("accepted", "incomplete", "rejected") if s in by_status)
        rows = [
            ["evidence:", ELIGIBILITY[r["evidence_eligibility"]]],
            ["complete:", "yes" if r["complete"] else "no"],
            ["policy:", "passed" if r["policy"]["passed"] else "failed"],
            ["tool:", f"sv0cov {escape_text(r['tool']['version'])}"],
            ["backends:", ", ".join(p["backends"]) or "none"],
            ["execution:", status],
            ["runs:", f"{len(p['run_ids'])} ({p['run_selection']})"],
            ["inputs:", inputs or "none"],
            ["sources:", p["source_accuracy"].replace("_", " ")],
            ["contexts:", ", ".join(self.context_name(c["context_index"]) for c in r["contexts"]) or "none"],
        ]
        if r["changes"] is not None:
            rows.append(["changes:", change_line(r["changes"])])
        if r["ratchet"] is not None:
            rows.append(["ratchet:", ratchet_line(r["ratchet"])])
        width = max(len(row[0]) for row in rows)
        for label, value in rows:
            if label in ("evidence:", "policy:"):
                self.status_line(f"{label.ljust(width)}  ", value)
            else:
                self.lines.append(f"{label.ljust(width)}  {value}")

    def summary(self) -> None:
        self.section("Summary")
        summary = self.r["summary"]
        rows = [["metric", "covered/total", "percent"]]
        for key, label in METRICS:
            m = summary[key]
            row = [label, *self.pair(m)]
            if key == "line" and m is not None:
                row.append(f"{m['partial']} partial")
            rows.append(row)
        self.lines += _table(rows, right=frozenset({1, 2}))
        self.lines += ["", "Contracts are reported separately and are not part of the metrics above."]
        self.lines += _table([[CONTRACT[1], *self.pair(summary[CONTRACT[0]])]], right=frozenset({1, 2}))

    def files(self) -> None:
        self.section("Files")
        if not self.r["sources"]:
            self.lines.append("(none)")
            return
        head = ["", *[label for _, label in METRICS], CONTRACT[1]]
        rows: list[list[str]] = [head]
        owned: dict[int, list[dict]] = {}
        for e in self.r["entities"]:
            if e["kind"] == "function":
                owned.setdefault(e["source_index"], []).append(e)

        def cells(name: str, summary: dict) -> list[str]:
            return [name, *[" ".join(self.pair(summary[k])).rstrip() for k, _ in (*METRICS, CONTRACT)]]

        groups: dict[tuple, list[dict]] = {}
        for s in self.r["sources"]:
            key = (0 if s["ownership"] == "user" else 1, s["package"] is not None, s["package"] or "")
            groups.setdefault(key, []).append(s)
        for key in sorted(groups):
            ownership = "user" if key[0] == 0 else "dependency"
            package = f"package {_quoted(key[2])}" if key[1] else "no package"
            rows.append([f"[{ownership}] {package}"])
            for s in sorted(groups[key], key=lambda s: s["path"].encode("utf-8")):
                rows.append(cells(f"  {escape_text(s['path'])}", s["summary"]))
                for e in sorted(owned.get(s["source_index"], []), key=lambda e: e["entity_index"]):
                    rows.append(cells(f"    fn {escape_text(e['qualified_name'])}", e["summary"]))
        self.lines += _table(rows)

    def uncovered(self) -> None:
        by_status: dict[str, dict[int, list[int]]] = {"partial": {}, "uncovered": {}}
        for line in self.r["lines"]:
            if line["status"] in by_status:
                by_status[line["status"]].setdefault(line["source_index"], []).append(line["line"])
        order = sorted(self.path, key=self.raw_path.__getitem__)
        for status, title in (("partial", "Partial lines"), ("uncovered", "Uncovered lines")):
            self.section(title)
            found = [i for i in order if i in by_status[status]]
            self.lines += [f"{self.path[i]}: {ranges(by_status[status][i])}" for i in found] or ["(none)"]
        self.section("Uncovered branch outcomes")
        rows = []
        for b in sorted(self.r["branches"], key=lambda b: (self.raw_path[b["source_index"]],
                                                          b["span"]["start_byte"], b["span"]["end_byte"], b["branch_index"])):
            missed = [o for o in b["outcomes"] if o["status"] == "uncovered"]
            if missed:
                names = ", ".join(escape_text(o["name"]) for o in sorted(missed, key=lambda o: o["ordinal"]))
                rows.append([self.where(b), b["kind"], f"not taken: {names}"])
        self.lines += _table(rows) if rows else ["(none)"]

    def contracts(self) -> None:
        self.section("Contracts")
        if not self.r["contracts"]:
            self.lines.append("(none)")
            return
        rows = [["location", "clause", "enforcement", "result", "true", "false"]]
        for c in self.r["contracts"]:
            name = escape_text(self.entity[c["entity_index"]]["qualified_name"])
            counts = ["-" if c[k] is None else count_text(c[k]) for k in ("count_true", "count_false")]
            rows.append([self.where(c), name, c["enforcement"], c["runtime_result"], *counts])
        self.lines += _table(rows, right=frozenset({4, 5}))
        for c in self.r["contracts"]:
            if c["evidence_identity"] is not None:
                self.lines.append(f"{self.where(c)} evidence: {_quoted(c['evidence_identity'])}")

    def exclusions(self) -> None:
        self.section("Exclusions")
        records = self.r["exclusions"]
        functions = {i for x in records for i in x["affected"]["entity_indices"] if self.entity[i]["kind"] == "function"}
        union = {k: {i for x in records for i in x["affected"][k]}
                 for k in ("region_indices", "line_indices", "branch_indices", "clause_indices")}
        self.lines.append(
            f"excluded: {_plural(len(functions), 'function')}, {_plural(len(union['region_indices']), 'region')}, "
            f"{_plural(len(union['line_indices']), 'line')}, {_plural(len(union['branch_indices']), 'branch', 'branches')}, "
            f"{_plural(len(union['clause_indices']), 'contract')}")
        unreachable = sum(1 for b in self.r["branches"] for o in b["outcomes"] if o["status"] == "statically_unreachable")
        self.lines.append(f"statically unreachable: {_plural(unreachable, 'branch outcome')}")
        for x in records:
            self.lines.append(f"#{x['exclusion_index']} {self.where(x)} {x['mode']} ({x['origin']}): {_quoted(x['reason'])}")

    def warnings(self) -> None:
        self.section("Warnings")
        out = []
        if not self.r["complete"]:
            out.append("WARNING: the evidence is incomplete; this report cannot be passing evidence.")
        for i in self.r["inputs"]:
            if i["status"] != "accepted":
                codes = f" [{', '.join(i['diagnostics'])}]" if i["diagnostics"] else ""
                out.append(f"WARNING: input {_quoted(i['name'])} was {i['status']}{codes}")
        for s in self.r["sources"]:
            if s["source_state"] != "current":
                state = "does not match the evidence" if s["source_state"] == "mismatch" else "was not available"
                out.append(f"WARNING: source {self.path[s['source_index']]} {state}; its lines may be wrong.")
        self.lines += out or ["(none)"]

    def policy(self) -> None:
        self.section("Policy")
        evaluations = self.r["policy"]["evaluations"]
        rows = [["result", "assertion", "metric", "required", "actual", "threshold source", "members", "diagnostics"]]
        for e in evaluations:
            limit, actual = e["limit"], e["actual"]
            required = "-" if limit is None else f"{COMPARISON[e['comparison']]} {limit['numerator']}/{limit['denominator']}"
            members = ", ".join(_plural(len(e["members"][k]), *names) for k, *names in MEMBERS if e["members"][k])
            rows.append([
                RESULT[e["result"]], f"{e['assertion_kind']} {_quoted(e['assertion_name'])}", e["metric"], required,
                "-" if actual is None else f"{actual['numerator']}/{actual['denominator']}",
                e["threshold_source"] or "-", members or "-", ", ".join(e["diagnostics"]) or "-"])
        table = _table(rows)
        self.lines.append(table[0])
        for e, line in zip(evaluations, table[1:]):
            word = RESULT[e["result"]]  # each row starts with its status word
            self.put(line, "head", len(word), _sgr(word))
        self.status_line("policy ", "passed" if self.r["policy"]["passed"] else "failed")

    def saturation(self) -> None:
        self.section("Saturation")
        s = self.r["saturation"]
        self.lines.append(f"policy: {s['policy']}")
        rows: list[list[str]] = []

        def add(what: str, record: dict, count: dict | None) -> None:
            if count is None:
                return
            if count["saturated"] or count["lower_bound"]:
                rows.append([what, self.where(record), "all contexts", count_text(count)])
            for c in count["by_context"]:
                if c["saturated"] or c["lower_bound"]:
                    rows.append([what, self.where(record), f"context {self.context_name(c['context_index'])}", count_text(c)])

        for p in self.r["points"]:
            add(f"point {p['point_id'][:12]}", p, p["count"])
        for g in self.r["regions"]:
            add(f"region {g['region_index']}", g, g["count"])
        for b in self.r["branches"]:
            for o in b["outcomes"]:
                add(f"branch {b['branch_index']} outcome {escape_text(o['name'])}", b, o["count"])
        for c in self.r["contracts"]:
            add(f"contract {c['clause_index']} true", c, c["count_true"])
            add(f"contract {c['clause_index']} false", c, c["count_false"])
        if not s["any"] and not rows:
            self.lines.append("no count is saturated")
            return
        self.lines.append("a count written >=N is a lower bound: the true count is N or more")
        self.lines += _table(rows, right=frozenset({3}))
        self.lines.append(f"metrics still decidable: {', '.join(s['eligible_metrics']) or 'none'}")
        self.lines.append(f"not usable for: {', '.join(s['ineligible_uses']) or 'nothing'}")

    def render(self, brief: bool = False) -> str:
        full = (self.header, self.summary, self.files, self.uncovered, self.contracts, self.exclusions,
                self.warnings, self.policy, self.saturation)
        for part in ((self.header, self.summary, self.warnings, self.policy, self.saturation) if brief else full):
            part()
        out = []
        for number, line in enumerate(self.lines):
            # Escaped once more as a whole, so that no field can carry a
            # control sequence even if a caller passes an unvalidated report.
            line = escape_text(line)
            if self.color and number in self.marks:
                where, length, sgr = self.marks[number]
                cut = length if where == "head" else len(line) - length
                head, tail = line[:cut], line[cut:]
                line = f"{sgr}{head}{SGR_RESET}{tail}" if where == "head" else f"{head}{sgr}{tail}{SGR_RESET}"
            out.append(line)
        return "\n".join(out) + "\n"


def render_terminal(report: dict, *, color: bool = False) -> str:
    """The terminal report for one validated native report document."""
    return _View(report, color).render()


def render_check(report: dict, *, color: bool = False) -> str:
    """What ``check`` says: the header, summary, warnings, policy and
    saturation sections of the terminal report, unchanged."""
    return _View(report, color).render(brief=True)


def terminal_bytes(report: dict) -> bytes:
    """The colorless report as the bytes of ``coverage.txt``."""
    return render_terminal(report).encode("utf-8")
