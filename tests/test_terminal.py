# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The terminal report (CV-230; SPEC 11.6, 20.2, 21.1; COV-REP-001,
COV-MET-011, COV-SEC-003).

The colorless text is byte-identical to its golden; every number in it is
read back and compared with the report; a zero total shows ``N/A``; color
only repeats a status word; and no text from a report can reach the
terminal as a control.
"""

from __future__ import annotations

import copy
import importlib.util
import random
import re
import sys
import unittest
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = ROOT / "tests" / "fixtures" / "terminal"
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

from sv0cov import diagnostics  # noqa: E402
from sv0cov.diagnostics import Diagnostic, escape_text, order_events, render_human  # noqa: E402
from sv0cov.formats.report import check_report_structure, ratio  # noqa: E402
from sv0cov.formats.terminal import count_text, percent, ranges, render_terminal, terminal_bytes  # noqa: E402

_spec = importlib.util.spec_from_file_location("terminal_fixture_build", GOLDEN / "build.py")
golden = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(golden)

SGR = re.compile(r"\x1b\[[0-9;]*m")
U64 = 2**64 - 1
LABEL = {"function": "functions", "region": "regions", "line": "lines", "branch": "branches", "contract": "contracts"}
WORD = {"pass": "PASS", "fail": "FAIL", "ineligible": "INELIGIBLE", "not_applicable": "N/A"}
REORDER = [0x061C, 0x200E, 0x200F, 0x2028, 0x2029, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069]
HOSTILE = "a" + chr(0x1B) + "[2J" + chr(0x1B) + "]0;t" + chr(7) + chr(13) + chr(10) + chr(0) + chr(0x7F) + chr(0x9B) + "31m" + chr(0x202E) + chr(0x2066) + chr(0x2028) + "z"
ESCAPED = "a|x1b[2J|x1b]0;t|x07|x0d|x0a|x00|x7f|x9b31m|u202e|u2066|u2028z".replace("|", chr(92))
REPORTS = golden.reports()


def sections(text: str) -> dict[str, list[str]]:
    """The body lines of each titled section, read back from the text."""
    lines = text.split("\n")
    out: dict[str, list[str]] = {}
    name = None
    for i, line in enumerate(lines):
        if i + 1 < len(lines) and line and lines[i + 1] == "-" * len(line):
            name = line
            out[name] = []
        elif name is not None and line != "-" * len(name):
            out[name].append(line)
    return {k: [x for x in v if x] for k, v in out.items()}


def unsafe(text: str) -> list[str]:
    return [c for c in text if (ord(c) < 0x20 and c != "\n") or 0x7F <= ord(c) <= 0x9F or ord(c) in REORDER]


def inexact(count: dict | None) -> int:
    if count is None:
        return 0
    return sum(1 for c in (count, *count["by_context"]) if c["saturated"] or c["lower_bound"])


class GoldenTest(unittest.TestCase):
    def test_goldens_are_current_and_complete(self) -> None:
        """SPEC 22: terminal output is byte-identical when color is disabled."""
        expected = golden.artifacts()
        self.assertEqual(len(expected), 13)
        for path, data in expected.items():
            with self.subTest(golden=path.name):
                self.assertEqual(path.read_bytes(), data)
        self.assertEqual({p.name for p in GOLDEN.glob("*.txt")}, {p.name for p in expected})

    def test_the_text_is_deterministic_and_tidy(self) -> None:
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                text = render_terminal(report)
                shuffled = {k: report[k] for k in sorted(report, reverse=True)}
                self.assertEqual(render_terminal(shuffled), text)
                self.assertEqual(terminal_bytes(report), text.encode("utf-8"))
                self.assertTrue(text.endswith("\n") and not text.endswith("\n\n"))
                self.assertEqual([ln for ln in text.split("\n") if ln != ln.rstrip()], [])
                self.assertEqual(unsafe(text), [])
                self.assertNotIn(str(ROOT), text)

    def test_every_section_is_present_in_a_fixed_order(self) -> None:
        want = ["Summary", "Files", "Partial lines", "Uncovered lines", "Uncovered branch outcomes", "Contracts",
                "Exclusions", "Warnings", "Policy", "Saturation"]
        for name, report in REPORTS.items():
            self.assertEqual(list(sections(render_terminal(report))), want, name)


class NumbersTest(unittest.TestCase):
    def test_summary_shows_the_exact_pairs(self) -> None:
        """COV-REP-001, COV-MET-011."""
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                rows = {r.split()[0]: r.split() for r in sections(render_terminal(report))["Summary"]}
                for key, label in LABEL.items():
                    m = report["summary"][key]
                    self.assertEqual(rows[label][1], f"{m['covered']}/{m['total']}")
                    if m["total"] == 0:
                        self.assertEqual(rows[label][2], "N/A")
                    else:
                        self.assertEqual(rows[label][2], percent(ratio(m["covered"], m["total"])))
                self.assertEqual(rows["lines"][3:], [str(report["summary"]["line"]["partial"]), "partial"])

    def test_contracts_are_kept_apart(self) -> None:
        body = sections(render_terminal(REPORTS["structure-all-kinds"]))["Summary"]
        self.assertEqual([r.split()[0] for r in body], ["metric", "functions", "regions", "lines", "branches", "Contracts", "contracts"])
        self.assertIn("reported separately", body[5])

    def test_percent_moves_the_point_and_never_rounds_again(self) -> None:
        self.assertEqual(percent(None), "N/A")
        self.assertEqual([percent(x) for x in ("0.000000", "0.000001", "0.050000", "0.848485", "1.000000")],
                         ["0.0000%", "0.0001%", "5.0000%", "84.8485%", "100.0000%"])
        self.assertEqual(percent(ratio(84, 99)), "84.8485%")  # not 85%
        rng = random.Random(230)
        for _ in range(4000):
            total = rng.choice([1, 3, 7, 99, 10**6, U64, rng.randrange(1, U64)])
            covered = rng.randrange(0, total + 1)
            want = (Decimal(covered) * 100 / Decimal(total)).quantize(Decimal("0.0001"), rounding=ROUND_HALF_EVEN)
            if Decimal(covered) * 10**6 % Decimal(total) * 2 != total:  # ties are settled on the ratio's last digit
                self.assertEqual(percent(ratio(covered, total)), f"{want}%", (covered, total))

    def test_a_zero_total_is_never_a_percentage(self) -> None:
        """COV-MET-011; SPEC 11.6."""
        text = render_terminal(REPORTS["structure-empty"])
        self.assertEqual(text.count("N/A"), 5)
        self.assertNotIn("%", text)
        for name, report in REPORTS.items():
            for line in render_terminal(report).split("\n"):
                self.assertNotRegex(line, r"(^|\s)\d+/0 \d", name)  # a zero total next to digits

    def test_file_and_function_rows_show_their_own_pairs(self) -> None:
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                body = sections(render_terminal(report))["Files"]
                for s in report["sources"]:
                    row = next(r for r in body if r.startswith(f"  {escape_text(s['path'])}"))
                    for key in LABEL:
                        m = s["summary"][key]
                        self.assertIn(f"{m['covered']}/{m['total']} {percent(m['ratio'])}", row)
                functions = [e for e in report["entities"] if e["kind"] == "function"]
                self.assertEqual(len([r for r in body if r.startswith("    fn ")]), len(functions))

    def test_hierarchy_is_ownership_then_package_then_path(self) -> None:
        report = copy.deepcopy(REPORTS["structure-all-kinds"])
        extra = copy.deepcopy(report["sources"][0])
        extra.update(path="src/aaa.sv0", source_index=7)
        report["sources"].append(extra)
        body = [r.split("  ")[0 if r.startswith("[") else 1] for r in sections(render_terminal(report))["Files"][1:]
                if not r.startswith("    fn")]
        self.assertEqual(body, ["[user] no package", "src/aaa.sv0", "src/app.sv0", '[dependency] package "dep-lib"', "vendor/dep/hot.sv0"])


class RangesTest(unittest.TestCase):
    def test_ranges_join_adjacent_numbers_only(self) -> None:
        self.assertEqual(ranges([]), "")
        self.assertEqual(ranges([9, 3, 5, 6, 7, 3]), "3, 5-7, 9")
        self.assertEqual(ranges([1, 2]), "1-2")
        self.assertEqual(ranges([1, 3]), "1, 3")
        rng = random.Random(7)
        for _ in range(500):
            numbers = {rng.randrange(1, 60) for _ in range(rng.randrange(0, 40))}
            back: set[int] = set()
            parts = [p for p in ranges(numbers).split(", ") if p]
            for part in parts:
                lo, _, hi = part.partition("-")
                self.assertTrue(lo not in back and (not hi or int(hi) > int(lo)))
                back |= set(range(int(lo), int(hi or lo) + 1))
            self.assertEqual(back, numbers)
            firsts = [int(p.partition("-")[0]) for p in parts]
            self.assertTrue(all(f - 1 not in numbers for f in firsts))  # each range is maximal

    def test_partial_and_uncovered_lines_read_back(self) -> None:
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                body = sections(render_terminal(report))
                path = {s["source_index"]: escape_text(s["path"]) for s in report["sources"]}
                for status, title in (("partial", "Partial lines"), ("uncovered", "Uncovered lines")):
                    want: dict[str, set[int]] = {}
                    for ln in report["lines"]:
                        if ln["status"] == status:
                            want.setdefault(path[ln["source_index"]], set()).add(ln["line"])
                    got: dict[str, set[int]] = {}
                    for row in body[title]:
                        if row == "(none)":
                            continue
                        where, _, spans = row.rpartition(": ")
                        for part in spans.split(", "):
                            lo, _, hi = part.partition("-")
                            got.setdefault(where, set()).update(range(int(lo), int(hi or lo) + 1))
                    self.assertEqual(got, want)
                    self.assertEqual([r.rpartition(": ")[0] for r in body[title] if r != "(none)"], sorted(want, key=str.encode))

    def test_uncovered_outcomes_read_back(self) -> None:
        seen = 0
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                rows = [r for r in sections(render_terminal(report))["Uncovered branch outcomes"] if r != "(none)"]
                missed = [b for b in report["branches"] if any(o["status"] == "uncovered" for o in b["outcomes"])]
                self.assertEqual(len(rows), len(missed))
                names = sorted(n for r in rows for n in r.split("not taken: ")[1].split(", "))
                self.assertEqual(names, sorted(escape_text(o["name"]) for b in missed for o in b["outcomes"] if o["status"] == "uncovered"))
                seen += len(rows)
                for b in missed:
                    self.assertTrue(any(f":{b['span']['start_line']}:{b['span']['start_column']} " in r and f" {b['kind']} " in r for r in rows))
        self.assertGreaterEqual(seen, 10)

    def test_covered_excluded_and_unreachable_outcomes_are_not_listed(self) -> None:
        report = REPORTS["structure-all-kinds"]
        statuses = {o["status"] for b in report["branches"] for o in b["outcomes"]}
        self.assertEqual(statuses, {"covered", "excluded", "statically_unreachable", "uncovered"})
        body = sections(render_terminal(report))
        self.assertEqual(len(body["Uncovered branch outcomes"]), 2)
        self.assertIn("statically unreachable: 1 branch outcome", body["Exclusions"])


class StatusTest(unittest.TestCase):
    def test_color_only_repeats_a_word(self) -> None:
        """SPEC 21.1: color is never the only carrier of status."""
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                plain, colored = render_terminal(report), render_terminal(report, color=True)
                self.assertNotIn("\x1b", plain)
                self.assertIn("\x1b[", colored)
                self.assertEqual(SGR.sub("", colored), plain)
                self.assertEqual(colored.count("\x1b[0m") * 2, len(SGR.findall(colored)))  # every sequence is closed
                for line in colored.split("\n"):
                    self.assertEqual(line.count("\x1b[0m") * 2, len(SGR.findall(line)))  # on its own line

    def test_color_marks_the_status_words(self) -> None:
        colored = render_terminal(REPORTS["structure-all-kinds"], color=True)
        for piece in ("\x1b[33mINCOMPLETE\x1b[0m", "\x1b[1;31mFAIL\x1b[0m ", "\x1b[32mPASS\x1b[0m ", "\x1b[33mINELIGIBLE\x1b[0m ",
                      "\x1b[33mN/A\x1b[0m ", "policy \x1b[1;31mfailed\x1b[0m", "\x1b[1mPolicy\x1b[0m"):
            self.assertIn(piece, colored)
        self.assertIn("evidence:   \x1b[32mPASSING\x1b[0m", render_terminal(REPORTS["structure-passing"], color=True))
        self.assertIn("policy:     \x1b[32mpassed\x1b[0m", render_terminal(REPORTS["structure-passing"], color=True))

    def test_header_states_eligibility_in_words(self) -> None:
        base = REPORTS["structure-passing"]
        for value, word in (("passing", "PASSING"), ("policy_failed", "POLICY FAILED"), ("incomplete", "INCOMPLETE"),
                            ("diagnostic_only", "DIAGNOSTIC ONLY")):
            self.assertIn(f"evidence:   {word}\n", render_terminal({**base, "evidence_eligibility": value}))
        text = render_terminal(REPORTS["structure-all-kinds"])
        for line in ("complete:   no", "policy:     failed", "execution:  failed (exit 3)", "backends:   native, vm-v1, vm-v2",
                     "runs:       2 (explicit-list)", "inputs:     3 accepted, 1 incomplete, 1 rejected", "sources:    mismatch allowed",
                     'contexts:   (default), "", "shard é"'):
            self.assertIn(line + "\n", text)
        signalled = {**base, "provenance": {**base["provenance"], "execution_status": "signaled", "execution_exit_code": None,
                                            "execution_signal": 9}}
        self.assertIn("execution:  signaled (signal 9)\n", render_terminal(signalled))

    def test_every_policy_assertion_is_shown_in_order(self) -> None:
        """SPEC 21.1: selector identity, threshold source, exact fraction, result."""
        compare = {"at_least": ">=", "at_most": "<=", "equal": "=="}
        total = 0
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                body = sections(render_terminal(report))["Policy"]
                evaluations = report["policy"]["evaluations"]
                self.assertEqual(len(body), len(evaluations) + 2)
                self.assertEqual(body[-1], "policy " + ("passed" if report["policy"]["passed"] else "failed"))
                for e, row in zip(evaluations, body[1:]):
                    total += 1
                    self.assertTrue(row.startswith(WORD[e["result"]] + " "), row)
                    self.assertIn(f' {e["assertion_kind"]} "{escape_text(e["assertion_name"])}" ', row)
                    self.assertIn(f"  {e['metric']}  ", row)
                    if e["limit"] is not None:
                        self.assertIn(f"  {compare[e['comparison']]} {e['limit']['numerator']}/{e['limit']['denominator']}  ", row)
                    if e["actual"] is not None:
                        self.assertIn(f"  {e['actual']['numerator']}/{e['actual']['denominator']}  ", row)
                    if e["threshold_source"] is not None:
                        self.assertIn(f"  {e['threshold_source']}  ", row)
                    self.assertTrue(row.endswith(", ".join(e["diagnostics"]) or "-"), row)
                    for key in e["members"]:
                        if e["members"][key]:
                            self.assertRegex(row, rf"\b{len(e['members'][key])} {key.split('_')[0][:5]}")
        self.assertGreater(total, 25)

    def test_threshold_boundary_is_shown_exactly(self) -> None:
        """84 of 99 against 85%: the row shows both exact fractions and FAIL."""
        report = copy.deepcopy(REPORTS["structure-passing"])
        e = next(x for x in report["policy"]["evaluations"] if x["metric"] == "line")
        e.update(actual={"numerator": 84, "denominator": 99}, result="fail", diagnostics=["COV4101"])
        row = next(r for r in sections(render_terminal(report))["Policy"] if " line " in r)
        self.assertRegex(row, r"^FAIL +project .project. +line +>= 8500/10000 +84/99 +project +3 lines +COV4101$")

    def test_warnings_name_every_problem(self) -> None:
        self.assertEqual(sections(render_terminal(REPORTS["structure-passing"]))["Warnings"], ["(none)"])
        body = sections(render_terminal(REPORTS["structure-all-kinds"]))["Warnings"]
        self.assertEqual(body, [
            "WARNING: the evidence is incomplete; this report cannot be passing evidence.",
            'WARNING: input "truncated.sv0profraw" was incomplete [COV2011]',
            'WARNING: input "collision.sv0profraw" was rejected [COV2112]',
            "WARNING: source src/app.sv0 does not match the evidence; its lines may be wrong.",
            "WARNING: source vendor/dep/hot.sv0 was not available; its lines may be wrong.",
        ])


class DetailTest(unittest.TestCase):
    def test_exclusions_are_counted_and_listed(self) -> None:
        """SPEC 15.x: excluded function, region, line, branch and contract counts."""
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                body = sections(render_terminal(report))["Exclusions"]
                kind = {e["entity_index"]: e["kind"] for e in report["entities"]}
                seen: dict[str, set] = {k: set() for k in ("function", "region", "line", "branch", "contract")}
                for x in report["exclusions"]:
                    a = x["affected"]
                    seen["function"] |= {i for i in a["entity_indices"] if kind[i] == "function"}
                    seen["region"] |= set(a["region_indices"])
                    seen["line"] |= set(a["line_indices"])
                    seen["branch"] |= set(a["branch_indices"])
                    seen["contract"] |= set(a["clause_indices"])
                got = dict(zip(seen, map(int, re.findall(r"(\d+) [a-z]+", body[0]))))
                self.assertEqual(got, {k: len(v) for k, v in seen.items()})
                self.assertEqual(len(body), 2 + len(report["exclusions"]))
                for x, row in zip(report["exclusions"], body[2:]):
                    self.assertTrue(row.startswith(f"#{x['exclusion_index']} "))
                    self.assertIn(f" {x['mode']} ({x['origin']}): \"{escape_text(x['reason'])}\"", row)
        self.assertIn("excluded: 0 functions, 1 region, 3 lines, 1 branch, 1 contract",
                      sections(render_terminal(REPORTS["structure-all-kinds"]))["Exclusions"])

    def test_contract_clauses_are_listed_with_their_counts(self) -> None:
        report = REPORTS["structure-all-kinds"]
        body = sections(render_terminal(report))["Contracts"]
        self.assertEqual(len(body), 1 + len(report["contracts"]) + 1)
        for c, row in zip(report["contracts"], body[1:]):
            cells = row.split()
            self.assertEqual(cells[2:4], [c["enforcement"], c["runtime_result"]])
            want = ["-" if c[k] is None else str(c[k]["value"]) for k in ("count_true", "count_false")]
            self.assertEqual(cells[4:], want)
        self.assertEqual(body[-1], 'src/app.sv0:8:1 evidence: "sv0c:smt:proof-1"')

    def test_every_inexact_count_is_a_lower_bound(self) -> None:
        """SPEC 21.1: every saturated count, in lower-bound notation, with the policy."""
        self.assertEqual(count_text({"saturated": False, "lower_bound": False, "value": 5}), "5")
        self.assertEqual(count_text({"saturated": True, "lower_bound": False, "value": U64}), f">={U64}")
        self.assertEqual(count_text({"saturated": False, "lower_bound": True, "value": 0}), ">=0")
        found = 0
        for name, report in REPORTS.items():
            with self.subTest(report=name):
                body = sections(render_terminal(report))["Saturation"]
                want = (sum(inexact(p["count"]) for p in report["points"]) + sum(inexact(g["count"]) for g in report["regions"])
                        + sum(inexact(o["count"]) for b in report["branches"] for o in b["outcomes"])
                        + sum(inexact(c["count_true"]) + inexact(c["count_false"]) for c in report["contracts"]))
                rows = [r for r in body if re.search(r" >=\d+$", r)]
                self.assertEqual(len(rows), want)
                self.assertEqual(body[0], f"policy: {report['saturation']['policy']}")
                self.assertEqual(body[1] == "no count is saturated", want == 0 and not report["saturation"]["any"])
                found += want
        self.assertGreater(found, 2)
        report = copy.deepcopy(REPORTS["structure-all-kinds"])
        clause = report["contracts"][0]
        clause["count_true"].update(saturated=True, value=U64)
        clause["count_true"]["by_context"][1].update(lower_bound=True)
        text = render_terminal(report)
        self.assertIn(f">={U64}", sections(text)["Contracts"][1])
        self.assertRegex(text, r'contract 0 true +src/app\.sv0:2:1 +context "shard é" +>=2\n')
        clause["count_false"].update(lower_bound=True)
        report["branches"][0]["outcomes"][0]["count"].update(saturated=True)
        rows = sections(render_terminal(report))["Saturation"]
        self.assertTrue(any(re.fullmatch(r"contract 0 false +src/app\.sv0:2:1 +all contexts +>=1", r) for r in rows), rows)
        outcome = report["branches"][0]["outcomes"][0]
        self.assertTrue(any(re.fullmatch(rf"branch 0 outcome {outcome['name']} +src/app\.sv0:4:1 +all contexts +>={outcome['count']['value']}", r)
                            for r in rows), rows)
        body = sections(render_terminal(REPORTS["structure-all-kinds"]))["Saturation"]
        self.assertEqual(body[-2:], ["metrics still decidable: branch, function, line, region",
                                     "not usable for: context_exact_counts, contract_counts, exact_count_assertions, ratchets, standard_exports"])

    def test_indices_are_identities_not_positions(self) -> None:
        report = REPORTS["structure-bounds"]
        self.assertEqual(report["sources"][0]["source_index"], 2**32 - 2)
        self.assertIn("#4294967294 d/", render_terminal(report))


class InjectionTest(unittest.TestCase):
    """COV-SEC-003; AC: text from a report is never a terminal control."""

    FREE_TEXT = (("sources", 0, "path"), ("sources", 1, "package"), ("entities", 0, "qualified_name"), ("contexts", 2, "value"),
                 ("exclusions", 0, "reason"), ("inputs", 3, "name"), ("contracts", 4, "evidence_identity"), ("tool", "version"),
                 ("policy", "evaluations", 3, "assertion_name"), ("branches", 0, "outcomes", 1, "name"))

    def setUp(self) -> None:
        self.base = REPORTS["structure-all-kinds"]
        check_report_structure(self.base)

    def test_free_text_is_escaped_and_cannot_add_a_line(self) -> None:
        lines = render_terminal(self.base).count("\n")
        for path in self.FREE_TEXT:
            with self.subTest(field=path):
                report = copy.deepcopy(self.base)
                node = report
                for key in path[:-1]:
                    node = node[key]
                self.assertIsInstance(node[path[-1]], str)
                node[path[-1]] = HOSTILE
                for color in (False, True):
                    text = render_terminal(report, color=color)
                    self.assertEqual(unsafe(SGR.sub("", text) if color else text), [])
                    self.assertEqual(SGR.sub("", text), render_terminal(report))
                    self.assertEqual(text.count("\n"), lines)
                    self.assertIn(ESCAPED, text)

    def test_no_string_anywhere_reaches_the_terminal_raw(self) -> None:
        """Every string in the report, one at a time, even where the schema
        would only allow a fixed word."""
        tried = rendered = 0

        def walk(node, trail):
            if isinstance(node, dict):
                for k, v in node.items():
                    yield from walk(v, (*trail, k))
            elif isinstance(node, list):
                for i, v in enumerate(node):
                    yield from walk(v, (*trail, i))
            elif isinstance(node, str):
                yield trail

        for trail in list(walk(self.base, ())):
            if trail[0] == "resolved_configuration":
                continue
            report = copy.deepcopy(self.base)
            node = report
            for key in trail[:-1]:
                node = node[key]
            node[trail[-1]] = HOSTILE + "\x1b[32m"
            tried += 1
            for color in (False, True):
                try:
                    text = render_terminal(report, color=color)
                except (KeyError, ValueError):
                    continue  # a fixed word the view looks up: nothing is printed
                rendered += 1
                # Whatever color there is, it is only the view's own sequences:
                self.assertEqual(SGR.sub("", text) if color else text, render_terminal(report), trail)
                self.assertEqual(unsafe(render_terminal(report)), [], trail)
        self.assertGreater(tried, 300)
        self.assertGreater(rendered, 500)

    def test_a_quote_cannot_close_a_quoted_field(self) -> None:
        report = copy.deepcopy(self.base)
        report["exclusions"][0]["reason"] = 'x" was rejected [COV0000]'
        self.assertIn(r'"x\" was rejected [COV0000]"', render_terminal(report))
        # A trailing backslash cannot turn the closing quote into an escaped one, and the
        # characters of an escape sequence cannot pass for the control they spell (CV-237).
        for text, shown in (("ends in \\", r'"ends in \\"'), ("\\x1b[2J", r'"\\x1b[2J"'), ("\x1b[2J", r'"\x1b[2J"'),
                            ('\\" forged', r'"\\\" forged"')):
            with self.subTest(text=text):
                report["exclusions"][0]["reason"] = text
                self.assertIn(f" (comment): {shown}", render_terminal(report))

    def test_diagnostics_escape_reordering_characters_too(self) -> None:
        self.assertEqual(escape_text("ok é ✓"), "ok é ✓")
        self.assertEqual(escape_text("".join(map(chr, REORDER))), "".join(f"\\u{n:04x}" for n in REORDER))
        self.assertEqual(escape_text(escape_text(HOSTILE)), escape_text(HOSTILE))
        registry = diagnostics.load_registry()
        (record,) = order_events([Diagnostic("COV0001", "invocation", facts=(("detail", "safe" + chr(0x202E) + "gnp.exe"),))], registry)
        text = render_human(record)
        self.assertNotIn(chr(0x202E), text)
        self.assertIn("safe" + chr(92) + "u202egnp.exe", text)


if __name__ == "__main__":
    unittest.main()
