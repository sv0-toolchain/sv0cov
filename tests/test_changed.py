# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Changed-region checks (CV-312; SPEC 22.3; COV-POL-003, COV-POL-004,
COV-POL-012..020, BL-050, AC-016, AC-045..049).

Three layers:

- the producer and the reader on every semantic fixture, against an
  independent oracle of what a changed line, region and branch outcome is,
  for many changed-line sets (synthetic captures);
- ``check`` on real Git fixture repositories, where Git itself says which
  lines changed;
- ``run`` with the recording stand-in driver of ``test_cmd_run``: the base
  is resolved before anything is built, and a source edited during the run
  publishes no result.
"""

from __future__ import annotations

import copy
import io
import json
import os
import random
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import test_cmd_run as tcr  # noqa: E402  (the module, so its test classes are not collected twice)
from test_cli import records  # noqa: E402
from test_gitdiff import Fx, fixture_env  # noqa: E402
from test_indexed_reader import FIXTURES, simple  # noqa: E402
from test_report import V, fixture_sources  # noqa: E402

from sv0cov import cli, gitdiff  # noqa: E402
from sv0cov.config_resolve import resolve  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.html import check_html, render_html  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.formats.terminal import render_terminal  # noqa: E402
from sv0cov.model.report import build_report, read_report  # noqa: E402

HAVE_GIT = shutil.which("git") is not None
HEAD = '[tool.sv0cov]\nschema = "1.0"\n'
DIFF_METRICS = ("branch", "line", "region")
EVIDENCE = "coverage.sv0covdata.json"
C1, C2, C3 = "1" * 40, "2" * 40, "3" * 40


def diff_config(toml: str = "", **limits):
    body = "[tool.sv0cov.diff]\nbase = \"merge-base:main\"\n" + "".join(f"{k} = {v}\n" for k, v in limits.items())
    return resolve("check", (), (HEAD + toml + body).encode())


def capture_record(sources: dict[str, bytes], changed: dict[str, list[int]], *, staged=(), unstaged=()) -> dict:
    """A capture of ``sources`` as :meth:`sv0cov.gitdiff.Capture.record` gives it."""
    import hashlib
    out = []
    for path in sorted(sources, key=lambda p: p.encode()):
        lines = sorted(set(changed.get(path, ())))
        out.append({"changed_lines": lines, "old_path": None, "path": path, "repo_path": path,
                    "sha256": hashlib.sha256(sources[path]).hexdigest(), "staged": path in staged,
                    "state": "modified" if lines else "unchanged", "unstaged": path in unstaged})
    return {"base": {"head": C1, "merge_base": C2, "reference": C3, "spelling": "merge-base:main"},
            "clean": not (staged or unstaged), "diff_options": list(gitdiff.DIFF_OPTIONS), "diff_sha256": "0" * 64,
            "git": {"executable_sha256": "f" * 64, "version": "git version 2.55.0"}, "sources": out}


def oracle(report: dict, changed: dict[str, list[int]]) -> dict[str, tuple[int, int, list[int]]]:
    """(covered, total, members) per diff metric, straight from SPEC 22.3."""
    path = {s["source_index"]: s["path"] for s in report["sources"]}

    def lines_of(rec):
        return set(changed.get(path[rec["source_index"]], ()))

    def meets(rec):
        return any(rec["span"]["start_line"] <= n <= rec["span"]["end_line"] for n in lines_of(rec))

    regions = [x for x in report["regions"] if x["classification"] == "user" and meets(x)]
    lines = [x for x in report["lines"] if x["status"] in ("covered", "partial", "uncovered") and x["line"] in lines_of(x)]
    branches = [b for b in report["branches"] if meets(b)]
    outcomes = [o for b in branches for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
    return {
        "region": (sum(x["count"]["value"] > 0 for x in regions), len(regions), [x["region_index"] for x in regions]),
        "line": (sum(x["status"] == "covered" for x in lines), len(lines), [x["line_index"] for x in lines]),
        "branch": (sum(o["status"] == "covered" for o in outcomes), len(outcomes),
                   sorted({b["branch_index"] for b in branches if any(o["status"] in ("covered", "uncovered") for o in b["outcomes"])})),
    }


def diff_evaluations(report: dict) -> dict[str, dict]:
    return {e["metric"]: e for e in report["policy"]["evaluations"] if e["assertion_kind"] == "diff"}


class ProducerTest(unittest.TestCase):
    """The diff evaluations against the oracle, and the reader's view of them."""

    def build(self, name: str, changed: dict[str, list[int]], cfg=None, **kw) -> dict:
        ix = simple(name)
        sources = fixture_sources(name, ix)
        report = build_report(encode(ix), cfg or diff_config(line=0, region=0, branch=0), sources, tool_version=V,
                              changes=capture_record(sources, changed, **kw))
        self.assertEqual(read_report(encode(report)), report)
        return report

    def test_every_fixture_under_many_changed_line_sets(self) -> None:
        rng = random.Random(312)
        for name in FIXTURES:
            ix = simple(name)
            sources = fixture_sources(name, ix)
            longest = {p: data.count(b"\n") + 1 for p, data in sources.items()}
            sets = [{}, {p: list(range(1, n + 1)) for p, n in longest.items()}]
            sets += [{p: [k] for p in longest} for k in (1, 2, 3, 5, 8)]
            sets += [{p: rng.sample(range(1, n + 1), rng.randint(1, n)) for p, n in longest.items()} for _ in range(6)]
            for changed in sets:
                with self.subTest(fixture=name, changed=changed):
                    report = self.build(name, changed)
                    want, got = oracle(report, changed), diff_evaluations(report)
                    self.assertEqual(sorted(got), list(DIFF_METRICS))
                    for metric, (covered, total, members) in want.items():
                        e = got[metric]
                        self.assertEqual(e["actual"], None if total == 0 else {"denominator": total, "numerator": covered}, metric)
                        key = {"branch": "branch_indices", "line": "line_indices", "region": "region_indices"}[metric]
                        self.assertEqual(e["members"][key], members, metric)
                        self.assertEqual(e["members"]["source_indices"],
                                         sorted(s["source_index"] for s in report["sources"] if changed.get(s["path"])))
                        self.assertEqual((e["threshold_source"], e["comparison"]), ("diff", "at_least"))

    def test_lines_outside_every_record_change_nothing(self) -> None:
        """A changed comment or blank line is no executable line: COV-POL-004's
        current denominator only has what the change touches."""
        report = self.build("f0", {"main.sv0": [10_000]}, cfg=diff_config(toml="empty = \"pass\"\n", line=100, region=100))
        got = diff_evaluations(report)
        for metric in DIFF_METRICS:
            self.assertIsNone(got[metric]["actual"])
        self.assertEqual(got["line"]["result"], "pass")  # empty = "pass"
        self.assertEqual(got["branch"]["result"], "not_applicable")  # no diff threshold for it

    def test_an_empty_change_follows_the_empty_policy(self) -> None:
        got = diff_evaluations(self.build("f0", {}, cfg=diff_config(line=50)))
        self.assertEqual((got["line"]["result"], got["line"]["diagnostics"]), ("fail", ["COV4102"]))

    def test_thresholds_are_exact_and_never_inherited(self) -> None:
        name = "branches"
        changed = {"main.sv0": list(range(1, 200))}
        probe = oracle(self.build(name, changed), changed)
        covered, total, _ = probe["line"]
        self.assertTrue(0 < covered < total)
        exact = covered * 10000 // total
        for limit, result in ((exact, "pass"), (exact + 1, "fail" if covered * 10000 < (exact + 1) * total else "pass")):
            cfg = diff_config(toml="[tool.sv0cov.thresholds]\nregion = 100\nbranch = 100\n", line=f'"{limit}bp"')
            got = diff_evaluations(self.build(name, changed, cfg=cfg))
            self.assertEqual(got["line"]["result"], result, limit)
            self.assertEqual(got["line"]["limit"], {"denominator": 10000, "numerator": limit})
            # The project's region and branch thresholds do not reach the diff assertion.
            self.assertEqual((got["region"]["comparison"], got["region"]["result"]), ("none", "not_applicable"))
            self.assertEqual((got["branch"]["comparison"], got["branch"]["result"]), ("none", "not_applicable"))

    def test_the_capture_is_kept_and_bound_by_digest(self) -> None:
        report = self.build("project", {"main.sv0": [1, 2]}, staged={"main.sv0"}, unstaged={"lib/util.sv0"})
        c = report["changes"]
        self.assertEqual(c["base"], {"head": C1, "merge_base": C2, "reference": C3, "spelling": "merge-base:main"})
        self.assertFalse(c["clean"])
        self.assertEqual([x["source_index"] for x in c["sources"]], [s["source_index"] for s in report["sources"]])
        self.assertEqual([x["sha256"] for x in c["sources"]], [s["digest"] for s in report["sources"]])

    def test_a_capture_of_other_bytes_is_stale(self) -> None:
        ix = simple("f0")
        sources = fixture_sources("f0", ix)
        cap = capture_record({"main.sv0": sources["main.sv0"] + b"\n"}, {})
        with self.assertRaises(ReportError) as cm:
            build_report(encode(ix), diff_config(line=0), sources, tool_version=V, changes=cap)
        self.assertEqual(cm.exception.code, "COV4305")

    def test_a_changed_source_is_stale_not_a_mismatch(self) -> None:
        ix = simple("f0")
        sources = fixture_sources("f0", ix)
        cap = capture_record(sources, {})
        for now in ({"main.sv0": sources["main.sv0"] + b"x"}, {}):
            with self.assertRaises(ReportError) as cm:
                build_report(encode(ix), diff_config(line=0), now, tool_version=V, changes=cap)
            self.assertEqual(cm.exception.code, "COV4305")

    def test_a_capture_is_given_exactly_with_a_diff_policy(self) -> None:
        ix = simple("f0")
        sources = fixture_sources("f0", ix)
        with self.assertRaises(ValueError):
            build_report(encode(ix), diff_config(line=0), sources, tool_version=V)
        with self.assertRaises(ValueError):
            build_report(encode(ix), resolve("check", (), None), sources, tool_version=V, changes=capture_record(sources, {}))
        with self.assertRaises(ValueError):
            build_report(encode(ix), diff_config(line=0), sources, tool_version=V, changes=capture_record({}, {}))
        report = build_report(encode(ix), resolve("check", (), None), sources, tool_version=V)
        self.assertIsNone(report["changes"])
        self.assertFalse(diff_evaluations(report))

    def test_the_reader_rederives_everything(self) -> None:
        report = self.build("question", {"main.sv0": [16, 23, 51, 52]})
        ev = report["policy"]["evaluations"]
        n = next(i for i, e in enumerate(ev) if e["assertion_kind"] == "diff" and e["metric"] == "region")

        def edited(fn):
            r = copy.deepcopy(report)
            fn(r)
            return r

        cases = {
            "a changed line moved": lambda r: r["changes"]["sources"][0].__setitem__("changed_lines", [16, 23, 51, 53]),
            "a changed line dropped": lambda r: r["changes"]["sources"][0].__setitem__("changed_lines", [16, 23, 51]),
            "another digest": lambda r: r["changes"]["sources"][0].__setitem__("sha256", "e" * 64),
            "a source missing": lambda r: r["changes"].__setitem__("sources", []),
            "a member dropped": lambda r: r["policy"]["evaluations"][n]["members"]["region_indices"].pop(),
            "another fraction": lambda r: r["policy"]["evaluations"][n].__setitem__("actual", {"denominator": 99, "numerator": 0}),
            "a diff evaluation removed": lambda r: r["policy"]["evaluations"].pop(n),
        }
        for what, fn in cases.items():
            with self.subTest(what):
                with self.assertRaises(ReportError) as cm:
                    read_report(encode(edited(fn)))
                self.assertIn(cm.exception.code, ("COV4001", "COV4002"), what)
        with self.assertRaises(ReportError) as cm:
            read_report(encode(edited(lambda r: r["changes"]["sources"][0].__setitem__("changed_lines", [5, 4]))))
        self.assertEqual(cm.exception.code, "COV4001")

    def test_terminal_and_html_name_the_base(self) -> None:
        report = self.build("f0", {"main.sv0": [2]}, unstaged={"main.sv0"})
        report["changes"]["base"]["spelling"] = "merge-base:\x1b[31mmain"  # escaped, never interpreted
        text = render_terminal(report)
        line = next(x for x in text.splitlines() if x.startswith("changes:"))
        self.assertIn(C2[:12], line)
        self.assertIn("dirty, not reproducible from HEAD alone", line)
        self.assertNotIn("\x1b", text)
        page = render_html(report, fixture_sources("f0", simple("f0")))
        check_html(page)
        self.assertIn(C2.encode(), page)
        self.assertIn(b"not reproducible from HEAD alone", page)
        self.assertNotIn(b"\x1b", page)
        clean = self.build("f0", {"main.sv0": [2]})
        self.assertIn("; clean", next(x for x in render_terminal(clean).splitlines() if x.startswith("changes:")))
        self.assertNotIn("changes:", render_terminal(build_report(encode(simple("f0")), resolve("check", (), None),
                                                                  fixture_sources("f0", simple("f0")), tool_version=V)))


def _replace_lines(data: bytes, numbers: dict[int, bytes]) -> bytes:
    lines = data.split(b"\n")
    for n, text in numbers.items():
        lines[n - 1] = text
    return b"\n".join(lines)


@unittest.skipUnless(HAVE_GIT, "git is not installed")
class CheckTest(unittest.TestCase):
    """``check`` on real repositories: Git decides which lines changed (AC-016, AC-045..049)."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.td = tmp.name
        env = mock.patch.dict(os.environ, fixture_env())
        env.start()
        self.addCleanup(env.stop)

    def repo(self, name: str = "f0", sub: str = "", base_edits: dict[str, dict[int, bytes]] | None = None) -> Fx:
        """A repository whose ``main`` holds the fixture with ``base_edits``
        applied, and whose checked-out branch ``topic`` holds the fixture
        exactly, with the evidence collected from it."""
        f = Fx(self.td, sub)
        ix = simple(name)
        self.sources = fixture_sources(name, ix)
        for path, data in self.sources.items():
            f.w(path, _replace_lines(data, (base_edits or {}).get(path, {})))
        f.commit("base")
        f.git("checkout", "-q", "-b", "topic")
        for path, data in self.sources.items():
            f.w(path, data)
        f.w(EVIDENCE, encode(ix))
        f.commit("topic")
        self.f = f
        return f

    def check(self, *args: str, cwd: Path | None = None) -> tuple[int, str, list[dict]]:
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["check", "--diagnostic-format=json-lines", *args, EVIDENCE], stdout=out, stderr=err, cwd=cwd or self.f.project)
        return code, out.getvalue(), records(err.getvalue())

    def report(self, spelling: str = "main") -> dict:
        """The report ``check`` evaluates, built the way it builds it."""
        base = gitdiff.resolve_base(self.f.project, spelling)
        cap = gitdiff.capture(base, list(self.sources))
        cfg = resolve("check", (("--diff-base", spelling), ("--diff-line", "0")), None)
        return build_report((self.f.project / EVIDENCE).read_bytes(), cfg, self.sources, changes=cap.record())

    def test_ac016_only_regions_meeting_changed_lines_count_and_the_base_is_recorded(self) -> None:
        edits = {"main.sv0": {12: b"    total = total + 99;", 16: b"    total = total - i;"}}
        for sub in ("", "pkg/app"):
            with self.subTest(sub=sub):
                self.setUp()
                f = self.repo(sub=sub, base_edits=edits)
                report = self.report()
                c = report["changes"]
                self.assertEqual(c["base"], {"head": f.rev("HEAD"), "merge_base": f.rev("main"), "reference": f.rev("main"),
                                             "spelling": "main"})
                self.assertTrue(c["clean"])
                self.assertEqual([x["changed_lines"] for x in c["sources"]], [[12, 16]])
                want = oracle(report, {"main.sv0": [12, 16]})
                got = diff_evaluations(report)
                for metric in DIFF_METRICS:
                    covered, total, _ = want[metric]
                    self.assertEqual(got[metric]["actual"], None if total == 0 else {"denominator": total, "numerator": covered})
                self.assertTrue(0 < want["region"][1] < sum(x["classification"] == "user" for x in report["regions"]))
                self.assertEqual(want["line"][2], [x["line_index"] for x in report["lines"] if x["line"] in (12, 16)])
                code, out, diags = self.check("--diff-base", "merge-base:main", "--diff-line", "0", "--diff-region", "0")
                self.assertEqual(code, cli.EXIT_OK, diags)
                self.assertIn(f"since {f.rev('main')[:12]}", out)

    def test_a_failing_changed_line_threshold_fails_check(self) -> None:
        self.repo(base_edits={"main.sv0": {n: b"// old" for n in range(1, 30)}})
        want = oracle(self.report(), {"main.sv0": list(range(1, 30))})
        covered, total, _ = want["line"]
        self.assertLess(covered, total)
        code, _, diags = self.check("--diff-base", "main", "--diff-line", "100")
        self.assertEqual(code, cli.EXIT_POLICY)
        (d,) = [x for x in diags if x["code"] == "COV4101"]
        facts = {x["name"]: x["value"] for x in d["facts"]}
        self.assertEqual(facts["assertion"], "diff:diff")
        self.assertEqual(facts["actual"], f"{covered}/{total}")

    def test_deleted_lines_never_enter_the_denominator(self) -> None:
        """COV-POL-004: the base had extra lines that the current side deleted."""
        f = Fx(self.td)
        ix = simple("f0")
        self.sources = fixture_sources("f0", ix)
        data = self.sources["main.sv0"]
        f.w("main.sv0", data + b"// gone 1\n// gone 2\n")
        f.commit("base")
        f.git("checkout", "-q", "-b", "topic")
        f.w("main.sv0", data)
        f.w(EVIDENCE, encode(ix))
        f.commit("topic")
        self.f = f
        report = self.report()
        self.assertEqual(report["changes"]["sources"][0]["changed_lines"], [])
        self.assertEqual(report["changes"]["sources"][0]["state"], "modified")
        for e in diff_evaluations(report).values():
            self.assertIsNone(e["actual"])
        code, _, diags = self.check("--diff-base", "main", "--diff-line", "90")
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_POLICY, ["COV4102"]))
        self.assertEqual(self.check("--diff-base", "main", "--diff-line", "90", "--empty", "pass")[0], cli.EXIT_OK)

    def test_ac045_no_base_fails_before_git_is_asked(self) -> None:
        self.repo()
        with mock.patch.object(gitdiff.Git, "run", side_effect=AssertionError("git ran")):
            code, _, diags = self.check("--diff-line", "90")
        self.assertEqual(code, cli.EXIT_USAGE)
        self.assertTrue(diags)

    def test_unresolvable_bases_are_configuration_errors(self) -> None:
        self.repo()
        for spelling in ("no-such-branch", "merge-base:no-such-branch", "merge-base:"):
            with self.subTest(spelling=spelling):
                code, out, diags = self.check("--diff-base", spelling, "--diff-line", "0")
                self.assertEqual(code, cli.EXIT_USAGE)
                self.assertIn([d["code"] for d in diags][0], ("COV4301", "COV4302"))
                self.assertNotIn("changes:", out)

    def test_ac046_ambiguous_merge_base_lists_every_candidate(self) -> None:
        f = self.repo()
        f.git("checkout", "-q", "-b", "a", "main")
        f.w("a.txt", "a")
        a1 = f.commit("a1")
        f.git("checkout", "-q", "-b", "b", "main")
        f.w("b.txt", "b")
        b1 = f.commit("b1")
        f.git("merge", "-q", "--no-edit", "a")
        f.git("checkout", "-q", "a")
        f.git("merge", "-q", "--no-edit", b1)
        f.git("checkout", "-q", "topic")
        f.git("merge", "-q", "--no-edit", "a")
        code, out, diags = self.check("--diff-base", "b", "--diff-line", "0")
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_USAGE, ["COV4303"]))
        detail = json.dumps(diags[0])
        for commit in (a1, b1):
            self.assertIn(commit, detail)
        self.assertNotIn("changes:", out)

    def test_ac047_staged_and_unstaged_bytes_are_the_current_side(self) -> None:
        f = Fx(self.td)
        ix = simple("project")
        self.sources = fixture_sources("project", ix)
        for path, data in self.sources.items():
            f.w(path, data.replace(b"\n", b" // base\n"))
        f.w(EVIDENCE, encode(ix))
        f.commit("base")
        self.f = f
        paths = sorted(self.sources)
        f.w(paths[0], self.sources[paths[0]])
        f.git("add", paths[0])  # staged
        f.w(paths[1], self.sources[paths[1]])  # unstaged
        f.w(paths[2], self.sources[paths[2]])
        f.git("add", paths[2])
        f.w(paths[2], self.sources[paths[2]] + b"// more\n")
        f.git("checkout", "-q", "--", paths[2])  # staged only, the working tree back to the staged bytes
        report = self.report("HEAD")
        by_path = {report["sources"][x["source_index"]]["path"]: x for x in report["changes"]["sources"]}
        self.assertEqual((by_path[paths[0]]["staged"], by_path[paths[0]]["unstaged"]), (True, False))
        self.assertEqual((by_path[paths[1]]["staged"], by_path[paths[1]]["unstaged"]), (False, True))
        self.assertFalse(report["changes"]["clean"])
        self.assertEqual([x["sha256"] for x in report["changes"]["sources"]], [s["digest"] for s in report["sources"]])
        code, out, diags = self.check("--diff-base", "HEAD", "--diff-line", "0")
        self.assertEqual(code, cli.EXIT_OK, diags)
        self.assertIn("dirty, not reproducible from HEAD alone", out)

    def test_ac048_a_compiled_untracked_source_blocks_an_unrelated_one_does_not(self) -> None:
        f = Fx(self.td)
        ix = simple("project")
        self.sources = fixture_sources("project", ix)
        paths = sorted(self.sources)
        for path in paths[1:]:
            f.w(path, self.sources[path])
        f.w(EVIDENCE, encode(ix))
        f.commit("base")
        self.f = f
        f.w("notes/scratch.sv0", "fn unrelated() {}\n")
        f.w(paths[0], self.sources[paths[0]])  # compiled, never added
        code, out, diags = self.check("--diff-base", "HEAD", "--diff-line", "0")
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_EVIDENCE, ["COV4304"]))
        self.assertIn(paths[0], json.dumps(diags))
        self.assertNotIn("scratch", json.dumps(diags))
        f.git("add", paths[0])
        self.assertEqual(self.check("--diff-base", "HEAD", "--diff-line", "0")[0], cli.EXIT_OK)

    def test_ac049_a_source_that_is_not_the_compiled_bytes_is_stale(self) -> None:
        f = self.repo()
        f.w("main.sv0", self.sources["main.sv0"] + b"// later\n")
        code, out, diags = self.check("--diff-base", "main", "--diff-line", "0")
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_EVIDENCE, ["COV4305"]))
        self.assertIn("main.sv0", json.dumps(diags))
        self.assertNotIn("changes:", out)
        (f.project / "main.sv0").unlink()
        code, _, diags = self.check("--diff-base", "main", "--diff-line", "0")
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_EVIDENCE, ["COV4305"]))

    def test_a_shallow_clone_is_refused(self) -> None:
        self.repo()
        clone = Path(self.td) / "shallow"
        self.f.git("clone", "-q", "--depth", "1", f"file://{self.f.root}", str(clone), cwd=Path(self.td))
        code, _, diags = self.check("--diff-base", "HEAD", "--diff-line", "0", cwd=clone)
        self.assertEqual((code, [d["code"] for d in diags]), (cli.EXIT_USAGE, ["COV4302"]))

    def test_report_evaluates_the_files_diff_table_as_check_does(self) -> None:
        """``report`` evaluates the policy of ``sv0.toml`` like ``check``, so the two never disagree."""
        f = self.repo(base_edits={"main.sv0": {12: b"    total = total + 99;"}})
        f.w("sv0.toml", HEAD + "[tool.sv0cov.diff]\nbase = \"main\"\nline = 100\n")
        f.commit("config")
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["report", "--format", "json", "--output", "-", EVIDENCE], stdout=out, stderr=err, cwd=f.project)
        self.assertEqual(code, cli.EXIT_OK, err.getvalue())
        report = json.loads(out.getvalue())
        self.assertEqual(report["changes"]["base"]["merge_base"], f.rev("main"))
        self.assertEqual([x["changed_lines"] for x in report["changes"]["sources"]], [[12]])
        self.assertEqual(diff_evaluations(report)["line"]["members"]["line_indices"],
                         [x["line_index"] for x in report["lines"] if x["line"] == 12])
        # --allow-source-mismatch does not let a changed source through to a changed-region result.
        f.w("main.sv0", self.sources["main.sv0"] + b"// later\n")
        out, err = io.StringIO(), io.StringIO()
        code = cli.main(["report", "--format", "json", "--output", "-", "--allow-source-mismatch", "--diagnostic-format=json-lines",
                         EVIDENCE], stdout=out, stderr=err, cwd=f.project)
        self.assertEqual((code, [r["code"] for r in records(err.getvalue())]), (cli.EXIT_EVIDENCE, ["COV4305"]))
        self.assertEqual(out.getvalue(), "")


@unittest.skipUnless(HAVE_GIT, "git is not installed")
class RunTest(tcr.Base):
    """``run`` resolves the base before it builds and checks the bytes up to publication."""

    def setUp(self) -> None:
        super().setUp()
        env = mock.patch.dict(os.environ, fixture_env())
        env.start()
        self.addCleanup(env.stop)
        self.environ.update({k: v for k, v in fixture_env().items() if k.startswith("GIT_")})
        f = Fx(str(self.top), name="demo", init=True)
        self.f = f
        data = (self.cwd / "main.sv0").read_bytes()
        f.w("main.sv0", _replace_lines(data, {12: b"    total = total + 99;"}))
        f.commit("base")
        f.git("checkout", "-q", "-b", "topic")
        f.w("main.sv0", data)
        f.commit("topic")

    def built(self) -> bool:
        return Path(f"{self.record}.build").exists()

    def test_a_changed_region_run_records_the_capture(self) -> None:
        code, out, err = self.run_cli("--run-id", tcr.RUN, "--report", "json", "--diff-base", "main", "--diff-line", "0", "--", "demo")
        self.assertEqual(code, cli.EXIT_OK, err)
        report = read_report((self.cwd / ".sv0cov/runs" / tcr.RUN / "reports/coverage.json").read_bytes())
        c = report["changes"]
        self.assertEqual((c["base"]["merge_base"], c["base"]["head"], c["clean"]), (self.f.rev("main"), self.f.rev("HEAD"), True))
        self.assertEqual([x["changed_lines"] for x in c["sources"]], [[12]])
        self.assertEqual(sorted(diff_evaluations(report)), list(DIFF_METRICS))

    def test_no_base_or_a_bad_base_builds_nothing(self) -> None:
        for args, want in ((("--diff-line", "0"), None), (("--diff-base", "nope", "--diff-line", "0"), "COV4302")):
            with self.subTest(args=args):
                code, _, err = self.run_cli(*args, "--", "demo")
                self.assertEqual(code, cli.EXIT_USAGE)
                if want:
                    self.assertEqual([r["code"] for r in records(err)], [want])
                self.assertFalse(self.built())
                self.assertEqual(self.run_dirs(), [])

    def test_ac049_a_source_edited_during_the_run_publishes_nothing(self) -> None:
        code, out, err = self.run_cli("--run-id", tcr.RUN, "--report", "json", "--diff-base", "main", "--diff-line", "0", "--", "demo",
                                      env={"FAKE_MUTATE": str(self.cwd / "main.sv0")})
        self.assertEqual(code, cli.EXIT_EVIDENCE, err)
        self.assertIn("COV4305", [r["code"] for r in records(err)])
        self.assertIn("main.sv0", err)
        self.assertFalse((self.cwd / ".sv0cov/runs" / tcr.RUN / "reports").exists())

    def test_ac048_a_compiled_untracked_source_publishes_nothing(self) -> None:
        self.f.git("rm", "-q", "--cached", "main.sv0")
        self.f.git("commit", "-q", "-m", "untrack")
        code, _, err = self.run_cli("--run-id", tcr.RUN, "--report", "json", "--diff-base", "main", "--diff-line", "0", "--", "demo")
        self.assertEqual(code, cli.EXIT_EVIDENCE, err)
        self.assertEqual([r["code"] for r in records(err)], ["COV4304"])
        self.assertTrue(self.built())
        self.assertFalse((self.cwd / ".sv0cov/runs" / tcr.RUN / "reports").exists())


if __name__ == "__main__":
    unittest.main()
