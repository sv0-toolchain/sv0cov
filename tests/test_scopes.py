# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The cumulative-assertion matrix for named scopes and entity checks
(CV-310; SPEC 18.2.1, 18.2.2, 22.1, 22.2, 22.2.1, 11.6; COV-SCP-005,
COV-SCP-006, COV-POL-002, COV-POL-022, COV-POL-023, COV-POL-026, COV-CFG-006,
COV-CFG-008).

Every scope and entity assertion is evaluated on its own, metric by metric;
none overrides another; a threshold is inherited only from the project value
of the same metric; the overall policy needs every evaluation to pass or not
apply. Every report built here also round-trips through ``read_report``, which
re-derives all of it.
"""

from __future__ import annotations

import copy
import itertools
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import map_samples as ms  # noqa: E402
import test_report as tr  # noqa: E402  (the module, so its test classes are not collected twice)
from test_indexed_reader import map_input, profile_input, raw, simple  # noqa: E402
from test_report import REPORT, STALE_OK, V, config, fixture_sources, oracle, thresholds  # noqa: E402

from sv0cov.config import ConfigError  # noqa: E402
from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.html import check_html, esc, render_html  # noqa: E402
from sv0cov.formats.map import validate_map  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.formats.terminal import render_terminal  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import _Detail, build_report, read_report, resolve_entity, scope_sources  # noqa: E402

METRICS = ("branch", "contract", "function", "line", "region")


def table(section: str, **fields) -> str:
    return f"[[tool.sv0cov.{section}]]\n" + "".join(f"{k} = {json.dumps(v)}\n" for k, v in fields.items())


def scope(name: str, **fields) -> str:
    return table("scopes", name=name, **fields)


def entity(name: str, source: str, qualified_name: str, kind: str = "function", **fields) -> str:
    return table("entities", name=name, source=source, qualified_name=qualified_name, kind=kind, **fields)


class Case:
    """Indexed evidence and the current source bytes a report is built from."""

    def __init__(self, indexed: bytes, sources: dict[str, bytes], options=REPORT) -> None:
        self.indexed, self.sources, self.options = indexed, sources, options

    @classmethod
    def fixture(cls, name: str) -> "Case":
        ix = simple(name)
        return cls(encode(ix), fixture_sources(name, ix))

    @classmethod
    def sample(cls) -> "Case":
        """The validator's two-source map (src/math.sv0, src/sign.sv0): a function
        with a runtime-checked ``requires`` (its own contract entity), a function
        excluded by an attribute (an entity with empty denominators), and a branch
        covered on one outcome only. Nothing is saturated and the sources are current."""
        data = encode(ms.build())
        m = validate_map(data)
        pts = {(p["kind"], m["entities"][p["entity_index"]]["qualified_name"], p["outcome_ordinal"]): p["point_id"] for p in m["points"]}
        counts = {pts[("function_entry", "div", None)]: 3, pts[("contract_true", "div#requires0", None)]: 3,
                  pts[("function_entry", "positive", None)]: 4, pts[("branch_outcome", "positive", 0)]: 2}
        ix = build_indexed([map_input("s.sv0covmap.json", data)], [profile_input("a.sv0profraw", raw(m, counts, 3), m)], tool_version=V)
        return cls(encode(ix), dict(ms.SOURCES))


_CACHE: dict[str, Case] = {}


def case(name: str) -> Case:
    if name not in _CACHE:
        _CACHE[name] = Case.sample() if name == "sample" else Case.fixture(name)
    return _CACHE[name]


class Base(unittest.TestCase):
    def build(self, name: str, toml: str = "", *, options=None) -> dict:
        """A report for the named case; it must read back unchanged."""
        c = case(name)
        report = build_report(c.indexed, config(options or c.options, toml), c.sources, tool_version=V)
        self.assertEqual(read_report(encode(report)), report)
        return report

    def failure(self, name: str, toml: str) -> str:
        c = case(name)
        return tr.code_of(build_report, c.indexed, config(c.options, toml), c.sources, tool_version=V)

    def evals(self, report: dict, kind: str, name: str | None = None) -> list[dict]:
        return [e for e in report["policy"]["evaluations"] if e["assertion_kind"] == kind and (name is None or e["assertion_name"] == name)]

    def ev(self, report: dict, kind: str, name: str, metric: str) -> dict:
        (e,) = [e for e in self.evals(report, kind, name) if e["metric"] == metric]
        return e

    def results(self, report: dict) -> dict[tuple, str]:
        """Every checked evaluation (not the ones that only report) -> its result."""
        return {(e["assertion_kind"], e["assertion_name"], e["metric"]): e["result"] for e in report["policy"]["evaluations"]
                if e["assertion_kind"] != "integrity" and e["result"] != "not_applicable"}

    def fraction(self, e: dict | None) -> tuple | None:
        return None if e is None else (e["numerator"], e["denominator"])


def project_oracle(report: dict, indices) -> dict[str, tuple]:
    """Summed independent counts of the given sources."""
    total = {k: [0, 0] for k in METRICS}
    for n in indices:
        for k, (c, t, _) in oracle(report, n).items():
            total[k][0] += c
            total[k][1] += t
    return {k: tuple(v) for k, v in total.items()}


def scope_fractions(report: dict, name: str) -> dict[str, tuple | None]:
    return {e["metric"]: (None if e["actual"] is None else (e["actual"]["numerator"], e["actual"]["denominator"]))
            for e in report["policy"]["evaluations"] if e["assertion_kind"] == "scope" and e["assertion_name"] == name}


def without_name(evaluations: list[dict]) -> list[dict]:
    return [{k: v for k, v in e.items() if k != "assertion_name"} for e in evaluations]


class SelectionTest(Base):
    """COV-SCP-005: a source counts once per scope, and scopes are independent of the aggregate."""

    def test_a_source_matched_by_several_selectors_counts_once(self) -> None:
        """COV-SCP-005: pattern + pattern + explicit source select `lib/util.sv0` once; the scope equals a single-selector scope."""
        single = self.build("project", scope("s", sources=["lib/util.sv0"], line=50))
        many = self.build("project", scope("s", include=["lib/*.sv0", "lib/util.sv0", "**/util.sv0"], sources=["lib/util.sv0"], line=50))
        wider = self.build("project", scope("s", include=["lib/*.sv0", "lib/util.sv0"], sources=["lib/util.sv0"], line=50))
        for report in (single, many, wider):
            for e in self.evals(report, "scope", "s"):
                self.assertEqual(e["members"]["source_indices"], [0] if report is not many else [0, 2])
        for report in (single, wider):
            self.assertEqual(without_name(self.evals(report, "scope", "s")), without_name(self.evals(single, "scope", "s")))
            self.assertEqual(scope_fractions(report, "s"), {k: (c, t) if t else None for k, (c, t, _) in oracle(single, 0).items()})
        # No member list holds an index twice, and every list is sorted.
        for e in self.evals(many, "scope", "s"):
            for key, values in e["members"].items():
                self.assertEqual(values, sorted(set(values)), key)
        # `**/util.sv0` adds the second util source; the first is still counted once.
        self.assertEqual(scope_fractions(many, "s"), {k: ((c, t) if t else None) for k, (c, t) in project_oracle(many, [0, 2]).items()})

    def test_packages_include_and_sources_select_a_source_once(self) -> None:
        """COV-SCP-005 with a package selector. No fixture compiles a package, so the evidence is given package names in memory."""
        report = case_report_with_packages(self)
        union = {"name": {"value": "u"}, "include": {"value": ["lib/*.sv0"]}, "packages": {"value": ["pkg_a"]},
                 "sources": {"value": ["lib/util.sv0", "main.sv0"]}}
        self.assertEqual(scope_sources(report, union), [0, 1])  # lib/util.sv0 matched three ways, main.sv0 two, each once
        none = {"include": {"value": None}, "packages": {"value": None}, "sources": {"value": None}}
        for field, value, want in (("packages", ["pkg_a"], [0, 1]), ("include", ["lib/*.sv0"], [0]), ("sources", ["lib/util.sv0"], [0])):
            self.assertEqual(scope_sources(report, {"name": {"value": "x"}, **none, field: {"value": value}}), want, field)
        both = {"name": {"value": "b"}, "include": {"value": None}, "packages": {"value": ["pkg_a", "pkg_b"]}, "sources": {"value": None}}
        self.assertEqual(scope_sources(report, both), [0, 1, 2])

    def test_the_project_aggregate_is_unchanged_by_scope_configuration(self) -> None:
        """COV-SCP-005: a source contributes once to the project aggregate whatever the scopes say."""
        bare = self.build("project", thresholds(line=50))
        scoped = self.build("project", thresholds(line=50) + scope("a", include=["**"]) + scope("b", include=["lib/*.sv0", "**/util.sv0"])
                            + scope("c", sources=["main.sv0"]) + entity("e", "lib/util.sv0", "lib::triple"))
        for key in ("summary", "entities", "sources", "regions", "lines", "points"):
            self.assertEqual(scoped[key], bare[key], key)
        self.assertEqual(self.evals(scoped, "project"), self.evals(bare, "project"))
        self.assertEqual(scoped["summary"]["region"]["total"], sum(oracle(bare, n)["region"][1] for n in range(3)))
        # Scope evaluations are additional; the integrity and project ones are exactly the unscoped ones.
        extra = [e for e in scoped["policy"]["evaluations"] if e["assertion_kind"] in ("scope", "entity")]
        self.assertEqual(len(extra), 3 * 5 + 5)
        self.assertEqual([e for e in scoped["policy"]["evaluations"] if e not in extra], bare["policy"]["evaluations"])

    def test_one_source_contributes_to_each_overlapping_scope_independently(self) -> None:
        """COV-SCP-005, COV-POL-002: `src/sign.sv0` is in three scopes with different verdicts for the same fraction (1 of 2 branch outcomes)."""
        toml = (scope("everything", include=["**"], branch=51) + scope("sign", sources=["src/sign.sv0"], branch=50)
                + scope("by-pattern", include=["sign.sv0"], branch=100) + scope("math", include=["math.sv0"], branch=100))
        report = self.build("sample", toml)
        for name in ("everything", "sign", "by-pattern"):
            e = self.ev(report, "scope", name, "branch")
            self.assertEqual(e["members"]["source_indices"], [0, 1] if name == "everything" else [1])
            self.assertEqual(e["actual"], {"numerator": 1, "denominator": 2}, name)
        self.assertEqual([self.ev(report, "scope", n, "branch")["result"] for n in ("everything", "sign", "by-pattern")], ["fail", "pass", "fail"])
        # `math` has no branch outcome at all: its denominator is empty and follows the empty policy (fail by default).
        math = self.ev(report, "scope", "math", "branch")
        self.assertEqual((math["members"]["source_indices"], math["actual"], math["result"], math["diagnostics"]), ([0], None, "fail", ["COV4102"]))
        self.assertEqual(self.ev(report, "scope", "everything", "branch")["members"]["branch_indices"],
                         self.ev(report, "scope", "sign", "branch")["members"]["branch_indices"])


def case_report_with_packages(test: Base) -> dict:
    report = copy.deepcopy(test.build("project"))
    for s, package in zip(report["sources"], ("pkg_a", "pkg_a", "pkg_b")):
        s["package"] = package
    return report


class IndependenceTest(Base):
    """COV-SCP-006 and COV-POL-002: no specificity or declaration-order winner."""

    TOML = ("[tool.sv0cov.thresholds]\nline = 50\n"
            + scope("all", include=["**"], region=100)
            + scope("math", include=["math.sv0"], branch=100, region=1)
            + scope("by-path", sources=["src/sign.sv0"], line=100, branch=40))
    ENTITIES = (entity("div", "src/math.sv0", "div", region=99) + entity("div-contract", "src/math.sv0", "div#requires0", "contract", contract=100)
                + entity("positive", "src/sign.sv0", "positive", branch=100))

    def toml(self, scopes: tuple[str, ...], entities: tuple[str, ...]) -> str:
        return "[tool.sv0cov.thresholds]\nline = 50\n" + "".join(scopes) + "".join(entities)

    def test_declaration_order_changes_nothing(self) -> None:
        """COV-SCP-006: every permutation of three scopes and three entities gives the same policy."""
        scopes = (scope("all", include=["**"], region=100), scope("math", include=["math.sv0"], branch=100, region=1),
                  scope("by-path", sources=["src/sign.sv0"], line=100, branch=40))
        entities = (entity("div", "src/math.sv0", "div", region=99), entity("div-contract", "src/math.sv0", "div#requires0", "contract", contract=100),
                    entity("positive", "src/sign.sv0", "positive", branch=100))
        base = self.build("sample", self.toml(scopes, entities))
        self.assertTrue(self.evals(base, "scope") and self.evals(base, "entity"))
        seen = 0
        for s in itertools.permutations(scopes):
            for e in itertools.permutations(entities):
                report = self.build("sample", self.toml(s, e))
                seen += 1
                self.assertEqual(report["policy"], base["policy"])
                self.assertEqual(encode(report), encode(base))
        self.assertEqual(seen, 36)

    def test_evaluations_are_in_canonical_order(self) -> None:
        """SPEC 22.2: kind, then name, then metric, bytewise; each metric of each assertion appears once."""
        report = self.build("sample", self.TOML + self.ENTITIES)
        keys = [(e["assertion_kind"].encode(), e["assertion_name"].encode(), e["metric"].encode()) for e in report["policy"]["evaluations"]]
        self.assertEqual(keys, sorted(keys))
        self.assertEqual(len(keys), len(set(keys)))
        kinds = [k[0].decode() for k in keys]
        self.assertEqual(sorted(set(kinds), key=kinds.index), ["entity", "integrity", "project", "scope"])
        self.assertEqual([e["metric"] for e in self.evals(report, "scope", "all")], list(METRICS))
        self.assertEqual({n: len(self.evals(report, "entity", n)) for n in ("div", "div-contract", "positive")},
                         {"div": 5, "div-contract": 1, "positive": 5})

    def test_a_narrow_scope_does_not_override_a_wide_one(self) -> None:
        """COV-SCP-006: `**`, a directory glob and one file all keep their own evaluations; adding or removing a scope never changes another."""
        scopes = {"wide": scope("wide", include=["**"], line=100), "dir": scope("dir", include=["lib/*.sv0"], line=1),
                  "file": scope("file", sources=["lib/util.sv0"], line=100)}
        alone = {n: self.build("project", t) for n, t in scopes.items()}
        together = self.build("project", "".join(scopes.values()))
        for n in scopes:
            self.assertEqual(self.evals(together, "scope", n), self.evals(alone[n], "scope", n), n)
        self.assertEqual([self.ev(together, "scope", n, "line")["members"]["source_indices"] for n in ("wide", "dir", "file")],
                         [[0, 1, 2], [0], [0]])
        # The dir and file scopes see exactly the same source yet are two assertions with two thresholds.
        self.assertEqual([self.ev(together, "scope", n, "line")["limit"]["numerator"] for n in ("dir", "file")], [100, 10000])
        self.assertEqual([self.ev(together, "scope", n, "line")["result"] for n in ("wide", "dir", "file")], ["pass", "pass", "pass"])

    def test_a_directory_pattern_and_a_shared_basename_select_different_sources(self) -> None:
        """COV-SCP-006: `lib/util.sv0` and `util/util.sv0` share a basename; a bare name selects both, a path selects one."""
        toml = (scope("base", include=["util.sv0"]) + scope("lib", include=["/lib/util.sv0"]) + scope("util", include=["util/"])
                + scope("exact", sources=["util/util.sv0"]))
        report = self.build("project", toml)
        got = {n: self.ev(report, "scope", n, "line")["members"]["source_indices"] for n in ("base", "lib", "util", "exact")}
        self.assertEqual(got, {"base": [0, 2], "lib": [0], "util": [2], "exact": [2]})

    def test_entity_checks_are_additional_not_overrides(self) -> None:
        """COV-SCP-006, SPEC 22.2: an entity check is an extra assertion; neither the project nor a matching scope changes."""
        base = self.build("sample", "[tool.sv0cov.thresholds]\nbranch = 100\n" + scope("s", sources=["src/sign.sv0"], branch=50))
        extra = self.build("sample", "[tool.sv0cov.thresholds]\nbranch = 100\n" + scope("s", sources=["src/sign.sv0"], branch=50)
                           + entity("positive", "src/sign.sv0", "positive", branch=50))
        for kind in ("project", "scope", "integrity"):
            self.assertEqual(self.evals(extra, kind), self.evals(base, kind), kind)
        self.assertEqual(len(self.evals(extra, "entity")), 5)
        self.assertEqual(self.results(base), {("project", "project", "branch"): "fail", ("scope", "s", "branch"): "pass"})
        # The entity (pass) and the project (fail) answer separate questions about the same function.
        self.assertEqual(self.ev(extra, "entity", "positive", "branch")["result"], "pass")
        self.assertEqual(self.ev(extra, "project", "project", "branch")["result"], "fail")


class InheritanceTest(Base):
    """COV-POL-023: only the project value of the same metric is inherited; an explicit value is the assertion's own."""

    # f0: line 14/16 (87.5 %), branch 4/6 (66.7 %), region 15/18, function 3/3, contract 0/0.
    BASE = "[tool.sv0cov.thresholds]\nline = 80\nbranch = 70\n"

    def test_a_project_threshold_is_inherited_for_the_same_metric_only(self) -> None:
        report = self.build("f0", self.BASE + scope("core", include=["**"]) + entity("classify", "main.sv0", "classify"))
        for kind, name in (("scope", "core"), ("entity", "classify")):
            by = {e["metric"]: e for e in self.evals(report, kind, name)}
            self.assertEqual({m: (by[m]["threshold_source"], by[m]["limit"], by[m]["comparison"]) for m in ("line", "branch")},
                             {"line": ("project", {"numerator": 8000, "denominator": 10000}, "at_least"),
                              "branch": ("project", {"numerator": 7000, "denominator": 10000}, "at_least")})
            for m in ("region", "function", "contract"):
                self.assertEqual((by[m]["comparison"], by[m]["result"], by[m]["limit"], by[m]["threshold_source"], by[m]["diagnostics"]),
                                 ("none", "not_applicable", None, None, []), (kind, m))
        self.assertEqual(self.ev(report, "scope", "core", "line")["result"], "pass")  # 14/16 >= 80 %
        self.assertEqual(self.ev(report, "scope", "core", "branch")["result"], "fail")  # 4/6 < 70 %

    def test_an_explicit_value_is_the_assertions_own_and_does_not_cascade(self) -> None:
        """No other scope, entity or metric sees it, and it replaces rather than adds to the project value."""
        toml = (self.BASE + scope("strict", include=["**"], line=90) + scope("plain", include=["**"])
                + entity("e-strict", "main.sv0", "classify", region=50) + entity("e-plain", "main.sv0", "classify"))
        report = self.build("f0", toml)
        strict = self.ev(report, "scope", "strict", "line")
        self.assertEqual((strict["threshold_source"], strict["limit"], strict["result"], strict["diagnostics"]),
                         ("assertion", {"numerator": 9000, "denominator": 10000}, "fail", ["COV4101"]))  # 87.5 % < 90 %, though 80 % would pass
        self.assertEqual(self.ev(report, "scope", "strict", "branch")["threshold_source"], "project")  # the other metric still inherits
        self.assertEqual(self.ev(report, "scope", "strict", "region")["threshold_source"], None)  # the explicit line threshold is not a region threshold
        for kind, name in (("scope", "plain"), ("entity", "e-plain"), ("entity", "e-strict")):
            self.assertEqual(self.ev(report, kind, name, "line")["limit"], {"numerator": 8000, "denominator": 10000}, (kind, name))
            self.assertEqual(self.ev(report, kind, name, "line")["threshold_source"], "project")
        region = self.ev(report, "entity", "e-strict", "region")
        self.assertEqual((region["threshold_source"], region["limit"]["numerator"]), ("assertion", 5000))
        self.assertEqual(self.ev(report, "entity", "e-plain", "region")["threshold_source"], None)
        self.assertEqual(self.ev(report, "project", "project", "line")["limit"]["numerator"], 8000)  # the project is not weakened or hardened

    def test_an_explicit_value_may_be_lower_than_the_project_value(self) -> None:
        """COV-POL-023: replacement, not minimum or maximum."""
        report = self.build("f0", "[tool.sv0cov.thresholds]\nline = 100\n" + scope("lenient", include=["**"], line=10))
        self.assertEqual((self.ev(report, "scope", "lenient", "line")["result"], self.ev(report, "project", "project", "line")["result"]),
                         ("pass", "fail"))

    def test_no_project_value_and_no_explicit_value_reports_without_checking(self) -> None:
        report = self.build("f0", scope("core", include=["**"]) + entity("m", "main.sv0", "main"))
        self.assertTrue(report["policy"]["passed"])
        self.assertEqual(self.evals(report, "project"), [])
        for kind, name in (("scope", "core"), ("entity", "m")):
            evaluations = self.evals(report, kind, name)
            self.assertEqual([e["metric"] for e in evaluations], list(METRICS))
            for e in evaluations:
                self.assertEqual((e["comparison"], e["result"], e["limit"], e["threshold_source"], e["diagnostics"]),
                                 ("none", "not_applicable", None, None, []))
        # The fraction is still reported (numerator over denominator; null only when the denominator is empty).
        want = oracle(report)
        self.assertEqual({m: self.fraction(self.ev(report, "scope", "core", m)["actual"]) for m in METRICS},
                         {m: ((c, t) if t else None) for m, (c, t, _) in want.items()})
        self.assertEqual(self.ev(report, "scope", "core", "contract")["actual"], None)
        self.assertEqual(self.ev(report, "scope", "core", "line")["actual"], {"numerator": 14, "denominator": 16})

    def test_basis_point_and_percentage_forms_are_the_same_threshold(self) -> None:
        """COV-POL-023 with the 8500bp / 85 spelling of one value, at every level."""
        def toml(value) -> str:
            return (f"[tool.sv0cov.thresholds]\nregion = {json.dumps(value)}\n" + scope("s", include=["**"], line=value, branch=value)
                    + entity("e", "main.sv0", "classify", line=value))
        percent, basis = self.build("f0", toml(85)), self.build("f0", toml("8500bp"))
        self.assertEqual(percent["policy"], basis["policy"])
        self.assertEqual(self.ev(basis, "scope", "s", "line")["limit"], {"numerator": 8500, "denominator": 10000})
        self.assertEqual(self.ev(basis, "entity", "e", "line")["limit"], {"numerator": 8500, "denominator": 10000})
        # A finer basis-point value is a different threshold: 8750bp is met by 14/16 exactly, 8751bp is not.
        for value, result in (("8750bp", "pass"), ("8751bp", "fail")):
            self.assertEqual(self.ev(self.build("f0", scope("s", include=["**"], line=value)), "scope", "s", "line")["result"], result)


class PolicyTest(Base):
    """COV-POL-022: every assertion passes independently, and each failure is reported."""

    FAIL_PROJECT = "[tool.sv0cov.thresholds]\nbranch = 100\n"          # sample: 1 of 2 outcomes
    PASS_PROJECT = "[tool.sv0cov.thresholds]\nfunction = 100\n"
    SCOPE_OK, SCOPE_BAD = scope("s", sources=["src/sign.sv0"], branch=50), scope("s", sources=["src/sign.sv0"], branch=100)
    ENTITY_OK, ENTITY_BAD = (entity("e", "src/sign.sv0", "positive", branch=50), entity("e", "src/sign.sv0", "positive", branch=100))

    def check(self, toml: str, failing: set[tuple]) -> dict:
        report = self.build("sample", toml)
        got = {k for k, v in self.results(report).items() if v == "fail"}
        self.assertEqual(got, failing)
        self.assertEqual(report["policy"]["passed"], not failing)
        self.assertEqual(report["evidence_eligibility"], "passing" if not failing else "policy_failed")
        for e in report["policy"]["evaluations"]:
            if (e["assertion_kind"], e["assertion_name"], e["metric"]) in failing:
                self.assertEqual((e["diagnostics"], e["actual"]), (["COV4101"], {"numerator": 1, "denominator": 2}))
        return report

    def test_everything_passing_passes(self) -> None:
        report = self.check(self.PASS_PROJECT + self.SCOPE_OK + self.ENTITY_OK, set())
        self.assertEqual(sorted(self.results(report)), [("entity", "e", "branch"), ("entity", "e", "function"), ("project", "project", "function"),
                          ("scope", "s", "branch"), ("scope", "s", "function")])

    def test_one_failure_at_each_level(self) -> None:
        """Project, scope and entity in turn: the others pass and the policy still fails."""
        self.check(self.FAIL_PROJECT + self.SCOPE_OK + self.ENTITY_OK, {("project", "project", "branch")})
        self.check(self.PASS_PROJECT + self.SCOPE_BAD + self.ENTITY_OK, {("scope", "s", "branch")})
        self.check(self.PASS_PROJECT + self.SCOPE_OK + self.ENTITY_BAD, {("entity", "e", "branch")})

    def test_several_simultaneous_failures_are_all_reported(self) -> None:
        self.check(self.FAIL_PROJECT + self.SCOPE_BAD + self.ENTITY_BAD, {("project", "project", "branch"), ("scope", "s", "branch"),
                                                                           ("entity", "e", "branch")})
        two = self.check(self.PASS_PROJECT + scope("s1", include=["**"], branch=100) + scope("s2", include=["**"], branch=51)
                         + scope("s3", include=["**"], branch=50), {("scope", "s1", "branch"), ("scope", "s2", "branch")})
        self.assertEqual(self.ev(two, "scope", "s3", "branch")["result"], "pass")

    def test_a_passing_assertion_never_rescues_a_failing_one(self) -> None:
        """A passing scope does not rescue a failing project, nor a passing project a failing scope or entity."""
        self.check(self.FAIL_PROJECT + scope("s", include=["**"], branch=1), {("project", "project", "branch")})
        self.check("[tool.sv0cov.thresholds]\nbranch = 1\n" + scope("s", include=["**"], branch=100), {("scope", "s", "branch")})
        self.check("[tool.sv0cov.thresholds]\nbranch = 1\n" + self.ENTITY_BAD, {("entity", "e", "branch")})
        # An inherited project value fails scope, entity and project together, each on its own account.
        inherited = self.check(self.FAIL_PROJECT + scope("s", include=["**"]) + entity("e", "src/sign.sv0", "positive"),
                               {("project", "project", "branch"), ("scope", "s", "branch"), ("entity", "e", "branch")})
        self.assertEqual({self.ev(inherited, k, n, "branch")["threshold_source"] for k, n in (("scope", "s"), ("entity", "e"))}, {"project"})

    def test_a_failing_assertion_on_a_not_applicable_metric_cannot_exist(self) -> None:
        """Unchecked metrics (no threshold at all) never fail the policy even when their fraction is poor."""
        report = self.build("sample", scope("s", include=["**"]) + entity("e", "src/sign.sv0", "positive"))
        self.assertTrue(report["policy"]["passed"])
        self.assertEqual(self.ev(report, "scope", "s", "branch")["actual"], {"numerator": 1, "denominator": 2})


class EntityTest(Base):
    """COV-POL-026, COV-CFG-008: SPEC 22.2.1."""

    ALL = 'empty = "pass"\n[tool.sv0cov.thresholds]\n' + "".join(f"{m} = 0\n" for m in METRICS)

    def owned(self, report: dict, n: int) -> dict:
        """What function entity ``n`` owns, counted from the records alone."""
        regions = [r for r in report["regions"] if r["classification"] == "user" and r["entity_index"] == n]
        outcomes = [(b["branch_index"], o) for b in report["branches"] if b["entity_index"] == n
                    for o in b["outcomes"] if o["status"] in ("covered", "uncovered")]
        entry = next(p for p in report["points"] if p["kind"] == "function_entry" and p["entity_index"] == n)
        user = entry["classification"] == "user"
        clauses = [c for c in report["contracts"] if c["function_entity_index"] == n and c["enforcement"] == "runtime_checked"
                   and not any(c["clause_index"] in x["affected"]["clause_indices"] for x in report["exclusions"])]
        lines = {}
        for line in report["lines"]:
            mine = [report["regions"][i]["count"]["value"] > 0 for i in line["region_indices"] if report["regions"][i] in regions]
            if mine:
                lines[line["line_index"]] = "covered" if all(mine) else "partial" if any(mine) else "uncovered"
        return {
            "region": ((sum(r["count"]["value"] > 0 for r in regions), len(regions)), [r["region_index"] for r in regions]),
            "branch": ((sum(o["status"] == "covered" for _, o in outcomes), len(outcomes)), sorted({b for b, _ in outcomes})),
            "function": ((int(user and entry["count"]["value"] > 0), int(user)), [n]),
            "line": ((sum(s == "covered" for s in lines.values()), len(lines)), sorted(lines)),
            "contract": ((sum(c["count_true"]["value"] + c["count_false"]["value"] > 0 for c in clauses), len(clauses)),
                         [c["clause_index"] for c in clauses]),
        }

    def test_a_function_entity_has_all_five_metrics_with_exact_denominators(self) -> None:
        """COV-POL-026: compare every function entity of five cases with an independent count."""
        checked = 0
        for name in ("f0", "branches", "match", "boolean", "sample"):
            c = case(name)
            ix = build_report(c.indexed, config(c.options), c.sources, tool_version=V)
            functions = [e for e in ix["entities"] if e["kind"] == "function"]
            toml = self.ALL + "".join(
                entity(f"n{e['entity_index']}", ix["sources"][e["source_index"]]["path"], e["qualified_name"]) for e in functions)
            report = self.build(name, toml)
            for e in functions:
                n, label = e["entity_index"], f"n{e['entity_index']}"
                with self.subTest(case=name, entity=e["qualified_name"]):
                    by = {x["metric"]: x for x in self.evals(report, "entity", label)}
                    self.assertEqual(list(by), list(METRICS))
                    want = self.owned(report, n)
                    for m in METRICS:
                        (covered, total), members = want[m]
                        x = by[m]
                        self.assertEqual(x["actual"], {"numerator": covered, "denominator": total} if total else None, m)
                        self.assertEqual(x["members"]["entity_indices"], [n])
                        key = tr_member_key(m)
                        if m != "function":
                            self.assertEqual(x["members"][key], members, m)
                        self.assertEqual(report["entities"][n]["summary"][m]["covered"], covered)
                        self.assertEqual(report["entities"][n]["summary"][m]["total"], total)
                        self.assertEqual((x["threshold_source"], x["result"]), ("project", "pass"))
                    checked += 1
        self.assertGreater(checked, 20)

    def test_a_contract_owner_function_counts_its_clauses(self) -> None:
        """COV-POL-026: `div` owns the `requires` clause through function_entity_index; the contract entity has the same clause."""
        report = self.build("sample", self.ALL + entity("fn", "src/math.sv0", "div") + entity("clause", "src/math.sv0", "div#requires0", "contract"))
        (clause,) = report["contracts"]
        self.assertEqual((clause["function_entity_index"], clause["entity_index"]), (0, 1))
        fn, ct = self.ev(report, "entity", "fn", "contract"), self.ev(report, "entity", "clause", "contract")
        for x in (fn, ct):
            self.assertEqual((x["actual"], x["members"]["clause_indices"]), ({"numerator": 1, "denominator": 1}, [0]))
        self.assertEqual((fn["members"]["entity_indices"], ct["members"]["entity_indices"]), ([0], [1]))

    def test_an_excluded_function_has_empty_denominators_that_follow_the_empty_policy(self) -> None:
        """COV-POL-026, SPEC 11.6, COV4102: `unused` is off by attribute, so each of its metrics is empty."""
        for empty, result, codes in (("fail", "fail", ["COV4102"]), ("pass", "pass", [])):
            report = self.build("sample", f'empty = "{empty}"\n' + thresholds(line=50, function=50) + entity("u", "src/math.sv0", "unused"))
            for m in ("line", "function"):
                x = self.ev(report, "entity", "u", m)
                self.assertEqual((x["actual"], x["result"], x["diagnostics"], x["threshold_source"]), (None, result, codes, "project"))
            self.assertEqual(self.ev(report, "entity", "u", "region")["result"], "not_applicable")
            self.assertEqual(report["policy"]["passed"], result == "pass")

    def test_lines_are_recomputed_from_owned_regions_when_two_entities_share_a_line(self) -> None:
        """COV-POL-026, SPEC 22.2.1. No fixture has two functions on one physical line (nested functions are not
        planned either), so f0's partial line 24 (regions 10 covered, 12 uncovered, both owned by `measure`) is given a second owner in memory."""
        report = copy.deepcopy(self.build("f0"))
        line = next(x for x in report["lines"] if x["status"] == "partial" and x["region_indices"] == [10, 12])
        self.assertEqual({report["regions"][i]["entity_index"] for i in line["region_indices"]}, {1})
        before = {n: _Detail(report).entity(report["entities"][n])["line"] for n in (1, 2)}
        report["regions"][12]["entity_index"] = 2  # the uncovered region now belongs to `main`
        detail = _Detail(report)
        after = {n: detail.entity(report["entities"][n])["line"] for n in (1, 2)}
        # `measure` no longer sees the uncovered region, so its half of the line is covered; `main` sees only an uncovered one.
        self.assertEqual((after[1]["covered"], after[1]["partial"], after[1]["total"]), (before[1]["covered"] + 1, before[1]["partial"] - 1, before[1]["total"]))
        self.assertEqual((after[2]["covered"], after[2]["partial"], after[2]["total"]), (before[2]["covered"], before[2]["partial"], before[2]["total"] + 1))
        for n in (1, 2):
            self.assertIn(line["line_index"], detail.entity_members(report["entities"][n], "line"))
        # The line itself, and so the project and source summaries, keep their status.
        self.assertEqual(line["status"], "partial")
        self.assertEqual(self.owned(report, 1)["line"][0], (after[1]["covered"], after[1]["total"]))
        self.assertEqual(self.owned(report, 2)["line"][0], (after[2]["covered"], after[2]["total"]))
        self.assertEqual(detail.group()["line"], _Detail(self.build("f0")).group()["line"])

    def test_a_contract_entity_has_only_the_contract_metric(self) -> None:
        """COV-CFG-008: its other summaries are null and no evaluation exists for them, even with every project threshold set."""
        report = self.build("sample", thresholds(line=1, region=1, function=1, branch=1, contract=1)
                            + entity("clause", "src/math.sv0", "div#requires0", "contract"))
        summary = report["entities"][1]["summary"]
        self.assertEqual({k: v is None for k, v in summary.items()}, {"branch": True, "contract": False, "function": True, "line": True, "region": True})
        evaluations = self.evals(report, "entity", "clause")
        self.assertEqual([e["metric"] for e in evaluations], ["contract"])
        self.assertEqual((evaluations[0]["threshold_source"], evaluations[0]["result"]), ("project", "pass"))
        self.assertEqual(evaluations[0]["members"]["clause_indices"], [0])
        # With no project threshold for `contract` the single evaluation only reports.
        bare = self.build("sample", thresholds(line=1) + entity("clause", "src/math.sv0", "div#requires0", "contract"))
        (only,) = self.evals(bare, "entity", "clause")
        self.assertEqual((only["metric"], only["result"], only["limit"], only["actual"]), ("contract", "not_applicable", None, {"numerator": 1, "denominator": 1}))
        # A function entity next to it still has five.
        both = self.build("sample", thresholds(line=1) + entity("clause", "src/math.sv0", "div#requires0", "contract") + entity("fn", "src/math.sv0", "div"))
        self.assertEqual((len(self.evals(both, "entity", "clause")), len(self.evals(both, "entity", "fn"))), (1, 5))

    def test_an_ordinary_metric_on_a_contract_entity_is_a_configuration_error(self) -> None:
        """COV-CFG-008, COV-CFG-006: refused when the configuration resolves, before any evidence is read."""
        for metric in ("line", "region", "function", "branch"):
            with self.subTest(metric=metric):
                with self.assertRaises(ConfigError) as caught:
                    config(toml=entity("c", "src/math.sv0", "div#requires0", "contract", **{metric: 50}))
                self.assertEqual(caught.exception.code, "COV0013")
                self.assertIn(metric, str(caught.exception))
        config(toml=entity("c", "src/math.sv0", "div#requires0", "contract", contract=50))  # the one allowed key
        self.assertEqual(self.failure("sample", entity("c", "src/math.sv0", "div#requires0", "contract", contract=50)), "valid")

    def test_entity_tuple_resolution_errors_are_configuration_conflicts(self) -> None:
        """COV-CFG-006: the (source, qualified name, kind) tuple must name exactly one entity."""
        cases = {
            "unknown name": entity("e", "src/math.sv0", "nope"),
            "wrong kind (function named as contract)": entity("e", "src/math.sv0", "div", "contract"),
            "wrong kind (contract named as function)": entity("e", "src/math.sv0", "div#requires0"),
            "wrong source": entity("e", "src/sign.sv0", "div"),
            "unknown source": entity("e", "src/none.sv0", "div"),
        }
        for label, toml in cases.items():
            with self.subTest(case=label):
                self.assertEqual(self.failure("sample", toml), "COV0013")
        self.assertEqual(self.failure("project", entity("e", "util/util.sv0", "lib::triple")), "COV0013")  # right name, the other util
        self.assertEqual(self.failure("project", entity("e", "lib/util.sv0", "lib::triple")), "valid")

    def test_an_ambiguous_entity_tuple_is_refused(self) -> None:
        """COV-CFG-006: two entities with one identity cannot occur in valid evidence, but the resolver still refuses several matches."""
        report = copy.deepcopy(self.build("sample", entity("e", "src/sign.sv0", "positive")))
        spec = report["resolved_configuration"]["coverage"]["entities"][0]
        self.assertEqual(resolve_entity(report, spec)["qualified_name"], "positive")
        report["entities"].append(dict(report["entities"][3], entity_index=4))
        with self.assertRaises(ReportError) as caught:
            resolve_entity(report, spec)
        self.assertEqual(caught.exception.code, "COV0013")
        self.assertIn("2 entities", str(caught.exception))


def tr_member_key(metric: str) -> str:
    return {"branch": "branch_indices", "contract": "clause_indices", "function": "entity_indices", "line": "line_indices",
            "region": "region_indices"}[metric]


class ConfigurationTest(Base):
    """COV-CFG-006: selectors, uniqueness, empty scopes."""

    def test_an_unknown_package_or_source_is_a_conflict(self) -> None:
        self.assertEqual(self.failure("project", scope("s", packages=["nope"])), "COV0013")
        self.assertEqual(self.failure("project", scope("s", sources=["lib/none.sv0"])), "COV0013")
        self.assertEqual(self.failure("project", scope("s", include=["**"], sources=["main.sv0", "util.sv0"])), "COV0013")
        self.assertEqual(self.failure("project", scope("s", sources=["lib/util.sv0"])), "valid")
        # One bad selector spoils the scope however many good ones accompany it, and the message names the scope.
        c = case("project")
        with self.assertRaises(ReportError) as caught:
            build_report(c.indexed, config(toml=scope("good", include=["**"]) + scope("bad", include=["**"], packages=["zzz"])), c.sources)
        self.assertEqual(caught.exception.code, "COV0013")
        self.assertIn("bad", str(caught.exception))
        # A package is a fact about the evidence (no source compiled here has one); a name is not matched as a pattern.
        self.assertEqual(self.failure("project", scope("s", packages=["lib"])), "COV0013")

    def test_a_scope_needs_a_selector(self) -> None:
        with self.assertRaises(ConfigError) as caught:
            config(toml=scope("s", line=50))
        self.assertEqual(caught.exception.code, "COV0013")

    def test_a_scope_selecting_nothing_is_empty_and_follows_the_empty_policy(self) -> None:
        """COV-CFG-006, SPEC 11.6: not an error; with a threshold and `empty = fail` every thresholded metric fails with COV4102."""
        toml = scope("none", include=["nowhere/**", "!main.sv0"], line=50) + scope("negated", include=["**", "!**"], region=50)
        for empty, result, codes, passed in (("fail", "fail", ["COV4102"], False), ("pass", "pass", [], True)):
            report = self.build("project", f'empty = "{empty}"\n' + toml)
            for name, metric in (("none", "line"), ("negated", "region")):
                e = self.ev(report, "scope", name, metric)
                self.assertEqual((e["members"]["source_indices"], e["members"]["line_indices"], e["actual"], e["result"], e["diagnostics"]),
                                 ([], [], None, result, codes), (empty, name))
                self.assertEqual(e["threshold_source"], "assertion")
            # Unthresholded metrics of an empty scope only report.
            other = self.ev(report, "scope", "none", "branch")
            self.assertEqual((other["result"], other["actual"], other["diagnostics"]), ("not_applicable", None, []))
            self.assertEqual(report["policy"]["passed"], passed)

    def test_duplicate_names_are_refused_by_the_resolver(self) -> None:
        """COV-CFG-006: assertion names are unique within their table."""
        dup_scopes = scope("a", include=["**"]) + scope("a", include=["lib/"])
        dup_entities = entity("e", "main.sv0", "main") + entity("e", "main.sv0", "main")
        for label, toml in (("scopes", dup_scopes), ("entities", dup_entities)):
            with self.subTest(table=label):
                with self.assertRaises(ConfigError) as caught:
                    config(toml=toml)
                self.assertEqual(caught.exception.code, "COV0013")
                self.assertIn("not unique", str(caught.exception))

    def test_a_scope_and_an_entity_may_share_a_name(self) -> None:
        """Uniqueness is per table; the two kinds are told apart by assertion_kind and stay separate evaluations."""
        report = self.build("f0", thresholds(line=50) + scope("x", include=["**"]) + entity("x", "main.sv0", "main"))
        self.assertEqual(len(self.evals(report, "scope", "x")), 5)
        self.assertEqual(len(self.evals(report, "entity", "x")), 5)
        self.assertNotEqual(self.ev(report, "scope", "x", "line")["members"], self.ev(report, "entity", "x", "line")["members"])


class SaturationTest(Base):
    """SPEC 22.2, 14.2.1: under the default `fail` policy no checked evaluation of any kind can pass."""

    def test_every_thresholded_scope_and_entity_evaluation_is_ineligible(self) -> None:
        saturated = tr.IntegrityTest().saturated("fail")
        toml = (thresholds(function=1, contract=1) + scope("s", include=["**"], line=1) + scope("quiet", include=["**"])
                + entity("f", "main.sv0", "main", branch=1) + entity("c", "src/math.sv0", "div#requires0", "contract"))
        report = build_report(saturated, config(STALE_OK, toml), {}, tool_version=V)
        self.assertEqual(read_report(encode(report)), report)
        self.assertTrue(report["saturation"]["any"])
        thresholded = [e for e in report["policy"]["evaluations"] if e["assertion_kind"] in ("project", "scope", "entity") and e["limit"] is not None]
        self.assertEqual(len(thresholded), 2 + 3 + 2 + 3 + 1)  # project 2; scope s 3, quiet 2; entity f 3, c 1
        for e in thresholded:
            self.assertEqual((e["result"], e["diagnostics"]), ("ineligible", ["COV4020"]), (e["assertion_kind"], e["assertion_name"], e["metric"]))
            self.assertIsNone(e["actual"])
            self.assertIn(e["threshold_source"], ("project", "assertion"))
        s = {e["metric"]: e for e in self.evals(report, "scope", "s")}
        self.assertEqual({m: s[m]["result"] for m in METRICS},
                         {"branch": "not_applicable", "contract": "ineligible", "function": "ineligible", "line": "ineligible", "region": "not_applicable"})
        self.assertEqual({m: x["result"] for m, x in ((x["metric"], x) for x in self.evals(report, "scope", "quiet"))},
                         {"branch": "not_applicable", "contract": "ineligible", "function": "ineligible", "line": "not_applicable",
                          "region": "not_applicable"})
        self.assertEqual({x["metric"]: x["result"] for x in self.evals(report, "entity", "f")},
                         {"branch": "ineligible", "contract": "ineligible", "function": "ineligible", "line": "not_applicable", "region": "not_applicable"})
        self.assertEqual([(x["metric"], x["result"]) for x in self.evals(report, "entity", "c")], [("contract", "ineligible")])
        self.assertFalse(report["policy"]["passed"])
        self.assertNotEqual(report["evidence_eligibility"], "passing")

    def test_an_assertion_that_checks_nothing_is_not_made_ineligible(self) -> None:
        report = build_report(tr.IntegrityTest().saturated("fail"), config(STALE_OK, scope("s", include=["**"]) + entity("f", "main.sv0", "main")), {},
                              tool_version=V)
        self.assertEqual({e["result"] for e in report["policy"]["evaluations"] if e["assertion_kind"] in ("scope", "entity")}, {"not_applicable"})
        self.assertEqual(read_report(encode(report)), report)


class RendererTest(Base):
    """SPEC 22.2: the terminal and the HTML report show every scope and entity evaluation."""

    TOML = (thresholds(line=80, branch=70) + scope("core", include=["**"], region=50) + scope("b.q_t-1", sources=["main.sv0"])
            + entity("classify", "main.sv0", "classify", line=100) + entity("main-fn", "main.sv0", "main"))

    def test_terminal_report_shows_every_row(self) -> None:
        report = self.build("f0", self.TOML)
        text = render_terminal(report)
        rows = [line for line in text.splitlines()]
        wanted = [e for e in report["policy"]["evaluations"] if e["assertion_kind"] in ("scope", "entity")]
        self.assertEqual(len(wanted), 2 * 5 + 2 * 5)
        for e in wanted:
            word = {"pass": "PASS", "fail": "FAIL", "ineligible": "INELIGIBLE", "not_applicable": "N/A"}[e["result"]]
            label = f'{e["assertion_kind"]} "{e["assertion_name"]}"'
            hits = [r for r in rows if r.startswith(word) and label in r and f" {e['metric']} " in r]
            self.assertEqual(len(hits), 1, (label, e["metric"], word))
            if e["limit"] is not None:
                self.assertIn(f">= {e['limit']['numerator']}/10000", hits[0])
            if e["actual"] is not None:
                self.assertIn(f"{e['actual']['numerator']}/{e['actual']['denominator']}", hits[0])
            self.assertIn(e["threshold_source"] or "-", hits[0])
        self.assertEqual(len([r for r in rows if r.startswith(("PASS", "FAIL", "N/A", "INELIGIBLE"))]), len(report["policy"]["evaluations"]))

    def test_html_report_shows_every_row(self) -> None:
        report = self.build("f0", self.TOML)
        c = case("f0")
        page = render_html(report, c.sources)
        check_html(page)
        text = page.decode()
        for e in report["policy"]["evaluations"]:
            label = esc(f'{e["assertion_kind"]} "{e["assertion_name"]}"')
            word = {"pass": "PASS", "fail": "FAIL", "ineligible": "INELIGIBLE", "not_applicable": "N/A"}[e["result"]]
            self.assertIn(f'<tr><td class="word">{word}</td><td>{label}</td><td>{e["metric"]}</td>', text, (label, e["metric"]))
        self.assertEqual(text.count("<td>scope "), 2 * 5)
        self.assertEqual(text.count("<td>entity "), 2 * 5)


class ReaderTest(Base):
    """The reader re-derives every scope and entity evaluation (COV-POL-023, COV-POL-026)."""

    def verdict(self, obj: dict) -> str:
        try:
            read_report(encode(obj))
        except ReportError as exc:
            return exc.code
        return "valid"

    def test_every_altered_scope_or_entity_evaluation_is_rejected(self) -> None:
        good = self.build("sample", "[tool.sv0cov.thresholds]\nbranch = 50\n" + scope("s", include=["**"], line=90)
                          + entity("e", "src/sign.sv0", "positive") + entity("c", "src/math.sv0", "div#requires0", "contract"))
        self.assertEqual(self.verdict(good), "valid")
        evaluations = good["policy"]["evaluations"]
        n_checked = 0
        for n, e in enumerate(evaluations):
            if e["assertion_kind"] not in ("scope", "entity"):
                continue
            changes = [{"threshold_source": "project" if e["threshold_source"] != "project" else "assertion"},
                       {"members": {**e["members"], "entity_indices": [*e["members"]["entity_indices"], 0]}}]
            if e["limit"] is not None:
                changes.append({"limit": {**e["limit"], "numerator": e["limit"]["numerator"] + 1}})
            if e["actual"] is not None:
                changes.append({"actual": {**e["actual"], "numerator": e["actual"]["numerator"] + 1}})
            for change in changes:
                o = copy.deepcopy(good)
                o["policy"]["evaluations"][n] = {**e, **change}
                with self.subTest(evaluation=(e["assertion_kind"], e["assertion_name"], e["metric"]), change=sorted(change)):
                    self.assertIn(self.verdict(o), ("COV4001", "COV4002"))
                n_checked += 1
            o = copy.deepcopy(good)
            del o["policy"]["evaluations"][n]
            with self.subTest(deleted=n):
                self.assertEqual(self.verdict(o), "COV4002")
        self.assertGreater(n_checked, 20)

    def test_a_report_naming_an_unknown_entity_does_not_read_back(self) -> None:
        good = self.build("sample", entity("e", "src/sign.sv0", "positive"))
        o = copy.deepcopy(good)
        o["resolved_configuration"]["coverage"]["entities"][0]["qualified_name"]["value"] = "negative"
        self.assertEqual(self.verdict(o), "COV4002")


if __name__ == "__main__":
    unittest.main()
