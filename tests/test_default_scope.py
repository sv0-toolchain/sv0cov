# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Default scope ignores directory conventions (SPEC AC-003; COV-SCP-004).

AC-003: given compiled user sources under src, tests, examples, fixtures and
vendor, when no explicit scope exclusion exists, every compiled user-owned
sv0 source enters the default denominator. COV-SCP-004: ownership comes from
the map's build metadata, never from path spelling -- a ``dependency``
source stays out of the user denominators even at ``src/...``, and a
``user`` source under ``vendor/`` stays in.
"""

from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tests"))

import map_samples as ms  # noqa: E402
from test_indexed_reader import map_input, profile_input, raw  # noqa: E402
from test_report import V, config, oracle  # noqa: E402

from sv0cov.formats.canonical_json import encode  # noqa: E402
from sv0cov.formats.map import validate_map  # noqa: E402
from sv0cov.model.identity import NO_ORDINAL, EntityKind, PointIdentity, PointKind, point_id  # noqa: E402
from sv0cov.model.indexed import build_indexed  # noqa: E402
from sv0cov.model.report import build_report  # noqa: E402

TEXT = "fn f() -> i32 {\n    return 1;\n}\n"
USER_PATHS = ["src/a.sv0", "tests/b.sv0", "examples/c.sv0", "fixtures/d.sv0", "vendor/e.sv0"]
# Looks like first-party code, is a dependency by build metadata.
DEP_PATH = "src/dep.sv0"


def _sources() -> dict[str, bytes]:
    # Distinct bytes per source (a trailing comment) so digests differ.
    return {p: (TEXT + f"// {p}\n").encode() for p in [*USER_PATHS, DEP_PATH]}


def _span(data: bytes, text: str) -> dict:
    start = data.index(text.encode())
    end = start + len(text.encode())
    t = ms._Text(data)
    sl, sc = t.position(start)
    el, ec = t.position(end)
    return {"end_byte": end, "end_column": ec, "end_line": el, "start_byte": start, "start_column": sc, "start_line": sl}


def build_map(texts: dict[str, bytes]) -> dict:
    """One function with one ``return`` region per source; the last path in
    ``texts`` order of ``DEP_PATH`` is a dependency source."""
    paths = sorted(texts)
    sources, entities, points, regions, fragments = [], [], [], [], []
    for i, p in enumerate(paths):
        data = texts[p]
        dep = p == DEP_PATH
        sources.append({"digest": hashlib.sha256(data).hexdigest(), "ownership": "dependency" if dep else "user",
                        "package": "dep" if dep else None, "path": p, "source_index": i})
        fn = _span(data, "fn f() -> i32 {\n    return 1;\n}")
        ret = _span(data, "return 1;")
        entities.append({"entity_index": i, "kind": "function", "qualified_name": "f", "source_index": i, "span": fn})
        pid = point_id(PointIdentity(source_path=p, source_digest=sources[i]["digest"], entity_kind=EntityKind.FUNCTION,
                                     entity_name="f", point_kind=PointKind.FUNCTION_ENTRY, start_byte=fn["start_byte"],
                                     end_byte=fn["end_byte"], outcome_ordinal=NO_ORDINAL, discriminator="entry"))
        points.append({"classification": "user", "counter_index": i, "entity_index": i, "fragment_index": i,
                       "kind": "function_entry", "outcome_ordinal": None, "point_id": pid,
                       "semantic_discriminator": "entry", "source_index": i, "span": dict(fn)})
        regions.append({"classification": "user", "counter_expression": {"terms": [{"coefficient": 1, "point_id": pid}]},
                        "entity_index": i, "kind": "return", "line_contributing": True,
                        "line_numbers": ms._Text(data).line_numbers(ret["start_byte"], ret["end_byte"]),
                        "region_index": i, "source_index": i, "span": ret})
        fragments.append({"fragment_id": "", "fragment_index": i, "slice_base": i, "slice_length": 1, "source_indices": [i]})
    points.sort(key=lambda x: x["point_id"])
    obj = {"branches": [], "capabilities": list(ms.CAPABILITIES), "compiler": {"identity": "sv0c@d1a51004", "name": "sv0c"},
           "contracts": [], "entities": entities, "exclusions": [], "fragments": fragments, "map_id": "",
           "point_identity_version": "1.0", "points": points, "program_counter_count": len(paths), "regions": regions,
           "schema": "sv0cov.map", "sources": sources, "target": {"kind": "executable", "name": "scope"}, "version": "1.0"}
    return ms.finalize(json.loads(json.dumps(obj)))


class DefaultScopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        texts = _sources()
        data = encode(build_map(texts))
        m = validate_map(data)
        counts = {p["point_id"]: 1 for p in m["points"]}  # every function entered once
        ix = build_indexed([map_input("scope.sv0covmap.json", data)],
                           [profile_input("p.sv0profraw", raw(m, counts, 1), m)], tool_version=V)
        cls.report = build_report(encode(ix), config(), texts, tool_version=V)  # no scopes configured

    def test_default_scope_ignores_directory_conventions(self) -> None:
        """AC-003 / COV-SCP-004: every user source enters the default
        denominator wherever it lives; a dependency at src/... does not."""
        r = self.report
        by_path = {s["path"]: s for s in r["sources"]}
        for p in USER_PATHS:
            self.assertEqual(by_path[p]["ownership"], "user", p)
        self.assertEqual(by_path[DEP_PATH]["ownership"], "dependency")
        user = [s["source_index"] for s in r["sources"] if s["ownership"] == "user"]
        dep = [s["source_index"] for s in r["sources"] if s["ownership"] == "dependency"]
        self.assertEqual(len(user), len(USER_PATHS))
        self.assertEqual(len(dep), 1)
        summary = r["summary"]
        for kind in ("function", "region", "line"):
            for i in user:
                self.assertEqual(oracle(r, i)[kind][1], 1, f"{kind} of user source {i}")
            by_src = {s["source_index"]: s["summary"][kind] for s in r["sources"]}
            self.assertEqual(by_src[dep[0]]["total"], 1, "the dependency has units of its own")
            # The project denominator is exactly the sum over user sources ...
            self.assertEqual(summary[kind]["total"], sum(by_src[i]["total"] for i in user), f"{kind} total")
            self.assertEqual(summary[kind]["covered"], sum(by_src[i]["covered"] for i in user), f"{kind} covered")
            self.assertEqual(summary[kind]["total"], len(USER_PATHS), f"{kind} total is five user units")

    def test_project_thresholds_leave_the_dependency_out(self) -> None:
        """SPEC 18.1: dependency sources are excluded from root thresholds by
        default; the evaluation's members are the user units only (B12)."""
        texts = _sources()
        data = encode(build_map(texts))
        m = validate_map(data)
        ix = build_indexed([map_input("scope.sv0covmap.json", data)],
                           [profile_input("p.sv0profraw", raw(m, {p["point_id"]: 1 for p in m["points"]}, 1), m)], tool_version=V)
        r = build_report(encode(ix), config(toml='[tool.sv0cov.thresholds]\nfunction = 100\n'), texts, tool_version=V)
        (e,) = [e for e in r["policy"]["evaluations"] if e["assertion_kind"] == "project"]
        dep = {s["source_index"] for s in r["sources"] if s["ownership"] == "dependency"}
        owners = {r["entities"][i]["source_index"] for i in e["members"]["entity_indices"]}
        self.assertEqual(len(e["members"]["entity_indices"]), len(USER_PATHS))
        self.assertFalse(owners & dep)
        self.assertEqual(e["actual"], {"denominator": len(USER_PATHS), "numerator": len(USER_PATHS)})


if __name__ == "__main__":
    unittest.main()
