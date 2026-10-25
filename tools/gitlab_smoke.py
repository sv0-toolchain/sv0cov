#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Write the GitLab coverage-visualization smoke kit (CV-419; SPEC 21.5;
AC-051): a tiny repository a maintainer pushes to GitLab once per release
to observe that GitLab draws ``sv0cov-cobertura-r1-core`` as sv0cov means
it, and records the GitLab release or GitLab.com observation date in the
release evidence (CV-415).

    python3 tools/gitlab_smoke.py --out DIR

The kit is the ``f0`` semantic fixture: its source, the Cobertura document
sv0cov exports for it (byte-identical to the golden), a ``.gitlab-ci.yml``
whose only job publishes that document as a ``coverage_report``, and
``EXPECTED.md`` with every annotated line, its colour, and the steps. The
GitLab runner needs no sv0 toolchain: the report is committed. Every
expected colour is what ``tools/gitlab_cobertura.py`` (the offline oracle
of GitLab's parser) gives for the document; the observation checks GitLab
against it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "tools")]

CI = """\
# sv0cov CV-419 GitLab coverage-visualization smoke. The report is committed:
# this job only publishes it (SPEC 21.5).
coverage:
  image: alpine:3.20
  script:
    - test -s cobertura.xml
  artifacts:
    paths:
      - cobertura.xml
    reports:
      coverage_report:
        coverage_format: cobertura
        path: cobertura.xml
"""


def kit() -> dict[str, bytes]:
    from gitlab_cobertura import visualize
    from test_report import fixture_report, fixture_sources

    from sv0cov.formats.cobertura import render_cobertura

    report, ix = fixture_report("f0")
    sources = fixture_sources("f0", ix)
    xml = render_cobertura(report)
    seen = visualize(xml, project_path="group/sv0cov-smoke", worktree_paths=list(sources))
    status = {(s["path"], x["line"]): x["status"] for s in report["sources"] for x in report["lines"] if x["source_index"] == s["source_index"]}
    rows = []
    for path in sorted(seen):
        for line, hits in sorted(seen[path].items()):
            native = status[(path, line)]
            rows.append(f"| `{path}` | {line} | {native} | {'green' if hits else 'red'} |")
    expected = "\n".join([
        "# sv0cov GitLab coverage-visualization smoke (CV-419)",
        "",
        "Steps, once per release (record the result in the release evidence, CV-415):",
        "",
        "1. Create an empty GitLab project. On `main`, commit only `.gitlab-ci.yml`",
        "   and an empty `main.sv0`.",
        "2. On a branch, commit `main.sv0` and `cobertura.xml` from this kit, and",
        "   open a merge request: the whole file is then in the diff.",
        "3. When the pipeline has finished, open the MR's Changes tab and compare",
        "   every line's coverage colour with the table below. Lines not listed",
        "   have no annotation.",
        "4. Record the GitLab version (Help > About, or the GitLab.com",
        "   observation date), the pipeline URL, and whether every row matched.",
        "",
        "`partial` lines are red: the profile's binary projection counts only",
        "fully covered lines as hit (`line_status_binary_covered_only`). GitLab",
        "shows no branch data at all, so nothing else is expected (mismatch M11).",
        "",
        "| file | line | native status | expected colour |",
        "|---|---|---|---|",
        *rows,
        "",
    ])
    record = {"gitlab": None, "observed_on": None, "pipeline_url": None, "all_rows_matched": None,
              "kit_sha256": None, "note": "Fill in after the observation; see EXPECTED.md."}
    out = {".gitlab-ci.yml": CI.encode(), "cobertura.xml": xml, "EXPECTED.md": expected.encode()}
    out.update({path: data for path, data in sources.items()})
    import hashlib
    record["kit_sha256"] = hashlib.sha256(b"".join(hashlib.sha256(out[k]).digest() for k in sorted(out))).hexdigest()
    out["observation.json"] = (json.dumps(record, indent=1, sort_keys=True) + "\n").encode()
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True, help="a new directory to write the kit into")
    args = ap.parse_args(argv)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    for name, data in kit().items():
        (out / name).parent.mkdir(parents=True, exist_ok=True)
        (out / name).write_bytes(data)
    print(f"gitlab smoke kit: written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
