#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Write the representative HTML report set for the accessibility checks
(CV-408; SPEC 21.2, R1-G8, COV-REP-007): every semantic fixture with failing
thresholds, the context filter, contracts + saturation + exclusions +
unavailable sources, changed regions, a ratchet, and scopes and entities.

    python3 tools/accessibility/build_reports.py OUT_DIR
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]


def reports() -> dict[str, bytes]:
    from test_changed import capture_record, diff_config
    from test_html import multi_context, rich
    from test_indexed_reader import FIXTURES, simple
    from test_ratchet import ratchet_toml
    from test_report import V, config, fixture_sources, thresholds
    from test_scopes import Case, entity, scope

    from sv0cov.config_resolve import resolve
    from sv0cov.formats.baseline import encode_baseline
    from sv0cov.formats.canonical_json import encode
    from sv0cov.formats.html import render_html
    from sv0cov.model.report import baseline_body, build_report

    out = {}
    strict = thresholds(function=100, region=90, line=90, branch=90)
    for name in FIXTURES:
        ix = simple(name)
        sources = fixture_sources(name, ix)
        out[f"fixture-{name}.html"] = render_html(build_report(encode(ix), config(toml=strict), sources, tool_version=V), sources)
    report, sources = multi_context()
    out["contexts.html"] = render_html(report, sources)
    out["rich.html"] = render_html(rich(), {})
    ix = simple("f0")
    sources = fixture_sources("f0", ix)
    changes = capture_record(sources, {"main.sv0": [11, 12, 16, 24]})
    out["changes.html"] = render_html(build_report(encode(ix), diff_config(line=100, region=0, branch=0), sources, tool_version=V,
                                                   changes=changes), sources)
    case = Case.fixture("f0")
    body = baseline_body(build_report(case.indexed, config(), case.sources, tool_version=V), commit=None)
    out["ratchet.html"] = render_html(build_report(case.indexed, resolve("check", (), ratchet_toml()), case.sources, tool_version=V,
                                                   ratchet={"ancestor": None, "data": encode_baseline(body), "head": None}), case.sources)
    sample = Case.sample()
    toml = scope("everything", include=["**"], branch=51) + entity("div", "src/math.sv0", "div", line=100)
    out["scopes.html"] = render_html(build_report(sample.indexed, config(toml=toml), sample.sources, tool_version=V), sample.sources)
    return out


def main() -> int:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    for name, data in reports().items():
        (out / name).write_bytes(data)
    print(f"accessibility reports: {len(list(out.glob('*.html')))} written to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
