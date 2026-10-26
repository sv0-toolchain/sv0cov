#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""R1 performance budget evaluator and DEC-087 exception records (CV-410;
SPEC 24, 24.1, 24.2; COV-PERF-008/009/023/024/035/036, BL-058, BL-093).

One host class at a time: the campaigns given (each one or more
``sv0cov.benchmark-results`` bundles) are checked to be one series, one
stage, one toolchain revision, one corpus and one protocol, and every gate
of ``bench/budgets.json`` is evaluated in every campaign:

- **overhead** (compile, execution): per fixture ``p95(on) / p95(off)``;
  within a category the geometric mean of its fixtures, across categories
  the geometric mean with equal weight (COV-PERF-008), against the limit;
- **size**: the same equal-weight geometric mean of artifact-size ratios
  against its limit, and every fixture against the per-fixture ceiling;
- **memory**: per fixture, ``p95 RSS(on) - p95 RSS(off)`` at most 16 bytes
  per planned point plus the fixed allowance;
- **absolute** (merge, reports): the fixture's p95 wall time and RSS;
- **determinism**: not a timing; it needs its own evidence and is
  ``no-evidence`` here.

A gate passes only when it passes in every campaign: a campaign never
compensates for another, and nothing is pooled across host classes or
observed hardware. Every fixture, category and campaign result stays in the
evaluation (COV-PERF-009). A gate is ``incomplete`` when an applicable
runnable fixture of the frozen corpus is missing or invalid, and when a
pending fixture applies to it (the corpus is not complete yet).

Where the evidence may come from (COV-PERF-023/024): ``reference-dedicated``
campaigns stand on their own; ``managed-ci-recorded`` campaigns (at least
three) satisfy a gate only together with a DEC-087 exception record naming
that gate, bound to exactly those bundles; anything else is ``ineligible``.
A recorded gate without its record is ``refused``. ``--template`` writes
the record with every observable fact filled in (host class, runner,
hardware, the descriptor fields that are ``unknown``, the measured variance
per gate, the bundle digests) and the human parts left empty: the accepted
risk, the owner and the date.

    python3 bench/evaluate.py --campaign a1.json,a2.json --campaign b1.json ... [--exception rec.json] [--template out.json]

Exit 0 when every gate passes, 1 otherwise; the evaluation is printed as
canonical JSON (``sv0cov.perf-evaluation`` 1.0).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path[:0] = [str(HERE), str(HERE.parent / "src")]

import harness as H  # noqa: E402

from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402

BUDGETS = HERE / "budgets.json"
MANIFEST = HERE / "corpus" / "manifest.json"
HOST_CLASSES = ("linux-arm64", "linux-x86_64", "macos-arm64", "macos-x86_64")
EXCEPTION_KEYS = ("bundles", "gates", "host_class", "measured_variance", "missing_descriptor_fields", "observed_hardware", "owner",
                  "provider", "recorded_on", "risk_accepted", "runner_image", "runner_label", "schema", "series", "version")
HARDWARE_KEYS = ("architecture", "cpu_model", "installed_memory_bytes", "logical_cpus", "virtualization")
PPM = 1_000_000


class EvaluationError(ValueError):
    """Input that cannot be evaluated at all (mixed series, unknown stage, bad record)."""


def host_class(d: dict) -> str:
    arch = {"aarch64": "arm64", "arm64": "arm64", "x86_64": "x86_64", "amd64": "x86_64"}.get(str(d["architecture"]).lower())
    name = f"{d['os_name']}-{arch}"
    if name not in HOST_CLASSES:
        raise EvaluationError(f"no R1 host class for {d['os_name']} {d['architecture']}")
    return name


def unknown_fields(d: dict) -> list[str]:
    return sorted(k for k, v in d.items() if v == H.UNKNOWN)


def _geomean_ppm(values: list[int]) -> int:
    """Geometric mean of positive integer ppm ratios: the exact integer floor of the n-th
    root of their product (big integers, no float rounding: a limit is never missed by one)."""
    n, product = len(values), math.prod(values)
    c = math.floor(math.exp(sum(math.log(v) for v in values) / n))
    while c ** n > product:
        c -= 1
    while (c + 1) ** n <= product:
        c += 1
    return c


def _equal_weight(per_fixture: dict[str, int], category_of: dict[str, str]) -> tuple[int, dict[str, int]]:
    by_cat: dict[str, list[int]] = {}
    for fid, v in per_fixture.items():
        by_cat.setdefault(category_of[fid], []).append(v)
    cats = {c: _geomean_ppm(vs) for c, vs in sorted(by_cat.items())}
    return _geomean_ppm(list(cats.values())), cats


def _fixtures(campaign: list[dict]) -> dict[str, dict]:
    out = {}
    for b in campaign:
        for f in b["fixtures"]:
            if f["id"] in out:
                raise EvaluationError(f"fixture {f['id']} appears twice in one campaign")
            out[f["id"]] = f
    return out


def _applicable(manifest: dict, gate: str) -> tuple[list[str], list[str]]:
    """(runnable fixture ids, pending fixture ids) the gate applies to."""
    runnable, pending = [], []
    for f in manifest["fixtures"]:
        if gate in f["applicable_budgets"]:
            (runnable if f["status"] == "runnable-baseline" else pending).append(f["id"])
    return runnable, pending


def evaluate_campaign(gate: dict, campaign: list[dict], manifest: dict) -> dict:
    """One gate in one campaign: its value, per category and per fixture."""
    found = _fixtures(campaign)
    category_of = {f["id"]: f["category"] for f in manifest["fixtures"]}
    runnable, pending = _applicable(manifest, gate["id"])
    kind = gate["kind"]
    if kind == "determinism":
        return {"result": "no-evidence", "reason": "determinism is evidenced by repeated-execution byte comparisons, not timings"}
    dim = {"size": "execute"}.get(kind, gate.get("dimension"))
    fixtures, missing, invalid = {}, [], []
    for fid in runnable:
        r = found.get(f"{fid}/{dim}")
        if r is None:
            missing.append(fid)
        elif not r["valid"] or (kind in ("overhead", "size", "memory") and r["arms"] != ["off", "on"]):
            invalid.append(fid)
        else:
            fixtures[fid] = r
    out: dict = {"fixtures": {}, "missing": missing, "invalid": invalid, "pending": pending}
    if kind == "overhead":
        values = {fid: r["overhead_p95_ratio_ppm"] for fid, r in fixtures.items()}
        out["fixtures"] = {fid: {"ppm": v} for fid, v in values.items()}
        if values:
            out["value_ppm"], out["categories"] = _equal_weight(values, category_of)
            ok = out["value_ppm"] <= gate["max_ppm"]
    elif kind == "size":
        values = {fid: r["facts"]["artifact_bytes"]["on"] * PPM // r["facts"]["artifact_bytes"]["off"] for fid, r in fixtures.items()}
        over = sorted(fid for fid, v in values.items() if v > gate["max_fixture_ppm"])
        out["fixtures"] = {fid: {"ppm": v, "ceiling_failed": fid in over} for fid, v in values.items()}
        if values:
            out["value_ppm"], out["categories"] = _equal_weight(values, category_of)
            ok = out["value_ppm"] <= gate["max_geomean_ppm"] and not over
            out["ceiling_failures"] = over
    elif kind == "memory":
        ok = True
        for fid, r in fixtures.items():
            extra = r["statistics"]["on"]["rss_bytes"]["p95"] - r["statistics"]["off"]["rss_bytes"]["p95"]
            allowed = gate["bytes_per_point"] * r["facts"]["planned_points"] + gate["fixed_bytes"]
            out["fixtures"][fid] = {"allowed_bytes": allowed, "extra_bytes": extra, "ceiling_failed": extra > allowed}
            ok = ok and extra <= allowed
        values = out["fixtures"]
    else:  # absolute
        ok = True
        for fid, r in fixtures.items():
            st = r["statistics"]["off"]
            failed = st["wall_ns"]["p95"] > gate["max_wall_ns"] or st["rss_bytes"]["p95"] > gate["max_rss_bytes"]
            out["fixtures"][fid] = {"p95_wall_ns": st["wall_ns"]["p95"], "p95_rss_bytes": st["rss_bytes"]["p95"], "ceiling_failed": failed}
            ok = ok and not failed
        values = out["fixtures"]
    if pending or missing or invalid or not runnable or not values:
        out["result"] = "incomplete"
        out["reason"] = "the frozen corpus is not complete for this gate: " + ", ".join(
            x for x in (f"{len(pending)} pending" if pending else "", f"{len(missing)} missing" if missing else "",
                        f"{len(invalid)} invalid or one-arm" if invalid else "", "no runnable fixture" if not runnable else "") if x)
    else:
        out["result"] = "pass" if ok else "fail"
    return out


def _bundle(path: Path) -> tuple[dict, str]:
    data = path.read_bytes()
    return H.validate_bundle(data), hashlib.sha256(data).hexdigest()


def _variance(per_campaign: list[dict]) -> dict:
    values = [c["value_ppm"] for c in per_campaign if "value_ppm" in c]
    return {"campaign_values_ppm": values, "spread_ppm": (max(values) - min(values)) if values else 0}


def check_exception(rec: dict, facts: dict) -> list[str]:
    """Problems with a DEC-087 exception record against the campaigns' own facts."""
    problems = []
    if sorted(rec) != sorted(EXCEPTION_KEYS) or rec.get("schema") != "sv0cov.perf-exception" or rec.get("version") != "1.0":
        return ["not a closed sv0cov.perf-exception 1.0 record"]
    for key in ("host_class", "provider", "runner_label", "runner_image", "series", "missing_descriptor_fields", "observed_hardware", "bundles"):
        if rec[key] != facts[key]:
            problems.append(f"{key} is not the campaigns' ({facts[key]!r})")
    for gid in rec["gates"]:
        if gid not in facts["measured_variance"] or rec["measured_variance"].get(gid) != facts["measured_variance"][gid]:
            problems.append(f"measured_variance of {gid} is not the campaigns'")
    if sorted(rec["measured_variance"]) != sorted(rec["gates"]):
        problems.append("measured_variance names exactly the gates")
    for key in ("risk_accepted", "owner"):
        if not (isinstance(rec[key], str) and rec[key].strip()):
            problems.append(f"{key} is empty: a record is accepted by a person")
    if not (isinstance(rec["recorded_on"], str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}", rec["recorded_on"])):
        problems.append("recorded_on is a YYYY-MM-DD date")
    return problems


def evaluate(campaign_paths: list[list[Path]], exception: dict | None = None, *, manifest_path: Path = MANIFEST) -> dict:
    """Every gate over the campaigns; ``manifest_path`` is the frozen corpus manifest."""
    budgets = decode_canonical(BUDGETS.read_bytes())
    manifest = json.loads(manifest_path.read_bytes())
    campaigns, digests = [], []
    for paths in campaign_paths:
        loaded = [_bundle(p) for p in paths]
        campaigns.append([b for b, _ in loaded])
        digests += [d for _, d in loaded]
    if not campaigns or not all(campaigns):
        raise EvaluationError("give at least one campaign of at least one bundle")
    first = campaigns[0][0]
    for c in campaigns:
        for b in c:
            for key, what in (("series", "observed hardware series"), ("corpus", "corpus")):
                if b[key] != first[key]:
                    raise EvaluationError(f"campaigns from another {what} cannot be pooled ({b[key]!r})")
            for key in ("stage", "toolchain_revision"):
                if b["host"][key] != first["host"][key]:
                    raise EvaluationError(f"campaigns with another {key} cannot be pooled")
            if host_class(b["host"]) != host_class(first["host"]):
                raise EvaluationError("one host class at a time: classes never compensate for each other")
    if first["corpus"].get("manifest_sha256") != hashlib.sha256(manifest_path.read_bytes()).hexdigest():
        raise EvaluationError("the campaigns ran another corpus manifest than the frozen one")
    host, stage = first["host"], first["host"]["stage"]
    needed = budgets["campaigns"].get(stage)
    gates = []
    for gate in budgets["gates"]:
        per = [evaluate_campaign(gate, c, manifest) for c in campaigns]
        results = {p["result"] for p in per}
        result = "pass" if results == {"pass"} else "fail" if "fail" in results else "incomplete" if "incomplete" in results else "no-evidence"
        gates.append({"campaigns": per, "id": gate["id"], "result": result, "variance": _variance(per)})
    facts = {
        "bundles": sorted(digests), "host_class": host_class(host), "measured_variance": {g["id"]: g["variance"] for g in gates},
        "missing_descriptor_fields": unknown_fields(host),
        "observed_hardware": {k: host[k] for k in HARDWARE_KEYS}, "provider": host["provider"],
        "runner_image": host["runner_image"], "runner_label": host["runner_label"], "series": first["series"],
    }
    problems = check_exception(exception, facts) if exception is not None else []
    covered = set(exception["gates"]) if exception is not None and not problems else set()
    for g in gates:
        if g["result"] != "pass":
            g["eligibility"] = "not-passed"
        elif needed is None:
            g["eligibility"] = "ineligible"
            g["reason"] = f"{stage} results never satisfy an R1 performance gate (COV-PERF-024)"
        elif len(campaigns) < needed:
            g["eligibility"] = "ineligible"
            g["reason"] = f"{stage} needs at least {needed} complete campaigns, there are {len(campaigns)}"
        elif stage == "managed-ci-recorded" and g["id"] not in covered:
            g["eligibility"] = "refused"
            g["reason"] = "a managed-ci-recorded gate needs its DEC-087 exception record (COV-PERF-024)"
        else:
            g["eligibility"] = "satisfied"
    return {
        "exception_problems": problems,
        "facts": facts,
        "gates": gates,
        "r1_gates_satisfied": all(g["eligibility"] == "satisfied" for g in gates),
        "schema": "sv0cov.perf-evaluation",
        "stage": stage,
        "version": "1.0",
    }


def template(evaluation: dict, gates: list[str] | None = None) -> dict:
    """A DEC-087 record with every observable fact filled in; a person fills the rest."""
    f = evaluation["facts"]
    ids = gates or [g["id"] for g in evaluation["gates"]]
    return {"bundles": f["bundles"], "gates": ids, "host_class": f["host_class"],
            "measured_variance": {g: f["measured_variance"][g] for g in ids}, "missing_descriptor_fields": f["missing_descriptor_fields"],
            "observed_hardware": f["observed_hardware"], "owner": "", "provider": f["provider"], "recorded_on": "", "risk_accepted": "",
            "runner_image": f["runner_image"], "runner_label": f["runner_label"], "schema": "sv0cov.perf-exception", "series": f["series"],
            "version": "1.0"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--campaign", action="append", required=True, help="comma-separated bundle paths of one campaign")
    ap.add_argument("--exception", type=Path)
    ap.add_argument("--template", type=Path, help="write the exception-record template here")
    args = ap.parse_args(argv)
    try:
        record = json.loads(args.exception.read_bytes()) if args.exception else None
        ev = evaluate([[Path(p) for p in c.split(",")] for c in args.campaign], record)
    except (EvaluationError, H.HarnessError) as exc:
        print(f"evaluate: {exc}", file=sys.stderr)
        return 2
    if args.template:
        args.template.write_bytes(encode(template(ev)))
    sys.stdout.buffer.write(encode(ev))
    for g in ev["gates"]:
        print(f"evaluate: {g['id']}: {g['result']} / {g['eligibility']}" + (f" ({g['reason']})" if "reason" in g else ""), file=sys.stderr)
    return 0 if ev["r1_gates_satisfied"] else 1


if __name__ == "__main__":
    sys.exit(main())
