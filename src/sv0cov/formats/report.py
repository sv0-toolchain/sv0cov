# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Native report 1.0 and resolved configuration 1.0: structure (CV-228; SPEC
21.3; COV-REP-017, COV-CFG-007, BL-036).

This is the first validation layer of ``sv0cov.report`` 1.0 and of the
``sv0cov.resolved-configuration`` 1.0 record it embeds:

1. canonical JSON bytes within the reader's size tier (SPEC 16.2, 16.3.9);
2. the closed generated schemas (shape, types, enumerations, integer and
   length bounds);
3. the rules one record can be checked against by itself:

   - lexical forms: digests, stable codes, run and profile identities,
     basenames, logical strings and paths, the producer version, assertion
     names, the ``0.dddddd`` ratio form;
   - strictly ordered, duplicate-free scalar arrays;
   - count-record flags, and everything the shared point, region, line,
     branch, contract, exclusion, saturation and input records already
     require in indexed evidence (:mod:`sv0cov.formats.indexed`);
   - a metric record's arithmetic (``covered <= total``, the line-only
     ``partial``, the exact rounded ``ratio``) and a metric set's
     applicability to a project, source, function or contract;
   - a source's state against its two digests; a region's ``point_ids``
     against its own expression;
   - a policy evaluation's null and diagnostic rules, its reserved name, and
     the single integrity evaluation;
   - the provenance record's execution and run-selection rules;
   - ``complete`` against ``evidence_eligibility``, as far as two fields of
     one object decide it;
   - the resolved configuration's leaves: sources that a file-only value
     cannot have, canonical set order, sorted unique assertion names, and
     the tier and table relations.

What is deliberately **not** checked here, and belongs to the
cross-validating reader (CV-229): record-array order and index positions,
references between records, recomputed point IDs, counts and statuses,
summaries against detail, policy fractions against members, provenance sets
against inputs, the saturation inventory against count flags, the full
eligibility precedence, and the configuration digest of SPEC 16.6.

Failures raise :class:`ReportError`: ``COV4001`` for an invalid report or
resolved configuration, ``COV6001`` for bytes over the reader's tier.
"""

from __future__ import annotations

import re

from sv0cov import config
from sv0cov._generated.validators import sv0cov_report_1_0 as _report_schema
from sv0cov._generated.validators import sv0cov_resolved_configuration_1_0 as _config_schema
from sv0cov.formats import indexed as _ix
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical
from sv0cov.formats.indexed import IndexedError
from sv0cov.formats.map import map_limits
from sv0cov.formats.structural import StructuralError
from sv0cov.model.logical import LogicalValueError, check_logical_path, check_logical_string

METRICS = ("branch", "contract", "function", "line", "region")
RE_RATIO = re.compile(r"0\.[0-9]{6}|1\.000000")
RE_COMMIT = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
RE_ASSERTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
SINGLETONS = {"diff": "diff", "exclusion": "exclusions", "integrity": "integrity", "project": "project", "ratchet": "ratchet"}
FILE_ONLY = ("scopes", "entities", "exclusions")
SET_LIKE = {"metrics", "packages", "sources", "forbidden_reasons"}
EMPTY_MEMBERS = {"branch_indices": [], "clause_indices": [], "entity_indices": [], "line_indices": [], "region_indices": [],
                 "source_indices": []}


class ReportError(ValueError):
    """``code``: COV4001 invalid native report, COV6001 over the reader's size tier."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(where: str, detail: str) -> None:
    raise ReportError("COV4001", f"{where}: {detail}")


def _shared(fn, *args) -> None:
    """Run a rule of the indexed structure layer, reporting it as a report fault."""
    try:
        fn(*args)
    except IndexedError as exc:
        raise ReportError("COV4001", exc.detail) from None


# ── metrics ─────────────────────────────────────────────────────────────────


def ratio(covered: int, total: int) -> str | None:
    """The display ratio of SPEC 21.3.1: ``covered / total`` rounded half to
    even to six fractional digits, or ``None`` for a zero total. Integer
    arithmetic only."""
    if total == 0:
        return None
    scaled, rest = divmod(covered * 1000000, total)
    if 2 * rest > total or (2 * rest == total and scaled % 2 == 1):
        scaled += 1
    return f"{scaled // 1000000}.{scaled % 1000000:06d}"


def _metric(m: dict, name: str, where: str) -> None:
    if m["covered"] > m["total"]:
        _fail(where, "covered exceeds total")
    if (m["partial"] is not None) != (name == "line"):
        _fail(f"{where}/partial", "partial is a count exactly for the line metric")
    if m["partial"] is not None and m["covered"] + m["partial"] > m["total"]:
        _fail(where, "covered plus partial exceeds total")
    if m["ratio"] is not None and not RE_RATIO.fullmatch(m["ratio"]):
        _fail(f"{where}/ratio", "not of the form 0.dddddd or 1.000000")
    want = ratio(m["covered"], m["total"])
    if m["ratio"] != want:
        _fail(f"{where}/ratio", f"must be {want if want is not None else 'null'} for these counts")


def _metric_set(s: dict, applicable: tuple[str, ...], where: str) -> None:
    for name in METRICS:
        if (s[name] is not None) != (name in applicable):
            _fail(f"{where}/{name}", "present exactly when the metric applies to this record")
        if s[name] is not None:
            _metric(s[name], name, f"{where}/{name}")


# ── the resolved configuration ──────────────────────────────────────────────


def _leaves(node: object, where: str):
    if isinstance(node, dict):
        if set(node) == {"source", "value"} and isinstance(node["source"], str):
            yield where, node
        else:
            for k, v in node.items():
                yield from _leaves(v, f"{where}/{k}")
    elif isinstance(node, list):
        for n, v in enumerate(node):
            yield from _leaves(v, f"{where}/{n}")


def _check_configuration(c: dict, at: str) -> None:
    cov = c["coverage"]
    for where, leaf in _leaves(c, at):
        value = leaf["value"]
        for n, item in enumerate(value if isinstance(value, list) else [value]):
            if isinstance(item, str):
                try:
                    item.encode("utf-8")
                except UnicodeEncodeError:
                    _fail(f"{where}/value", "not valid UTF-8")
        key = where.rsplit("/", 1)[1]
        if value is None and (leaf["source"] == "sv0.toml" or (leaf["source"] == "cli" and key != "context")):
            _fail(f"{where}/source", "an absent value is a default (or, for context, a command-line absence)")
        if key in SET_LIKE and value is not None and value != sorted(set(value), key=lambda s: s.encode("utf-8")):
            _fail(f"{where}/value", "a set is bytewise sorted and duplicate-free")
        if key == "reports" and len(set(value)) != len(value):
            _fail(f"{where}/value", "report formats are unique")
        if key in ("reports", "metrics", "include", "packages", "sources") and value == []:
            _fail(f"{where}/value", "must not be empty")
    for table in FILE_ONLY:
        for where, leaf in _leaves(cov[table], f"{at}/coverage/{table}"):
            if leaf["source"] == "cli":
                _fail(f"{where}/source", "a file-only value cannot come from the command line")
            if leaf["source"] == "default" and leaf["value"] not in (None, []):
                _fail(f"{where}/source", "a configured file-only value comes from sv0.toml")
    for table in ("scopes", "entities"):
        names = [row["name"]["value"] for row in cov[table]]
        for n, name in enumerate(names):
            if not (name.isascii() and RE_ASSERTION.fullmatch(name)):
                _fail(f"{at}/coverage/{table}/{n}/name/value", "not an assertion name")
        _shared(_ix._sorted_unique, names, f"{at}/coverage/{table}", lambda s: s.encode("ascii"))
    for n, row in enumerate(cov["scopes"]):
        if all(row[k]["value"] is None for k in ("include", "packages", "sources")):
            _fail(f"{at}/coverage/scopes/{n}", "a scope needs a selector")
    for n, row in enumerate(cov["entities"]):
        if row["kind"]["value"] == "contract" and any(row[m]["value"] is not None for m in METRICS if m != "contract"):
            _fail(f"{at}/coverage/entities/{n}", "a contract entity accepts only the contract metric")
    paths = [("output_dir", cov["output_dir"]["value"])]
    if cov["ratchet"] is not None:
        paths.append(("ratchet/baseline", cov["ratchet"]["baseline"]["value"]))
    for where, value in paths:
        try:
            config.check_artifact_path(value, where)
        except config.ConfigError as exc:
            _fail(f"{at}/coverage/{where}/value", exc.detail)
    rp = cov["limits"]["raw_profile"]
    custom = rp["tier"]["value"] == "custom"
    for key in ("max_counters", "max_bytes"):
        if (rp[key]["value"] is not None) != custom:
            _fail(f"{at}/coverage/limits/raw_profile/{key}", "present exactly for the custom tier")
    # The schema already requires a diff's base and a ratchet's baseline and metrics.
    if cov["diff"] is not None and all(cov["diff"][m]["value"] is None for m in ("branch", "line", "region")):
        _fail(f"{at}/coverage/diff", "a diff needs a threshold")
    if cov["schema"]["source"] == "cli":
        _fail(f"{at}/coverage/schema/source", "the schema declaration cannot come from the command line")
    for where, leaf in _leaves(c["report"], f"{at}/report"):
        if (leaf["source"] == "cli") != leaf["value"] or leaf["source"] == "sv0.toml":
            _fail(where, "a report control is true exactly when the command line set it")


def check_resolved_configuration(obj: object) -> dict:
    """Schema and record-level rules of a decoded resolved-configuration record."""
    try:
        _config_schema.validate(obj)
    except StructuralError as exc:
        raise ReportError("COV4001", str(exc)) from exc
    assert isinstance(obj, dict)
    _check_configuration(obj, "")
    return obj


# ── the report ──────────────────────────────────────────────────────────────


def _check_policy(p: dict) -> None:
    integrity = 0
    for n, e in enumerate(p["evaluations"]):
        w = f"/policy/evaluations/{n}"
        name, kind = e["assertion_name"], e["assertion_kind"]
        if not (name.isascii() and RE_ASSERTION.fullmatch(name)):
            _fail(f"{w}/assertion_name", "not an assertion name")
        if kind in SINGLETONS and name != SINGLETONS[kind]:
            _fail(f"{w}/assertion_name", f"a {kind} evaluation is named {SINGLETONS[kind]}")
        _shared(_ix._codes, e["diagnostics"], f"{w}/diagnostics")
        if bool(e["diagnostics"]) != (e["result"] in ("fail", "ineligible")):
            _fail(f"{w}/diagnostics", "diagnostics are present exactly for a fail or ineligible result")
        if (e["limit"] is None) != (e["comparison"] == "none"):
            _fail(f"{w}/limit", "a limit is absent exactly when nothing is compared")
        if e["comparison"] == "none" and e["threshold_source"] is not None:
            _fail(f"{w}/threshold_source", "no threshold applies when nothing is compared")
        if e["comparison"] != "none" and e["threshold_source"] is None:
            _fail(f"{w}/threshold_source", "a comparison names the source of its threshold")
        for key, values in e["members"].items():
            _shared(_ix._sorted_unique, values, f"{w}/members/{key}")
        if kind == "integrity":
            integrity += 1
            if (e["metric"], e["comparison"], e["actual"], e["limit"], e["threshold_source"], e["members"]) != \
                    ("evidence", "none", None, None, None, EMPTY_MEMBERS):
                _fail(w, "the integrity evaluation has metric evidence, no comparison, no fraction, and no member")
        elif e["metric"] == "evidence":
            _fail(f"{w}/metric", "only the integrity evaluation uses the evidence metric")
        if (e["metric"] == "exclusion_records") and kind not in ("exclusion", "ratchet"):
            _fail(f"{w}/metric", "only an exclusion or ratchet evaluation counts exclusion records")
        if kind == "diff" and e["metric"] not in ("branch", "line", "region"):
            _fail(f"{w}/metric", "a diff evaluation uses line, region, or branch")
    if integrity != 1:
        _fail("/policy/evaluations", "exactly one integrity evaluation")
    failing = any(e["result"] in ("fail", "ineligible") for e in p["evaluations"])
    if p["passed"] and failing:
        _fail("/policy/passed", "a failed or ineligible evaluation cannot pass")


def _check_changes(c: dict) -> None:
    """The changed-region capture (SPEC 22.3) as far as it decides itself."""
    for key in ("head", "merge_base", "reference"):
        if not RE_COMMIT.fullmatch(c["base"][key]):
            _fail(f"/changes/base/{key}", "a Git object name is 40 or 64 lowercase hex digits")
    if any(not 0x20 <= ord(ch) <= 0x7E for ch in c["git"]["version"]):
        _fail("/changes/git/version", "printable ASCII")
    try:
        check_logical_string(c["base"]["spelling"], "spelling", min_bytes=1, max_bytes=4096)
    except LogicalValueError as exc:
        _fail("/changes/base/spelling", exc.detail)
    for key in ("diff_sha256",):
        _shared(_ix._digest, c[key], f"/changes/{key}")
    _shared(_ix._digest, c["git"]["executable_sha256"], "/changes/git/executable_sha256")
    _shared(_ix._sorted_unique, [s["source_index"] for s in c["sources"]], "/changes/sources")
    for n, s in enumerate(c["sources"]):
        w = f"/changes/sources/{n}"
        _shared(_ix._digest, s["sha256"], f"{w}/sha256")
        _shared(_ix._sorted_unique, s["changed_lines"], f"{w}/changed_lines")
        for key in ("repo_path", "old_path"):
            if s[key] is not None:
                try:
                    check_logical_string(s[key], key, min_bytes=1, max_bytes=4096)
                except LogicalValueError as exc:
                    _fail(f"{w}/{key}", exc.detail)
        if (s["old_path"] is not None) != (s["state"] == "renamed"):
            _fail(f"{w}/old_path", "an old path is present exactly for a renamed source")
        if s["state"] == "unchanged" and s["changed_lines"]:
            _fail(f"{w}/changed_lines", "an unchanged source has no changed line")
    if c["clean"] != (not any(s["staged"] or s["unstaged"] for s in c["sources"])):
        _fail("/changes/clean", "clean exactly when no source has a staged or unstaged change")


def _check_ratchet(t: dict) -> None:
    """The ratchet record (SPEC 22.4) as far as it decides itself."""
    for key in ("head",):
        if t[key] is not None and not RE_COMMIT.fullmatch(t[key]):
            _fail(f"/ratchet/{key}", "a Git object name is 40 or 64 lowercase hex digits")
    if t["baseline_sha256"] is not None:
        _shared(_ix._digest, t["baseline_sha256"], "/ratchet/baseline_sha256")
    b = t["baseline"]
    if b is not None:
        if b["commit"] is not None and not RE_COMMIT.fullmatch(b["commit"]):
            _fail("/ratchet/baseline/commit", "a Git object name is 40 or 64 lowercase hex digits")
        if any(not 0x20 <= ord(ch) <= 0x7E for ch in b["metric_schema"]):
            _fail("/ratchet/baseline/metric_schema", "printable ASCII")
        if any(not 0x21 <= ord(ch) <= 0x7E for ch in b["tool_version"]):
            _fail("/ratchet/baseline/tool_version", "each byte is ASCII 0x21 through 0x7e")
        for m in METRICS:
            if b["metrics"][m]["covered"] > b["metrics"][m]["total"]:
                _fail(f"/ratchet/baseline/metrics/{m}", "covered is at most total")
    for key, paths in (("baseline/sources", [] if b is None else b["sources"]), ("sources_added", t["sources_added"]),
                       ("sources_removed", t["sources_removed"])):
        for n, path in enumerate(paths):
            try:
                check_logical_path(path, f"/ratchet/{key}/{n}")
            except LogicalValueError as exc:
                _fail(f"/ratchet/{key}/{n}", exc.detail)
        _shared(_ix._sorted_unique, [x.encode() for x in paths], f"/ratchet/{key}")
    if set(t["sources_added"]) & set(t["sources_removed"]):
        _fail("/ratchet/sources_added", "a source is not both added and removed")
    metrics = [c["metric"] for c in t["comparisons"]]
    if metrics not in ([], list(METRICS)):
        _fail("/ratchet/comparisons", "none, or one for each metric in order")
    for n, c in enumerate(t["comparisons"]):
        _shared(_ix._sorted_unique, c["outcomes"], f"/ratchet/comparisons/{n}/outcomes")
    usable = t["state"] in ("ok", "stale", "incompatible")
    if (b is not None) != usable:
        _fail("/ratchet/baseline", "a decoded baseline is present exactly for the ok, stale and incompatible states")
    if (t["baseline_sha256"] is None) != (t["state"] == "missing"):
        _fail("/ratchet/baseline_sha256", "a file digest is absent exactly for a missing baseline")
    if t["state"] != "ok" and (t["comparisons"] or t["sources_added"] or t["sources_removed"]):
        _fail("/ratchet/comparisons", "only a usable baseline is compared")
    if t["state"] == "ok" and not t["comparisons"]:
        _fail("/ratchet/comparisons", "a usable baseline is compared on every metric")
    if t["state"] == "stale" and b["commit"] is None:
        _fail("/ratchet/state", "only a baseline made at a commit can be stale")


def _check_provenance(v: dict) -> None:
    for key in ("indexed_diagnostic_registry_sha256", "indexed_input_sha256", "semantic_projection_sha256"):
        _shared(_ix._digest, v[key], f"/provenance/{key}")
    _shared(_ix._digests, v["map_ids"], "/provenance/map_ids")
    for n, r in enumerate(v["run_ids"]):
        _shared(_ix._identity, r, f"/provenance/run_ids/{n}")
    _shared(_ix._sorted_unique, v["run_ids"], "/provenance/run_ids")
    _shared(_ix._sorted_unique, v["backends"], "/provenance/backends")
    if v["run_manifest_sha256"] is not None:
        _shared(_ix._digest, v["run_manifest_sha256"], "/provenance/run_manifest_sha256")
    if (v["run_manifest_sha256"] is not None) != (v["run_selection"] == "manifest"):
        _fail("/provenance/run_manifest_sha256", "a manifest digest is present exactly for manifest selection")
    if v["run_selection"] == "none" and v["run_ids"]:
        _fail("/provenance/run_ids", "no run set exists when selection is none")
    status, code, signal = v["execution_status"], v["execution_exit_code"], v["execution_signal"]
    want = {"not_applicable": (False, False), "passed": (True, False), "failed": (True, False), "signaled": (False, True)}[status]
    if (code is not None, signal is not None) != want:
        _fail("/provenance/execution_status", f"status {status} fixes which of the exit code and signal are null")
    if (status == "passed" and code != 0) or (status == "failed" and code == 0):
        _fail("/provenance/execution_exit_code", "passed is exit code 0 and failed is 1..255")


def _check_report(o: dict) -> None:
    # Everything the shared records already require in indexed evidence.
    shared = {k: o[k] for k in ("contexts", "sources", "entities", "points", "regions", "lines", "branches", "contracts", "exclusions",
                                "saturation")}
    _shared(_ix._check_semantic, {**shared, "diagnostics": [], "map_ids": []}, "")
    for n, r in enumerate(o["inputs"]):
        w = f"/inputs/{n}"
        _shared(_ix._check_input, r, w, ("artifact_sha256", "backend", "context_index", "map_id", "profile_id", "run_id"))
        for key in ("profile_id", "run_id"):
            if r[key] is not None:
                _shared(_ix._identity, r[key], f"{w}/{key}")

    tool = o["tool"]
    _shared(_ix._digest, tool["diagnostic_registry_sha256"], "/tool/diagnostic_registry_sha256")
    if any(not 0x21 <= ord(ch) <= 0x7E for ch in tool["version"]):
        _fail("/tool/version", "each byte is ASCII 0x21 through 0x7e")

    _metric_set(o["summary"], METRICS, "/summary")
    for n, s in enumerate(o["sources"]):
        w = f"/sources/{n}"
        _metric_set(s["summary"], METRICS, f"{w}/summary")
        if s["observed_digest"] is not None:
            _shared(_ix._digest, s["observed_digest"], f"{w}/observed_digest")
        state, same = s["source_state"], s["observed_digest"] == s["digest"]
        if (state == "current" and not same) or (state == "mismatch" and (same or s["observed_digest"] is None)) or \
                (state == "unavailable" and s["observed_digest"] is not None):
            _fail(f"{w}/source_state", "current is equal digests, mismatch unequal ones, unavailable no observed digest")
    for n, e in enumerate(o["entities"]):
        _metric_set(e["summary"], METRICS if e["kind"] == "function" else ("contract",), f"/entities/{n}/summary")
    for n, m in enumerate(o["maps"]):
        w = f"/maps/{n}"
        _shared(_ix._digest, m["map_id"], f"{w}/map_id")
        if not m["compiler_identity"].isascii() or any(ord(ch) not in _ix.PRINTABLE for ch in m["compiler_identity"]):
            _fail(f"{w}/compiler_identity", "not printable ASCII without whitespace")
        try:
            check_logical_string(m["target"]["name"], "name", min_bytes=1, max_bytes=1024)
        except LogicalValueError as exc:
            _fail(f"{w}/target/name", exc.detail)
        _shared(_ix._sorted_unique, m["source_indices"], f"{w}/source_indices")
    for n, r in enumerate(o["regions"]):
        if r["point_ids"] != sorted({t["point_id"] for t in r["counter_expression"]["terms"]}):
            _fail(f"/regions/{n}/point_ids", "exactly the points its expression names, sorted")
    for n, x in enumerate(o["exclusions"]):
        _shared(_ix._sorted_unique, x["affected"]["line_indices"], f"/exclusions/{n}/affected/line_indices")

    _check_policy(o["policy"])
    _check_provenance(o["provenance"])
    if o["changes"] is not None:
        _check_changes(o["changes"])
    if o["ratchet"] is not None:
        _check_ratchet(o["ratchet"])
    if (o["ratchet"] is None) != (o["resolved_configuration"]["coverage"]["ratchet"] is None):
        _fail("/ratchet", "a ratchet record is present exactly when a ratchet policy is configured")
    if (o["changes"] is None) != (o["resolved_configuration"]["coverage"]["diff"] is None):
        _fail("/changes", "a changed-region capture is present exactly when a diff policy is configured")
    _check_configuration(o["resolved_configuration"], "/resolved_configuration")

    if (o["evidence_eligibility"] == "incomplete") != (not o["complete"]):
        _fail("/evidence_eligibility", "incomplete exactly when complete is false")
    if o["evidence_eligibility"] == "passing" and (not o["policy"]["passed"] or o["provenance"]["source_accuracy"] != "current"):
        _fail("/evidence_eligibility", "passing needs a passed policy and current sources")
    if o["evidence_eligibility"] == "policy_failed" and o["policy"]["passed"]:
        _fail("/evidence_eligibility", "policy_failed needs a failed policy")
    stale = any(s["source_state"] != "current" for s in o["sources"])
    if (o["provenance"]["source_accuracy"] == "mismatch_allowed") != stale:
        _fail("/provenance/source_accuracy", "mismatch_allowed exactly when a source is not current")
    if o["saturation"]["policy"] != o["resolved_configuration"]["coverage"]["integrity"]["saturation"]["value"]:
        _fail("/saturation/policy", "the saturation policy is the resolved one")


def check_report_structure(obj: object) -> dict:
    """Schema and record-level rules of a decoded report."""
    try:
        _report_schema.validate(obj)
    except StructuralError as exc:
        raise ReportError("COV4001", str(exc)) from exc
    assert isinstance(obj, dict)
    _check_report(obj)
    return obj


def decode_report_structure(data: bytes, *, tier: str = "standard") -> dict:
    """Canonical report bytes -> a well-formed report (not yet cross-validated;
    see the module docstring). ``tier`` is the reader's size tier."""
    try:
        obj = decode_canonical(data, map_limits(tier))
    except CanonicalJsonError as exc:
        if exc.reason == "size_limit":
            raise ReportError("COV6001", f"the report is {len(data)} bytes; the {tier} tier allows {map_limits(tier).max_bytes}") from exc
        raise ReportError("COV4001", str(exc)) from exc
    return check_report_structure(obj)
