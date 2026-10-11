# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Closed indexed evidence 1.0: schemas and record-level rules (SPEC 16.5).

``sv0cov.indexed`` 1.0 is the self-contained merge result; it embeds one
``sv0cov.indexed-semantic`` 1.0 object and names the SHA-256 of that
object's standalone canonical serialization (the semantic projection).

This module is the first of two validation layers (CV-220):

1. canonical bytes (SPEC 16.2) and the generated closed-schema validators:
   exact property sets, types, enumerations, integer and length bounds;
2. what one record decides by itself: lexical forms (digests, stable codes,
   run and profile identities, basenames, byte bounds), scalar-array order,
   and the null/value rules a record's own status, mode, kind, or
   enforcement fixes (SPEC 16.5.1-16.5.5, 21.3.1-21.3.5, 21.3.8);
3. the projection digest (SPEC 16.5.6).

A document that passes is well formed. It is not yet accepted evidence: the
rules that relate records to each other (references, array order and index
positions, binding coverage, recomputed counts, statuses, line membership,
saturation inventories, completeness) belong to the indexed reader's
cross-validation (CV-222), which starts from these functions.

Failures raise :class:`IndexedError`: ``COV3010`` invalid indexed evidence,
``COV3011`` semantic projection mismatch.
"""

from __future__ import annotations

import hashlib
import re

from sv0cov._generated.validators import sv0cov_indexed_1_0 as _indexed_schema
from sv0cov._generated.validators import sv0cov_indexed_semantic_1_0 as _semantic_schema
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.structural import StructuralError
from sv0cov.model.logical import LogicalValueError, check_logical_path, check_logical_string

RE_DIGEST = re.compile(r"[0-9a-f]{64}")
RE_CODE = re.compile(r"COV[0-9]{4}")
RE_IDENTITY = re.compile(r"[0-9a-f]{32}")
ZERO_IDENTITY = "0" * 32
UINT64_MAX = 2**64 - 1
#: tier -> (max_counters, max_bytes), SPEC 16.4. ``custom`` is bounded by the schema.
TIERS = {"standard": (4194304, 67108864), "large": (16777216, 268435456)}
ELIGIBLE_METRICS = ["branch", "function", "line", "region"]
PRINTABLE = frozenset(range(0x21, 0x7F))


class IndexedError(ValueError):
    """``code``: COV3010 invalid indexed evidence, COV3011 projection mismatch."""

    def __init__(self, code: str, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _fail(where: str, detail: str) -> None:
    raise IndexedError("COV3010", f"{where}: {detail}")


# ── scalars ─────────────────────────────────────────────────────────────────


def _digest(v: str, where: str) -> None:
    if not RE_DIGEST.fullmatch(v):
        _fail(where, "not 64 lowercase hexadecimal characters")


def _identity(v: str, where: str) -> None:
    if not RE_IDENTITY.fullmatch(v) or v == ZERO_IDENTITY:
        _fail(where, "not a nonzero identity of 32 lowercase hexadecimal characters")


def _utf8_len(v: str, where: str) -> int:
    """Byte length of a string that must be encodable (no lone surrogate)."""
    try:
        return len(v.encode("utf-8"))
    except UnicodeEncodeError:
        _fail(where, "not valid UTF-8")
        raise AssertionError("unreachable") from None


def _logical(v: str, where: str, *, min_bytes: int = 0, max_bytes: int = 4096) -> None:
    try:
        check_logical_string(v, where, min_bytes=min_bytes, max_bytes=max_bytes)
    except LogicalValueError as exc:
        _fail(where, str(exc))


def _sorted_unique(values: list, where: str, key=lambda v: v) -> None:
    keys = [key(v) for v in values]
    if any(not a < b for a, b in zip(keys, keys[1:])):
        _fail(where, "not strictly ordered, or contains a duplicate")


def _codes(values: list[str], where: str) -> None:
    for n, c in enumerate(values):
        if not RE_CODE.fullmatch(c):
            _fail(f"{where}/{n}", "not a stable code (COV and four digits)")
    _sorted_unique(values, where, lambda c: c.encode("ascii"))


def _digests(values: list[str], where: str) -> None:
    for n, d in enumerate(values):
        _digest(d, f"{where}/{n}")
    _sorted_unique(values, where)


def _span(span: dict, where: str) -> None:
    if span["end_byte"] < span["start_byte"]:
        _fail(where, "the span ends before it starts")


def _count(rec: dict, where: str) -> None:
    """A count record's own rules (SPEC 21.3.1)."""
    for part, r in [(where, rec)] + [(f"{where}/by_context/{n}", c) for n, c in enumerate(rec["by_context"])]:
        if r["saturated"] != r["lower_bound"]:
            _fail(part, "saturated and lower_bound must be equal")
    for n, c in enumerate(rec["by_context"]):
        if c["value"] == 0 and not c["lower_bound"]:
            _fail(f"{where}/by_context/{n}", "an exact zero context count is omitted")
    _sorted_unique(rec["by_context"], f"{where}/by_context", lambda c: c["context_index"])
    if any(c["lower_bound"] for c in rec["by_context"]) and not rec["lower_bound"]:
        _fail(where, "an inexact context count makes the aggregate inexact")
    if not rec["lower_bound"] and rec["value"] != sum(c["value"] for c in rec["by_context"]):
        _fail(where, "an exact aggregate is the sum of its context counts")


def _is_zero(rec: dict) -> bool:
    return rec["value"] == 0


# ── the semantic object ─────────────────────────────────────────────────────


def _check_semantic(s: dict, at: str) -> None:
    _codes(s["diagnostics"], f"{at}/diagnostics")
    _digests(s["map_ids"], f"{at}/map_ids")
    for n, c in enumerate(s["contexts"]):
        if c["value"] is not None and _utf8_len(c["value"], f"{at}/contexts/{n}/value") > 256:
            _fail(f"{at}/contexts/{n}/value", "longer than 256 UTF-8 bytes")
    for n, r in enumerate(s["sources"]):
        w = f"{at}/sources/{n}"
        _digest(r["digest"], f"{w}/digest")
        try:
            check_logical_path(r["path"], f"{w}/path")
        except LogicalValueError as exc:
            _fail(f"{w}/path", str(exc))
        if r["package"] is not None:
            _logical(r["package"], f"{w}/package", min_bytes=1, max_bytes=1024)
    for n, r in enumerate(s["entities"]):
        w = f"{at}/entities/{n}"
        _logical(r["qualified_name"], f"{w}/qualified_name", min_bytes=1)
        _span(r["span"], f"{w}/span")
    for n, r in enumerate(s["points"]):
        w = f"{at}/points/{n}"
        _digest(r["point_id"], f"{w}/point_id")
        _logical(r["semantic_discriminator"], f"{w}/semantic_discriminator", min_bytes=1, max_bytes=256)
        _span(r["span"], f"{w}/span")
        _count(r["count"], f"{w}/count")
        if (r["outcome_ordinal"] is not None) != (r["kind"] == "branch_outcome"):
            _fail(f"{w}/outcome_ordinal", "an ordinal is present exactly for a branch_outcome point")
        if r["kind"] in ("contract_true", "contract_false") and r["entity_index"] is None:
            _fail(f"{w}/entity_index", "a contract point names its contract entity")
        if r["kind"] == "function_entry" and r["entity_index"] is None:
            _fail(f"{w}/entity_index", "a function_entry point names its function entity")
    for n, r in enumerate(s["regions"]):
        w = f"{at}/regions/{n}"
        _span(r["span"], f"{w}/span")
        _count(r["count"], f"{w}/count")
        terms = r["counter_expression"]["terms"]
        for k, t in enumerate(terms):
            _digest(t["point_id"], f"{w}/counter_expression/terms/{k}/point_id")
            if t["coefficient"] == 0:
                _fail(f"{w}/counter_expression/terms/{k}", "zero coefficient")
        _sorted_unique(terms, f"{w}/counter_expression/terms", lambda t: t["point_id"])
        _sorted_unique(r["line_numbers"], f"{w}/line_numbers")
    for n, r in enumerate(s["lines"]):
        _sorted_unique(r["region_indices"], f"{at}/lines/{n}/region_indices")
    for n, b in enumerate(s["branches"]):
        w = f"{at}/branches/{n}"
        _span(b["span"], f"{w}/span")
        for k, o in enumerate(b["outcomes"]):
            wo = f"{w}/outcomes/{k}"
            _digest(o["point_id"], f"{wo}/point_id")
            _logical(o["name"], f"{wo}/name", min_bytes=1, max_bytes=256)
            _count(o["count"], f"{wo}/count")
            if o["ordinal"] != k:
                _fail(f"{wo}/ordinal", "ordinals start at zero and equal their positions")
            if (o["evidence_identity"] is not None) != (o["status"] == "statically_unreachable"):
                _fail(f"{wo}/evidence_identity", "evidence is present exactly for a statically_unreachable outcome")
            if o["evidence_identity"] is not None:
                _logical(o["evidence_identity"], f"{wo}/evidence_identity", min_bytes=1)
            if o["status"] == "covered" and _is_zero(o["count"]):
                _fail(f"{wo}/status", "a covered outcome has a nonzero count")
            if o["status"] == "uncovered" and not _is_zero(o["count"]):
                _fail(f"{wo}/status", "an uncovered outcome has a zero count")
            if o["status"] in ("excluded", "statically_unreachable") and (not _is_zero(o["count"]) or o["count"]["by_context"]
                                                                          or o["count"]["lower_bound"]):
                _fail(f"{wo}/count", "an uncounted outcome has the exact zero count")
        if len(b["outcomes"]) < 2 and b["kind"] != "match":
            _fail(f"{w}/outcomes", "only a match may have a single outcome")
    for n, c in enumerate(s["contracts"]):
        w = f"{at}/contracts/{n}"
        _span(c["span"], f"{w}/span")
        runtime = c["enforcement"] == "runtime_checked"
        for side in ("count_true", "count_false"):
            if (c[side] is not None) != runtime:
                _fail(f"{w}/{side}", "counts are present exactly for a runtime_checked clause")
            if c[side] is not None:
                _count(c[side], f"{w}/{side}")
        if (c["evidence_identity"] is not None) != (c["enforcement"] == "statically_verified"):
            _fail(f"{w}/evidence_identity", "evidence is present exactly for a statically_verified clause")
        if c["evidence_identity"] is not None:
            _logical(c["evidence_identity"], f"{w}/evidence_identity", min_bytes=1)
        if runtime:
            t, f = not _is_zero(c["count_true"]), not _is_zero(c["count_false"])
            want = "mixed" if t and f else "evaluated_true" if t else "evaluated_false" if f else "not_evaluated"
        else:
            want = "not_applicable"
        if c["runtime_result"] != want:
            _fail(f"{w}/runtime_result", f"must be {want} for these counts and this enforcement")
    for n, x in enumerate(s["exclusions"]):
        w = f"{at}/exclusions/{n}"
        _span(x["span"], f"{w}/span")
        if not 1 <= _utf8_len(x["reason"], f"{w}/reason") <= 1024:
            _fail(f"{w}/reason", "not 1..1024 UTF-8 bytes")
        for key in ("branch_indices", "clause_indices", "entity_indices", "region_indices"):
            _sorted_unique(x["affected"][key], f"{w}/affected/{key}")
        _digests(x["affected"]["point_ids"], f"{w}/affected/point_ids")
    sat = s["saturation"]
    w = f"{at}/saturation"
    _digests(sat["affected_point_ids"], f"{w}/affected_point_ids")
    _sorted_unique(sat["affected_region_indices"], f"{w}/affected_region_indices")
    _sorted_unique(sat["ineligible_uses"], f"{w}/ineligible_uses")
    if sat["any"] != bool(sat["affected_point_ids"] or sat["affected_region_indices"]):
        _fail(f"{w}/any", "true exactly when a point or region is affected")
    eligible = ELIGIBLE_METRICS if sat["any"] and sat["policy"] == "allow-ordinary" else []
    if sat["eligible_metrics"] != eligible:
        _fail(f"{w}/eligible_metrics", f"must be {eligible} for this policy and saturation state")
    if not sat["any"] and sat["ineligible_uses"]:
        _fail(f"{w}/ineligible_uses", "empty when nothing saturated")


# ── the full object ─────────────────────────────────────────────────────────


def _check_basename(name: str, where: str) -> None:
    if not 1 <= _utf8_len(name, where) <= 255 or any(ch in name for ch in ("\x00", "/", "\\")):
        _fail(where, "not a basename of 1..255 UTF-8 bytes without NUL, slash, or backslash")


def _check_input(r: dict, where: str, non_null: tuple[str, ...]) -> None:
    _check_basename(r["name"], f"{where}/name")
    _codes(r["diagnostics"], f"{where}/diagnostics")
    for key in ("artifact_sha256", "map_id"):
        if r[key] is not None:
            _digest(r[key], f"{where}/{key}")
    if r["status"] == "accepted":
        if r["diagnostics"]:
            _fail(f"{where}/diagnostics", "an accepted input has no diagnostic")
        for key in non_null:
            if r[key] is None:
                _fail(f"{where}/{key}", "an accepted input names this value")
    elif not r["diagnostics"]:
        _fail(f"{where}/diagnostics", f"a {r['status']} input has at least one diagnostic")


def _check_full(o: dict) -> None:
    _codes(o["diagnostics"], "/diagnostics")
    _digest(o["semantic_projection_sha256"], "/semantic_projection_sha256")

    e = o["execution"]
    want = {"not_applicable": (False, False), "passed": (True, False), "failed": (True, False), "signaled": (False, True)}[e["status"]]
    if (e["exit_code"] is not None, e["signal"] is not None) != want:
        _fail("/execution", f"status {e['status']} fixes which of exit_code and signal are null")
    if e["status"] == "passed" and e["exit_code"] != 0:
        _fail("/execution/exit_code", "a passed execution has exit code 0")
    if e["status"] == "failed" and e["exit_code"] == 0:
        _fail("/execution/exit_code", "a failed execution has an exit code in 1..255")

    m = o["merge"]
    _digest(m["tool"]["diagnostic_registry_sha256"], "/merge/tool/diagnostic_registry_sha256")
    _logical(m["tool"]["version"], "/merge/tool/version", min_bytes=1, max_bytes=128)
    lim = m["limits"]
    if lim["tier"] in TIERS and (lim["max_counters"], lim["max_bytes"]) != TIERS[lim["tier"]]:
        _fail("/merge/limits", f"the {lim['tier']} tier has fixed ceilings {TIERS[lim['tier']]}")

    for n, r in enumerate(o["map_inputs"]):
        _check_input(r, f"/map_inputs/{n}", ("artifact_sha256", "map_id"))
    for n, r in enumerate(o["profile_inputs"]):
        w = f"/profile_inputs/{n}"
        _check_input(r, w, ("artifact_sha256", "backend", "context_index", "map_id", "profile_id", "run_id"))
        for key in ("profile_id", "run_id"):
            if r[key] is not None:
                _identity(r[key], f"{w}/{key}")

    for n, b in enumerate(o["maps"]):
        w = f"/maps/{n}"
        _digest(b["map_id"], f"{w}/map_id")
        ident = b["compiler_identity"]
        if not ident.isascii() or any(ord(ch) not in PRINTABLE for ch in ident):
            _fail(f"{w}/compiler_identity", "not printable ASCII without whitespace")
        _logical(b["target"]["name"], f"{w}/target/name", min_bytes=1, max_bytes=1024)
        _sorted_unique(b["source_indices"], f"{w}/source_indices")
        if len(b["bindings"]) != b["program_counter_count"]:
            _fail(f"{w}/bindings", "one binding per counter of the map")
        for k, x in enumerate(b["bindings"]):
            if x["counter_index"] != k:
                _fail(f"{w}/bindings/{k}/counter_index", "counter indexes start at zero and equal their positions")
            _digest(x["point_id"], f"{w}/bindings/{k}/point_id")

    rs = o["run_selection"]
    for key in ("requested_run_ids", "selected_run_ids"):
        for n, v in enumerate(rs[key]):
            _identity(v, f"/run_selection/{key}/{n}")
        _sorted_unique(rs[key], f"/run_selection/{key}")
    if rs["manifest_sha256"] is not None:
        _digest(rs["manifest_sha256"], "/run_selection/manifest_sha256")
    mode = rs["mode"]
    if (rs["manifest_sha256"] is not None) != (mode == "manifest"):
        _fail("/run_selection/manifest_sha256", "a manifest digest is present exactly in manifest mode")
    if mode in ("explicit-list", "manifest") and not rs["requested_run_ids"]:
        _fail("/run_selection/requested_run_ids", f"{mode} mode has a nonempty requested set")
    if mode in ("implicit-single", "none") and rs["requested_run_ids"]:
        _fail("/run_selection/requested_run_ids", f"{mode} mode has an empty requested set")
    if mode == "none" and rs["selected_run_ids"]:
        _fail("/run_selection/selected_run_ids", "none mode has an empty selected set")


# ── entry points ────────────────────────────────────────────────────────────


def semantic_projection(semantic: dict) -> bytes:
    """Standalone canonical bytes of an embedded semantic object (SPEC 16.5.6)."""
    return encode(semantic)


def projection_sha256(semantic: dict) -> str:
    return hashlib.sha256(semantic_projection(semantic)).hexdigest()


def check_semantic_structure(obj: object) -> dict:
    """Schema and record-level rules of a decoded semantic object."""
    try:
        _semantic_schema.validate(obj)
    except StructuralError as exc:
        raise IndexedError("COV3010", str(exc)) from exc
    assert isinstance(obj, dict)
    _check_semantic(obj, "")
    return obj


def check_indexed_structure(obj: object) -> dict:
    """Schema, record-level rules, and projection digest of a decoded indexed object."""
    try:
        _indexed_schema.validate(obj)
    except StructuralError as exc:
        raise IndexedError("COV3010", str(exc)) from exc
    assert isinstance(obj, dict)
    _check_semantic(obj["semantic"], "/semantic")
    _check_full(obj)
    if projection_sha256(obj["semantic"]) != obj["semantic_projection_sha256"]:
        raise IndexedError("COV3011", "semantic_projection_sha256 is not the digest of the embedded semantic object's canonical bytes")
    return obj


def _decode(data: bytes) -> object:
    try:
        return decode_canonical(data)
    except CanonicalJsonError as exc:
        raise IndexedError("COV3010", str(exc)) from exc


def decode_semantic_structure(data: bytes) -> dict:
    """Canonical semantic-projection bytes -> a well-formed semantic object."""
    return check_semantic_structure(_decode(data))


def decode_indexed_structure(data: bytes) -> dict:
    """Canonical indexed bytes -> a well-formed indexed object (not yet
    cross-validated; see the module docstring)."""
    return check_indexed_structure(_decode(data))
