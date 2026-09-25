# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Doctor result 1.0 and the fixed probe registry (SPEC 20.7).

This slice freezes the protocol: the eighteen probes, their applicability,
direct prerequisites, and exact pass facts; how skips, the summary, the
status, and the diagnostics are derived; and the closed, self-hashed
aggregate. The probes themselves are implemented later (CV-235, CV-242).

Interpretations recorded here:

- ``D016`` (VM-v2 smoke) is ``not_applicable`` in toolchain mode while the
  embedded version manifest does not advertise ``vm-v2`` (SPEC 15.6).
- Each failed probe's diagnostic uses phase ``execution`` and the single
  fact ``probe_id``.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from sv0cov._generated.validators import sv0cov_doctor_1_0 as _schema
from sv0cov.diagnostics import Diagnostic, DiagnosticError, Registry, load_registry, order_events, validate_record
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.compatibility import PolicyError, check_policy_object
from sv0cov.formats.structural import StructuralError
from sv0cov.formats.version_manifest import ManifestError, check_manifest_object

MAX_BYTES = 262144
FIXTURE_ID = "doctor-r1-smoke"
RE_DIGEST = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class Probe:
    id: str
    title: str
    toolchain_only: bool
    prerequisites: tuple[str, ...]
    pass_facts: tuple[str, ...]


PROBES = (
    Probe("D001", "Version-manifest integrity", False, (), ("manifest_sha256",)),
    Probe("D002", "Diagnostic-registry integrity", False, (), ("registry_revision", "registry_sha256")),
    Probe("D003", "Installed schema-bundle integrity", False, ("D001",), ("validated_schema_count",)),
    Probe("D004", "Installed logical package layout", False, ("D001",), ("validated_member_count",)),
    Probe("D005", "Current host support", False, ("D001",), ("host",)),
    Probe("D006", "Active implementation and runtime identity", False, ("D001",), ("language", "runtime_name", "runtime_version")),
    Probe("D007", "Private temporary storage and cleanup", False, (), ()),
    Probe("D008", "Packaged C runtime-source integrity", False, ("D004",), ("validated_member_count",)),
    Probe("D009", "Root compatibility-policy integrity", True, (), ("compatibility_sha256",)),
    Probe("D010", ".gitmodules, gitlink, and submodule state", True, ("D009",), ("expected_revision",)),
    Probe("D011", "Cross-component diagnostic-registry alignment", True, ("D002", "D009", "D010"), ("registry_revision", "registry_sha256")),
    Probe("D012", "Root compatibility evaluation", True, ("D001", "D005", "D006", "D009", "D010", "D011"), ("compatibility_sha256", "manifest_sha256")),
    Probe("D013", "sv0c coverage-map smoke", True, ("D003", "D004", "D007", "D010", "D012"), ("fixture_id", "map_id")),
    Probe("D014", "Generated-C collection smoke", True, ("D007", "D008", "D013"), ("fixture_id", "semantic_projection_sha256")),
    Probe("D015", "VM-v1 collection smoke", True, ("D007", "D013"), ("fixture_id", "semantic_projection_sha256")),
    Probe("D016", "VM-v2 collection smoke", True, ("D007", "D013"), ("fixture_id", "semantic_projection_sha256")),
    Probe("D017", "Three-backend semantic parity", True, ("D014", "D015", "D016"), ("fixture_id", "semantic_projection_sha256")),
    Probe("D018", "Merge, native-report, and check smoke", True, ("D014", "D015", "D016", "D017"), ("fixture_id", "native_report_sha256")),
)
BY_ID = {p.id: p for p in PROBES}


class DoctorError(ValueError):
    """An invalid aggregate, or one that cannot be constructed (exit 8)."""


def applicable(probe: Probe, mode: str, manifest: dict) -> bool:
    if mode == "standalone":
        return not probe.toolchain_only
    if probe.id == "D016" and "vm-v2" not in manifest["backends"]:
        return False
    return True


def doctor_digest(obj: dict) -> str:
    return hashlib.sha256(encode({k: v for k, v in obj.items() if k != "doctor_sha256"})).hexdigest()


def build(
    *,
    mode: str,
    manifest: dict,
    policy: dict | None,
    toolchain: dict | None,
    results: dict[str, tuple],
    registry: Registry | None = None,
) -> bytes:
    """Assemble and validate an aggregate.

    ``results`` maps each applicable, non-skipped probe ID to
    ``("pass", {fact: value})`` or ``("fail", "COVxxxx")``. Probes whose
    direct prerequisites failed or were skipped are skipped automatically
    and must not appear in ``results``.
    """
    reg = registry or load_registry()
    probes, failed, events = [], [], []
    status_of: dict[str, str] = {}
    for probe in PROBES:
        record = {"blocked_by": [], "diagnostic_code": None, "facts": [], "id": probe.id, "status": "not_applicable"}
        if applicable(probe, mode, manifest):
            blocked = [p for p in probe.prerequisites if status_of.get(p) in ("fail", "skipped")]
            if blocked:
                record.update(status="skipped", blocked_by=blocked)
                if probe.id in results:
                    raise DoctorError(f"{probe.id} was skipped by prerequisites but has a result")
            else:
                if probe.id not in results:
                    raise DoctorError(f"{probe.id} is applicable but has no result")
                outcome, detail = results[probe.id]
                if outcome == "pass":
                    record.update(status="pass", facts=[{"name": k, "value": detail[k]} for k in sorted(detail)])
                elif outcome == "fail":
                    record.update(status="fail", diagnostic_code=detail)
                    failed.append(probe.id)
                    events.append(Diagnostic(detail, "execution", facts=(("probe_id", probe.id),)))
                else:
                    raise DoctorError(f"{probe.id}: unknown outcome {outcome!r}")
        status_of[probe.id] = record["status"]
        probes.append(record)
    counts = {s: sum(1 for p in probes if p["status"] == s) for s in ("pass", "fail", "not_applicable", "skipped")}
    body = {
        "compatibility_policy": policy,
        "diagnostics": order_events(events, reg),
        "mode": mode,
        "probes": probes,
        "schema": "sv0cov.doctor",
        "status": "pass" if counts["fail"] == 0 and counts["skipped"] == 0 else "fail",
        "summary": {
            "failed": counts["fail"],
            "not_applicable": counts["not_applicable"],
            "passed": counts["pass"],
            "skipped": counts["skipped"],
            "total": len(PROBES),
        },
        "toolchain": toolchain,
        "version": "1.0",
        "version_manifest": manifest,
    }
    body["doctor_sha256"] = doctor_digest(body)
    data = encode(body)
    validate(data, registry=reg)
    return data


def _fail(detail: str) -> None:
    raise DoctorError(detail)


def _check_facts(probe: Probe, facts: list[dict], obj: dict) -> None:
    names = [f["name"] for f in facts]
    if names != sorted(probe.pass_facts):
        _fail(f"{probe.id}: pass facts must be exactly {sorted(probe.pass_facts)}")
    values = {f["name"]: f["value"] for f in facts}
    m = obj["version_manifest"]
    expected = {
        "manifest_sha256": m["manifest_sha256"],
        "host": f"{m['host']['operating_system']}-{m['host']['architecture']}",
        "language": m["implementation"]["language"],
        "runtime_name": m["implementation"]["runtime"]["name"],
        "runtime_version": m["implementation"]["runtime"]["version"],
        "fixture_id": FIXTURE_ID,
    }
    if probe.id == "D002":
        expected.update(registry_revision=m["diagnostic_registry"]["revision"], registry_sha256=m["diagnostic_registry"]["sha256"])
    if obj["compatibility_policy"] is not None:
        policy = obj["compatibility_policy"]
        expected.update(compatibility_sha256=policy["compatibility_sha256"], expected_revision=policy["expected_revision"])
        if probe.id == "D011":
            reg = policy["allowed_diagnostic_registries"][0]
            expected.update(registry_revision=reg["revision"], registry_sha256=reg["sha256"])
    for name, value in values.items():
        if name in expected and value != expected[name]:
            _fail(f"{probe.id}: fact {name} disagrees with the embedded objects")
        if name.endswith("_count") and not (isinstance(value, int) and not isinstance(value, bool) and value > 0):
            _fail(f"{probe.id}: {name} must be a positive integer")
        if name.endswith("_sha256") or name == "map_id":
            if not (isinstance(value, str) and RE_DIGEST.fullmatch(value)):
                _fail(f"{probe.id}: {name} must be a lowercase SHA-256")


def validate(data: bytes, *, registry: Registry | None = None) -> dict:
    """Validate a complete aggregate (SPEC 20.7). Raises :class:`DoctorError`."""
    reg = registry or load_registry()
    if len(data) > MAX_BYTES:
        _fail(f"aggregate exceeds {MAX_BYTES} bytes")
    try:
        obj = decode_canonical(data)
        _schema.validate(obj)
    except (CanonicalJsonError, StructuralError) as exc:
        raise DoctorError(str(exc)) from exc
    try:
        check_manifest_object(obj["version_manifest"])
    except ManifestError as exc:
        raise DoctorError(f"embedded version manifest: {exc}") from exc
    mode, policy, toolchain = obj["mode"], obj["compatibility_policy"], obj["toolchain"]
    if mode == "standalone" and (policy is not None or toolchain is not None):
        _fail("standalone mode has no compatibility policy or toolchain record")
    if mode == "toolchain" and toolchain is None:
        _fail("toolchain mode requires the toolchain record")
    if policy is not None:
        try:
            check_policy_object(policy)
        except PolicyError as exc:
            raise DoctorError(f"embedded compatibility policy: {exc}") from exc
    if toolchain is not None:
        for side in ("root", "submodule"):
            rev, tree = toolchain[f"{side}_revision"], toolchain[f"{side}_worktree"]
            if (rev is None) != (tree == "unavailable"):
                _fail(f"{side}_revision is null exactly when its worktree is unavailable")
            if rev is not None and not re.fullmatch(r"[0-9a-f]{40}", rev):
                _fail(f"{side}_revision must be a lowercase 40-hex commit")

    probes = obj["probes"]
    if [p["id"] for p in probes] != [p.id for p in PROBES]:
        _fail("probes must be exactly D001..D018 in registry order")
    status_of: dict[str, str] = {}
    failed = []
    for record, probe in zip(probes, PROBES):
        status = record["status"]
        blocked = [p for p in probe.prerequisites if status_of.get(p) in ("fail", "skipped")]
        if not applicable(probe, mode, obj["version_manifest"]):
            if status != "not_applicable":
                _fail(f"{probe.id} must be not_applicable in {mode} mode")
        elif blocked:
            if status != "skipped" or record["blocked_by"] != blocked:
                _fail(f"{probe.id} must be skipped, blocked by {blocked}")
        elif status not in ("pass", "fail"):
            _fail(f"{probe.id} is applicable and unblocked, so it must pass or fail")
        if status != "skipped" and record["blocked_by"]:
            _fail(f"{probe.id}: blocked_by is only for skipped probes")
        if (status == "fail") != (record["diagnostic_code"] is not None):
            _fail(f"{probe.id}: diagnostic_code is set exactly for a failed probe")
        if status == "fail":
            try:
                reg.entry(record["diagnostic_code"])
            except DiagnosticError as exc:
                raise DoctorError(str(exc)) from exc
            failed.append(record)
        if status == "pass":
            _check_facts(probe, record["facts"], obj)
        elif record["facts"]:
            _fail(f"{probe.id}: facts are only for passed probes")
        status_of[probe.id] = status
    for bootstrap in ("D001", "D002"):
        if status_of[bootstrap] != "pass":
            _fail(f"{bootstrap} must pass in every complete aggregate")
    if mode == "toolchain" and policy is None and status_of["D009"] != "fail":
        _fail("a toolchain aggregate without a validated policy must fail D009")

    diagnostics = obj["diagnostics"]
    for d in diagnostics:
        try:
            validate_record(d, reg)
        except DiagnosticError as exc:
            raise DoctorError(str(exc)) from exc
    expected = order_events(
        (Diagnostic(r["diagnostic_code"], "execution", facts=(("probe_id", r["id"]),)) for r in failed), reg
    )
    if diagnostics != expected:
        _fail("diagnostics must be exactly one ordered record per failed probe")

    counts = {s: sum(1 for p in probes if p["status"] == s) for s in ("pass", "fail", "not_applicable", "skipped")}
    summary = {"failed": counts["fail"], "not_applicable": counts["not_applicable"], "passed": counts["pass"], "skipped": counts["skipped"], "total": 18}
    if obj["summary"] != summary:
        _fail("summary does not match the probes")
    if obj["status"] != ("pass" if counts["fail"] == 0 and counts["skipped"] == 0 else "fail"):
        _fail("status does not match the probes")
    if not RE_DIGEST.fullmatch(obj["doctor_sha256"]) or doctor_digest(obj) != obj["doctor_sha256"]:
        _fail("doctor_sha256 does not match the aggregate")
    return obj
