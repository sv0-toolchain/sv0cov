# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The doctor probe engine and the standalone probes D001 to D008 (CV-235,
CV-242; SPEC 20.7; COV-CLI-011).

:func:`run` executes the eight probes that check the installed sv0cov
product itself and, given a toolchain root, the toolchain probes D009 to
D018 of :mod:`sv0cov.toolchain`; it runs each applicable probe in registry
order unless a direct prerequisite failed or was skipped, and assembles the
closed ``sv0cov.doctor`` 1.0 aggregate (:mod:`sv0cov.formats.doctor`).
Without a root, D009 to D018 are ``not_applicable``.

Every probe checks fixed logical members, never a directory listing, so the
counts are the same for a source checkout and an installed wheel:

- D001: the version manifest of the running build is constructed and passes
  its own validator.
- D002: the diagnostic registry is canonical and self-consistent.
- D003: each schema of :data:`SCHEMAS` is present, is a JSON object for
  draft 2020-12 named by its file, and has the exact bytes its generated
  validator was made from.
- D004: each member of :data:`MODULES` and of the resource inventory is a
  regular file.
- D005: the effective host is the manifest's and is supported.
- D006: the interpreter is the manifest's CPython of a supported line, and
  ``sv0cov`` is imported from the package the resources were found beside.
- D007: a private directory can be made with mode ``0700``, written, read
  and emptied.
- D008: the C runtime sources are present with the exact bytes of
  :data:`RUNTIME_SHA256`.

D001 and D002 are bootstrap probes: if either cannot pass there is no
trustworthy aggregate, and :class:`Bootstrap` is raised instead (exit 8).
Nothing a probe observes is serialized except the facts SPEC 20.7 names: no
path, time or environment value.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import sv0cov
from sv0cov import capabilities
from sv0cov.diagnostics import Registry, RegistryError, load_registry
from sv0cov.formats import doctor
from sv0cov.formats.version_manifest import ManifestError, build, current_host, validate_manifest

SCHEMAS = (
    "sv0cov.baseline-1.0.schema.json", "sv0cov.compatibility-1.0.schema.json", "sv0cov.diagnostic-1.0.schema.json", "sv0cov.diagnostic-registry-1.0.schema.json",
    "sv0cov.doctor-1.0.schema.json", "sv0cov.export-manifest-1.0.schema.json", "sv0cov.indexed-1.0.schema.json", "sv0cov.indexed-semantic-1.0.schema.json",
    "sv0cov.map-1.0.schema.json", "sv0cov.release-manifest-1.0.schema.json", "sv0cov.report-1.0.schema.json",
    "sv0cov.resolved-configuration-1.0.schema.json", "sv0cov.run-set-1.0.schema.json", "sv0cov.version-1.0.schema.json",
    "sv0cov.vm-binding-1.0.schema.json",
)
#: Every module of the import package, as installed logical paths.
MODULES = (
    "sv0cov/__init__.py", "sv0cov/_generated/__init__.py", "sv0cov/_generated/validators/__init__.py",
    "sv0cov/_generated/validators/sv0cov_baseline_1_0.py",
    "sv0cov/_generated/validators/sv0cov_compatibility_1_0.py", "sv0cov/_generated/validators/sv0cov_diagnostic_1_0.py",
    "sv0cov/_generated/validators/sv0cov_diagnostic_registry_1_0.py", "sv0cov/_generated/validators/sv0cov_doctor_1_0.py", "sv0cov/_generated/validators/sv0cov_export_manifest_1_0.py",
    "sv0cov/_generated/validators/sv0cov_indexed_1_0.py", "sv0cov/_generated/validators/sv0cov_indexed_semantic_1_0.py",
    "sv0cov/_generated/validators/sv0cov_map_1_0.py", "sv0cov/_generated/validators/sv0cov_release_manifest_1_0.py",
    "sv0cov/_generated/validators/sv0cov_report_1_0.py", "sv0cov/_generated/validators/sv0cov_resolved_configuration_1_0.py",
    "sv0cov/_generated/validators/sv0cov_run_set_1_0.py", "sv0cov/_generated/validators/sv0cov_version_1_0.py",
    "sv0cov/_generated/validators/sv0cov_vm_binding_1_0.py", "sv0cov/capabilities.py", "sv0cov/cli.py", "sv0cov/cmd_baseline.py", "sv0cov/cmd_check.py",
    "sv0cov/cmd_clean.py", "sv0cov/cmd_doctor.py", "sv0cov/cmd_merge.py", "sv0cov/cmd_report.py", "sv0cov/cmd_run.py",
    "sv0cov/config.py", "sv0cov/config_resolve.py", "sv0cov/console.py", "sv0cov/diagnostics.py", "sv0cov/evidence.py",
    "sv0cov/exports.py", "sv0cov/expr.py", "sv0cov/formats/__init__.py", "sv0cov/formats/baseline.py", "sv0cov/formats/canonical_json.py", "sv0cov/formats/cobertura.py", "sv0cov/formats/compatibility.py",
    "sv0cov/formats/crc32c.py", "sv0cov/formats/doctor.py", "sv0cov/formats/export_manifest.py", "sv0cov/formats/html.py", "sv0cov/formats/indexed.py", "sv0cov/formats/lcov.py", "sv0cov/formats/map.py",
    "sv0cov/formats/rawprofile.py", "sv0cov/formats/release.py", "sv0cov/formats/report.py", "sv0cov/formats/runset.py",
    "sv0cov/formats/structural.py", "sv0cov/formats/terminal.py", "sv0cov/formats/version_manifest.py", "sv0cov/formats/vmbinding.py", "sv0cov/gitdiff.py", "sv0cov/gitignore.py",
    "sv0cov/invocation.py", "sv0cov/lines.py", "sv0cov/model/__init__.py", "sv0cov/model/context.py", "sv0cov/model/identity.py", "sv0cov/model/indexed.py",
    "sv0cov/model/inventory.py", "sv0cov/model/logical.py", "sv0cov/model/merge.py", "sv0cov/model/report.py",
    "sv0cov/model/semantic.py", "sv0cov/parity.py", "sv0cov/probes.py", "sv0cov/publish.py", "sv0cov/resolve.py",
    "sv0cov/toolchain.py",
)
REGISTRY = "registries/diagnostics-v1.json"
#: The packaged C runtime sources and their exact bytes.
RUNTIME_SHA256 = {
    "runtime/c/sv0cov_rt.c": "3e2cf87cb6bb946cd48f75854099532c343b9c55f4c7843f17e82bf044bf1a4b",
    "runtime/c/sv0cov_rt.h": "e3221bcb88065d657520e85c41b35f7cf5fe10342836a4e050553c18849ed04b",
}
#: The doctor's smoke fixture and its hand-checked oracle (CV-242; SPEC 20.7).
SMOKE = ("resources/doctor/doctor-r1-smoke.oracle.json", "resources/doctor/doctor-r1-smoke.sv0")
RESOURCES = (REGISTRY, *(f"schemas/{s}" for s in SCHEMAS), *RUNTIME_SHA256, *SMOKE)
DRAFT = "https://json-schema.org/draft/2020-12/schema"
RE_VALIDATOR_DIGEST = re.compile(r"^# schema-sha256: ([0-9a-f]{64})$", re.M)
PROBE_BYTES = b"sv0cov doctor D007\n"


class Bootstrap(Exception):
    """D001 or D002 cannot pass: no aggregate can be trusted (exit 8)."""


class _Failed(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class Observed:
    """What the probes compare the manifest with. Tests pin these to reproduce a golden."""

    host: dict = field(default_factory=current_host)
    language: str = "python"
    runtime_name: str = field(default_factory=lambda: platform.python_implementation().lower())
    runtime_version: str = field(default_factory=platform.python_version)


@dataclass(frozen=True)
class Layout:
    """Where the logical members live: the installed package and its resources."""

    package: Path
    resources: Path

    @classmethod
    def current(cls) -> Layout:
        package = Path(sv0cov.__file__).resolve().parent
        packaged = package / "_resources"
        if packaged.is_dir():
            return cls(package, packaged)
        return cls(package, package.parents[1])  # a source checkout: src/sv0cov beside registries/, schemas/, runtime/

    def module(self, logical: str) -> Path:
        return self.package.parent / logical

    def resource(self, logical: str) -> Path:
        return self.resources / logical


def _regular(path: Path) -> bytes:
    """The bytes of a regular file reached without a symlink in its last step."""
    try:
        st = os.lstat(path)
    except OSError:
        raise _Failed("COV5004") from None
    if not stat.S_ISREG(st.st_mode):
        raise _Failed("COV5004")
    try:
        return path.read_bytes()
    except OSError:
        raise _Failed("COV5004") from None


def _strict_object(data: bytes) -> dict:
    def pairs(items: list) -> dict:
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    obj = json.loads(data.decode("utf-8"), object_pairs_hook=pairs)
    if not isinstance(obj, dict):
        raise ValueError("not an object")
    return obj


def d003_schemas(layout: Layout) -> dict:
    validators = layout.module("sv0cov/_generated/validators")
    for name in SCHEMAS:
        data = _regular(layout.resource(f"schemas/{name}"))
        try:
            obj = _strict_object(data)
        except (ValueError, UnicodeDecodeError):
            raise _Failed("COV5004") from None
        if obj.get("$schema") != DRAFT:
            raise _Failed("COV5004")
        generated = validators / (name.removesuffix(".schema.json").replace(".", "_").replace("-", "_") + ".py")
        if generated.exists():
            match = RE_VALIDATOR_DIGEST.search(_regular(generated).decode("utf-8", "replace"))
            if match is None or match.group(1) != hashlib.sha256(data).hexdigest():
                raise _Failed("COV5004")
    return {"validated_schema_count": len(SCHEMAS)}


def d004_layout(layout: Layout) -> dict:
    for logical in MODULES:
        _regular(layout.module(logical))
    for logical in RESOURCES:
        _regular(layout.resource(logical))
    return {"validated_member_count": len(MODULES) + len(RESOURCES)}


def d005_host(manifest: dict, seen: Observed) -> dict:
    host = f"{seen.host['operating_system']}-{seen.host['architecture']}"
    if seen.host != manifest["host"] or host not in manifest["supported_hosts"]:
        raise _Failed("COV5001")
    return {"host": host}


def d006_runtime(manifest: dict, seen: Observed, layout: Layout) -> dict:
    impl = manifest["implementation"]
    line = ".".join(seen.runtime_version.split(".")[:2])
    if seen.runtime_name != "cpython" or line not in manifest["supported_python_versions"]:
        raise _Failed("COV0016")
    if (seen.language, seen.runtime_name, seen.runtime_version) != (impl["language"], impl["runtime"]["name"], impl["runtime"]["version"]):
        raise _Failed("COV5004")
    # Import origin: the running package is the one whose members and resources were checked.
    if Path(sv0cov.__file__).resolve().parent != layout.package.resolve():
        raise _Failed("COV5004")
    return {"language": impl["language"], "runtime_name": impl["runtime"]["name"], "runtime_version": impl["runtime"]["version"]}


def d007_storage(private: Path) -> dict:
    st = os.lstat(private)
    if not stat.S_ISDIR(st.st_mode) or stat.S_IMODE(st.st_mode) & 0o077:
        raise _Failed("COV6002")
    probe = private / "d007"
    fd = os.open(probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        os.write(fd, PROBE_BYTES)
    finally:
        os.close(fd)
    if probe.read_bytes() != PROBE_BYTES:
        raise _Failed("COV5004")
    probe.unlink()
    if os.listdir(private):
        raise _Failed("COV5004")
    return {}


def d008_runtime(layout: Layout) -> dict:
    for logical, digest in RUNTIME_SHA256.items():
        if hashlib.sha256(_regular(layout.resource(logical))).hexdigest() != digest:
            raise _Failed("COV5004")
    return {"validated_member_count": len(RUNTIME_SHA256)}


def _attempt(check: Callable[[], dict]) -> tuple:
    from sv0cov import toolchain

    try:
        return ("pass", check())
    except (_Failed, toolchain.Failed) as exc:
        return ("fail", exc.code)
    except OSError:
        return ("fail", "COV5004")


def _execute(mode: str, man: dict, table: dict[str, Callable[[], dict]], results: dict) -> dict:
    """Run each applicable probe in registry order unless a direct
    prerequisite failed or was skipped; ``results`` holds D001 and D002."""
    status = {pid: outcome for pid, (outcome, _) in results.items()}
    for probe in doctor.PROBES:
        if probe.id in results:
            continue
        if not doctor.applicable(probe, mode, man):
            status[probe.id] = "not_applicable"
        elif any(status.get(p) in ("fail", "skipped") for p in probe.prerequisites):
            status[probe.id] = "skipped"
        else:
            results[probe.id] = _attempt(table[probe.id])
            status[probe.id] = results[probe.id][0]
    return results


def _bootstrap(manifest: bytes | None, registry: Registry | None) -> tuple[dict, Registry]:
    try:
        reg = registry or load_registry()
    except RegistryError as exc:
        raise Bootstrap(f"D002: {exc}") from None
    try:
        if manifest is None:
            manifest = build(tool_version=capabilities.tool_version(), revision=capabilities.revision(),
                             runtime_version=capabilities.runtime_version(), host=current_host(), registry_revision=reg.revision,
                             registry_sha256=reg.sha256, advertised=capabilities.ADVERTISED)
        man = validate_manifest(manifest)
    except (ManifestError, OSError, KeyError, ValueError) as exc:
        raise Bootstrap(f"D001: {exc}") from None
    if (man["diagnostic_registry"]["revision"], man["diagnostic_registry"]["sha256"]) != (reg.revision, reg.sha256):
        raise Bootstrap("D002: the manifest names another diagnostic registry")
    return man, reg


def run(*, toolchain_root: Path | None = None, manifest: bytes | None = None, registry: Registry | None = None,
        observed: Observed | None = None, layout: Layout | None = None) -> bytes:
    """The doctor aggregate, as canonical bytes: standalone, or toolchain mode
    for the physical root ``toolchain_root``. Raises :class:`Bootstrap`."""
    from sv0cov import toolchain

    man, reg = _bootstrap(manifest, registry)
    seen = observed or Observed()
    where = layout or Layout.current()
    mode = "standalone" if toolchain_root is None else "toolchain"
    results = {
        "D001": ("pass", {"manifest_sha256": man["manifest_sha256"]}),
        "D002": ("pass", {"registry_revision": reg.revision, "registry_sha256": reg.sha256}),
    }
    private = Path(tempfile.mkdtemp(prefix="sv0cov-doctor-"))
    policy = lambda: None  # noqa: E731
    try:
        table = {
            "D003": lambda: d003_schemas(where),
            "D004": lambda: d004_layout(where),
            "D005": lambda: d005_host(man, seen),
            "D006": lambda: d006_runtime(man, seen, where),
            "D007": lambda: d007_storage(private),
            "D008": lambda: d008_runtime(where),
        }
        if toolchain_root is not None:
            more, policy = toolchain.checks(toolchain_root, private, man, reg, lambda logical: _regular(where.resource(logical)))
            table.update(more)
        _execute(mode, man, table, results)
    finally:
        try:
            shutil.rmtree(private)
        except OSError as exc:
            raise Bootstrap(f"the private temporary directory could not be removed ({type(exc).__name__})") from None
    observed_root = toolchain.observed(toolchain_root) if toolchain_root is not None else None
    try:
        return doctor.build(mode=mode, manifest=man, policy=policy(), toolchain=observed_root, results=results, registry=reg)
    except doctor.DoctorError as exc:
        raise Bootstrap(f"the aggregate is invalid: {exc}") from None


def run_standalone(**kw) -> bytes:
    """The standalone aggregate (CV-235)."""
    return run(**kw)
