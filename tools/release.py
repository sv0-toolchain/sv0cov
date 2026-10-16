#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The release pipeline, dry run only (CV-243; SPEC 25.2.7, 25.2.7.1, 25.4;
R0-G8, COV-REL-001, COV-PKG-001, COV-PKG-007, COV-PKG-028).

``dry-run OUT [--commit REV]``
    1. Preflight: ``REV`` (default ``HEAD``) is a commit; ``pyproject.toml``
       in it has a valid static product version; a ``v<version>`` tag, if
       one exists, peels to that commit; ``OUT`` does not exist.
    2. Export the commit's tree (never the working tree) into a private
       directory, refusing anything but regular files, and write the release
       build-info resource ``src/sv0cov/_build_info.json`` naming the commit.
    3. Build once, twice: each time the locked ``build`` group in a fresh
       environment, ``SOURCE_DATE_EPOCH`` = the commit time, the sdist from
       the export and the wheel from that sdist, without build isolation
       (``check_packaging.build_once``); the two results must be
       byte-identical.
    4. Inspect: the sdist and wheel allowlists, metadata and records; every
       sdist member is the commit's file byte for byte, except ``PKG-INFO``
       and the build-info, which both archives carry unchanged; the wheel,
       unpacked and run as installed, reports the product version and the
       commit in ``version --json`` and passes the standalone doctor.
    5. Attach (role): the sdist and wheel (``package``), the complete
       source archive (``source``), the schema/registry/doctor-fixture
       bundle (``protocol``), ``CHANGELOG.md`` and the compatibility matrix
       (``documentation``), the root compatibility policy this release
       proposes (``support``), the license inventory (``license``), the
       SPDX 2.3 SBOM (``sbom``) and the build evidence (``evidence``); then
       the sealed ``sv0cov.release-manifest`` 1.0 and ``SHA256SUMS``.
    6. ``verify`` the result.

``verify OUT [--commit REV]``
    Check a dry-run directory from its bytes alone: exactly the attachments
    ``SHA256SUMS`` names plus itself; every digest; the manifest and its
    reconciliation with ``SHA256SUMS``; sizes and roles; the archives and
    their build-info; the installed wheel's identity and doctor; the SBOM,
    policy, matrix and evidence against the manifest and the commit.

Nothing is tagged, attested, uploaded or published: the tool has no such
step. The SBOM covers the shipped files and the generated build-info; the
full supply-chain closure (build distributions, CPython, licenses of every
component) is CV-411. Every attachment is a pure function of the commit, so
two dry runs of one commit on any host produce the same ``SHA256SUMS``.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))

import check_packaging as cp  # noqa: E402

from sv0cov import capabilities  # noqa: E402
from sv0cov.diagnostics import validate_registry  # noqa: E402
from sv0cov.formats import compatibility, release as R  # noqa: E402
from sv0cov.formats.canonical_json import decode_canonical, encode  # noqa: E402
from sv0cov.formats.doctor import validate as validate_doctor  # noqa: E402
from sv0cov.formats.version_manifest import validate_manifest  # noqa: E402
from sv0cov.model import inventory as inv  # noqa: E402

BUILD_INFO = "src/sv0cov/_build_info.json"
REGISTRY = "registries/diagnostics-v1.json"
PROTOCOL = ("schemas/", "registries/", "resources/doctor/")
LICENSE_FILES = ("LICENSE", "LICENSE-APACHE", "LICENSE-MIT", "LICENSES/", "REUSE.toml")
WORKFLOW = ".github/workflows/release.yml"
RELEASES = "https://github.com/sv0-toolchain/sv0cov/releases"
SUPPLIER = "Organization: sv0-toolchain"
BOOT = "import sys; sys.path.insert(0, sys.argv.pop(1)); from sv0cov.cli import main; sys.exit(main())"
CHILD_ENV_DROP = ("PYTHON", "SV0COV_")


class ReleaseFailure(Exception):
    pass


def git(*args: str, binary: bool = False) -> bytes | str:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    r = subprocess.run(["git", *args], cwd=ROOT, env=env, capture_output=True, check=False)
    if r.returncode:
        raise ReleaseFailure(f"git {' '.join(args)}: {r.stderr.decode('utf-8', 'replace').strip()}")
    return r.stdout if binary else r.stdout.decode("utf-8").strip()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ── 1. preflight ─────────────────────────────────────────────────────────────


def preflight(rev: str) -> dict:
    commit = git("rev-parse", "--verify", f"{rev}^{{commit}}")
    py = tomllib.loads(git("show", f"{commit}:pyproject.toml"))
    version = py["project"]["version"]
    try:
        inv.parse_product_version(version)
    except inv.InventoryError as exc:
        raise ReleaseFailure(f"pyproject.toml: {exc}") from None
    tag = f"v{version}"
    tagged = subprocess.run(["git", "rev-parse", "-q", "--verify", f"refs/tags/{tag}^{{commit}}"], cwd=ROOT, capture_output=True,
                            text=True, check=False).stdout.strip()
    if tagged and tagged != commit:
        raise ReleaseFailure(f"tag {tag} exists and peels to {tagged}, not {commit}")
    epoch = int(git("show", "-s", "--format=%ct", commit))
    return {"commit": commit, "version": version, "tag": tag, "tagged": bool(tagged), "epoch": epoch}


# ── 2. export ────────────────────────────────────────────────────────────────


#: The only place the tree may hold a symlink: the vendored upstream suite, which
#: the sdist excludes and the complete source archive keeps as it is.
VENDOR = "tests/vendor/"
LINK = -1


def export(commit: str, dest: Path) -> dict[str, tuple[int, bytes]]:
    """The commit's tree as ``{path: (mode, bytes)}``, also written below ``dest``.
    A symlink (only under ``tests/vendor/``, relative, staying inside it) is
    ``(LINK, target)`` and is not written out."""
    data = git("archive", "--format=tar", commit, binary=True)
    tree: dict[str, tuple[int, bytes]] = {}
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for m in tf.getmembers():
            if m.isdir() or m.name == "pax_global_header":
                continue
            parts = Path(m.name).parts
            if m.name.startswith("/") or ".." in parts:
                raise ReleaseFailure(f"the tree has an unsafe path {m.name}")
            if m.issym() and m.name.startswith(VENDOR):
                resolved = os.path.normpath(os.path.join(os.path.dirname(m.name), m.linkname))
                if m.linkname.startswith("/") or not resolved.startswith(VENDOR):
                    raise ReleaseFailure(f"the vendored symlink {m.name} leaves {VENDOR}")
                tree[m.name] = (LINK, m.linkname.encode())
                continue
            if not m.isfile():
                raise ReleaseFailure(f"the tree has a non-regular member {m.name}")
            body = tf.extractfile(m).read()
            mode = 0o755 if m.mode & 0o111 else 0o644
            tree[m.name] = (mode, body)
            target = dest / m.name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
            target.chmod(mode)
    return tree


def targz(entries: dict[str, tuple[int, bytes]], prefix: str, epoch: int) -> bytes:
    """A reproducible ``.tar.gz``: sorted members under ``prefix/``, fixed time,
    owner and modes, gzip without a name or time."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name in sorted(entries, key=str.encode):
            mode, body = entries[name]
            info = tarfile.TarInfo(f"{prefix}/{name}")
            info.mtime, info.uid, info.gid, info.uname, info.gname = epoch, 0, 0, "", ""
            if mode == LINK:
                info.type, info.linkname, info.mode = tarfile.SYMTYPE, body.decode(), 0o777
                tf.addfile(info)
            else:
                info.size, info.mode = len(body), mode
                tf.addfile(info, io.BytesIO(body))
    out = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=out, mtime=0, compresslevel=9) as gz:
        gz.write(raw.getvalue())
    return out.getvalue()


# ── 3-4. build and inspect ───────────────────────────────────────────────────


def build_twice(src: Path, work: Path, epoch: int) -> Path:
    first, second = work / "build-a", work / "build-b"
    try:
        cp.build_once(src, first, str(epoch), work / "venv-a")
        cp.build_once(src, second, str(epoch), work / "venv-b")
    except subprocess.CalledProcessError as exc:
        raise ReleaseFailure(f"the build failed: {exc}") from None
    names = sorted(p.name for p in first.iterdir() if p.name != ".gitignore")
    if names != sorted(p.name for p in second.iterdir() if p.name != ".gitignore"):
        raise ReleaseFailure("the two builds produced different files")
    for name in names:
        if (first / name).read_bytes() != (second / name).read_bytes():
            raise ReleaseFailure(f"{name} is not byte-identical across two builds")
    return first


def inspect_archives(sdist: Path, wheel: Path, facts: dict, tree: dict[str, tuple[int, bytes]] | None) -> dict:
    """The allowlist checks, the build-info in both archives, and (with the
    commit's tree) every sdist member against the commit. Returns the inventories."""
    version = facts["version"]
    prefix = f"sv0cov-{version}"
    errors = cp.check_sdist(sdist, prefix) + cp.check_wheel(wheel, f"{prefix}.dist-info")
    info = capabilities.build_info(facts["commit"])
    inventories = {"sdist": [], "wheel": []}
    with tarfile.open(sdist) as tf:
        for m in sorted(tf.getmembers(), key=lambda m: m.name.encode()):
            if not m.isfile():
                continue
            body = tf.extractfile(m).read()
            rel = m.name.split("/", 1)[1]
            inventories["sdist"].append({"name": rel, "sha256": sha(body), "size": len(body)})
            if rel == BUILD_INFO:
                if body != info:
                    errors.append("the sdist's build-info does not name the release commit")
            elif rel != "PKG-INFO" and tree is not None and tree.get(rel, (0, None))[1] != body:
                errors.append(f"sdist member {rel} is not the commit's file")
        if f"{prefix}/{BUILD_INFO}" not in tf.getnames():
            errors.append("the sdist has no build-info")
    with zipfile.ZipFile(wheel) as zf:
        for name in sorted(zf.namelist(), key=str.encode):
            body = zf.read(name)
            inventories["wheel"].append({"name": name, "sha256": sha(body), "size": len(body)})
        if "sv0cov/_build_info.json" not in zf.namelist() or zf.read("sv0cov/_build_info.json") != info:
            errors.append("the wheel's build-info is missing or does not name the release commit")
    if errors:
        raise ReleaseFailure("; ".join(errors))
    return inventories


def installed(wheel: Path, work: Path, facts: dict) -> dict:
    """Run the wheel as installed: its version manifest and its standalone doctor."""
    site = work / "site"
    if site.exists():
        shutil.rmtree(site)
    with zipfile.ZipFile(wheel) as zf:
        zf.extractall(site)
    env = {k: v for k, v in os.environ.items() if not k.startswith(CHILD_ENV_DROP)}

    def run(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run([sys.executable, "-I", "-B", "-c", BOOT, str(site), *args], cwd=work, env=env, capture_output=True,
                              timeout=300, check=False)

    v = run("version", "--json")
    if v.returncode:
        raise ReleaseFailure(f"installed version --json exited {v.returncode}: {v.stderr.decode('utf-8', 'replace').strip()}")
    manifest = validate_manifest(v.stdout)
    if manifest["tool"] != {"name": "sv0cov", "version": facts["version"]} or manifest["implementation"]["revision"] != facts["commit"]:
        raise ReleaseFailure(f"the installed wheel reports {manifest['tool']} at {manifest['implementation']['revision']}")
    d = run("doctor", "--json")
    if d.returncode or validate_doctor(d.stdout)["status"] != "pass":
        raise ReleaseFailure(f"the installed standalone doctor did not pass (exit {d.returncode})")
    return manifest


# ── 5. attachments ───────────────────────────────────────────────────────────


def matrix(manifest: dict, version: str) -> bytes:
    """The compatibility matrix: what this release supports and advertises, without
    the host or runtime of the machine that built it."""
    return encode({
        "artifact_versions": manifest["artifact_versions"],
        "backends": manifest["backends"],
        "bytecode_profiles": manifest["bytecode_profiles"],
        "commands": manifest["commands"],
        "diagnostic_registry": manifest["diagnostic_registry"],
        "features": manifest["features"],
        "implementation_language": manifest["implementation"]["language"],
        "product": "sv0cov",
        "supported_hosts": manifest["supported_hosts"],
        "supported_python_versions": manifest["supported_python_versions"],
        "version": version,
        "version_manifest_version": manifest["version"],
    })


def proposed_policy(manifest: dict, facts: dict) -> bytes:
    """The root compatibility policy that would select this release: required sets are
    what it advertises (pre-R1 subsets, SPEC 15.6) and all four hosts. The root owns the
    values it commits; this is the proposal its `--write` reseals to."""
    return compatibility.seal({
        "allowed_diagnostic_registries": [manifest["diagnostic_registry"]],
        "allowed_implementation_languages": ["python"],
        "default_implementation_language": "python",
        "expected_artifact_versions": manifest["artifact_versions"],
        "expected_revision": facts["commit"],
        "expected_tool": {"name": "sv0cov", "version": facts["version"]},
        "required_backends": manifest["backends"],
        "required_bytecode_profiles": manifest["bytecode_profiles"],
        "required_commands": manifest["commands"],
        "required_features": manifest["features"],
        "required_hosts": list(inv.HOSTS),
        "schema": "sv0cov.compatibility",
        "submodule_path": "sv0cov",
        "version": "1.0",
        "version_manifest_version": "1.0",
    })


def licenses(tree: dict[str, tuple[int, bytes]]) -> bytes:
    files = [{"path": p, "sha256": sha(tree[p][1])} for p in sorted(tree, key=str.encode)
             if any(p == f or (f.endswith("/") and p.startswith(f)) for f in LICENSE_FILES)]
    return encode({"documentation_license": "CC-BY-4.0", "files": files, "product": "sv0cov", "software_license": "MIT OR Apache-2.0"})


def spdx_time(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def sbom(facts: dict, sdist: bytes, wheel: bytes) -> bytes:
    """SPDX 2.3 JSON for the product, its two package archives and the generated
    build-info. The closure of build tools, CPython and every license is CV-411."""
    v, commit = facts["version"], facts["commit"]
    info = capabilities.build_info(commit)
    lic = "MIT OR Apache-2.0"
    copyright_text = "Copyright 2026 Sasank Vishnubhatla"
    release = f"{RELEASES}/download/{facts['tag']}"

    def package(spdx_id: str, name: str, purpose: str, location: str, data: bytes | None) -> dict:
        p = {"SPDXID": spdx_id, "copyrightText": copyright_text, "downloadLocation": location, "filesAnalyzed": False,
             "licenseConcluded": lic, "licenseDeclared": lic, "name": name, "primaryPackagePurpose": purpose,
             "supplier": SUPPLIER, "versionInfo": v}
        if data is not None:
            p["checksums"] = [{"algorithm": "SHA256", "checksumValue": sha(data)}]
            p["packageFileName"] = name
        return p

    doc = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "comment": "sv0cov release dry run (CV-243): the product, its sdist and wheel, and the generated build-info. "
                   "Build distributions, the CPython runtime closure and component licenses are added by CV-411.",
        "creationInfo": {"created": spdx_time(facts["epoch"]), "creators": [f"Tool: sv0cov-tools-release-{v}"]},
        "dataLicense": "CC0-1.0",
        "documentDescribes": ["SPDXRef-Package-sv0cov"],
        "documentNamespace": f"{RELEASES}/tag/{facts['tag']}/spdx",
        "files": [{
            "SPDXID": "SPDXRef-File-build-info",
            "checksums": [{"algorithm": "SHA1", "checksumValue": hashlib.sha1(info).hexdigest()},  # noqa: S324 - SPDX 2.3 requires SHA1 for files
                          {"algorithm": "SHA256", "checksumValue": sha(info)}],
            "comment": "Generated by tools/release.py before the build (SPEC 25.2.7.1); not tracked in Git.",
            "copyrightText": "NOASSERTION",
            "fileName": "./src/sv0cov/_build_info.json",
            "fileTypes": ["OTHER"],
            "licenseConcluded": lic,
        }],
        "name": f"sv0cov-{v}",
        "packages": [
            package("SPDXRef-Package-sv0cov", "sv0cov", "APPLICATION", f"git+https://github.com/sv0-toolchain/sv0cov.git@{commit}", None),
            package("SPDXRef-Package-sdist", R.sdist_name(v), "SOURCE", f"{release}/{R.sdist_name(v)}", sdist),
            package("SPDXRef-Package-wheel", R.wheel_name(v), "INSTALL", f"{release}/{R.wheel_name(v)}", wheel),
        ],
        "relationships": [
            {"relatedSpdxElement": "SPDXRef-Package-sv0cov", "relationshipType": "DESCRIBES", "spdxElementId": "SPDXRef-DOCUMENT"},
            {"relatedSpdxElement": "SPDXRef-File-build-info", "relationshipType": "CONTAINS", "spdxElementId": "SPDXRef-Package-sdist"},
            {"relatedSpdxElement": "SPDXRef-File-build-info", "relationshipType": "CONTAINS", "spdxElementId": "SPDXRef-Package-wheel"},
            {"relatedSpdxElement": "SPDXRef-Package-sv0cov", "relationshipType": "GENERATED_FROM", "spdxElementId": "SPDXRef-File-build-info"},
            {"relatedSpdxElement": "SPDXRef-Package-sv0cov", "relationshipType": "GENERATED_FROM", "spdxElementId": "SPDXRef-Package-sdist"},
            {"relatedSpdxElement": "SPDXRef-Package-sdist", "relationshipType": "GENERATED_FROM", "spdxElementId": "SPDXRef-Package-wheel"},
        ],
        "spdxVersion": "SPDX-2.3",
    }
    return encode(doc)


def check_sbom(data: bytes, facts: dict, sdist: bytes, wheel: bytes) -> None:
    """The SPDX 2.3 shape this pipeline relies on, its identities and its digests."""
    doc = decode_canonical(data)
    required = {"SPDXID", "creationInfo", "dataLicense", "documentNamespace", "name", "spdxVersion"}
    if not required <= set(doc) or doc["spdxVersion"] != "SPDX-2.3" or doc["dataLicense"] != "CC0-1.0" or doc["SPDXID"] != "SPDXRef-DOCUMENT":
        raise ReleaseFailure("the SBOM is not an SPDX 2.3 document")
    if doc["creationInfo"]["created"] != spdx_time(facts["epoch"]) or doc["documentNamespace"] != f"{RELEASES}/tag/{facts['tag']}/spdx":
        raise ReleaseFailure("the SBOM's creation time or namespace is not the release's")
    ids = [p["SPDXID"] for p in doc["packages"]] + [f["SPDXID"] for f in doc["files"]]
    if len(ids) != len(set(ids)):
        raise ReleaseFailure("the SBOM repeats an SPDX identifier")
    for r in doc["relationships"]:
        if {r["spdxElementId"], r["relatedSpdxElement"]} - set(ids) - {"SPDXRef-DOCUMENT"}:
            raise ReleaseFailure(f"an SBOM relationship names an unknown element: {r}")
    want = {R.sdist_name(facts["version"]): sha(sdist), R.wheel_name(facts["version"]): sha(wheel)}
    got = {p["packageFileName"]: p["checksums"][0]["checksumValue"] for p in doc["packages"] if "packageFileName" in p}
    if got != want or any(p["versionInfo"] != facts["version"] for p in doc["packages"]):
        raise ReleaseFailure("the SBOM's package digests or versions are not the release's")
    if data != sbom(facts, sdist, wheel):
        raise ReleaseFailure("the SBOM is not the one the release produces")


def hatchling_lock() -> dict:
    lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    (pkg,) = [p for p in lock["package"] if p["name"] == "hatchling"]
    return {"version": pkg["version"], "wheel_sha256": [w["hash"] for w in pkg["wheels"]]}


def evidence(facts: dict, tree: dict, inventories: dict, manifest: dict) -> bytes:
    return encode({
        "build": {
            "backend": "hatchling.build",
            "environment": "inherited minus HATCH_*, UV_*, PIP_* and PYTHON*; SOURCE_DATE_EPOCH and UV_PROJECT_ENVIRONMENT set",
            "frontend": ["uv", "build", "--no-config", "--no-python-downloads", "--no-build-isolation"],
            "hatchling": hatchling_lock(),
            "sdist_to_wheel": True,
            "source": "git archive of the release commit, plus the build-info",
            "source_date_epoch": facts["epoch"],
            "sync": ["uv", "sync", "--no-config", "--no-python-downloads", "--locked", "--no-default-groups", "--group", "build",
                     "--no-install-project"],
        },
        "dry_run": True,
        "installed": {"doctor": "pass", "implementation_revision": manifest["implementation"]["revision"], "tool": manifest["tool"]},
        "inventories": inventories,
        "pyproject_sha256": sha(tree["pyproject.toml"][1]),
        "release_commit": facts["commit"],
        "release_tag": facts["tag"],
        "reproduced": "two builds byte-identical",
        "uv_lock_sha256": sha(tree["uv.lock"][1]),
    })


MEDIA = {".whl": "application/zip", ".gz": "application/gzip", ".md": "text/markdown", ".json": "application/json"}


def attachments(facts: dict, tree: dict, dist: Path, inventories: dict, manifest: dict) -> dict[str, tuple[str, bytes]]:
    """``{filename: (role, bytes)}`` for every attachment except the manifest and SHA256SUMS."""
    v, epoch = facts["version"], facts["epoch"]
    sdist, wheel = (dist / R.sdist_name(v)).read_bytes(), (dist / R.wheel_name(v)).read_bytes()
    protocol = {p: tree[p] for p in tree if p.startswith(PROTOCOL)}
    return {
        R.sdist_name(v): ("package", sdist),
        R.wheel_name(v): ("package", wheel),
        f"sv0cov-{v}-source.tar.gz": ("source", targz(tree, f"sv0cov-{v}", epoch)),
        f"sv0cov-{v}-protocol.tar.gz": ("protocol", targz(protocol, f"sv0cov-{v}-protocol", epoch)),
        "CHANGELOG.md": ("documentation", tree["CHANGELOG.md"][1]),
        f"sv0cov-{v}.compatibility-matrix.json": ("documentation", matrix(manifest, v)),
        f"sv0cov-{v}.compatibility-policy.json": ("support", proposed_policy(manifest, facts)),
        f"sv0cov-{v}.licenses.json": ("license", licenses(tree)),
        R.sbom_name(v): ("sbom", sbom(facts, sdist, wheel)),
        f"sv0cov-{v}.evidence.json": ("evidence", evidence(facts, tree, inventories, manifest)),
    }


def media_type(name: str) -> str:
    if name.endswith(".spdx.json"):
        return "application/spdx+json"
    return MEDIA[Path(name).suffix]


def release_manifest(facts: dict, files: dict[str, tuple[str, bytes]], tree: dict) -> bytes:
    v = facts["version"]
    reg = validate_registry(tree[REGISTRY][1])
    artifacts = [{"filename": n, "media_type": media_type(n), "role": role, "sha256": sha(data), "size": len(data)}
                 for n, (role, data) in sorted(files.items(), key=lambda kv: kv[0].encode())]
    return R.seal_manifest({
        "artifacts": artifacts,
        "attestation_policy": {"expected_issuer": R.ISSUER, "offline_bundle_retention": True, "online_verification": True,
                               "repository": R.REPOSITORY, "subject_digest_algorithm": "sha256", "workflow": WORKFLOW},
        "compatibility_policy_sha256": sha(files[f"sv0cov-{v}.compatibility-policy.json"][1]),
        "diagnostic_registry": {"revision": reg.revision, "sha256": reg.sha256},
        "evidence_manifest_sha256": sha(files[f"sv0cov-{v}.evidence.json"][1]),
        "license_inventory_sha256": sha(files[f"sv0cov-{v}.licenses.json"][1]),
        "product": "sv0cov",
        "release_commit": facts["commit"],
        "release_tag": facts["tag"],
        "sbom_sha256": sha(files[R.sbom_name(v)][1]),
        "schema": "sv0cov.release-manifest",
        "source_date_epoch": facts["epoch"],
        "version": "1.0",
    })


# ── the commands ─────────────────────────────────────────────────────────────


def dry_run(out: Path, rev: str, log=print) -> dict:
    facts = preflight(rev)
    if out.exists():
        raise ReleaseFailure(f"{out} exists; a dry run writes only into a new directory")
    log(f"release dry run: sv0cov {facts['version']} at {facts['commit']} ({facts['tag']} {'tagged' if facts['tagged'] else 'not tagged'})")
    with tempfile.TemporaryDirectory(prefix="sv0cov-release-") as tmp:
        work = Path(tmp)
        src = work / "src"
        tree = export(facts["commit"], src)
        (src / BUILD_INFO).write_bytes(capabilities.build_info(facts["commit"]))
        dist = build_twice(src, work, facts["epoch"])
        v = facts["version"]
        inventories = inspect_archives(dist / R.sdist_name(v), dist / R.wheel_name(v), facts, tree)
        manifest = installed(dist / R.wheel_name(v), work, facts)
        files = attachments(facts, tree, dist, inventories, manifest)
        man = release_manifest(facts, files, tree)
        staged = work / "out"
        staged.mkdir()
        for name, (_, data) in files.items():
            (staged / name).write_bytes(data)
        (staged / R.manifest_name(v)).write_bytes(man)
        sums = {n: sha(d) for n, (_, d) in files.items()} | {R.manifest_name(v): sha(man)}
        (staged / R.SUMS_NAME).write_bytes(R.encode_sums(sums))
        verify(staged, facts["commit"], tree=tree)
        shutil.copytree(staged, out)
    log(f"release dry run: {len(files) + 2} attachments in {out}; nothing published")
    return facts


def verify(out: Path, rev: str, *, tree: dict | None = None) -> None:
    """Check a dry-run directory from its bytes (see the module docstring)."""
    facts = preflight(rev)
    v = facts["version"]
    sums_bytes = (out / R.SUMS_NAME).read_bytes()
    sums = R.parse_sums(sums_bytes)
    present = sorted(p.name for p in out.iterdir())
    if present != sorted([*sums, R.SUMS_NAME]):
        raise ReleaseFailure(f"the directory holds {present}, SHA256SUMS names {sorted(sums)}")
    for name, digest in sums.items():
        if sha((out / name).read_bytes()) != digest:
            raise ReleaseFailure(f"{name} does not have its SHA256SUMS digest")
    man_bytes = (out / R.manifest_name(v)).read_bytes()
    R.reconcile(man_bytes, sums_bytes)
    man = R.validate_manifest(man_bytes)
    if (man["release_commit"], man["release_tag"], man["source_date_epoch"]) != (facts["commit"], facts["tag"], facts["epoch"]):
        raise ReleaseFailure("the release manifest names another commit, tag or epoch")
    by_name = {a["filename"]: a for a in man["artifacts"]}
    for name, a in by_name.items():
        data = (out / name).read_bytes()
        if a["size"] != len(data) or a["media_type"] != media_type(name):
            raise ReleaseFailure(f"{name}: size or media type disagrees with the manifest")
    tree = tree if tree is not None else export_tree(facts["commit"])
    reg = validate_registry(tree[REGISTRY][1])
    if man["diagnostic_registry"] != {"revision": reg.revision, "sha256": reg.sha256}:
        raise ReleaseFailure("the manifest's diagnostic registry is not the commit's")
    sdist, wheel = out / R.sdist_name(v), out / R.wheel_name(v)
    inspect_archives(sdist, wheel, facts, tree)
    with tempfile.TemporaryDirectory(prefix="sv0cov-verify-") as tmp:
        manifest = installed(wheel, Path(tmp), facts)
    check_sbom((out / R.sbom_name(v)).read_bytes(), facts, sdist.read_bytes(), wheel.read_bytes())
    policy = compatibility.validate_policy((out / f"sv0cov-{v}.compatibility-policy.json").read_bytes())
    if (policy["expected_revision"], policy["expected_tool"]["version"]) != (facts["commit"], v) or \
            policy["allowed_diagnostic_registries"] != [man["diagnostic_registry"]]:
        raise ReleaseFailure("the proposed compatibility policy does not select this release")
    if sha((out / f"sv0cov-{v}.compatibility-policy.json").read_bytes()) != man["compatibility_policy_sha256"]:
        raise ReleaseFailure("compatibility_policy_sha256 is not the proposed policy's digest")
    if (out / f"sv0cov-{v}.compatibility-matrix.json").read_bytes() != matrix(manifest, v):
        raise ReleaseFailure("the compatibility matrix is not the installed release's")
    if sha((out / f"sv0cov-{v}.licenses.json").read_bytes()) != man["license_inventory_sha256"] or \
            (out / f"sv0cov-{v}.licenses.json").read_bytes() != licenses(tree):
        raise ReleaseFailure("the license inventory is not the commit's")
    ev = decode_canonical((out / f"sv0cov-{v}.evidence.json").read_bytes())
    if sha((out / f"sv0cov-{v}.evidence.json").read_bytes()) != man["evidence_manifest_sha256"] or \
            (ev["release_commit"], ev["dry_run"]) != (facts["commit"], True):
        raise ReleaseFailure("the evidence is not this dry run's")
    if (out / "CHANGELOG.md").read_bytes() != tree["CHANGELOG.md"][1]:
        raise ReleaseFailure("CHANGELOG.md is not the commit's")
    for name, prefix in ((f"sv0cov-{v}-source.tar.gz", f"sv0cov-{v}"), (f"sv0cov-{v}-protocol.tar.gz", f"sv0cov-{v}-protocol")):
        with tarfile.open(out / name) as tf:
            got = {}
            for m in tf.getmembers():
                if m.name.split("/", 1)[0] != prefix or not (m.isfile() or m.issym()):
                    raise ReleaseFailure(f"{name}: member {m.name} is outside {prefix}/ or neither a file nor a vendored link")
                got[m.name.split("/", 1)[1]] = (LINK, m.linkname.encode()) if m.issym() else (0o755 if m.mode & 0o111 else 0o644,
                                                                                                tf.extractfile(m).read())
        want = {p: e for p, e in tree.items() if name.endswith("-source.tar.gz") or p.startswith(PROTOCOL)}
        if got != want:
            raise ReleaseFailure(f"{name} is not the commit's files")


def export_tree(commit: str) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        return export(commit, Path(tmp))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("dry-run", "verify"):
        p = sub.add_parser(name)
        p.add_argument("out", type=Path)
        p.add_argument("--commit", default="HEAD")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "dry-run":
            dry_run(args.out.resolve(), args.commit)
        else:
            verify(args.out.resolve(), args.commit)
            print(f"release verify: {args.out} is a valid dry run of {args.commit}")
    except (ReleaseFailure, R.ReleaseError, compatibility.PolicyError, OSError, ValueError) as exc:
        print(f"release {args.cmd}: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
