# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The toolchain doctor probes D009 to D018 (CV-242; SPEC 20.7, 20.6.1-20.6.3;
COV-CLI-011, AC-117).

``sv0cov doctor --toolchain-root <root>`` adds these to the standalone
probes (:mod:`sv0cov.probes`). ``<root>`` is the physical sv0-toolchain
checkout; nothing here finds a root any other way.

- D009: ``compatibility/sv0cov.json`` is a regular file reached without a
  symlink, within its size bound, and a valid policy.
- D010: ``.gitmodules`` declares exactly the sv0cov entry, the staged gitlink
  is the policy's ``expected_revision``, and the submodule is checked out at
  exactly that commit with no tracked or untracked change.
- D011: the running build's diagnostic registry, the policy's one allowed
  registry and the registry the checked-out submodule carries are the same.
- D012: the policy and this build's capability manifest agree under SPEC
  20.6.2 (:func:`sv0cov.formats.compatibility.evaluate`).
- D013 to D018: the bundled smoke fixture ``resources/doctor/doctor-r1-smoke.sv0``
  goes through the checked-out toolchain's own driver ``<root>/scripts/sv0``:
  a map (D013), a generated-C build and run (D014), a VM-v1 build and run
  (D015), the same semantic projection from both (D017; D016 is
  ``not_applicable`` while VM-v2 is unadvertised), and the merge of both
  profiles into a native report that passes a fixed policy (D018). Each
  backend's counts and line states must be the fixture's oracle
  (``doctor-r1-smoke.oracle.json``), checked by hand.

D018 publishes the digest of the report's *transport-free projection*
(:func:`report_projection`, planning-hub decision D-12): every raw profile
carries a profile ID from the secure random source, and the report records
it, so the bytes of a fresh report differ on every run while SPEC 20.7
requires the doctor result to be byte-identical.

Children run as argv without a shell, from the private directory, with the
caller's environment less every ``SV0COV_*`` name (plus exactly the
transport for the programs that collect), each bounded to 60 seconds and
1 MiB of output, the whole doctor to 300 seconds and 64 MiB of temporary
storage. Git (for D010 and the observed ``toolchain`` record) runs with no
``GIT_*`` variable. Nothing is fetched, installed or written outside the
private directory, though the driver may build its own compiler on first
use, as any build through it does.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from sv0cov.diagnostics import Registry, RegistryError, validate_registry
from sv0cov.formats import compatibility
from sv0cov.formats.canonical_json import CanonicalJsonError, decode_canonical, encode
from sv0cov.formats.doctor import FIXTURE_ID
from sv0cov.formats.map import MapError, validate_map
from sv0cov.formats.version_manifest import current_host
from sv0cov.formats import runset

POLICY = ("compatibility", "sv0cov.json")
SUBMODULE = "sv0cov"
URL = "git@github.com:sv0-toolchain/sv0cov.git"
REGISTRY = ("registries", "diagnostics-v1.json")
DRIVER = ("scripts", "sv0")
FIXTURE = "resources/doctor/doctor-r1-smoke.sv0"
ORACLE = "resources/doctor/doctor-r1-smoke.oracle.json"
NAME = "doctor-r1-smoke"
CHILD_SECONDS = 60
CHILD_OUTPUT = 1 << 20
TOTAL_SECONDS = 300
STORAGE = 64 << 20
#: The fixed policy of D018: every metric the fixture has, in full.
CHECK_TOML = (b'[tool.sv0cov]\nschema = "1.0"\n'
              b"[tool.sv0cov.thresholds]\nfunction = 100\nregion = 100\nline = 100\nbranch = 100\n")


class Failed(Exception):
    """A probe failed with this registered code."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


# ── the root ─────────────────────────────────────────────────────────────────


def _beneath(root: Path, parts: tuple[str, ...], *, final: str) -> Path:
    """``root/parts...`` with no symlinked component; the last a regular file
    (``final="file"``) or a directory (``"dir"``)."""
    path = root
    for i, part in enumerate(parts):
        path = path / part
        try:
            st = os.lstat(path)
        except OSError:
            raise Failed("COV5002") from None
        if stat.S_ISLNK(st.st_mode):
            raise Failed("COV6002")
        last = i == len(parts) - 1
        if not last and not stat.S_ISDIR(st.st_mode):
            raise Failed("COV5002")
    if final == "file" and not stat.S_ISREG(st.st_mode) or final == "dir" and not stat.S_ISDIR(st.st_mode):
        raise Failed("COV5002")
    return path


def _git_env() -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if not k.startswith("GIT_") and not k.upper().startswith("SV0COV_")}


def git(cwd: Path, *args: str) -> str | None:
    """Git's stdout, or None when it fails or says too much."""
    try:
        r = subprocess.run(["git", "-c", "core.quotepath=off", *args], cwd=cwd, env=_git_env(), stdin=subprocess.DEVNULL,
                           capture_output=True, timeout=CHILD_SECONDS, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if r.returncode != 0 or len(r.stdout) > CHILD_OUTPUT:
        return None
    return r.stdout.decode("utf-8", "replace")


def _worktree(cwd: Path) -> tuple[str | None, str]:
    head = (git(cwd, "rev-parse", "--verify", "-q", "HEAD") or "").strip()
    if len(head) != 40:
        return None, "unavailable"
    status = git(cwd, "status", "--porcelain=v1", "--untracked-files=all")
    if status is None:
        return None, "unavailable"
    return head, "clean" if not status.strip() else "dirty"


def observed(root: Path) -> dict:
    """The aggregate's ``toolchain`` record: revisions and worktree states only."""
    root_rev, root_state = _worktree(root)
    sub = root / SUBMODULE
    sub_rev, sub_state = (None, "unavailable")
    if sub.is_dir() and not sub.is_symlink() and (sub / ".git").exists():
        sub_rev, sub_state = _worktree(sub)
    return {"root_revision": root_rev, "root_worktree": root_state, "submodule_revision": sub_rev, "submodule_worktree": sub_state}


def d009_policy(root: Path) -> dict:
    path = _beneath(root, POLICY, final="file")
    try:
        with open(path, "rb") as f:
            data = f.read(compatibility.MAX_BYTES + 1)
        return compatibility.validate_policy(data)
    except OSError:
        raise Failed("COV5002") from None
    except compatibility.PolicyError:
        raise Failed("COV5002") from None


def _gitmodules_ok(root: Path) -> bool:
    _beneath(root, (".gitmodules",), final="file")
    listing = git(root, "config", "--file", ".gitmodules", "--null", "--list")
    if listing is None:
        return False
    entries = [e.split("\n", 1) for e in listing.split("\0") if e]
    ours: dict[str, str] = {}
    for item in entries:
        if len(item) != 2:
            return False
        key, value = item
        section, _, rest = key.partition(".")
        name, _, var = rest.rpartition(".")
        if section != "submodule":
            continue
        if name == SUBMODULE:
            if var in ours:
                return False
            ours[var] = value
        elif name.lower() == SUBMODULE or (var == "path" and value.strip("/").lower() == SUBMODULE) or (var == "url" and "sv0cov" in value.lower()):
            return False  # an alias, a case variant, or another entry for the same path or repository
    return ours == {"path": SUBMODULE, "url": URL}


def d010_submodule(root: Path, policy: dict) -> dict:
    expected = policy["expected_revision"]
    if not _gitmodules_ok(root):
        raise Failed("COV5002")
    staged = (git(root, "ls-files", "-s", "--", SUBMODULE) or "").strip()
    if staged != f"160000 {expected} 0\t{SUBMODULE}":
        raise Failed("COV5002")
    sub = _beneath(root, (SUBMODULE,), final="dir")
    rev, state = _worktree(sub)
    if rev != expected or state != "clean":
        raise Failed("COV5002")
    return {"expected_revision": expected}


def _checked_out_registry(root: Path) -> Registry:
    path = _beneath(root, (SUBMODULE, *REGISTRY), final="file")
    try:
        return validate_registry(path.read_bytes())
    except (OSError, RegistryError):
        raise Failed("COV8002") from None


def d011_registries(root: Path, policy: dict, running: Registry) -> dict:
    mine = {"revision": running.revision, "sha256": running.sha256}
    pinned = _checked_out_registry(root)
    if policy["allowed_diagnostic_registries"] != [mine] or (pinned.revision, pinned.sha256) != (running.revision, running.sha256):
        raise Failed("COV5002")
    return {"registry_revision": running.revision, "registry_sha256": running.sha256}


def d012_compatibility(root: Path, policy: dict, manifest: dict) -> dict:
    pinned = _checked_out_registry(root)
    try:
        compatibility.evaluate(policy, manifest, current_host(), {"revision": pinned.revision, "sha256": pinned.sha256})
    except compatibility.Incompatible:
        raise Failed("COV5002") from None
    return {"compatibility_sha256": policy["compatibility_sha256"], "manifest_sha256": manifest["manifest_sha256"]}


# ── the smoke workflow ───────────────────────────────────────────────────────


def report_projection(report: dict) -> dict:
    """The native report without what is particular to one execution
    (planning-hub D-12): each input's artifact digest, name, profile ID and
    run ID are dropped and the inputs put in the order of what remains; the
    provenance loses the indexed-input digest and the run IDs. Everything
    the report says about the code and the policy is kept."""
    transport = ("artifact_sha256", "name", "profile_id", "run_id")
    inputs = [{k: v for k, v in r.items() if k not in transport} for r in report["inputs"]]
    provenance = {k: v for k, v in report["provenance"].items() if k not in ("indexed_input_sha256", "run_ids")}
    return {**report, "inputs": sorted(inputs, key=encode), "provenance": provenance}


@dataclass
class Smoke:
    """One pass of the smoke workflow through ``<root>/scripts/sv0``, in ``private``."""

    root: Path
    private: Path
    fixture: bytes
    oracle: dict
    deadline: float = field(default_factory=lambda: time.monotonic() + TOTAL_SECONDS)
    run_id: str = field(default_factory=lambda: runset.new_run_id(os.urandom))
    map: bytes | None = None
    profiles: dict = field(default_factory=dict)
    projections: dict = field(default_factory=dict)

    @property
    def work(self) -> Path:
        return self.private / "smoke"

    def driver(self) -> Path:
        path = _beneath(self.root, DRIVER, final="file")
        if not os.access(path, os.X_OK):
            raise Failed("COV5002")
        return path

    def child(self, argv: list[str], *, transport: Path | None = None, failure: str) -> int:
        """Run ``argv`` from the work directory; its status, or :class:`Failed`
        with ``failure`` when it cannot run, and ``COV6001`` past a bound."""
        env = {k: v for k, v in os.environ.items() if not k.upper().startswith("SV0COV_")}
        if transport is not None:
            env.update(SV0COV_PROFILE_DIR=str(transport), SV0COV_RUN_ID=self.run_id, SV0COV_REQUIRED="1")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise Failed("COV6001")
        logs = self.private / "logs"
        logs.mkdir(mode=0o700, exist_ok=True)
        out, err = logs / "stdout", logs / "stderr"
        try:
            with open(out, "wb") as o, open(err, "wb") as e:
                r = subprocess.run(argv, cwd=self.work, env=env, stdin=subprocess.DEVNULL, stdout=o, stderr=e,
                                   timeout=min(CHILD_SECONDS, remaining), check=False)
        except subprocess.TimeoutExpired:
            raise Failed("COV6001") from None
        except OSError:
            raise Failed(failure) from None
        too_much = out.stat().st_size + err.stat().st_size > CHILD_OUTPUT
        out.unlink()
        err.unlink()
        if too_much:
            raise Failed("COV6001")
        return r.returncode

    def storage(self) -> None:
        used = sum(p.lstat().st_size for p in self.private.rglob("*"))
        if used > STORAGE:
            raise Failed("COV6001")

    def built_map(self, directory: str) -> bytes:
        path = self.work / directory / f"{NAME}.sv0covmap.json"
        try:
            st = os.lstat(path)
            if not stat.S_ISREG(st.st_mode):
                raise Failed("COV1020")
            return path.read_bytes()
        except OSError:
            raise Failed("COV1020") from None

    def d013_map(self) -> dict:
        if hashlib.sha256(self.fixture).hexdigest() != self.oracle["source_sha256"]:
            raise Failed("COV1004")
        self.work.mkdir(mode=0o700)
        fd = os.open(self.work / f"{NAME}.sv0", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            os.write(fd, self.fixture)
        finally:
            os.close(fd)
        (self.work / "map").mkdir()
        if self.child([str(self.driver()), "native-compile", "--coverage=map", "-o", f"map/{NAME}", f"{NAME}.sv0"], failure="COV1020"):
            raise Failed("COV1020")
        data = self.built_map("map")
        try:
            m = validate_map(data)
        except MapError as exc:
            raise Failed(exc.code) from None
        self.map = data
        self.storage()
        return {"fixture_id": FIXTURE_ID, "map_id": m["map_id"]}

    def collect(self, backend: str, build: list[str], run: list[str], directory: str) -> dict:
        """Build with instrumentation, run once, merge the one profile, compare with the oracle."""
        (self.work / directory).mkdir()
        if self.child([str(self.driver()), *build], failure="COV1020"):
            raise Failed("COV1020")
        if self.built_map(directory) != self.map:
            raise Failed("COV1013")  # the same compiler and target must plan the same map
        profiles = self.work / f"{directory}-profiles"
        profiles.mkdir(mode=0o700)
        if self.child(run, transport=profiles, failure="COV2130"):
            raise Failed("COV2130")
        found = sorted(profiles.iterdir())
        if len(found) != 1:
            raise Failed("COV2010")
        indexed = self.merge({backend: found[0].read_bytes()})
        semantic = indexed["semantic"]
        counts = sorted(({"count": p["count"]["value"], "point_id": p["point_id"]} for p in semantic["points"]), key=lambda d: d["point_id"])
        lines = [{"line": entry["line"], "status": entry["status"]} for entry in semantic["lines"]]
        if counts != self.oracle["counts"] or lines != self.oracle["lines"]:
            raise Failed("COV5004")
        self.profiles[backend] = found[0].read_bytes()
        self.projections[backend] = indexed["semantic_projection_sha256"]
        self.storage()
        return {"fixture_id": FIXTURE_ID, "semantic_projection_sha256": indexed["semantic_projection_sha256"]}

    def merge(self, profiles: dict[str, bytes]) -> dict:
        from sv0cov.model.merge import Artifact, merge, select_runs

        result = merge([Artifact(f"{NAME}.sv0covmap.json", self.map)],
                       [Artifact(f"{backend}.sv0profraw", data) for backend, data in sorted(profiles.items())],
                       run_selection=select_runs([self.run_id]))
        if result.findings:
            raise Failed(result.findings[0].code)
        if not result.complete:
            raise Failed("COV3010")
        return result.indexed

    def d014_native(self) -> dict:
        exe = self.work / "native" / NAME
        return self.collect("native", ["native-compile", "--coverage=instrument", "-o", f"native/{NAME}", f"{NAME}.sv0"],
                            [str(exe)], "native")

    def d015_vm(self) -> dict:
        driver = str(self.driver())
        return self.collect("vm-v1", ["vm-native-compile", "--coverage=instrument", f"{NAME}.sv0", f"vm/{NAME}.sv0b"],
                            [driver, "vm-run", "--coverage-binding", f"vm/{NAME}.sv0covbind.json", f"vm/{NAME}.sv0b"], "vm")

    def d016_vm_v2(self) -> dict:
        raise Failed("COV5001")  # no VM-v2 collection in this build; D016 is not applicable while vm-v2 is unadvertised

    def d017_parity(self) -> dict:
        digests = set(self.projections.values())
        if len(digests) != 1:
            raise Failed("COV5004")
        return {"fixture_id": FIXTURE_ID, "semantic_projection_sha256": digests.pop()}

    def d018_report(self) -> dict:
        import sv0cov.cli  # noqa: F401 - the command modules import each other through it
        from sv0cov.cmd_check import exit_status
        from sv0cov.config_resolve import resolve
        from sv0cov.formats.report import ReportError
        from sv0cov.model.report import build_report, read_report

        indexed = self.merge(self.profiles)
        try:
            config = resolve("check", [], CHECK_TOML)
            report = read_report(encode(build_report(encode(indexed), config, {f"{NAME}.sv0": self.fixture})))
        except ReportError as exc:
            raise Failed(exc.code) from None
        if exit_status(report) != 0:
            codes = [c for e in report["policy"]["evaluations"] if e["result"] not in ("pass", "not_applicable") for c in e["diagnostics"]]
            raise Failed(codes[0] if codes else "COV5004")
        return {"fixture_id": FIXTURE_ID, "native_report_sha256": hashlib.sha256(encode(report_projection(report))).hexdigest()}


def load_oracle(data: bytes) -> dict:
    try:
        obj = decode_canonical(data)
    except CanonicalJsonError:
        raise Failed("COV5004") from None
    if not isinstance(obj, dict) or sorted(obj) != ["counts", "fixture_id", "lines", "source_sha256"] or obj["fixture_id"] != FIXTURE_ID:
        raise Failed("COV5004")
    return obj


def checks(root: Path, private: Path, manifest: dict, running: Registry, read: Callable[[str], bytes]) -> tuple[dict, Callable]:
    """The ten toolchain checks, keyed by probe ID, and the policy they
    validated (``None`` until D009 passes). ``read`` gives a resource's bytes."""
    state: dict = {"policy": None, "smoke": None}

    def policy() -> dict:
        state["policy"] = d009_policy(root)
        return {"compatibility_sha256": state["policy"]["compatibility_sha256"]}

    def smoke() -> Smoke:
        if state["smoke"] is None:
            try:
                fixture, oracle = read(FIXTURE), load_oracle(read(ORACLE))
            except OSError:
                raise Failed("COV5004") from None
            state["smoke"] = Smoke(root, private, fixture, oracle)
        return state["smoke"]

    table = {
        "D009": policy,
        "D010": lambda: d010_submodule(root, state["policy"]),
        "D011": lambda: d011_registries(root, state["policy"], running),
        "D012": lambda: d012_compatibility(root, state["policy"], manifest),
        "D013": lambda: smoke().d013_map(),
        "D014": lambda: smoke().d014_native(),
        "D015": lambda: smoke().d015_vm(),
        "D016": lambda: smoke().d016_vm_v2(),
        "D017": lambda: smoke().d017_parity(),
        "D018": lambda: smoke().d018_report(),
    }
    return table, lambda: state["policy"]

