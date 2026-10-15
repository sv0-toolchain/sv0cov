#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Parser fuzzing and resource-limit checks (CV-236; SPEC 28.4; COV-SEC-004,
COV-FMT-022, BL-032).

A deterministic, standard-library-only mutation fuzzer. Each harness feeds
one artifact reader (or the merge engine, or the counter-expression
evaluator) inputs derived from checked-in seeds, and holds it to three
rules:

1. **No crash.** An input is either accepted or rejected with the reader's
   own documented error, and a coded error carries a code of the diagnostic
   registry. Any other exception (``KeyError``, ``TypeError``,
   ``RecursionError``, ``MemoryError``, ...) is a finding.
2. **No hang.** One input may take at most :data:`TIME_LIMIT` seconds.
3. **Bounded memory.** On sampled inputs, the peak Python allocation while
   reading stays within a fixed multiple of the input size plus a constant:
   a declared length or count is not trusted before it is checked.

Some harnesses add properties: an accepted canonical JSON document
re-encodes to the same bytes; a publishable merge result reads back; an
evaluated counter expression lies in ``[0, UINT64_MAX]`` and equals the
plain sum when nothing saturates.

A finding is minimized (bytes removed while the same finding persists) and
written as ``<crash-dir>/<harness>/<sha256-prefix>.bin``. Checked into
``tests/fixtures/fuzz/<harness>/`` it becomes a regression fixture that
``tests/test_fuzz.py`` replays on every run.

    python3 tools/fuzz.py run [--harness NAME]... [--iterations N | --seconds S]
                              [--seed N] [--crash-dir DIR]
    python3 tools/fuzz.py replay DIR
    python3 tools/fuzz.py list
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import signal
import sys
import time
import tracemalloc
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov import diagnostics, expr  # noqa: E402
from sv0cov.diagnostics import RegistryError, validate_registry  # noqa: E402
from sv0cov.formats import canonical_json, doctor, rawprofile, release, runset, version_manifest  # noqa: E402
from sv0cov.formats.canonical_json import CanonicalJsonError  # noqa: E402
from sv0cov.formats.compatibility import policy_digest  # noqa: E402
from sv0cov.formats.crc32c import crc32c  # noqa: E402
from sv0cov.formats.map import map_id as map_digest  # noqa: E402
from sv0cov.formats.compatibility import PolicyError, validate_policy  # noqa: E402
from sv0cov.formats.indexed import IndexedError, projection_sha256  # noqa: E402
from sv0cov.formats.map import MapError, validate_map  # noqa: E402
from sv0cov.formats.report import ReportError  # noqa: E402
from sv0cov.model import merge as merge_model  # noqa: E402
from sv0cov.model.indexed import read_indexed  # noqa: E402
from sv0cov.model.report import read_report  # noqa: E402

U64 = 2**64 - 1
TIME_LIMIT = 5.0
#: Peak allocation allowed while reading an input of n bytes: SLOPE * n + BASE.
SLOPE, BASE = 64, 8 << 20
MEMORY_SAMPLE = 25  # every Nth input is measured
FIXTURES = ROOT / "tests" / "fixtures"
REGRESSIONS = FIXTURES / "fuzz"


class Finding(Exception):
    """An input broke a rule. ``signature`` identifies the finding for minimization."""

    def __init__(self, signature: str, detail: str) -> None:
        super().__init__(f"{signature}: {detail}")
        self.signature = signature


class _Timeout(BaseException):
    pass


@dataclass(frozen=True)
class Harness:
    name: str
    seeds: Callable[[], list[bytes]]
    target: Callable[[bytes], None]
    errors: tuple[type[BaseException], ...]
    structured: bool = False  # mutate decoded JSON trees as well as bytes
    #: Recompute a self-digest or checksum after a mutation, so that the reader
    #: gets past it and the rest of its validation is exercised.
    fix_tree: Callable[[object], object] | None = None
    fix_bytes: Callable[[bytes], bytes] | None = None


# ── seeds ────────────────────────────────────────────────────────────────────


def _files(*patterns: str) -> Callable[[], list[bytes]]:
    def load() -> list[bytes]:
        out = []
        for pattern in patterns:
            out += [p.read_bytes() for p in sorted(ROOT.glob(pattern)) if p.is_file()]
        if not out:
            raise SystemExit(f"fuzz: no seed matches {patterns}")
        return out

    return load


def _manifest_seeds() -> list[bytes]:
    reg = diagnostics.load_registry()
    host = {"architecture": "arm64", "operating_system": "macos"}
    adv = version_manifest.Advertised(("version",), ("native", "vm-v1"), ("sv0vm-v1-coverage",), ())
    return [version_manifest.build(tool_version="0.1.0", revision="a" * 40, runtime_version="3.13.0", host=host,
                                   registry_revision=reg.revision, registry_sha256=reg.sha256, advertised=adv)]


def _runset_seeds() -> list[bytes]:
    return [runset.encode_run_set(["0123456789abcdef0123456789abcdef", "f" * 32]), runset.encode_run_set(["1" * 32])]


def _policy_seeds() -> list[bytes]:
    golden = json.loads((FIXTURES / "doctor" / "toolchain-d012-fail.json").read_bytes())
    return [canonical_json.encode(golden["compatibility_policy"])]


def _tests_on_path() -> None:
    if str(ROOT / "tests") not in sys.path:
        sys.path.insert(0, str(ROOT / "tests"))


def _indexed_seeds() -> list[bytes]:
    """Valid evidence of every semantic fixture and of the rich multi-run inputs, plus the structure fixtures."""
    _tests_on_path()
    from test_indexed_reader import FIXTURES as SEMANTIC, rich_inputs, simple  # noqa: N811

    from sv0cov.model.indexed import build_indexed

    out = [canonical_json.encode(simple(name)) for name in SEMANTIC]
    maps, profiles, selection = rich_inputs()
    out.append(canonical_json.encode(build_indexed(maps, profiles, run_selection=selection, tool_version="0.0.0-fuzz")))
    return out + _files("tests/fixtures/indexed/empty.json", "tests/fixtures/indexed/all-kinds.json")()


def _report_seeds() -> list[bytes]:
    """Valid reports of the same evidence, with thresholds and with stale sources allowed, plus the structure fixtures."""
    _tests_on_path()
    from test_report import STALE_OK, config, thresholds

    from sv0cov.model.report import build_report

    out = []
    for i, data in enumerate(_indexed_seeds()[:-2]):
        toml = thresholds(line=80, branch=50, function=100, region=1) if i % 2 else ""
        out.append(canonical_json.encode(build_report(data, config(STALE_OK, toml), {}, tool_version="0.0.0-fuzz")))
    return out + _files("tests/fixtures/report/passing.json", "tests/fixtures/report/all-kinds.json")()


# ── fix-ups: keep self-digests and checksums consistent with the mutation ───


def _self_hash(key: str, digest: Callable[[dict], str]) -> Callable[[object], object]:
    def fix(tree: object) -> object:
        if isinstance(tree, dict) and key in tree:
            try:
                tree[key] = digest(tree)
            except (CanonicalJsonError, ValueError, TypeError, KeyError, OverflowError):
                pass
        return tree

    return fix


def _fix_raw(data: bytes) -> bytes:
    if len(data) < 16:
        return data
    return data[:-4] + crc32c(data[:-4]).to_bytes(4, "little")


def _fix_indexed(tree: object) -> object:
    if isinstance(tree, dict) and isinstance(tree.get("semantic"), dict):
        try:
            tree["semantic_projection_sha256"] = projection_sha256(tree["semantic"])
        except (CanonicalJsonError, ValueError, TypeError, OverflowError):
            pass
    return tree


# ── targets ──────────────────────────────────────────────────────────────────


def _json_target(data: bytes) -> None:
    value = canonical_json.decode_canonical(data)
    again = canonical_json.encode(value)
    if again != data:
        raise Finding("json/roundtrip", "an accepted canonical document re-encodes to other bytes")


def _raw_target(data: bytes) -> None:
    """Decode unbound, then bound to maps of a few sizes around the profile's own."""
    profile = rawprofile.decode(data)
    bound = max((i for i, _ in profile.counts), default=-1) + 1
    for n in sorted({bound, bound + 1, max(bound, 64)}):
        try:
            rawprofile.decode(data, map_counter_count=n, expected_map_id=profile.map_id)
        except rawprofile.RawProfileError:
            pass  # a documented refusal: only another exception is a finding


def _merge_target(data: bytes) -> None:
    """The bytes choose a map and a set of mutated profiles; the merge must
    either refuse with a coded error or produce evidence that reads back."""
    maps = _merge_pool()
    rng = random.Random(hashlib.sha256(data).digest())
    m_name, m_bytes, profiles = maps[rng.randrange(len(maps))]
    chosen = [p for p in profiles if rng.random() < 0.7] or profiles[:1]
    arts = []
    for i, p in enumerate(chosen):
        mutated = p if rng.random() < 0.5 else _mutate_bytes(rng, p, [data])
        arts.append(merge_model.Artifact(f"p{i}.sv0profraw", mutated))
    if rng.random() < 0.3:
        arts.append(merge_model.Artifact("extra.sv0profraw", data))
    map_arts = [merge_model.Artifact(m_name, m_bytes if rng.random() < 0.8 else _mutate_bytes(rng, m_bytes, [data]))]
    result = merge_model.merge(map_arts, arts, allow_rejected_inputs=rng.random() < 0.5)
    if result.publishable:
        read_indexed(result.data)


_POOL: list | None = None


def _merge_pool() -> list:
    global _POOL
    if _POOL is None:
        _tests_on_path()
        from test_indexed_reader import FIXTURES as SEMANTIC, fixture_inputs, raw  # noqa: N811

        pool = []
        for name in SEMANTIC:
            data, m, counts = fixture_inputs(name)
            profiles = [raw(m, counts, n) for n in (1, 2)] + [raw(m, {k: U64 for k in counts}, 3)]
            pool.append((f"{name}.sv0covmap.json", data, profiles))
        _POOL = pool
    return _POOL


def _expr_target(data: bytes) -> None:
    """The bytes are a JSON case {"terms": [...], "counts": {point: value or "sat"}}
    or, when they are not, seed a random well-typed case."""
    try:
        case = json.loads(data.decode("utf-8"))
        terms_in, counts_in = case["terms"], case["counts"]
    except (ValueError, UnicodeDecodeError, KeyError, TypeError):
        rng = random.Random(data)
        ids = [hashlib.sha256(bytes([i])).hexdigest() for i in range(rng.randrange(0, 6))]
        terms_in = [{"coefficient": rng.choice([1, -1, 2, -3, 2**31 - 1, -(2**31), 0, 2**31]), "point_id": p} for p in sorted(ids)]
        if len(terms_in) > 1 and rng.random() < 0.2:
            terms_in.reverse()
        counts_in = {p: rng.choice([0, 1, 5, U64 - 1, U64, "sat"]) for p in ids}
    counted = list(counts_in) if isinstance(counts_in, dict) else None
    terms = expr.check_expression({"terms": terms_in}, counted)
    if not isinstance(counts_in, dict):
        return
    counts = {}
    for p, v in counts_in.items():
        if v == "sat":
            counts[p] = expr.Count(U64, True)
        elif isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= U64:
            counts[p] = expr.Count.physical(v)
        else:
            return
    got = expr.evaluate(terms, counts)
    if not 0 <= got.value <= U64:
        raise Finding("expr/range", f"evaluated {got.value}")
    if not any(counts[p].inexact for _, p in terms):
        plain = sum(c * counts[p].value for c, p in terms)
        if 0 <= plain <= U64 and (got.value, got.inexact) != (plain, False):
            raise Finding("expr/exact", f"exact inputs gave {got}, the sum is {plain}")


HARNESSES = {h.name: h for h in (
    Harness("rawprofile", _files("tests/fixtures/rawprofile/*.sv0profraw"), _raw_target, (rawprofile.RawProfileError,),
            fix_bytes=_fix_raw),
    Harness("json", _files("tests/fixtures/report/*.json", "tests/fixtures/indexed/empty.json", "registries/*.json"), _json_target,
            (CanonicalJsonError,), structured=True),
    Harness("map", _files("tests/fixtures/semantic/*/expected-map.json"), lambda d: validate_map(d), (MapError,), structured=True,
            fix_tree=_self_hash("map_id", map_digest)),
    Harness("indexed", _indexed_seeds, lambda d: read_indexed(d), (IndexedError,), structured=True, fix_tree=_fix_indexed),
    Harness("report", _report_seeds, lambda d: read_report(d), (ReportError, IndexedError), structured=True),
    Harness("runset", _runset_seeds, lambda d: runset.decode_run_set(d), (runset.RunIdError,), structured=True),
    Harness("manifest", _manifest_seeds, lambda d: version_manifest.validate_manifest(d), (version_manifest.ManifestError,), structured=True,
            fix_tree=_self_hash("manifest_sha256", version_manifest.manifest_digest)),
    Harness("doctor", _files("tests/fixtures/doctor/*.json"), lambda d: doctor.validate(d), (doctor.DoctorError,), structured=True,
            fix_tree=_self_hash("doctor_sha256", doctor.doctor_digest)),
    Harness("registry", _files("registries/diagnostics-v1.json"), lambda d: validate_registry(d), (RegistryError,), structured=True,
            fix_tree=_self_hash("registry_sha256", diagnostics.registry_digest)),
    Harness("compatibility", _policy_seeds, lambda d: validate_policy(d), (PolicyError,), structured=True,
            fix_tree=_self_hash("compatibility_sha256", policy_digest)),
    Harness("release", _files("tests/fixtures/release/*.release.json"), lambda d: release.validate_manifest(d), (release.ReleaseError,),
            structured=True, fix_tree=_self_hash("release_manifest_sha256", release.manifest_digest)),
    Harness("merge", _files("tests/fixtures/rawprofile/*.sv0profraw"), _merge_target, (merge_model.MergeError,)),
    Harness("expr", lambda: [json.dumps(c).encode() for c in _expr_cases()], _expr_target, (expr.ExprError,)),
)}


def _expr_cases() -> list[dict]:
    """The fixture expressions, each with every referenced point counted once."""
    doc = json.loads((FIXTURES / "expressions" / "expressions.json").read_text())
    cases = []
    for entry in doc.get("evaluate", []):
        if isinstance(entry, dict) and isinstance(entry.get("terms"), list):
            points = [t.get("point_id") for t in entry["terms"] if isinstance(t, dict)]
            cases.append({"terms": entry["terms"], "counts": {p: 1 for p in points if isinstance(p, str)}})
    return cases or [{"terms": [], "counts": {}}]


# ── mutation ─────────────────────────────────────────────────────────────────

INTERESTING_INTS = [0, 1, -1, 2**31 - 1, 2**31, -(2**31), 2**32 - 1, 2**32, U64, U64 + 1, 2**63, -(2**63), 10**400]
INTERESTING_BYTES = [b"\x00", b"\xff", b"\x7f", b"\x80", b"\xc0\x80", b"\xed\xa0\x80", b"\\u0000", b"\\ud800", b"1e309", b"-0",
                     b"[[[[[[[[[[[[[[[[[[[[", b'"' + b"A" * 300 + b'"', b"\xef\xbb\xbf"]


def _mutate_bytes(rng: random.Random, data: bytes, others: list[bytes]) -> bytes:
    b = bytearray(data)
    for _ in range(rng.choice([1, 1, 1, 2, 3, 8])):
        op = rng.randrange(9)
        pos = rng.randrange(len(b) + 1)
        if op == 0 and b:  # flip a bit
            i = rng.randrange(len(b))
            b[i] ^= 1 << rng.randrange(8)
        elif op == 1 and b:  # set a byte
            b[rng.randrange(len(b))] = rng.choice([0, 0xFF, 0x7F, 0x80, rng.randrange(256)])
        elif op == 2:  # insert
            b[pos:pos] = rng.choice(INTERESTING_BYTES) if rng.random() < 0.5 else bytes([rng.randrange(256)])
        elif op == 3 and b:  # delete a span
            end = min(len(b), pos + rng.randrange(1, 64))
            del b[pos:end]
        elif op == 4 and b:  # truncate
            del b[rng.randrange(len(b)):]
        elif op == 5 and b:  # duplicate a span
            end = min(len(b), pos + rng.randrange(1, 64))
            b[pos:pos] = b[pos:end]
        elif op == 6 and len(b) >= 4:  # overwrite a little-endian word with an extreme value
            i = rng.randrange(len(b) - 3)
            b[i:i + 4] = rng.choice([0, 1, 0x7FFFFFFF, 0xFFFFFFFF, 0x80000000]).to_bytes(4, "little")
        elif op == 7 and others:  # splice with another seed
            other = rng.choice(others)
            cut = rng.randrange(len(other) + 1)
            b[pos:] = other[cut:]
        elif op == 8 and len(b) >= 8:  # an extreme 64-bit word
            i = rng.randrange(len(b) - 7)
            b[i:i + 8] = rng.choice([0, U64, 2**63, 1]).to_bytes(8, "little")
    return bytes(b)


def _mutate_tree(rng: random.Random, value):
    """One structural change somewhere in a decoded JSON tree."""
    if isinstance(value, dict) and value and rng.random() < 0.85:
        key = rng.choice(list(value))
        op = rng.randrange(6)
        out = dict(value)
        if op == 0:
            del out[key]
        elif op == 1:
            out[key + rng.choice(["", "_x", "\u0000", "é"])] = out[key]
        elif op == 2:
            out[key] = _mutate_tree(rng, out[key])
        elif op == 3:
            out[key] = rng.choice([None, True, 0, -1, "", [], {}, U64, U64 + 1, "x" * 5000])
        else:
            out[key] = _mutate_tree(rng, out[key])
        return out
    if isinstance(value, list) and value and rng.random() < 0.85:
        out = list(value)
        i = rng.randrange(len(out))
        op = rng.randrange(5)
        if op == 0:
            del out[i]
        elif op == 1:
            out.insert(i, out[i])
        elif op == 2:
            out[i], out[-1] = out[-1], out[i]
        else:
            out[i] = _mutate_tree(rng, out[i])
        return out
    if isinstance(value, bool) or value is None:
        return rng.choice([True, False, None, 0, "true"])
    if isinstance(value, int):
        return rng.choice(INTERESTING_INTS + [value + 1, value - 1, -value])
    if isinstance(value, str):
        return rng.choice(["", value + value, value[:-1], value.upper(), "\x00", "\ud800" if False else "‮", "../" + value,
                           "0" * len(value), "x" * 70000])
    return rng.choice([None, 0, "", [], {}])


def mutate(rng: random.Random, harness: Harness, seeds: list[bytes], corpus: list[bytes]) -> bytes:
    base = rng.choice(corpus if corpus and rng.random() < 0.5 else seeds)
    if harness.structured and rng.random() < 0.5:
        try:
            tree = json.loads(base)
        except (ValueError, UnicodeDecodeError):
            tree = None
        if tree is not None:
            for _ in range(rng.choice([1, 1, 2, 4])):
                tree = _mutate_tree(rng, tree)
            if harness.fix_tree is not None and rng.random() < 0.85:
                tree = harness.fix_tree(tree)
            try:
                return canonical_json.encode(tree)
            except (CanonicalJsonError, ValueError, TypeError, OverflowError):
                return json.dumps(tree, ensure_ascii=False).encode("utf-8", "surrogatepass") + b"\n"
    data = _mutate_bytes(rng, base, seeds)
    if harness.fix_bytes is not None and rng.random() < 0.85:
        data = harness.fix_bytes(data)
    return data


# ── execution ────────────────────────────────────────────────────────────────


def _alarm(_signum, _frame):
    raise _Timeout()


def check(harness: Harness, data: bytes, *, measure: bool = False) -> None:
    """Run one input. Raises :class:`Finding` when a rule is broken."""
    registry = diagnostics.load_registry()
    previous = signal.signal(signal.SIGALRM, _alarm)
    signal.setitimer(signal.ITIMER_REAL, TIME_LIMIT)
    if measure:
        tracemalloc.start()
    try:
        harness.target(data)
    except Finding:
        raise
    except _Timeout:
        raise Finding(f"{harness.name}/hang", f"over {TIME_LIMIT} s") from None
    except harness.errors as exc:
        code = getattr(exc, "code", None)
        if code is not None and code not in registry.entries:
            raise Finding(f"{harness.name}/code:{code}", f"{type(exc).__name__} with an unregistered code") from None
    except RecursionError:
        raise Finding(f"{harness.name}/RecursionError", "unbounded recursion") from None
    except Exception as exc:  # noqa: BLE001 - any other exception is the finding
        tb = exc.__traceback__
        while tb is not None and tb.tb_next is not None:
            tb = tb.tb_next
        where = f"{Path(tb.tb_frame.f_code.co_filename).name}:{tb.tb_lineno}" if tb is not None else "?"
        raise Finding(f"{harness.name}/{type(exc).__name__}@{where}", str(exc)[:200]) from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
        if measure:
            _, peak = tracemalloc.get_traced_memory()
            tracemalloc.stop()
            if peak > SLOPE * len(data) + BASE:
                raise Finding(f"{harness.name}/memory", f"peak {peak} bytes for a {len(data)}-byte input")


def minimize(harness: Harness, data: bytes, signature: str) -> bytes:
    """Remove chunks while the same finding persists (ddmin-style, bounded)."""

    def same(candidate: bytes) -> bool:
        try:
            check(harness, candidate)
        except Finding as f:
            return f.signature == signature
        return False

    chunk = max(1, len(data) // 2)
    deadline = time.monotonic() + 60
    while chunk >= 1 and time.monotonic() < deadline:
        i, changed = 0, False
        while i < len(data) and time.monotonic() < deadline:
            candidate = data[:i] + data[i + chunk:]
            if candidate != data and same(candidate):
                data, changed = candidate, True
            else:
                i += chunk
        if not changed:
            chunk //= 2
    return data


def fuzz(names: Iterable[str], *, seed: int, iterations: int | None, seconds: float | None, crash_dir: Path | None,
         log=print) -> list[tuple[str, str, Path | None]]:
    """Fuzz each harness; return the findings (harness, signature, file)."""
    findings: list[tuple[str, str, Path | None]] = []
    for name in names:
        harness = HARNESSES[name]
        seeds = harness.seeds()
        rng = random.Random(f"{seed}:{name}")
        corpus: list[bytes] = []
        seen: set[str] = set()
        start, n = time.monotonic(), 0
        for s in seeds:
            check(harness, s)  # every seed must itself be handled
        while (iterations is None or n < iterations) and (seconds is None or time.monotonic() - start < seconds):
            data = mutate(rng, harness, seeds, corpus)
            n += 1
            try:
                check(harness, data, measure=n % MEMORY_SAMPLE == 0)
            except Finding as f:
                if f.signature in seen:
                    continue
                seen.add(f.signature)
                small = minimize(harness, data, f.signature)
                path = None
                if crash_dir is not None:
                    path = crash_dir / name / f"{hashlib.sha256(small).hexdigest()[:16]}.bin"
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(small)
                findings.append((name, f.signature, path))
                log(f"FINDING {f.signature} ({len(small)} bytes){' -> ' + str(path) if path else ''}: {f}")
                continue
            if len(corpus) < 256 and rng.random() < 0.05:
                corpus.append(data)
        log(f"{name}: {n} inputs, {len(seen)} findings, {time.monotonic() - start:.1f} s")
    return findings


def replay(directory: Path = REGRESSIONS) -> list[tuple[Path, str]]:
    """Every checked-in regression input, run once; the findings that recur."""
    failures = []
    for path in sorted(directory.glob("*/*.bin")):
        try:
            check(HARNESSES[path.parent.name], path.read_bytes(), measure=True)
        except Finding as f:
            failures.append((path, f.signature))
    return failures


def _cap_memory(limit: int = 2 << 30) -> None:
    """Where the host enforces an address-space limit (Linux), an input that
    makes a reader allocate without bound ends as a ``MemoryError`` finding
    instead of the operating system killing the fuzzer."""
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        if sys.platform.startswith("linux") and (soft == resource.RLIM_INFINITY or soft > limit):
            resource.setrlimit(resource.RLIMIT_AS, (limit, hard))
    except (ImportError, ValueError, OSError):
        pass


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run")
    run.add_argument("--harness", action="append", choices=sorted(HARNESSES))
    run.add_argument("--iterations", type=int)
    run.add_argument("--seconds", type=float)
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--crash-dir", type=Path)
    rp = sub.add_parser("replay")
    rp.add_argument("directory", type=Path, nargs="?", default=REGRESSIONS)
    sub.add_parser("list")
    args = ap.parse_args(argv)
    if args.cmd == "list":
        print("\n".join(sorted(HARNESSES)))
        return 0
    if args.cmd == "replay":
        failures = replay(args.directory)
        for path, sig in failures:
            print(f"REGRESSION {path}: {sig}")
        return 1 if failures else 0
    if args.iterations is None and args.seconds is None:
        args.iterations = 500
    _cap_memory()
    names = args.harness or sorted(HARNESSES)
    findings = fuzz(names, seed=args.seed, iterations=args.iterations, seconds=args.seconds, crash_dir=args.crash_dir)
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
