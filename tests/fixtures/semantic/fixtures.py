# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Hand-reviewed semantic fixtures (CV-027 F0, CV-028 R0 matrix).

Each fixture returns a :class:`Fixture`: the planning decisions (made by
hand, following docs/planning-conventions.md), the expected point counts for
the program's fixed input, the hand-derived status of every source line, and
the program's exit code on both backends. Nothing here is produced by a
compiler; these are the oracle the sv0c planner must reproduce.

Regenerate the checked-in artifacts after a reviewed change:

    python3 tests/fixtures/semantic/build.py --write
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from plan import Plan, Point

HERE = Path(__file__).resolve().parent

C, P, U, N = "covered", "partial", "uncovered", "non_executable"


@dataclass
class Fixture:
    plan: Plan
    counts: dict[Point, int]
    lines: dict[str, list[str]]  # path -> status per line (1-based order)
    exit_code: int
    matrix: list[str] = field(default_factory=list)  # SPEC 28.2 rows exercised


def read(name: str, *paths: str) -> dict[str, bytes]:
    return {p: (HERE / name / p).read_bytes() for p in paths}


# ── F0 (CV-027) ─────────────────────────────────────────────────────────────


def f0() -> Fixture:
    src = read("f0", "main.sv0")
    p = Plan("f0", src)
    m = "main.sv0"

    classify = p.function(m, "classify")
    at_if = p.find(m, "if n > 10 {")[0]
    if_ = p.branch(classify, "if", p.through_block(m, "if n > 10 {"))
    at_while = p.find(m, "while i < n {")[0]
    loop = p.branch(classify, "loop", p.through_block(m, "while i < n {"))
    e = classify.entry
    p.region(classify, "initializer", p.find(m, "let mut total = 0;"), e)
    p.region(classify, "expression", p.find(m, "n > 10"), e)
    p.region(classify, "branch_body", p.through_block(m, "{", after=at_if), if_["true"], lc=False)
    p.region(classify, "assignment", p.find(m, "total = total + 100;"), if_["true"])
    p.region(classify, "initializer", p.find(m, "let mut i = 0;"), e)
    p.region(classify, "expression", p.find(m, "i < n"), loop["body"], loop["exit"])
    p.region(classify, "loop_body", p.through_block(m, "{", after=at_while), loop["body"], lc=False)
    p.region(classify, "assignment", p.find(m, "total = total + i;"), loop["body"])
    p.region(classify, "assignment", p.find(m, "i = i + 1;"), loop["body"])
    p.region(classify, "return", p.find(m, "return total;"), e)

    measure = p.function(m, "measure")
    match_span = p.through_block(m, "match s {")
    match = p.branch(measure, "match", match_span, arms=2)
    p.region(measure, "return", (p.find(m, "return match s {")[0], match_span[1] + 1), measure.entry)
    p.region(measure, "match_arm", p.find(m, "0", after=p.find(m, "Shape::Dot() =>")[1]), match["arm:0"])
    p.region(measure, "match_arm", p.find(m, "len", after=p.find(m, "Shape::Line(len) =>")[1]), match["arm:1"])

    main = p.function(m, "main")
    for stmt in ('let label = "Größe";', "let a = classify(3);", "let b = measure(Shape::Line(2));", "return a + b - 5;"):
        p.region(main, "initializer" if stmt.startswith("let") else "return", p.find(m, stmt), main.entry)

    counts = {
        classify.entry: 1,
        if_["false"]: 1,
        loop["body"]: 3,
        loop["exit"]: 1,
        measure.entry: 1,
        match["arm:1"]: 1,
        main.entry: 1,
    }
    lines = [
        N, N, N, N, N, N, N, N,  # 1-8: comments, enum, blank
        N, C, C, U, N, C, C, C, C, N, C, N,  # 9-20: classify
        N, N, C, P, C, C, N,  # 21-27: measure (24: arm 0 never taken)
        N, N, C, C, C, C, N,  # 28-34: main
    ]
    return Fixture(p, counts, {m: lines}, 0, ["functions: called once", "regions: initializer, assignment, return", "if: false only, no else", "loops: many", "match: enum, one arm never", "source text: multibyte UTF-8 string"])



# ── R0 matrix (CV-028) ──────────────────────────────────────────────────────


def functions() -> Fixture:
    m = "main.sv0"
    p = Plan("functions", read("functions", m))
    fns = {}
    for name, body in (("never", "return x + 1;"), ("once", "return x * 2;"), ("twice", "return x - 1;"), ("noop", "return 0;")):
        fns[name] = f = p.function(m, name)
        p.region(f, "return", p.find(m, body), f.entry)
    main = p.function(m, "main")
    for stmt in ("let a = once(3);", "let b = twice(a);", "let c = twice(b);"):
        p.region(main, "initializer", p.find(m, stmt), main.entry)
    p.region(main, "expression_statement", p.find(m, "noop();"), main.entry)
    p.region(main, "return", p.find(m, "return c - 4;"), main.entry)
    counts = {fns["once"].entry: 1, fns["twice"].entry: 2, fns["noop"].entry: 1, main.entry: 1}
    lines = [N, N, N, N, U, N, N, N, C, N, N, N, C, N, N, N, C, N, N, N, C, C, C, C, C, N]
    return Fixture(p, counts, {m: lines}, 0, ["functions: uncalled", "functions: called once", "functions: called repeatedly", "regions: expression-statement call"])


def branches() -> Fixture:
    m = "main.sv0"
    p = Plan("branches", read("branches", m))
    sign = p.function(m, "sign")
    s0 = sign.span[0]
    at_outer = p.find(m, "if n < 0 {", after=s0)[0]
    then_block = p.through_block(m, "{", after=at_outer)
    else_at = p.find(m, "else {", after=then_block[1])[0]
    else_block = p.through_block(m, "{", after=else_at)
    outer = p.branch(sign, "if", (at_outer, else_block[1]))
    inner_span = p.through_block(m, "if n == 0 {")
    inner = p.branch(sign, "if", inner_span)
    e = sign.entry
    p.region(sign, "expression", p.find(m, "n < 0", after=s0), e)
    p.region(sign, "branch_body", then_block, outer["true"], lc=False)
    p.region(sign, "return", p.find(m, "return 0 - 1;"), outer["true"])
    p.region(sign, "branch_body", else_block, outer["false"], lc=False)
    p.region(sign, "expression", p.find(m, "n == 0"), outer["false"])
    p.region(sign, "branch_body", p.through_block(m, "{", after=inner_span[0]), inner["true"], lc=False)
    p.region(sign, "return", p.find(m, "return 0;"), inner["true"])
    # Both earlier returns leave the function, so `return 1;` runs e - T1 - T2 times.
    p.region(sign, "return", p.find(m, "return 1;"), e, (outer["true"], -1), (inner["true"], -1))

    clamp = p.function(m, "clamp")
    c_if = p.branch(clamp, "if", p.through_block(m, "if r > 100 {"))
    p.region(clamp, "initializer", p.find(m, "let mut r = n;"), clamp.entry)
    p.region(clamp, "expression", p.find(m, "r > 100"), clamp.entry)
    p.region(clamp, "branch_body", p.through_block(m, "{", after=c_if.span[0]), c_if["true"], lc=False)
    p.region(clamp, "assignment", p.find(m, "r = 100;"), c_if["true"])
    p.region(clamp, "return", p.find(m, "return r;"), clamp.entry)

    mag = p.function(m, "magnitude")
    at_mag = p.find(m, "if n < 0 {", after=mag.span[0])[0]
    m_if = p.branch(mag, "if", (at_mag, p.block_end(m, at_mag)))
    p.region(mag, "expression", p.find(m, "n < 0", after=mag.span[0]), mag.entry)
    p.region(mag, "branch_body", p.through_block(m, "{", after=at_mag), m_if["true"], lc=False)
    p.region(mag, "return", p.find(m, "return 0 - n;"), m_if["true"])
    p.region(mag, "return", p.find(m, "return n;"), mag.entry, (m_if["true"], -1))

    main = p.function(m, "main")
    for stmt in ("let a = sign(5);", "let b = sign(0);", "let c = clamp(7);", "let d = magnitude(0 - 3);"):
        p.region(main, "initializer", p.find(m, stmt), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d - 11;"), main.entry)

    counts = {
        e: 2, outer["false"]: 2, inner["true"]: 1, inner["false"]: 1,
        clamp.entry: 1, c_if["false"]: 1,
        mag.entry: 1, m_if["true"]: 1,
        main.entry: 1,
    }
    lines = [
        N, N, N,
        N, C, U, N, C, C, N, N, C, N,  # 4-13 sign
        N, N, C, C, U, N, C, N,  # 14-21 clamp
        N, N, C, C, N, U, N,  # 22-28 magnitude
        N, N, C, C, C, C, C, N,  # 29-36 main
    ]
    return Fixture(p, counts, {m: lines}, 0, ["if: true only", "if: false only", "if: both", "if: no else", "if: else", "if: nested", "regions: return after early return"])


def loops() -> Fixture:
    m = "main.sv0"
    p = Plan("loops", read("loops", m))
    cu = p.function(m, "count_up")
    a = cu.span[0]
    cu_loop = p.branch(cu, "loop", p.through_block(m, "while i < n {", after=a))
    p.region(cu, "initializer", p.find(m, "let mut i = 0;", after=a), cu.entry)
    p.region(cu, "expression", p.find(m, "i < n", after=a), cu_loop["body"], cu_loop["exit"])
    p.region(cu, "loop_body", p.through_block(m, "{", after=cu_loop.span[0]), cu_loop["body"], lc=False)
    p.region(cu, "assignment", p.find(m, "i = i + 1;", after=a), cu_loop["body"])
    p.region(cu, "return", p.find(m, "return i;", after=a), cu.entry)

    fo = p.function(m, "first_over")
    a = fo.span[0]
    fo_loop = p.branch(fo, "loop", p.through_block(m, "while true {", after=a))
    fo_if = p.branch(fo, "if", p.through_block(m, "if i > limit {", after=a))
    p.region(fo, "initializer", p.find(m, "let mut i = 0;", after=a), fo.entry)
    p.region(fo, "expression", p.find(m, "true", after=fo_loop.span[0]), fo_loop["body"], fo_loop["exit"])
    p.region(fo, "loop_body", p.through_block(m, "{", after=fo_loop.span[0]), fo_loop["body"], lc=False)
    p.region(fo, "assignment", p.find(m, "i = i + 1;", after=a), fo_loop["body"])
    p.region(fo, "expression", p.find(m, "i > limit"), fo_loop["body"])
    p.region(fo, "branch_body", p.through_block(m, "{", after=fo_if.span[0]), fo_if["true"], lc=False)
    p.region(fo, "break", p.find(m, "break;", after=fo.span[0]), fo_if["true"])
    p.region(fo, "return", p.find(m, "return i;", after=a), fo.entry)

    od = p.function(m, "odd_sum")
    a = od.span[0]
    od_loop = p.branch(od, "loop", p.through_block(m, "while i < n {", after=a))
    od_if = p.branch(od, "if", p.through_block(m, "if i == 2 {", after=a))
    p.region(od, "initializer", p.find(m, "let mut s = 0;"), od.entry)
    p.region(od, "initializer", p.find(m, "let mut i = 0;", after=a), od.entry)
    p.region(od, "expression", p.find(m, "i < n", after=a), od_loop["body"], od_loop["exit"])
    p.region(od, "loop_body", p.through_block(m, "{", after=od_loop.span[0]), od_loop["body"], lc=False)
    p.region(od, "assignment", p.find(m, "i = i + 1;", after=a), od_loop["body"])
    p.region(od, "expression", p.find(m, "i == 2"), od_loop["body"])
    p.region(od, "branch_body", p.through_block(m, "{", after=od_if.span[0]), od_if["true"], lc=False)
    p.region(od, "continue", p.find(m, "continue;", after=od.span[0]), od_if["true"])
    p.region(od, "assignment", p.find(m, "s = s + i;"), od_loop["body"], (od_if["true"], -1))
    p.region(od, "return", p.find(m, "return s;"), od.entry)

    main = p.function(m, "main")
    for stmt in ("let a = count_up(0);", "let b = count_up(1);", "let c = count_up(3);", "let d = first_over(2);", "let e = odd_sum(3);"):
        p.region(main, "initializer", p.find(m, stmt), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d + e - 11;"), main.entry)

    counts = {
        cu.entry: 3, cu_loop["body"]: 4, cu_loop["exit"]: 3,
        fo.entry: 1, fo_loop["body"]: 3, fo_if["true"]: 1, fo_if["false"]: 2,
        od.entry: 1, od_loop["body"]: 3, od_loop["exit"]: 1, od_if["true"]: 1, od_if["false"]: 2,
        main.entry: 1,
    }
    lines = [
        N, N, N,
        N, C, C, C, N, C, N,  # 4-10 count_up
        N, N, C, C, C, C, C, N, N, C, N,  # 11-21 first_over
        N, N, C, C, C, C, C, C, N, C, N, C, N,  # 22-34 odd_sum
        N, N, C, C, C, C, C, C, N,  # 35-43 main
    ]
    return Fixture(p, counts, {m: lines}, 0, ["loops: zero iterations", "loops: one iteration", "loops: many iterations", "loops: break", "loops: continue", "regions: break", "regions: continue"])


def match_() -> Fixture:
    m = "main.sv0"
    p = Plan("match", read("match", m))
    code = p.function(m, "code")
    cm = p.through_block(m, "match c {")
    cb = p.branch(code, "match", cm, arms=3)
    p.region(code, "return", (p.find(m, "return match c {")[0], cm[1] + 1), code.entry)
    for i, (pat, result) in enumerate((("Color::Red() =>", "1"), ("Color::Green() =>", "2"), ("Color::Blue() =>", "3"))):
        p.region(code, "match_arm", p.find(m, result, after=p.find(m, pat)[1]), cb[f"arm:{i}"])
    bucket = p.function(m, "bucket")
    bm = p.through_block(m, "match n {")
    bb = p.branch(bucket, "match", bm, arms=3)
    p.region(bucket, "return", (p.find(m, "return match n {")[0], bm[1] + 1), bucket.entry)
    for i, (pat, result) in enumerate((("0 =>", "10"), ("1 =>", "20"), ("_ =>", "30"))):
        p.region(bucket, "match_arm", p.find(m, result, after=p.find(m, pat, after=bm[0])[1]), bb[f"arm:{i}"])
    main = p.function(m, "main")
    for stmt in ("let a = code(Color::Red());", "let b = code(Color::Blue());", "let c = bucket(0);", "let d = bucket(7);"):
        p.region(main, "initializer", p.find(m, stmt), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d - 44;"), main.entry)
    counts = {code.entry: 2, cb["arm:0"]: 1, cb["arm:2"]: 1, bucket.entry: 2, bb["arm:0"]: 1, bb["arm:2"]: 1, main.entry: 1}
    lines = [N, N, N, N, N, N, N, N, N, N, C, C, P, C, C, N, N, N, C, C, P, C, C, N, N, N, C, C, C, C, C, N]
    return Fixture(p, counts, {m: lines}, 0, ["match: enum arms", "match: integer with default arm", "match: arm never taken"])


def source_text() -> Fixture:
    m = "main.sv0"
    p = Plan("source-text", read("source-text", m))
    main = p.function(m, "main")
    e = main.entry
    if_span = p.through_block(m, "if a > 5 {")
    b = p.branch(main, "if", if_span)
    p.region(main, "initializer", p.find(m, "let a = 1;"), e)
    p.region(main, "initializer", p.find(m, "let b = 2;"), e)
    p.region(main, "initializer", p.find(m, 'let s = "日本";'), e)
    p.region(main, "expression", p.find(m, "a > 5"), e)
    p.region(main, "branch_body", p.through_block(m, "{", after=if_span[0]), b["true"], lc=False)
    p.region(main, "return", p.find(m, "return 9;"), b["true"])
    p.region(main, "return", p.find(m, "return a + b - 3;"), e)
    counts = {e: 1, b["false"]: 1}
    lines = [N, N, N, N, C, C, P, C, N]
    return Fixture(p, counts, {m: lines}, 0, ["source text: CRLF line endings", "source text: tabs", "source text: no final newline", "source text: CJK multibyte string", "regions: several on one line", "regions: partial line"])


def project() -> Fixture:
    paths = ("lib/util.sv0", "main.sv0", "util/util.sv0")
    p = Plan("project", read("project", *paths))
    triple = p.function("lib/util.sv0", "triple", "lib::triple")
    p.region(triple, "return", p.find("lib/util.sv0", "return x * 3;"), triple.entry)
    doubled = p.function("util/util.sv0", "doubled", "util::doubled")
    p.region(doubled, "return", p.find("util/util.sv0", "return x * 2;"), doubled.entry)
    main = p.function("main.sv0", "main")
    for stmt in ("let a = doubled(2);", "let b = triple(a);"):
        p.region(main, "initializer", p.find("main.sv0", stmt), main.entry)
    p.region(main, "return", p.find("main.sv0", "return b - 12;"), main.entry)
    counts = {triple.entry: 1, doubled.entry: 1, main.entry: 1}
    lines = {
        "lib/util.sv0": [N, N, N, N, C, N],
        "main.sv0": [N, N, N, N, N, N, N, C, C, C, N],
        "util/util.sv0": [N, N, N, N, C, N],
    }
    return Fixture(p, counts, lines, 0, ["projects: many files", "projects: same basename in two directories", "projects: module-qualified names"])


FIXTURES = {
    "f0": f0,
    "functions": functions,
    "branches": branches,
    "loops": loops,
    "match": match_,
    "source-text": source_text,
    "project": project,
}
