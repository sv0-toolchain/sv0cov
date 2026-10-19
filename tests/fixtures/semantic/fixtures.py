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
    p.region(measure, "expression", p.find(m, "s", after=p.find(m, "match s {")[0] + len("match ")), measure.entry)
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
    # `while true` can never evaluate false: its exit is statically
    # unreachable, uncounted, and the condition counts body only (CV-203).
    fo_loop = p.branch(fo, "loop", p.through_block(m, "while true {", after=a),
                       unreachable={"exit": "sv0c:loop:condition-literal-true"})
    fo_if = p.branch(fo, "if", p.through_block(m, "if i > limit {", after=a))
    p.region(fo, "initializer", p.find(m, "let mut i = 0;", after=a), fo.entry)
    p.region(fo, "expression", p.find(m, "true", after=fo_loop.span[0]), fo_loop["body"])
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
    p.region(od, "initializer", p.find(m, "let mut s = 0;", after=a), od.entry)
    p.region(od, "initializer", p.find(m, "let mut i = 0;", after=a), od.entry)
    p.region(od, "expression", p.find(m, "i < n", after=a), od_loop["body"], od_loop["exit"])
    p.region(od, "loop_body", p.through_block(m, "{", after=od_loop.span[0]), od_loop["body"], lc=False)
    p.region(od, "assignment", p.find(m, "i = i + 1;", after=a), od_loop["body"])
    p.region(od, "expression", p.find(m, "i == 2"), od_loop["body"])
    p.region(od, "branch_body", p.through_block(m, "{", after=od_if.span[0]), od_if["true"], lc=False)
    p.region(od, "continue", p.find(m, "continue;", after=od.span[0]), od_if["true"])
    p.region(od, "assignment", p.find(m, "s = s + i;"), od_loop["body"], (od_if["true"], -1))
    p.region(od, "return", p.find(m, "return s;"), od.entry)

    # for: the iterable is evaluated once per entry; body counts iterations
    # entered, exit an exhausted iterator (not a break).
    fs = p.function(m, "for_sum")
    a = fs.span[0]
    fs_loop = p.branch(fs, "loop", p.through_block(m, "for k in 0..n {", after=a))
    fs_if = p.branch(fs, "if", p.through_block(m, "if k == 3 {", after=a))
    p.region(fs, "initializer", p.find(m, "let mut s = 0;", after=a), fs.entry)
    p.region(fs, "expression", p.find(m, "0..n", after=a), fs.entry)
    p.region(fs, "loop_body", p.through_block(m, "{", after=p.find(m, "0..n", after=a)[1]), fs_loop["body"], lc=False)
    p.region(fs, "expression", p.find(m, "k == 3", after=a), fs_loop["body"])
    p.region(fs, "branch_body", p.through_block(m, "{", after=fs_if.span[0]), fs_if["true"], lc=False)
    p.region(fs, "break", p.find(m, "break;", after=a), fs_if["true"])
    p.region(fs, "assignment", p.find(m, "s = s + k;", after=a), fs_loop["body"], (fs_if["true"], -1))
    p.region(fs, "return", p.find(m, "return s;", after=a), fs.entry)

    # loop { }: no condition, so no condition region and an unreachable exit.
    un = p.function(m, "until")
    a = un.span[0]
    un_loop = p.branch(un, "loop", p.through_block(m, "loop {", after=a),
                       unreachable={"exit": "sv0c:loop:no-condition"})
    un_if = p.branch(un, "if", p.through_block(m, "if i >= n {", after=a))
    p.region(un, "initializer", p.find(m, "let mut i = 0;", after=a), un.entry)
    p.region(un, "loop_body", p.through_block(m, "{", after=un_loop.span[0]), un_loop["body"], lc=False)
    p.region(un, "assignment", p.find(m, "i = i + 1;", after=a), un_loop["body"])
    p.region(un, "expression", p.find(m, "i >= n", after=a), un_loop["body"])
    p.region(un, "branch_body", p.through_block(m, "{", after=un_if.span[0]), un_if["true"], lc=False)
    p.region(un, "break", p.find(m, "break;", after=a), un_if["true"])
    p.region(un, "return", p.find(m, "return i;", after=a), un.entry)

    main = p.function(m, "main")
    for stmt in ("let a = count_up(0);", "let b = count_up(1);", "let c = count_up(3);", "let d = first_over(2);", "let e = odd_sum(3);",
                 "let f = for_sum(0);", "let g = for_sum(2);", "let h = for_sum(5);", "let u = until(2);"):
        p.region(main, "initializer", p.find(m, stmt), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d + e + f + g + h + u - 17;"), main.entry)

    counts = {
        cu.entry: 3, cu_loop["body"]: 4, cu_loop["exit"]: 3,
        fo.entry: 1, fo_loop["body"]: 3, fo_if["true"]: 1, fo_if["false"]: 2,
        od.entry: 1, od_loop["body"]: 3, od_loop["exit"]: 1, od_if["true"]: 1, od_if["false"]: 2,
        # for_sum(0): exit; (2): k=0,1, exit; (5): k=0..3, break at 3.
        fs.entry: 3, fs_loop["body"]: 6, fs_loop["exit"]: 2, fs_if["true"]: 1, fs_if["false"]: 5,
        # until(2): i=1 (continue), i=2 (break).
        un.entry: 1, un_loop["body"]: 2, un_if["true"]: 1, un_if["false"]: 1,
        main.entry: 1,
    }
    lines = [
        N, N, N,
        N, C, C, C, N, C, N,  # 4-10 count_up
        N, N, C, C, C, C, C, N, N, C, N,  # 11-21 first_over
        N, N, C, C, C, C, C, C, N, C, N, C, N,  # 22-34 odd_sum
        N, N, C, C, C, C, N, C, N, C, N,  # 35-45 for_sum
        N, N, C, N, C, C, C, N, N, C, N,  # 46-56 until (`loop {` has no region of its own)
        N, N, C, C, C, C, C, C, C, C, C, C, N,  # 57-69 main
    ]
    return Fixture(p, counts, {m: lines}, 0, ["loops: zero iterations", "loops: one iteration", "loops: many iterations", "loops: break", "loops: continue", "loops: for", "loops: loop", "loops: unreachable exit", "regions: break", "regions: continue"])


def match_() -> Fixture:
    m = "main.sv0"
    p = Plan("match", read("match", m))
    code = p.function(m, "code")
    cm = p.through_block(m, "match c {")
    cb = p.branch(code, "match", cm, arms=3)
    p.region(code, "return", (p.find(m, "return match c {")[0], cm[1] + 1), code.entry)
    p.region(code, "expression", p.find(m, "c", after=p.find(m, "match c {")[0] + len("match ")), code.entry)
    for i, (pat, result) in enumerate((("Color::Red() =>", "1"), ("Color::Green() =>", "2"), ("Color::Blue() =>", "3"))):
        p.region(code, "match_arm", p.find(m, result, after=p.find(m, pat)[1]), cb[f"arm:{i}"])
    bucket = p.function(m, "bucket")
    bm = p.through_block(m, "match n {")
    bb = p.branch(bucket, "match", bm, arms=3)
    p.region(bucket, "return", (p.find(m, "return match n {")[0], bm[1] + 1), bucket.entry)
    p.region(bucket, "expression", p.find(m, "n", after=p.find(m, "match n {")[0] + len("match ")), bucket.entry)
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
    p.region(main, "return", p.find(m, "return a + b - 3;"), e, (b["true"], -1))
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


def question() -> Fixture:
    m = "main.sv0"
    p = Plan("question", read("question", m))

    def early(fn_name: str, first: str, last: str):
        """`if <first> { return ...; } return <last>;` as in the branches fixture."""
        fn = p.function(m, fn_name)
        span = p.through_block(m, f"if {first} {{")
        b = p.branch(fn, "if", span)
        p.region(fn, "expression", p.find(m, first), fn.entry)
        p.region(fn, "branch_body", p.through_block(m, "{", after=span[0]), b["true"], lc=False)
        p.region(fn, "return", p.find(m, "return", after=span[0])[0:1] + (p.find(m, ";", after=span[0])[1],), b["true"])
        p.region(fn, "return", p.find(m, last), fn.entry, (b["true"], -1))
        return fn, b

    def mark(fn, stmt: str, occurrence: int = 0):
        """The `?` number ``occurrence`` inside the statement or condition ``stmt``."""
        at = p.find(m, stmt)[0]
        return p.question(fn, p.find(m, "?", occurrence, after=at))

    pick, pb = early("pick", "n > 0", "return Opt::None;")
    check, cb = early("check", "n < 10", "return Res::Err(n);")

    # One `?`: the statement counts every start; what follows it counts the
    # starts that did not return early.
    one = {}
    for name, stmt, ret in (("sure", "let v: i32 = pick(n + 1)?;", "return Opt::Some(v + 1);"),
                            ("plain", "let v: i32 = pick(n)?;", "return Opt::Some(v + 1);"),
                            ("pass_on", "let v: i32 = o?;", "return Opt::Some(v * 2);")):
        fn = p.function(m, name)
        p.region(fn, "initializer", p.find(m, stmt), fn.entry)
        q = mark(fn, stmt)
        p.region(fn, "return", p.find(m, ret, after=fn.span[0]), fn.entry, (q, -1))
        one[name] = (fn, q)

    # Two in one statement: each is its own point, and both leave the function.
    twice = p.function(m, "twice")
    ts = "let s: i32 = pick(a)? + pick(b)?;"
    p.region(twice, "initializer", p.find(m, ts), twice.entry)
    tq1, tq2 = mark(twice, ts, 0), mark(twice, ts, 1)
    p.region(twice, "return", p.find(m, "return Opt::Some(s);"), twice.entry, (tq1, -1), (tq2, -1))

    # In a loop body: the rest of the iteration and the code after the loop
    # both lose the early returns.
    total = p.function(m, "total")
    tw = p.through_block(m, "while i < limit {")
    tl = p.branch(total, "loop", tw)
    p.region(total, "initializer", p.find(m, "let mut sum: i32 = 0;"), total.entry)
    p.region(total, "initializer", p.find(m, "let mut i: i32 = 0;"), total.entry)
    p.region(total, "expression", p.find(m, "i < limit"), tl["body"], tl["exit"])
    p.region(total, "loop_body", p.through_block(m, "{", after=tw[0]), tl["body"], lc=False)
    p.region(total, "assignment", p.find(m, "sum = sum + check(i * 4)?;"), tl["body"])
    lq = mark(total, "sum = sum + check(i * 4)?;")
    p.region(total, "assignment", p.find(m, "i = i + 1;"), tl["body"], (lq, -1))
    p.region(total, "return", p.find(m, "return Res::Ok(sum);"), total.entry, (lq, -1))

    # In a loop condition: an evaluation ends in body, exit, or the early return.
    drain = p.function(m, "drain")
    dw = p.through_block(m, "while pick(k)? > 1 {")
    dl = p.branch(drain, "loop", dw)
    dq = mark(drain, "pick(k)? > 1")
    p.region(drain, "initializer", p.find(m, "let mut k: i32 = n;"), drain.entry)
    p.region(drain, "expression", p.find(m, "pick(k)? > 1"), dl["body"], dl["exit"], dq)
    p.region(drain, "loop_body", p.through_block(m, "{", after=dw[0]), dl["body"], lc=False)
    p.region(drain, "assignment", p.find(m, "k = k - 1;"), dl["body"])
    p.region(drain, "return", p.find(m, "return Opt::Some(k);"), drain.entry, (dq, -1))

    arms = {}
    for name, scrut, results in (("some_or", "o", (("Opt::Some(x) =>", "x"), ("Opt::None =>", "d"))),
                                 ("ok_or", "r", (("Res::Ok(x) =>", "x"), ("Res::Err(x) =>", "d - x")))):
        fn = p.function(m, name)
        ms = p.through_block(m, f"match {scrut} {{")
        mb = p.branch(fn, "match", ms, arms=2)
        p.region(fn, "return", (p.find(m, f"return match {scrut} {{")[0], ms[1] + 1), fn.entry)
        p.region(fn, "expression", p.find(m, scrut, after=ms[0] + len("match ")), fn.entry)
        for i, (pat, result) in enumerate(results):
            p.region(fn, "match_arm", p.find(m, result, after=p.find(m, pat)[1]), mb[f"arm:{i}"])
        arms[name] = (fn, mb)

    main = p.function(m, "main")
    for start in ("let a = ", "let b = ", "let c = ", "let d = ", "let e = "):
        at = p.find(m, start)[0]
        p.region(main, "initializer", (at, p.find(m, ";", after=at)[1]), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d + e - 111130;"), main.entry)

    (sure, sq), (plain, pq), (pass_on, oq) = one["sure"], one["plain"], one["pass_on"]
    (some_or, sm), (ok_or, om) = arms["some_or"], arms["ok_or"]
    counts = {
        pick.entry: 12, pb["true"]: 8, pb["false"]: 4,
        check.entry: 6, cb["true"]: 5, cb["false"]: 1,
        sure.entry: 1,
        plain.entry: 2, pq: 1,
        twice.entry: 3, tq1: 1, tq2: 1,
        pass_on.entry: 2, oq: 1,
        total.entry: 2, tl["body"]: 6, tl["exit"]: 1, lq: 1,
        drain.entry: 2, dl["body"]: 2, dl["exit"]: 1, dq: 1,
        some_or.entry: 10, sm["arm:0"]: 5, sm["arm:1"]: 5,
        ok_or.entry: 2, om["arm:0"]: 1, om["arm:1"]: 1,
        main.entry: 1,
    }
    fn2 = [N, C, C, N]  # a function of two statements, then a blank line
    lines = ([N] * 14 + [C, C, N, C, N, N] + [N, C, C, N, C, N, N] + fn2 + [N] + fn2 + [N] + fn2 + [N] + fn2 + [N]
             + [N, C, C, C, C, C, N, C, N, N] + [N, C, C, C, N, C, N, N] + [N, C, C, C, C, N, N] + [N, C, C, C, C, N, N]
             + [N, C, C, C, C, C, C, N])
    return Fixture(p, counts, {m: lines}, 0, ["question: never propagates", "question: propagates", "question: twice in one statement", "question: on a variable", "question: in a loop body", "question: in a loop condition", "regions: synthetic support"])


# ── R0.1 (CV-307) ──────────────────────────────────────────────────────────


def boolean() -> Fixture:
    m = "main.sv0"
    p = Plan("boolean", read("boolean", m))

    def short(fn: Function, text: str, rhs: tuple[int, int], after: int = 0) -> Branch:
        """The short circuit spelled ``text``; its right operand ``rhs`` is an
        `expression` region counted by `evaluated`."""
        b = p.branch(fn, "short_circuit", p.find(m, text, after=after))
        p.region(fn, "expression", rhs, b["evaluated"])
        return b

    seen = p.function(m, "seen")
    p.region(seen, "return", p.find(m, "return b;"), seen.entry)

    both = p.function(m, "both")
    p.region(both, "return", p.find(m, "return a && seen(b);"), both.entry)
    bb = short(both, "a && seen(b)", p.find(m, "seen(b)", after=both.span[0]))

    either = p.function(m, "either")
    p.region(either, "return", p.find(m, "return a || seen(b);"), either.entry)
    eb = short(either, "a || seen(b)", p.find(m, "seen(b)", after=either.span[0]))

    # `a && b && seen(c)` is `(a && b) && seen(c)`: two decisions starting at `a`.
    chain = p.function(m, "chain")
    p.region(chain, "return", p.find(m, "return a && b && seen(c);"), chain.entry)
    cs = chain.span[0]
    c_outer = short(chain, "a && b && seen(c)", p.find(m, "seen(c)", after=cs), after=cs)
    inner_b = p.find(m, "b && seen(c)", after=cs)[0]
    c_inner = short(chain, "a && b", (inner_b, inner_b + 1), after=cs)

    # `a || b && seen(c)` is `a || (b && seen(c))`.
    mixed = p.function(m, "mixed")
    p.region(mixed, "return", p.find(m, "return a || b && seen(c);"), mixed.entry)
    ms = mixed.span[0]
    m_outer = short(mixed, "a || b && seen(c)", p.find(m, "b && seen(c)", after=ms), after=ms)
    m_inner = short(mixed, "b && seen(c)", p.find(m, "seen(c)", after=ms), after=ms)

    gate = p.function(m, "gate")
    g_if = p.branch(gate, "if", p.through_block(m, "if ready && n > 2 {"))
    p.region(gate, "expression", p.find(m, "ready && n > 2"), gate.entry)
    g_sc = short(gate, "ready && n > 2", p.find(m, "n > 2"))
    p.region(gate, "branch_body", p.through_block(m, "{", after=g_if.span[0]), g_if["true"], lc=False)
    p.region(gate, "return", p.find(m, "return 1;", after=gate.span[0]), g_if["true"])
    p.region(gate, "return", p.find(m, "return 0;", after=gate.span[0]), gate.entry, (g_if["true"], -1))

    # Called only with `ready` false: the right operand never runs, so its
    # line is partial (SPEC 27.3).
    never = p.function(m, "never")
    p.region(never, "initializer", p.find(m, "let ok: bool = ready && seen(true);"), never.entry)
    n_sc = short(never, "ready && seen(true)", p.find(m, "seen(true)"))
    p.region(never, "return", p.find(m, "return ok;"), never.entry)

    count = p.function(m, "count")
    k_if = p.branch(count, "if", p.through_block(m, "if x {"))
    p.region(count, "expression", p.find(m, "x", after=k_if.span[0] + 3), count.entry)
    p.region(count, "branch_body", p.through_block(m, "{", after=k_if.span[0]), k_if["true"], lc=False)
    p.region(count, "return", p.find(m, "return 1;", after=count.span[0]), k_if["true"])
    p.region(count, "return", p.find(m, "return 0;", after=count.span[0]), count.entry, (k_if["true"], -1))

    main = p.function(m, "main")
    for start in ("let a = ", "let b = ", "let c = ", "let d = ", "let e = ", "let f = "):
        at = p.find(m, start)[0]
        p.region(main, "initializer", (at, p.find(m, ";", after=at)[1]), main.entry)
    p.region(main, "return", p.find(m, "return a + b + c + d + e + f - 8;"), main.entry)

    counts = {
        seen.entry: 8,
        both.entry: 4, bb["evaluated"]: 2, bb["skipped"]: 2,
        either.entry: 4, eb["evaluated"]: 2, eb["skipped"]: 2,
        chain.entry: 4, c_inner["evaluated"]: 3, c_inner["skipped"]: 1, c_outer["evaluated"]: 2, c_outer["skipped"]: 2,
        mixed.entry: 4, m_outer["evaluated"]: 3, m_outer["skipped"]: 1, m_inner["evaluated"]: 2, m_inner["skipped"]: 1,
        gate.entry: 3, g_if["true"]: 1, g_if["false"]: 2, g_sc["evaluated"]: 2, g_sc["skipped"]: 1,
        never.entry: 1, n_sc["evaluated"]: 0, n_sc["skipped"]: 1,
        count.entry: 17, k_if["true"]: 7, k_if["false"]: 10,
        main.entry: 1,
    }
    fn1 = [N, C, N, N]  # a function of one statement, then a blank line
    lines = ([N] * 3 + fn1 * 5 + [N, C, C, N, C, N, N] + [N, P, C, N, N] + [N, C, C, N, C, N, N]
             + [N] + [C] * 7 + [N])
    return Fixture(p, counts, {m: lines}, 0, ["boolean: && all truth combinations", "boolean: || all truth combinations",
                                              "boolean: chain", "boolean: mixed precedence", "boolean: in an if condition",
                                              "boolean: right operand never evaluated (partial line)"])


FIXTURES = {
    "f0": f0,
    "functions": functions,
    "branches": branches,
    "loops": loops,
    "match": match_,
    "source-text": source_text,
    "project": project,
    "question": question,
    "boolean": boolean,
}
