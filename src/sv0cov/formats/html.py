# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The HTML report (CV-309; SPEC 20.2.1, 21.2, 17.4, 19.5, 23.2;
COV-REP-002, COV-SEC-003, AC-020, AC-021).

:func:`render_html` is a pure view of one validated native report and the
current bytes of its source files: one self-contained UTF-8 document with
its style, script, navigation data and annotated sources inside. Like the
terminal report it computes no coverage fact of its own; per-context
numbers come from :func:`sv0cov.model.context.context_view`.

- **Offline.** A Content-Security-Policy of ``default-src 'none'`` admits
  only the document's own style and script, pinned by their SHA-256. The
  document has no URL but ``#`` fragments, no external resource, no form
  and no event-handler attribute, so it can make no request.
- **Escaped.** Every text from a source file, a path, a context, a reason,
  a name or a diagnostic is escaped for HTML after its control and
  line-reordering characters are made visible (as in the terminal report;
  tabs in source lines are kept). Navigation data is JSON in a data block
  with ``<``, ``>`` and ``&`` escaped, and the script changes only text
  and class names, never markup.
- **Navigable.** A skip link, landmarks, a section index, a table of files
  and functions linking to their sources, and one chain through every
  uncovered or partial line and every line with an outcome not taken: each
  stop links to the next, so the chain works without the script; with it,
  ``n`` and ``p`` move along the chain of the context being shown.
- **Status in words.** Every status is written out; color only repeats it.
- **Contexts.** With two or more contexts, a filter shows the summary, the
  file and function metrics, line statuses and outcome counts of one
  context, or of all of them (the aggregate, the default).
- **Deterministic.** No clock, locale or randomness: the same report and
  sources give the same bytes.

:func:`check_html` is the structural check run before publication: it
fails on anything that would let the document reach the network or break
its own navigation.
"""

from __future__ import annotations

import base64
import hashlib
import html
import json
from html.parser import HTMLParser
from typing import Mapping

from sv0cov.diagnostics import escape_text
from sv0cov.formats.terminal import (COMPARISON, CONTRACT, ELIGIBILITY, MEMBERS, METRICS, RESULT, TITLE, _plural, change_line,
                                     count_text, exclusion_audit, percent, ranges, ratchet_line)
from sv0cov.model.context import context_view
from sv0cov.model.report import excluded_units

LINE_CODE = {"covered": "c", "partial": "p", "uncovered": "u", "non_executable": "n", "excluded": "x"}
OUTCOME_CODE = {"covered": "c", "uncovered": "u", "excluded": "x", "statically_unreachable": "s"}
STATUS_WORD = {"covered": "covered", "partial": "partial", "uncovered": "uncovered", "non_executable": "", "excluded": "excluded"}
ALL_METRICS = (*METRICS, CONTRACT)

STYLE = """
:root{color-scheme:light;--fg:#1b1b1b;--muted:#4a4a4a;--line:#d0d0d0;--cov:#dff3e4;--par:#fff1c2;--unc:#fbdde0;--exc:#ececec;--focus:#0b57d0}
*{box-sizing:border-box}
body{margin:0;font:15px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--fg);background:#fff;overflow-wrap:anywhere}
select{max-width:100%}
a{color:#0b4fb3}
a:focus,tr:focus,select:focus{outline:3px solid var(--focus);outline-offset:1px}
.skip{position:absolute;left:-999px;top:0;background:#fff;padding:.5em}
.skip:focus{left:.5em}
header,nav,main,footer{padding:0 1.25em}
header{border-bottom:1px solid var(--line)}
nav ul{list-style:none;padding:0;display:flex;flex-wrap:wrap;gap:.25em 1.25em}
h1{font-size:1.5em}h2{font-size:1.25em;margin-top:2em}h3{font-size:1.05em;margin-top:1.5em}
table{border-collapse:collapse;margin:.5em 0}
th,td{border:1px solid var(--line);padding:.15em .5em;text-align:left;vertical-align:top}
td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
dl.kv{display:grid;grid-template-columns:max-content auto;gap:.15em 1em}
dl.kv dt{font-weight:600}dl.kv dd{margin:0}
.word{font-weight:700}
code,.src td.code,.hash{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.hash{overflow-wrap:anywhere}
.src{width:100%}
.src td,.src th{border:0;padding:0 .5em}
.src td.code{white-space:pre;tab-size:4;width:100%}
.src th{font-weight:400;color:var(--muted);text-align:right}
.src td.st{white-space:nowrap;font-size:12px}
.wrap{overflow-x:auto}
.src tr.note td{padding-bottom:.2em}
tr.l-c td.code{background:var(--cov)}tr.l-p td.code{background:var(--par)}
tr.l-u td.code{background:var(--unc)}tr.l-x td.code{background:var(--exc)}
.o-u{background:var(--unc)}.o-c{background:var(--cov)}
.ann{color:var(--muted);font-size:12px;white-space:normal}
.nx{font-size:12px}
footer{border-top:1px solid var(--line);color:var(--muted);margin-top:3em;padding-bottom:2em}
""".strip() + "\n"

SCRIPT = """
(function () {
  "use strict";
  var block = document.getElementById("sv0cov-data");
  if (!block) { return; }
  var data = JSON.parse(block.textContent);
  var lineWords = {c: "covered", p: "partial", u: "uncovered", n: "", x: "excluded"};
  var shown = 0;
  function apply(v) {
    var view = data.views[v];
    shown = v;
    var cells = document.querySelectorAll("[data-m]");
    for (var i = 0; i < cells.length; i++) {
      var t = view.m[cells[i].getAttribute("data-m")];
      if (t !== undefined) { cells[i].textContent = t; }
    }
    var rows = document.querySelectorAll("tr[data-l]");
    for (var j = 0; j < rows.length; j++) {
      var code = view.l.charAt(Number(rows[j].getAttribute("data-l")));
      rows[j].className = "l-" + code;
      var st = rows[j].querySelector("td.st");
      if (st) { st.textContent = lineWords[code]; }
    }
    var outs = document.querySelectorAll("[data-o]");
    for (var k = 0; k < outs.length; k++) {
      var n = Number(outs[k].getAttribute("data-o"));
      outs[k].className = "o-" + view.u.charAt(n);
      var count = outs[k].querySelector(".cnt");
      if (count) { count.textContent = view.o[n]; }
    }
    var label = document.getElementById("sv0cov-shown");
    if (label) { label.textContent = view.name; }
  }
  function stops() {
    var view = data.views[shown];
    var rows = document.querySelectorAll("tr[data-l]");
    var out = [];
    for (var i = 0; i < rows.length; i++) {
      var code = view.l.charAt(Number(rows[i].getAttribute("data-l")));
      var missed = rows[i].querySelector(".o-u");
      if (code === "u" || code === "p" || missed) { out.push(rows[i]); }
    }
    return out;
  }
  function move(step) {
    var list = stops();
    if (list.length === 0) { return; }
    var at = list.indexOf(document.activeElement);
    var next = at < 0 ? (step > 0 ? 0 : list.length - 1) : (at + step + list.length) % list.length;
    list[next].focus();
    list[next].scrollIntoView({block: "center"});
  }
  var select = document.getElementById("sv0cov-context");
  if (select) {
    select.addEventListener("change", function () { apply(Number(select.value)); });
  }
  document.addEventListener("keydown", function (e) {
    var tag = e.target && e.target.tagName;
    if (e.altKey || e.ctrlKey || e.metaKey || tag === "SELECT" || tag === "INPUT" || tag === "TEXTAREA") { return; }
    if (e.key === "n" || e.key === "j") { move(1); e.preventDefault(); }
    else if (e.key === "p" || e.key === "k") { move(-1); e.preventDefault(); }
  });
})();
""".strip() + "\n"


def _digest(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii") + "'"


CSP = (f"default-src 'none'; style-src {_digest(STYLE)}; script-src {_digest(SCRIPT)}; img-src 'none'; "
       "connect-src 'none'; font-src 'none'; form-action 'none'; base-uri 'none'; frame-ancestors 'none'")


def esc(text: str) -> str:
    """Untrusted text for HTML: controls and reordering characters made
    visible, then markup characters escaped."""
    return html.escape(escape_text(text), quote=True)


def esc_code(line: str) -> str:
    """A source line: as :func:`esc`, but tabs stay tabs."""
    return "\t".join(esc(part) for part in line.split("\t"))


def _quoted(text: str | None) -> str:
    return "(default)" if text is None else '"' + escape_text(text.replace("\\", "\\\\")).replace('"', '\\"') + '"'


def _json_block(obj: object) -> str:
    """JSON that cannot end its script element or open a comment."""
    text = json.dumps(obj, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return text.replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")


def _metric_texts(summary: dict) -> dict[str, str]:
    out = {}
    for key, _ in ALL_METRICS:
        m = summary.get(key)
        out[f"{key}:f"] = "-" if m is None else f"{m['covered']}/{m['total']}"
        out[f"{key}:p"] = "" if m is None else percent(m["ratio"])
        if key == "line":
            out["line:x"] = "" if m is None or m["partial"] is None else f"{m['partial']} partial"
    return out


def _view_data(name: str, view: dict) -> dict:
    m = {f"S:{k}": v for k, v in _metric_texts(view["summary"]).items()}
    for s in view["sources"]:
        m.update({f"F{s['source_index']}:{k}": v for k, v in _metric_texts(s["summary"]).items()})
    for e in view["entities"]:
        if e["kind"] == "function":
            m.update({f"E{e['entity_index']}:{k}": v for k, v in _metric_texts(e["summary"]).items()})
    outcomes = [o for b in view["branches"] for o in b["outcomes"]]
    return {"name": name, "m": m, "l": "".join(LINE_CODE[x["status"]] for x in view["lines"]),
            "o": [count_text(o["count"]) for o in outcomes], "u": "".join(OUTCOME_CODE[o["status"]] for o in outcomes)}


class _Page:
    def __init__(self, report: dict, sources: Mapping[str, bytes | None]) -> None:
        self.r = report
        self.sources = sources
        self.out: list[str] = []
        self.path = {s["source_index"]: s["path"] for s in report["sources"]}
        self.order = sorted(self.path, key=lambda i: self.path[i].encode("utf-8"))
        self.entity = {e["entity_index"]: e for e in report["entities"]}
        self.outcome_index: dict[tuple[int, int], int] = {}
        for b in report["branches"]:
            for o in b["outcomes"]:
                self.outcome_index[(b["branch_index"], o["ordinal"])] = len(self.outcome_index)
        self.filtered = len(report["contexts"]) >= 2
        self.targets: dict[int, set[int]] = {}  # lines some link points at, per source

    # -- helpers --------------------------------------------------------------

    def w(self, *parts: str) -> None:
        self.out.extend(parts)

    def where(self, record: dict) -> str:
        span = record["span"]
        return f"{esc(self.path[record['source_index']])}:{span['start_line']}:{span['start_column']}"

    def href(self, source: int, line: int) -> str:
        """The fragment of a source line; its row or list item will exist."""
        self.targets.setdefault(source, set()).add(line)
        return f"#L{source}-{line}"

    def link(self, record: dict) -> str:
        return f'<a href="{self.href(record["source_index"], record["span"]["start_line"])}">{self.where(record)}</a>'

    def metric_cells(self, prefix: str, summary: dict, keys=ALL_METRICS) -> str:
        texts = _metric_texts(summary)
        cells = []
        for key, _ in keys:
            cells.append(f'<td class="n" data-m="{prefix}:{key}:f">{esc(texts[f"{key}:f"])}</td>'
                         f'<td class="n" data-m="{prefix}:{key}:p">{esc(texts[f"{key}:p"])}</td>')
        return "".join(cells)

    def section(self, ident: str, title: str) -> None:
        self.w(f'<section id="{ident}" aria-labelledby="{ident}-h"><h2 id="{ident}-h">{esc(title)}</h2>\n')

    # -- parts ----------------------------------------------------------------

    def head(self) -> None:
        self.w("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n",
               f'<meta http-equiv="Content-Security-Policy" content="{html.escape(CSP, quote=True)}">\n',
               '<meta name="referrer" content="no-referrer">\n',
               '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
               f"<title>{esc(TITLE)}</title>\n<style>{STYLE}</style>\n</head>\n<body>\n",
               '<a class="skip" href="#main">Skip to the report</a>\n')

    def banner(self) -> None:
        r, p = self.r, self.r["provenance"]
        status = p["execution_status"].replace("_", " ")
        if p["execution_exit_code"] is not None:
            status += f" (exit {p['execution_exit_code']})"
        if p["execution_signal"] is not None:
            status += f" (signal {p['execution_signal']})"
        self.w(f"<header>\n<h1>{esc(TITLE)}</h1>\n<dl class=\"kv\">\n",
               f'<dt>evidence</dt><dd class="word">{ELIGIBILITY[r["evidence_eligibility"]]}</dd>\n',
               f'<dt>complete</dt><dd>{"yes" if r["complete"] else "no"}</dd>\n',
               f'<dt>policy</dt><dd class="word">{"passed" if r["policy"]["passed"] else "failed"}</dd>\n',
               f"<dt>execution</dt><dd>{esc(status)}</dd>\n",
               f'<dt>backends</dt><dd>{esc(", ".join(p["backends"]) or "none")}</dd>\n',
               f'<dt>sources</dt><dd>{esc(p["source_accuracy"].replace("_", " "))}</dd>\n',
               f'<dt>contexts</dt><dd>{esc(", ".join(_quoted(c["value"]) for c in r["contexts"]) or "none")}</dd>\n',
               "" if r["changes"] is None else f"<dt>changes</dt><dd>{esc(change_line(r['changes']))}</dd>\n",
               "" if r["ratchet"] is None else f"<dt>ratchet</dt><dd>{esc(ratchet_line(r['ratchet']))}</dd>\n",
               "</dl>\n")
        if self.filtered:
            self.w('<p><label for="sv0cov-context">Show the counts of</label> <select id="sv0cov-context">\n',
                   '<option value="0" selected>all contexts (aggregate)</option>\n')
            for n, c in enumerate(self.r["contexts"], 1):
                self.w(f'<option value="{n}">context {esc(_quoted(c["value"]))}</option>\n')
            self.w('</select> <span class="ann">showing: <span id="sv0cov-shown">all contexts (aggregate)</span>. '
                   "Policy and thresholds always use the aggregate.</span></p>\n")
        self.w("</header>\n")

    def nav(self) -> None:
        parts = (("summary", "Summary"), ("files", "Files"), ("uncovered", "Uncovered"), ("contracts", "Contracts"),
                 ("exclusions", "Exclusions"), ("warnings", "Warnings"), ("policy", "Policy"), ("saturation", "Saturation"),
                 ("provenance", "Provenance"), ("sources", "Sources"))
        self.w('<nav aria-label="Report sections"><ul>\n')
        self.w("".join(f'<li><a href="#{i}">{t}</a></li>\n' for i, t in parts))
        self.w("</ul></nav>\n")

    def summary(self) -> None:
        self.section("summary", "Summary")
        self.w("<table>\n<thead><tr><th scope=\"col\">metric</th><th scope=\"col\" class=\"n\">covered/total</th>"
               "<th scope=\"col\" class=\"n\">percent</th><th scope=\"col\">partial</th></tr></thead>\n<tbody>\n")
        texts = _metric_texts(self.r["summary"])
        for key, label in METRICS:
            extra = f'<td data-m="S:line:x">{esc(texts["line:x"])}</td>' if key == "line" else "<td></td>"
            self.w(f'<tr><th scope="row">{label}</th><td class="n" data-m="S:{key}:f">{esc(texts[f"{key}:f"])}</td>'
                   f'<td class="n" data-m="S:{key}:p">{esc(texts[f"{key}:p"])}</td>{extra}</tr>\n')
        self.w("</tbody>\n</table>\n<p>Contracts are reported separately and are not part of the metrics above.</p>\n<table>\n"
               f'<tbody><tr><th scope="row">{CONTRACT[1]}</th><td class="n" data-m="S:contract:f">{esc(texts["contract:f"])}</td>'
               f'<td class="n" data-m="S:contract:p">{esc(texts["contract:p"])}</td></tr></tbody>\n</table>\n</section>\n')

    def files(self) -> None:
        self.section("files", "Files")
        if not self.r["sources"]:
            self.w("<p>(none)</p>\n</section>\n")
            return
        self.w("<table>\n<thead><tr><th scope=\"col\">file or function</th>")
        for _, label in ALL_METRICS:
            self.w(f'<th scope="col" class="n">{label}</th><th scope="col" class="n">%</th>')
        self.w("</tr></thead>\n<tbody>\n")
        owned: dict[int, list[dict]] = {}
        for e in self.r["entities"]:
            if e["kind"] == "function":
                owned.setdefault(e["source_index"], []).append(e)
        groups: dict[tuple, list[dict]] = {}
        for s in self.r["sources"]:
            groups.setdefault((0 if s["ownership"] == "user" else 1, s["package"] is not None, s["package"] or ""), []).append(s)
        for key in sorted(groups):
            ownership = "user" if key[0] == 0 else "dependency"
            package = f"package {_quoted(key[2])}" if key[1] else "no package"
            self.w(f'<tr><th scope="rowgroup" colspan="{1 + 2 * len(ALL_METRICS)}">[{ownership}] {esc(package)}</th></tr>\n')
            for s in sorted(groups[key], key=lambda s: s["path"].encode("utf-8")):
                n = s["source_index"]
                self.w(f'<tr><th scope="row"><a href="#src-{n}">{esc(s["path"])}</a></th>'
                       f'{self.metric_cells(f"F{n}", s["summary"])}</tr>\n')
                for e in sorted(owned.get(n, []), key=lambda e: e["entity_index"]):
                    line = e["span"]["start_line"]
                    cells = self.metric_cells(f"E{e['entity_index']}", e["summary"])
                    self.w(f'<tr><th scope="row">&#8195;fn <a href="{self.href(n, line)}">{esc(e["qualified_name"])}</a></th>'
                           f"{cells}</tr>\n")
        self.w("</tbody>\n</table>\n</section>\n")

    def stops(self) -> list[tuple[int, int, str]]:
        """(source, line, why) of every stop of the aggregate chain, in path
        then line order."""
        why: dict[tuple[int, int], list[str]] = {}
        for line in self.r["lines"]:
            if line["status"] in ("uncovered", "partial"):
                why.setdefault((line["source_index"], line["line"]), []).append(f"{line['status']} line")
        for b in self.r["branches"]:
            missed = [o["name"] for o in sorted(b["outcomes"], key=lambda o: o["ordinal"]) if o["status"] == "uncovered"]
            if missed:
                why.setdefault((b["source_index"], b["span"]["start_line"]), []).append(
                    f"{b['kind']} not taken: {', '.join(escape_text(x) for x in missed)}")
        rank = {s: k for k, s in enumerate(self.order)}
        return [(s, ln, "; ".join(w)) for (s, ln), w in sorted(why.items(), key=lambda kv: (rank[kv[0][0]], kv[0][1]))]

    def uncovered(self, stops: list[tuple[int, int, str]]) -> None:
        self.section("uncovered", "Uncovered")
        if not stops:
            self.w("<p>Every line, branch outcome and region counted ran at least once.</p>\n</section>\n")
            return
        self.w(f"<p>{_plural(len(stops), 'place')} to look at, in file and line order (all contexts). In a source, "
               "each one links to the next; with scripts on, <kbd>n</kbd> and <kbd>p</kbd> move along them for the "
               "context being shown.</p>\n<ol>\n")
        for s, ln, why in stops:
            self.w(f'<li><a href="{self.href(s, ln)}">{esc(self.path[s])}:{ln}</a> {esc(why)}</li>\n')
        self.w("</ol>\n</section>\n")

    def contracts(self) -> None:
        self.section("contracts", "Contracts")
        if not self.r["contracts"]:
            self.w("<p>(none)</p>\n</section>\n")
            return
        self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col"{" class=\"n\"" if h in ("true", "false") else ""}>{h}</th>'
                                                for h in ("location", "clause", "enforcement", "result", "true", "false", "evidence"))
               + "</tr></thead>\n<tbody>\n")
        for c in self.r["contracts"]:
            counts = ["-" if c[k] is None else count_text(c[k]) for k in ("count_true", "count_false")]
            evidence = "-" if c["evidence_identity"] is None else _quoted(c["evidence_identity"])
            self.w(f"<tr><td>{self.link(c)}</td><td>{esc(self.entity[c['entity_index']]['qualified_name'])}</td>"
                   f"<td>{c['enforcement']}</td><td>{c['runtime_result']}</td><td class=\"n\">{counts[0]}</td>"
                   f"<td class=\"n\">{counts[1]}</td><td>{esc(evidence)}</td></tr>\n")
        self.w("</tbody>\n</table>\n</section>\n")

    def exclusions(self) -> None:
        self.section("exclusions", "Exclusions")
        records = self.r["exclusions"]
        functions = {i for x in records for i in x["affected"]["entity_indices"] if self.entity[i]["kind"] == "function"}
        union = {k: {i for x in records for i in x["affected"][k]}
                 for k in ("region_indices", "line_indices", "branch_indices", "clause_indices")}
        unreachable = sum(1 for b in self.r["branches"] for o in b["outcomes"] if o["status"] == "statically_unreachable")
        self.w(f"<p>excluded: {_plural(len(functions), 'function')}, {_plural(len(union['region_indices']), 'region')}, "
               f"{_plural(len(union['line_indices']), 'line')}, {_plural(len(union['branch_indices']), 'branch', 'branches')}, "
               f"{_plural(len(union['clause_indices']), 'contract')}<br>\n"
               f"statically unreachable: {_plural(unreachable, 'branch outcome')}</p>\n")
        if records:
            self.w("<table>\n<thead><tr><th scope=\"col\">#</th><th scope=\"col\">location</th><th scope=\"col\">mode</th>"
                   "<th scope=\"col\">origin</th><th scope=\"col\">reason</th><th scope=\"col\">removes and evidence</th>"
                   "</tr></thead>\n<tbody>\n")
            for x in records:
                self.w(f"<tr><td class=\"n\">{x['exclusion_index']}</td><td>{self.link(x)}</td><td>{x['mode']}</td>"
                       f"<td>{x['origin']}</td><td>{esc(_quoted(x['reason']))}</td><td>{esc(exclusion_audit(self.r, x))}</td></tr>\n")
            self.w("</tbody>\n</table>\n")
        self.w("</section>\n")

    def warnings(self) -> None:
        self.section("warnings", "Warnings")
        out = []
        if not self.r["complete"]:
            out.append("WARNING: the evidence is incomplete; this report cannot be passing evidence.")
        for i in self.r["inputs"]:
            if i["status"] != "accepted":
                codes = f" [{', '.join(i['diagnostics'])}]" if i["diagnostics"] else ""
                out.append(f"WARNING: input {_quoted(i['name'])} was {i['status']}{codes}")
        for s in self.r["sources"]:
            if s["source_state"] != "current":
                state = "does not match the evidence" if s["source_state"] == "mismatch" else "was not available"
                out.append(f"WARNING: source {escape_text(s['path'])} {state}; its lines are not shown.")
        self.w("".join(f"<p>{esc(line)}</p>\n" for line in out) or "<p>(none)</p>\n", "</section>\n")

    def policy(self) -> None:
        self.section("policy", "Policy")
        heads = ("result", "assertion", "metric", "required", "actual", "threshold source", "members", "diagnostics")
        self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>\n<tbody>\n")
        for e in self.r["policy"]["evaluations"]:
            limit, actual = e["limit"], e["actual"]
            required = "-" if limit is None else f"{COMPARISON[e['comparison']]} {limit['numerator']}/{limit['denominator']}"
            members = ", ".join(_plural(len(e["members"][k]), *names) for k, *names in MEMBERS if e["members"][k])
            cells = (f"{e['assertion_kind']} {_quoted(e['assertion_name'])}", e["metric"], required,
                     "-" if actual is None else f"{actual['numerator']}/{actual['denominator']}",
                     e["threshold_source"] or "-", members or "-", ", ".join(e["diagnostics"]) or "-")
            self.w(f'<tr><td class="word">{RESULT[e["result"]]}</td>' + "".join(f"<td>{esc(c)}</td>" for c in cells) + "</tr>\n")
        self.w("</tbody>\n</table>\n",
               f'<p>policy <span class="word">{"passed" if self.r["policy"]["passed"] else "failed"}</span></p>\n</section>\n')

    def saturation(self) -> None:
        self.section("saturation", "Saturation")
        s = self.r["saturation"]
        context = {c["context_index"]: c["value"] for c in self.r["contexts"]}
        rows: list[tuple[str, str, str, str]] = []

        def add(what: str, record: dict, count: dict | None) -> None:
            if count is None:
                return
            if count["saturated"] or count["lower_bound"]:
                rows.append((what, self.where(record), "all contexts", count_text(count)))
            for c in count["by_context"]:
                if c["saturated"] or c["lower_bound"]:
                    rows.append((what, self.where(record), f"context {esc(_quoted(context[c['context_index']]))}", count_text(c)))

        for p in self.r["points"]:
            add(f"point {p['point_id'][:12]}", p, p["count"])
        for g in self.r["regions"]:
            add(f"region {g['region_index']}", g, g["count"])
        for b in self.r["branches"]:
            for o in b["outcomes"]:
                add(f"branch {b['branch_index']} outcome {esc(o['name'])}", b, o["count"])
        for c in self.r["contracts"]:
            add(f"contract {c['clause_index']} true", c, c["count_true"])
            add(f"contract {c['clause_index']} false", c, c["count_false"])
        self.w(f"<p>policy: {s['policy']}</p>\n")
        if not s["any"] and not rows:
            self.w("<p>no count is saturated</p>\n</section>\n")
            return
        self.w("<p>a count written &gt;=N is a lower bound: the true count is N or more</p>\n<table>\n<thead><tr>"
               '<th scope="col">count</th><th scope="col">location</th><th scope="col">scope</th>'
               '<th scope="col" class="n">value</th></tr></thead>\n<tbody>\n')
        for what, where, scope, value in rows:
            self.w(f'<tr><td>{what}</td><td>{where}</td><td>{scope}</td><td class="n">{html.escape(value)}</td></tr>\n')
        self.w("</tbody>\n</table>\n",
               f"<p>metrics still decidable: {esc(', '.join(s['eligible_metrics']) or 'none')}<br>\n"
               f"not usable for: {esc(', '.join(s['ineligible_uses']) or 'nothing')}</p>\n</section>\n")

    def provenance(self) -> None:
        self.section("provenance", "Provenance")
        r, p = self.r, self.r["provenance"]
        hashes = (("indexed input", p["indexed_input_sha256"]), ("semantic projection", p["semantic_projection_sha256"]),
                  ("run manifest", p["run_manifest_sha256"]), ("indexed diagnostic registry", p["indexed_diagnostic_registry_sha256"]))
        self.w('<dl class="kv">\n',
               f"<dt>tool</dt><dd>sv0cov {esc(r['tool']['version'])} (diagnostic registry revision "
               f"{r['tool']['diagnostic_registry_revision']})</dd>\n",
               f"<dt>run selection</dt><dd>{esc(p['run_selection'])}</dd>\n",
               f'<dt>runs</dt><dd class="hash">{esc(", ".join(p["run_ids"]) or "none")}</dd>\n',
               f'<dt>maps</dt><dd class="hash">{esc(", ".join(p["map_ids"]) or "none")}</dd>\n')
        for label, value in hashes:
            self.w(f'<dt>{label} sha256</dt><dd class="hash">{esc(value or "none")}</dd>\n')
        self.w("</dl>\n")
        c = r["changes"]
        if c is not None:
            b, path = c["base"], {s["source_index"]: s["path"] for s in r["sources"]}
            self.w('<h3>Changed-region capture</h3>\n<dl class="kv">\n',
                   f"<dt>base</dt><dd>{esc(_quoted(b['spelling']))}</dd>\n",
                   *(f'<dt>{label}</dt><dd class="hash">{esc(b[key])}</dd>\n'
                     for label, key in (("reference", "reference"), ("HEAD", "head"), ("merge base", "merge_base"))),
                   f"<dt>working tree</dt><dd>{'clean' if c['clean'] else 'dirty: not reproducible from HEAD alone'}</dd>\n",
                   f'<dt>diff sha256</dt><dd class="hash">{esc(c["diff_sha256"])}</dd>\n',
                   f"<dt>diff options</dt><dd>{esc(' '.join(c['diff_options']))}</dd>\n",
                   f"<dt>git</dt><dd>{esc(c['git']['version'])}</dd>\n",
                   f'<dt>git sha256</dt><dd class="hash">{esc(c["git"]["executable_sha256"])}</dd>\n',
                   "</dl>\n")
            if c["sources"]:
                heads = ("source", "state", "index", "work tree", "changed lines", "sha256")
                self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>\n<tbody>\n")
                for x in c["sources"]:
                    state = x["state"] if x["old_path"] is None else f"renamed from {_quoted(x['old_path'])}"
                    cells = (_quoted(path[x["source_index"]]), state, "staged" if x["staged"] else "-",
                             "unstaged" if x["unstaged"] else "-", ranges(x["changed_lines"]) or "-", x["sha256"])
                    self.w("<tr>" + "".join(f"<td>{esc(v)}</td>" for v in cells) + "</tr>\n")
                self.w("</tbody>\n</table>\n")
        t = r["ratchet"]
        if t is not None and t["baseline"] is not None:
            b = t["baseline"]
            self.w('<h3>Ratchet baseline</h3>\n<dl class="kv">\n',
                   f'<dt>file sha256</dt><dd class="hash">{esc(t["baseline_sha256"])}</dd>\n',
                   f'<dt>made at</dt><dd class="hash">{esc(b["commit"] or "outside Git")}</dd>\n',
                   f'<dt>HEAD now</dt><dd class="hash">{esc(t["head"] or "outside Git")}</dd>\n',
                   f"<dt>made by</dt><dd>sv0cov {esc(b['tool_version'])} ({esc(b['metric_schema'])}, "
                   f"saturation {esc(b['saturation_policy'])})</dd>\n</dl>\n")
            heads = ("metric", "baseline covered/total", "baseline excluded", "now covered/total", "now excluded", "outcomes")
            self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>\n<tbody>\n")
            outcomes = {c["metric"]: c["outcomes"] for c in t["comparisons"]}
            for m in sorted(b["metrics"]):
                old, now = b["metrics"][m], r["summary"][m]
                cells = (m, f"{old['covered']}/{old['total']}", str(old["excluded"]), f"{now['covered']}/{now['total']}",
                         str(excluded_units(r, m)),
                         "-" if m not in outcomes else ", ".join(o.replace("_", " ") for o in outcomes[m]) or "none")
                self.w("<tr>" + "".join(f"<td>{esc(v)}</td>" for v in cells) + "</tr>\n")
            self.w("</tbody>\n</table>\n")
            for label, paths in (("Sources added since the baseline", t["sources_added"]),
                                 ("Sources removed since the baseline", t["sources_removed"])):
                if paths:
                    self.w(f"<h4>{label}</h4>\n<ul>\n" + "".join(f"<li>{esc(_quoted(x))}</li>\n" for x in paths) + "</ul>\n")
        self.w("<h3>Inputs</h3>\n")
        context = {c["context_index"]: c["value"] for c in r["contexts"]}
        if r["inputs"]:
            heads = ("name", "status", "backend", "context", "run", "profile", "sha256", "diagnostics")
            self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>\n<tbody>\n")
            for i in r["inputs"]:
                ctx = "-" if i["context_index"] is None else _quoted(context[i["context_index"]])
                cells = (_quoted(i["name"]), i["status"], i["backend"] or "-", ctx, i["run_id"] or "-", i["profile_id"] or "-",
                         i["artifact_sha256"], ", ".join(i["diagnostics"]) or "-")
                self.w("<tr>" + "".join(f'<td class="hash">{esc(c)}</td>' for c in cells) + "</tr>\n")
            self.w("</tbody>\n</table>\n")
        else:
            self.w("<p>(none)</p>\n")
        self.w("<h3>Source digests</h3>\n")
        if r["sources"]:
            heads = ("path", "ownership", "package", "evidence sha256", "observed sha256", "state")
            self.w("<table>\n<thead><tr>" + "".join(f'<th scope="col">{h}</th>' for h in heads) + "</tr></thead>\n<tbody>\n")
            for n in self.order:
                s = r["sources"][n]
                cells = (s["path"], s["ownership"], "-" if s["package"] is None else _quoted(s["package"]), s["digest"],
                         s["observed_digest"] or "-", s["source_state"])
                self.w("<tr>" + "".join(f'<td class="hash">{esc(c)}</td>' for c in cells) + "</tr>\n")
            self.w("</tbody>\n</table>\n")
        else:
            self.w("<p>(none)</p>\n")
        self.w("</section>\n")

    def annotations(self) -> dict[tuple[int, int], list[str]]:
        """Per (source, line): the notes shown beside it, already HTML."""
        notes: dict[tuple[int, int], list[str]] = {}
        for b in self.r["branches"]:
            parts = []
            for o in sorted(b["outcomes"], key=lambda o: o["ordinal"]):
                k = self.outcome_index[(b["branch_index"], o["ordinal"])]
                word = {"uncovered": " (not taken)", "excluded": " (excluded)", "statically_unreachable": " (unreachable)"}.get(
                    o["status"], "")
                parts.append(f'<span data-o="{k}" class="o-{OUTCOME_CODE[o["status"]]}">{esc(o["name"])} '
                             f'<span class="cnt">{count_text(o["count"])}</span>{word}</span>')
            notes.setdefault((b["source_index"], b["span"]["start_line"]), []).append(
                f"{b['kind']} (column {b['span']['start_column']}): " + " &middot; ".join(parts))
        for c in self.r["contracts"]:
            counts = "" if c["count_true"] is None else f" (true {count_text(c['count_true'])}, false {count_text(c['count_false'])})"
            notes.setdefault((c["source_index"], c["span"]["start_line"]), []).append(
                f"{c['kind']}: {c['enforcement'].replace('_', ' ')}, {c['runtime_result'].replace('_', ' ')}{counts}")
        for x in self.r["exclusions"]:
            notes.setdefault((x["source_index"], x["span"]["start_line"]), []).append(
                f"exclusion #{x['exclusion_index']} {x['mode']} ({x['origin']}): {esc(_quoted(x['reason']))}")
        return notes

    def source_files(self, stops: list[tuple[int, int, str]]) -> None:
        self.section("sources", "Sources")
        status = {(x["source_index"], x["line"]): x for x in self.r["lines"]}
        notes = self.annotations()
        nxt = {}
        for k, (s, ln, _) in enumerate(stops):
            nxt[(s, ln)] = self.href(*stops[k + 1][:2]) if k + 1 < len(stops) else "#uncovered"
        for n in self.order:
            s = self.r["sources"][n]
            self.w(f'<section id="src-{n}" aria-labelledby="src-{n}-h"><h3 id="src-{n}-h">{esc(s["path"])}</h3>\n<p>')
            texts = _metric_texts(s["summary"])
            self.w("; ".join(f'{label} <span data-m="F{n}:{key}:f">{esc(texts[f"{key}:f"])}</span>'
                             for key, label in METRICS) + "</p>\n")
            data = self.sources.get(s["path"])
            text = None
            if s["source_state"] == "current" and data is not None:
                try:
                    text = data.decode("utf-8")
                except UnicodeDecodeError:
                    text = None
            known = sorted({ln for (src, ln) in status if src == n} | self.targets.get(n, set()))
            if text is None:
                state = "does not match the evidence" if s["source_state"] == "mismatch" else "is not available"
                self.w(f"<p>The source {state}, so its text is not shown. Lines by status:</p>\n<ul>\n")
                for ln in known:
                    x = status.get((n, ln))
                    word = "no line record" if x is None else STATUS_WORD[x["status"]] or "no code"
                    note = "; ".join(notes.get((n, ln), []))
                    self.w(f'<li id="L{n}-{ln}">line {ln}: {word}{"; " + note if note else ""}</li>\n')
                self.w("</ul>\n</section>\n")
                continue
            lines = text.split("\n")
            if lines and lines[-1] == "":
                lines.pop()
            if known and known[-1] > len(lines):
                lines += [""] * (known[-1] - len(lines))
            self.w(f'<div class="wrap" tabindex="0" role="region" aria-label="source lines of {esc(s["path"])}">'
                   '<table class="src">\n<thead><tr><th scope="col">line</th><th scope="col">status</th>'
                   '<th scope="col">source</th></tr></thead>\n<tbody>\n')
            for ln, raw in enumerate(lines, 1):
                x = status.get((n, ln))
                if raw.endswith("\r"):
                    raw = raw[:-1]
                attrs = f' id="L{n}-{ln}"'
                word = ""
                if x is not None:
                    attrs += f' class="l-{LINE_CODE[x["status"]]}" data-l="{x["line_index"]}" tabindex="-1"'
                    word = STATUS_WORD[x["status"]]
                note = "<br>".join(notes.get((n, ln), []))
                if (n, ln) in nxt:
                    note += (" " if note else "") + f'<a class="nx" href="{nxt[(n, ln)]}">next uncovered</a>'
                self.w(f'<tr{attrs}><th scope="row"><a href="#L{n}-{ln}">{ln}</a></th><td class="st">{word}</td>'
                       f'<td class="code">{esc_code(raw)}</td></tr>\n')
                if note:
                    self.w(f'<tr class="note"><td></td><td></td><td class="ann">{note}</td></tr>\n')
            self.w("</tbody>\n</table></div>\n</section>\n")
        if not self.r["sources"]:
            self.w("<p>(none)</p>\n")
        self.w("</section>\n")

    def data(self) -> None:
        if not self.filtered:
            return
        views = [_view_data("all contexts (aggregate)", context_view_all(self.r))]
        for c in self.r["contexts"]:
            views.append(_view_data(f"context {_quoted(c['value'])}", context_view(self.r, c["context_index"])))
        self.w(f'<script type="application/json" id="sv0cov-data">{_json_block({"views": views})}</script>\n')

    def render(self) -> bytes:
        self.head()
        self.banner()
        self.nav()
        stops = self.stops()
        self.w('<main id="main">\n')
        self.summary()
        self.files()
        self.uncovered(stops)
        self.contracts()
        self.exclusions()
        self.warnings()
        self.policy()
        self.saturation()
        self.provenance()
        self.source_files(stops)
        self.w("</main>\n")
        p = self.r["provenance"]
        self.w(f"<footer><p>sv0cov {esc(self.r['tool']['version'])}; indexed input sha256 "
               f'<span class="hash">{esc(p["indexed_input_sha256"])}</span></p></footer>\n')
        self.data()
        self.w(f"<script>{SCRIPT}</script>\n</body>\n</html>\n")
        return "".join(self.out).encode("utf-8")


def context_view_all(report: dict) -> dict:
    """The aggregate in the shape of a context view."""
    return {k: report[k] for k in ("branches", "entities", "lines", "sources", "summary")}


def render_html(report: dict, sources: Mapping[str, bytes | None]) -> bytes:
    """The HTML report for one validated native report and the current bytes
    of its sources (a missing or ``None`` entry: the file is unavailable)."""
    return _Page(report, sources).render()


# ── structural check ────────────────────────────────────────────────────────

FORBIDDEN_TAGS = frozenset({"base", "link", "img", "iframe", "frame", "object", "embed", "audio", "video", "source", "track",
                            "form", "input", "button", "picture", "svg", "math", "meta-refresh", "applet", "portal"})
URL_ATTRS = frozenset({"src", "srcset", "action", "formaction", "poster", "data", "background", "ping", "xlink:href", "manifest",
                       "codebase", "cite", "longdesc", "usemap", "lowsrc", "dynsrc"})


class HtmlError(ValueError):
    """The document breaks a rule of :func:`check_html`."""


class _Checker(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.ids: set[str] = set()
        self.hrefs: list[str] = []
        self.scripts: list[tuple[dict, list[str]]] = []
        self.styles: list[list[str]] = []
        self.csp: list[str] = []
        self.stack: list[tuple[str, dict]] = []
        self.lang = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag in FORBIDDEN_TAGS:
            raise HtmlError(f"the document has a <{tag}> element")
        for k, v in a.items():
            if k.startswith("on"):
                raise HtmlError(f"<{tag}> has an event handler attribute {k}")
            if k in URL_ATTRS:
                raise HtmlError(f"<{tag}> has a {k} attribute")
            if k == "style":
                raise HtmlError(f"<{tag}> has an inline style")
        if "id" in a:
            if a["id"] in self.ids:
                raise HtmlError(f"the id {a['id']!r} is used twice")
            self.ids.add(a["id"])
        if "href" in a:
            if not a["href"].startswith("#"):
                raise HtmlError(f"a link leaves the document: {a['href']!r}")
            self.hrefs.append(a["href"][1:])
        if tag == "meta":
            if a.get("http-equiv", "").lower() == "content-security-policy":
                self.csp.append(a.get("content", ""))
            elif a.get("http-equiv"):
                raise HtmlError(f"a <meta http-equiv={a['http-equiv']!r}>")
        if tag == "html":
            self.lang = a.get("lang")
        if tag == "script":
            self.scripts.append((a, []))
        if tag == "style":
            self.styles.append([])
        self.stack.append((tag, a))

    def handle_endtag(self, tag: str) -> None:
        if self.stack and self.stack[-1][0] == tag:
            self.stack.pop()

    def handle_data(self, data: str) -> None:
        if self.stack and self.stack[-1][0] == "script":
            self.scripts[-1][1].append(data)
        elif self.stack and self.stack[-1][0] == "style":
            self.styles[-1].append(data)


def check_html(data: bytes) -> None:
    """Raise :class:`HtmlError` unless ``data`` is a self-contained document
    that can make no request: UTF-8, ``<!DOCTYPE html>``, a language, one
    Content-Security-Policy of ``default-src 'none'`` whose hashes match
    every inline style and executable script, no element or attribute that
    loads anything, no event handler or inline style, links only to ids of
    the document, and unique ids."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise HtmlError("the document is not UTF-8") from None
    if not text.startswith("<!DOCTYPE html>\n"):
        raise HtmlError("the document does not start with <!DOCTYPE html>")
    p = _Checker()
    p.feed(text)
    p.close()
    if not p.lang:
        raise HtmlError("the document names no language")
    if len(p.csp) != 1 or not p.csp[0].startswith("default-src 'none';"):
        raise HtmlError("the document needs exactly one Content-Security-Policy of default-src 'none'")
    policy = {d.split()[0]: d.split()[1:] for d in (x.strip() for x in p.csp[0].split(";")) if d}
    for kind, bodies in (("style-src", ["".join(s) for s in p.styles]),
                         ("script-src", ["".join(b) for a, b in p.scripts if a.get("type") != "application/json"])):
        allowed = policy.get(kind, [])
        for body in bodies:
            if _digest(body) not in allowed:
                raise HtmlError(f"an inline {kind.split('-')[0]} is not pinned by the policy")
        if any(not (src.startswith("'sha256-") and src.endswith("'")) for src in allowed):
            raise HtmlError(f"{kind} admits something other than a pinned hash")
    for a, _ in p.scripts:
        if a.get("type") not in (None, "", "application/json"):
            raise HtmlError(f"a script of type {a.get('type')!r}")
    if any("url(" in "".join(s) or "@import" in "".join(s) for s in p.styles):
        raise HtmlError("a style loads a resource")
    for target in p.hrefs:
        if target not in p.ids:
            raise HtmlError(f"a link to #{target} has no target")
