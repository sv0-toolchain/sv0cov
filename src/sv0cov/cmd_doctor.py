# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""The ``doctor`` command, standalone mode (CV-235; SPEC 20.7; COV-CLI-011)::

    sv0cov doctor [--json] [--quiet]

It runs the standalone probes (:mod:`sv0cov.probes`) and reports one model
three ways, which therefore always agree:

- ``--json``: the canonical ``sv0cov.doctor`` 1.0 aggregate on stdout and
  nothing else, validated before the first byte is written;
- otherwise one line per probe and a summary on stdout, which ``--quiet``
  removes;
- every failed probe's diagnostic on stderr, in the chosen format, in both
  cases and whatever ``--quiet`` says.

Exit 0 when every applicable probe passed, 7 when one failed or was skipped,
8 when the bootstrap probes cannot pass or the private directory cannot be
removed (and then no JSON is written). ``--toolchain-root`` selects toolchain
mode, which this build does not have yet: ``COV5001``, exit 7.
"""

from __future__ import annotations

from sv0cov import cli, probes
from sv0cov.diagnostics import Diagnostic
from sv0cov.formats.doctor import BY_ID, validate
from sv0cov.publish import PublishError, publish_stdout

STATUS_WORD = {"pass": "pass", "fail": "FAIL", "skipped": "skipped", "not_applicable": "n/a"}


def render(obj: dict) -> str:
    """The human form: every probe ID and status, then the summary."""
    width = max(len(w) for w in STATUS_WORD.values())
    lines = []
    for p in obj["probes"]:
        line = f"{p['id']}  {STATUS_WORD[p['status']].ljust(width)}  {BY_ID[p['id']].title}"
        if p["status"] == "fail":
            line += f" ({p['diagnostic_code']})"
        elif p["status"] == "skipped":
            line += f" (after {', '.join(p['blocked_by'])})"
        lines.append(line.rstrip())
    s = obj["summary"]
    lines.append(f"doctor ({obj['mode']}): {obj['status']}: {s['passed']} passed, {s['failed']} failed, {s['skipped']} skipped, "
                 f"{s['not_applicable']} not applicable")
    return "\n".join(lines)


@cli.command("doctor")
def cmd_doctor(ctx: cli.Context) -> int:
    console, controls = ctx.console, ctx.config.controls
    if "--toolchain-root" in controls:
        console.report(Diagnostic("COV5001", "invocation", facts=(
            ("detail", "this build of sv0cov has only the standalone doctor; toolchain mode comes with the toolchain probes"),)))
        return cli.EXIT_UNSUPPORTED
    try:
        data = probes.run_standalone()
        obj = validate(data)
    except (probes.Bootstrap, ValueError) as exc:
        console.report(Diagnostic("COV8001", "internal", facts=(("detail", cli.fact_text(str(exc))),)))
        return cli.EXIT_INTERNAL
    for record in obj["diagnostics"]:
        facts = tuple((f["name"], f["value"]) for f in record["facts"])
        console.report(Diagnostic(record["code"], record["phase"], facts=facts))
    if controls.get("--json"):
        try:
            publish_stdout(console.binary_stdout(), data, validate=validate)
        except PublishError as exc:
            console.abandon_stdout()
            console.report(Diagnostic(exc.code, "publication", facts=(("artifact", "doctor-result"), ("detail", cli.fact_text(exc.detail)))))
            return cli.EXIT_INTERNAL
    else:
        console.say(render(obj))
    return cli.EXIT_OK if obj["status"] == "pass" else cli.EXIT_UNSUPPORTED
