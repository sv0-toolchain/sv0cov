# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Console entry point and command framework (CV-225; SPEC 18.2.3, 20.1,
20.2, 20.3, 20.5.2).

Every invocation goes through the same steps:

1. the diagnostic format and color mode are read from the arguments, so
   that even a usage error is rendered as asked
   (:func:`sv0cov.invocation.diagnostic_format`, ``color_mode``);
2. the arguments are split (:func:`sv0cov.invocation.split`);
3. for a project command, ``sv0.toml`` in the working directory is read;
4. options and file are resolved (:func:`sv0cov.config_resolve.resolve`),
   which is where applicability, repeats, conflicts and values are checked;
5. the command's handler runs and returns its exit code.

Steps 2-4 fail with exit 2 before any artifact is touched. A command this
build does not implement yet fails with exit 7 (``COV5001``) after its
usage and configuration have been checked, so a wrong invocation is always
reported as wrong. An unexpected exception is exit 8 (``COV8001``) and names
only the exception type.

Implemented commands: ``version``. A handler is registered with
:func:`command` and receives a :class:`Context`.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TextIO

from sv0cov import capabilities
from sv0cov import config as C
from sv0cov.config_resolve import Resolved, resolve
from sv0cov.console import Console
from sv0cov.diagnostics import Diagnostic, RegistryError, load_registry
from sv0cov.formats.version_manifest import ManifestError, build, current_host, validate_manifest
from sv0cov.invocation import Invocation, color_mode, diagnostic_format, split

# SPEC 20.3.
EXIT_OK = 0
EXIT_POLICY = 1
EXIT_USAGE = 2
EXIT_BUILD = 3
EXIT_TEST = 4
EXIT_EVIDENCE = 5
EXIT_REPORT = 6
EXIT_UNSUPPORTED = 7
EXIT_INTERNAL = 8

PROJECT_COMMANDS = ("run", "merge", "report", "check", "clean")  # the ones that read sv0.toml
MANIFEST = "sv0.toml"
FACT_BYTES = 4096


@dataclass(frozen=True)
class Context:
    invocation: Invocation
    config: Resolved
    console: Console
    cwd: Path


Handler = Callable[[Context], int]
HANDLERS: dict[str, Handler] = {}


def command(name: str) -> Callable[[Handler], Handler]:
    """Register the handler of one of the seven commands."""
    if name not in C.COMMANDS:
        raise ValueError(f"{name!r} is not an sv0cov command")

    def register(fn: Handler) -> Handler:
        HANDLERS[name] = fn
        return fn

    return register


def fact_text(text: str) -> str:
    """``text`` as a diagnostic fact value: valid UTF-8, one line, at most
    4,096 bytes (SPEC 20.5.2)."""
    clean = text.encode("utf-8", "replace").decode("utf-8")
    clean = "".join("?" if c in "\x00\r\n" else c for c in clean)
    data = clean.encode("utf-8")[:FACT_BYTES]
    return data.decode("utf-8", "ignore")


def config_diagnostic(exc: C.ConfigError) -> Diagnostic:
    """A usage error is an invocation event; everything else the resolver
    raises is a configuration event."""
    phase = "invocation" if exc.code == "COV0001" else "configuration"
    return Diagnostic(exc.code, phase, facts=(("detail", fact_text(exc.detail)), ("subject", fact_text(exc.path))))


def read_manifest(cwd: Path) -> bytes | None:
    """The bytes of ``sv0.toml`` in ``cwd``, or ``None`` when there is none."""
    path = cwd / MANIFEST
    try:
        if not path.exists() and not path.is_symlink():
            return None
        return path.read_bytes()
    except OSError:
        raise C.ConfigError(C.TOML_ERROR, MANIFEST, "cannot be read") from None


def version_manifest() -> bytes:
    registry = load_registry()
    return build(
        tool_version=capabilities.tool_version(),
        revision=capabilities.revision(),
        runtime_version=capabilities.runtime_version(),
        host=current_host(),
        registry_revision=registry.revision,
        registry_sha256=registry.sha256,
        advertised=capabilities.ADVERTISED,
    )


@command("version")
def cmd_version(ctx: Context) -> int:
    try:
        data = version_manifest()
    except (ManifestError, RegistryError, OSError) as exc:
        code = "COV8002" if isinstance(exc, RegistryError) else "COV8001"
        ctx.console.report(Diagnostic(code, "internal", facts=(("detail", fact_text(str(exc))),)))
        return EXIT_INTERNAL
    if ctx.config.controls.get("--json"):
        ctx.console.write_artifact(data)
        return EXIT_OK
    m = validate_manifest(data)
    impl = m["implementation"]
    host = f"{m['host']['operating_system']}-{m['host']['architecture']}"
    # The answer to `version` is its output, not incidental text: --quiet does not apply to this command.
    ctx.console.stdout.write(
        f"sv0cov {m['tool']['version']} ({impl['language']}, {impl['runtime']['name']} "
        f"{impl['runtime']['version']}, {host}, revision {impl['revision'][:12]})\n"
    )
    return EXIT_OK


def _run(args: list[str], console: Console, cwd: Path) -> int:
    try:
        invocation = split(args)
        toml = read_manifest(cwd) if invocation.command in PROJECT_COMMANDS else None
        config = resolve(invocation.command, invocation.options, toml)
    except C.ConfigError as exc:
        console.report(config_diagnostic(exc))
        return EXIT_USAGE
    console.configure(quiet=bool(config.controls.get("--quiet")), color=config.controls.get("--color", "auto"))
    handler = HANDLERS.get(invocation.command)
    if handler is None:
        console.report(Diagnostic("COV5001", "invocation", facts=(
            ("command", invocation.command), ("detail", "this build of sv0cov does not implement the command yet"))))
        return EXIT_UNSUPPORTED
    return handler(Context(invocation, config, console, cwd))


def main(argv: list[str] | None = None, *, stdout: TextIO | None = None, stderr: TextIO | None = None,
         cwd: Path | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    console = Console(stdout or sys.stdout, stderr or sys.stderr, diagnostic_format=diagnostic_format(args), color=color_mode(args))
    try:
        status = _run(args, console, cwd or Path.cwd())
    except Exception as exc:  # noqa: BLE001 - the last line of defence; the type name is all that is disclosed
        console.report(Diagnostic("COV8001", "internal", facts=(("exception", type(exc).__name__),)))
        status = EXIT_INTERNAL
    try:
        console.flush()
    except RegistryError as exc:
        console.stderr.write(f"COV8002 error: Diagnostic registry is invalid\n  detail: {fact_text(str(exc))}\n")
        return EXIT_INTERNAL
    return status


if __name__ == "__main__":
    sys.exit(main())
