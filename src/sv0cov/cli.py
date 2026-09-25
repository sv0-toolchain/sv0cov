# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Console entry point.

Implemented so far: ``sv0cov version [--json]`` (SPEC 20.6). Every other
invocation is a usage error (exit 2, COV0001) until its command lands.
Exit codes follow SPEC 20.3.
"""

from __future__ import annotations

import sys

from sv0cov import capabilities
from sv0cov.diagnostics import Diagnostic, RegistryError, load_registry, render_human
from sv0cov.formats.version_manifest import ManifestError, build, current_host, validate_manifest

EXIT_USAGE = 2
EXIT_INTERNAL = 8


def _usage(message: str) -> int:
    try:
        sys.stderr.write(render_human(Diagnostic("COV0001", "invocation", facts=(("detail", message),)).to_json()))
    except RegistryError:
        return EXIT_INTERNAL
    return EXIT_USAGE


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


def cmd_version(args: list[str]) -> int:
    if args not in ([], ["--json"]):
        return _usage("version accepts only --json")
    try:
        data = version_manifest()
    except (ManifestError, RegistryError, OSError) as exc:
        code = "COV8002" if isinstance(exc, RegistryError) else "COV8001"
        try:
            sys.stderr.write(render_human(Diagnostic(code, "internal", facts=(("detail", str(exc)[:4096]),)).to_json()))
        except RegistryError:
            sys.stderr.write(f"{code}: {exc}\n")
        return EXIT_INTERNAL
    if args == ["--json"]:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.flush()
        return 0
    m = validate_manifest(data)
    impl = m["implementation"]
    host = f"{m['host']['operating_system']}-{m['host']['architecture']}"
    sys.stdout.write(
        f"sv0cov {m['tool']['version']} ({impl['language']}, {impl['runtime']['name']} "
        f"{impl['runtime']['version']}, {host}, revision {impl['revision'][:12]})\n"
    )
    return 0


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        return _usage("a command is required")
    command, rest = args[0], args[1:]
    if command == "version":
        return cmd_version(rest)
    return _usage(f"unknown or not yet implemented command {command!r}")


if __name__ == "__main__":
    sys.exit(main())
