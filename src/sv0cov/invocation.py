# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""Splitting an argument vector into a command, its option occurrences and
its operands (CV-225; SPEC 18.2.3, 20.1, 20.4).

The grammar is fixed::

    sv0cov <command> [--option[=value] | --option value | operand]... [-- rest...]

- The command comes first and is one of the seven exact names. There are no
  aliases, abbreviations, short options, or options before the command.
- A valued option takes its value after ``=`` or from the next argument.
  The ``--`` separator is never taken as a value; write ``--context=--``.
- For ``run``, everything after ``--`` is the test command, kept as an argv
  vector and never joined (SPEC 20.4). For other commands it is more
  operands, so an operand may begin with ``-``.
- Operand counts are exact per command (SPEC 20.1).

Whether an option applies to the command, may repeat, or conflicts with
another is decided by :func:`sv0cov.config_resolve.resolve`; this module
only needs each option's arity to split correctly. Every failure is a usage
error: :class:`sv0cov.config.ConfigError` with code ``COV0001``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from sv0cov import config as C

USAGE = "COV0001"
# command -> (fewest operands, most operands or None for no bound, what they are)
OPERANDS = {
    "run": (0, 0, ""),
    "merge": (1, None, "raw profile, map, or directory"),
    "report": (1, 1, "indexed profile"),
    "check": (1, 1, "indexed profile or native report"),
    "baseline": (1, 1, "indexed profile"),
    "clean": (0, 0, ""),
    "doctor": (0, 0, ""),
    "version": (0, 0, ""),
}
FORMAT_OPTION = "--diagnostic-format"


@dataclass(frozen=True)
class Invocation:
    command: str
    options: tuple[tuple[str, str | None], ...]
    operands: tuple[str, ...]
    test_command: tuple[str, ...]  # run only


def _usage(subject: str, detail: str) -> C.ConfigError:
    return C.ConfigError(USAGE, subject, detail)


def _requested(argv: Sequence[str], option: str, allowed: tuple[str, ...], default: str) -> str:
    value, previous = default, ""
    for arg in argv:
        if arg == "--":
            break
        text = arg[len(option) + 1:] if arg.startswith(option + "=") else arg if previous == option else None
        if text is not None:
            value = text if text in allowed else default
        previous = arg
    return value


def diagnostic_format(argv: Sequence[str]) -> str:
    """The diagnostic format an argument vector asks for, decided before
    anything else can fail so that even a usage error is rendered in it.
    This is the launcher's rule (``scripts/sv0cov``): the last
    ``--diagnostic-format`` before ``--`` decides, and anything but exactly
    ``json-lines`` means ``human``."""
    return _requested(argv, FORMAT_OPTION, ("json-lines",), "human")


def color_mode(argv: Sequence[str]) -> str:
    """The color mode asked for, read the same way and for the same reason:
    ``--color=never`` must hold for a usage error too. Anything invalid
    means ``auto``."""
    return _requested(argv, "--color", ("always", "never"), "auto")


def split(argv: Sequence[str]) -> Invocation:
    """Split ``argv`` (without the program name). Raises ``COV0001``."""
    if not argv:
        raise _usage("sv0cov", "a command is required: " + ", ".join(C.COMMANDS))
    command = argv[0]
    if command not in C.COMMANDS:
        raise _usage("sv0cov", "the first argument must be one of " + ", ".join(C.COMMANDS))
    options: list[tuple[str, str | None]] = []
    operands: list[str] = []
    rest: list[str] = []
    i = 1
    while i < len(argv):
        arg = argv[i]
        i += 1
        if arg == "--":
            rest = list(argv[i:])
            break
        if arg.startswith("--"):
            name, eq, text = arg.partition("=")
            opt = C.OPTION.get(name)
            if opt is None:
                raise _usage(name[:64], "is not an sv0cov option")
            if opt.arity == "flag":
                if eq:
                    raise _usage(name, "takes no value")
                options.append((name, None))
            elif eq:
                options.append((name, text))
            elif i < len(argv) and argv[i] != "--":
                options.append((name, argv[i]))
                i += 1
            else:
                raise _usage(name, "needs a value")
        elif arg.startswith("-") and arg != "-":
            raise _usage(arg[:64], "is not an sv0cov option; options are spelled --name")
        else:
            operands.append(arg)
    test_command: tuple[str, ...] = ()
    if command == "run":
        if not rest:
            raise _usage("run", "needs a test command after --")
        test_command = tuple(rest)
    else:
        operands += rest
    low, high, what = OPERANDS[command]
    if len(operands) < low:
        raise _usage(command, f"needs {'one' if high == 1 else 'at least one'} {what}")
    if high is not None and len(operands) > high:
        raise _usage(command, f"takes exactly one {what}" if high else "takes no operand" + (" before --" if command == "run" else ""))
    return Invocation(command, tuple(options), tuple(operands), test_command)
