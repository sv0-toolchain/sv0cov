# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""What a command writes, and where (CV-225; SPEC 20.2, 20.5.2).

- **Diagnostics** go to stderr, in the chosen format. They are buffered,
  put in the SPEC's order, deduplicated, and written by :meth:`flush`.
  ``--quiet`` never suppresses them. JSON Lines carry nothing else: one
  canonical record per line, no color, no extra text.
- **Incidental human output** (:meth:`say`) goes to stdout and is what
  ``--quiet`` suppresses.
- **A requested artifact** (:meth:`write_artifact`) goes to stdout as bytes
  and is never suppressed or decorated.

Color applies only to human text on a terminal: ``always`` forces it,
``never`` forbids it, ``auto`` uses it when the stream is a terminal. No
environment variable is consulted.
"""

from __future__ import annotations

from typing import BinaryIO, TextIO

from sv0cov.diagnostics import Diagnostic, Registry, load_registry, order_events, render_human, render_json_line

FORMATS = ("human", "json-lines")
COLORS = ("auto", "always", "never")
SGR_ERROR, SGR_OTHER, SGR_RESET = "\x1b[1;31m", "\x1b[1;33m", "\x1b[0m"


def _is_terminal(stream: object) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


class _TextBytes:
    """A byte-stream face for a text stream that has no buffer (a test double)."""

    def __init__(self, stream: TextIO) -> None:
        self._stream = stream

    def write(self, data: bytes) -> int:
        self._stream.write(bytes(data).decode("utf-8"))
        return len(data)

    def flush(self) -> None:
        self._stream.flush()


class Console:
    def __init__(self, stdout: TextIO, stderr: TextIO, *, diagnostic_format: str = "human", quiet: bool = False,
                 color: str = "auto", registry: Registry | None = None) -> None:
        if diagnostic_format not in FORMATS or color not in COLORS:
            raise ValueError("unknown diagnostic format or color mode")
        self.stdout, self.stderr = stdout, stderr
        self.diagnostic_format, self.quiet, self.color = diagnostic_format, quiet, color
        self._registry = registry
        self._pending: list[Diagnostic] = []
        self.emitted: list[dict] = []

    def configure(self, *, quiet: bool, color: str) -> None:
        if color not in COLORS:
            raise ValueError("unknown color mode")
        self.quiet, self.color = quiet, color

    def colored(self, stream: object) -> bool:
        """Whether human text on ``stream`` may carry terminal sequences."""
        return self.color == "always" or (self.color == "auto" and _is_terminal(stream))

    # -- diagnostics ----------------------------------------------------------

    def report(self, diagnostic: Diagnostic) -> None:
        self._pending.append(diagnostic)

    def flush(self) -> None:
        """Write the buffered diagnostics in order, each once."""
        if not self._pending:
            return
        registry = self._registry or load_registry()
        records = [r for r in order_events(self._pending, registry) if r not in self.emitted]
        self._pending = []
        for record in records:
            if self.diagnostic_format == "json-lines":
                self._bytes(self.stderr, render_json_line(record))
            else:
                text = render_human(record)
                if self.colored(self.stderr):
                    head, newline, tail = text.partition("\n")
                    code, _, title = head.partition(": ")
                    sgr = SGR_ERROR if record["severity"] == "error" else SGR_OTHER
                    text = f"{sgr}{code}{SGR_RESET}: {title}{newline}{tail}"
                self.stderr.write(text)
            self.emitted.append(record)
        self.stderr.flush()

    # -- stdout ---------------------------------------------------------------

    def say(self, text: str) -> None:
        """Incidental human output: a summary or progress line."""
        if not self.quiet:
            self.stdout.write(text if text.endswith("\n") else text + "\n")

    def write_artifact(self, data: bytes) -> None:
        """A format the user explicitly sent to stdout."""
        self._bytes(self.stdout, data)
        self.stdout.flush()

    def binary_stdout(self) -> BinaryIO:
        """Stdout as a byte stream, for an artifact that is published to it."""
        self.stdout.flush()
        raw = getattr(self.stdout, "buffer", None)
        return raw if raw is not None else _TextBytes(self.stdout)

    @staticmethod
    def _bytes(stream: object, data: bytes) -> None:
        raw: BinaryIO | None = getattr(stream, "buffer", None)
        if raw is not None:
            stream.flush()
            raw.write(data)
            raw.flush()
        else:
            stream.write(data.decode("utf-8"))
