<!-- SPDX-License-Identifier: CC-BY-4.0 -->
<!-- SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla -->

# Security suite

`tests/test_security.py` is the R0 security gate (SPEC 23, R0-G5). Each
property is checked across every command at once; the per-command suites
(`test_cmd_run`, `test_cmd_clean`, `test_publish`, `test_terminal`,
`test_fuzz`) go deeper on one command each.

## No network (COV-SEC-001)

- Every command (merge, report to files and to stdout, check, version,
  doctor, run with a stand-in driver, clean) runs end to end in one fresh
  `-I -B` interpreter, as the launcher starts it. An audit hook ends the
  process on any socket, name-resolution, URL, HTTP, mail or browser event.
  The run must also import no networking module and start no process but the
  driver and the test command.
- No production module imports a networking module.
- On the Linux CI legs the suite runs again inside an empty network
  namespace (`unshare --net`), where a test checks that connecting anywhere
  really fails.

## Containment (COV-SEC-002)

- `check` and `report` read a source file only where it really is inside the
  project. A source that is, or lies beneath, a symlink pointing out of the
  project is refused with `COV6002` (exit 5), even when its bytes are right.
  A symlink that stays inside is fine. A symlink loop makes the source
  unreadable (`COV1004`).
- Managed output (`merge`, `report`, `clean`) is never written or removed
  through a symlinked output directory; the target outside is untouched.
- A map cannot name a source path that climbs out: `..`, absolute, drive,
  backslash, empty and NUL paths are `COV1010`.
- `merge` does not follow a symlink it finds in an input directory.

## Injection (COV-SEC-003)

A context value made of terminal controls, an OSC title sequence, CR/LF, a
right-to-left override, quotes, a backslash and markup goes through merge,
report and check:

- the native JSON holds no raw control byte, is canonical, and gives the
  exact string back;
- the terminal report, with or without color, holds no control and no
  reordering character, adds no line, and shows the value escaped; a
  backslash is doubled inside quotes, so a trailing backslash cannot forge
  an escaped quote and the characters `\x1b` cannot pass for ESC;
- a hostile file name reaches human diagnostics escaped and JSON Lines as
  one canonical record per line.

## Environment poisoning (COV-SEC-006, AC-098)

Every command is run twice in fresh isolated interpreters, from identical
copies of a project: once with a minimal environment, once with reserved
`SV0COV_*` names of every kind, locale, time zone, color, terminal-width,
`PYTHON*`, compiler and Git variables, an unusable `HOME` and another
`TMPDIR`. Exit statuses, stdout, stderr and every published byte must be
identical.

## Fixed by this suite

- A source symlink pointing outside the project was read by `check` and
  `report`.
- A quoted field ending in a backslash rendered as `"...\"`, which reads as
  an escaped quote.
