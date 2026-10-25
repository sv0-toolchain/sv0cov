# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
"""HTML report accessibility checks that need no browser (CV-408; WCAG 2.2
AA; SPEC 21.2, R1-G8, COV-REP-007).

The browser checks (axe-core 4.14.0 on the representative report set, and
the keyboard walk) are ``tools/accessibility/axe_check.mjs``, run by the CI
``accessibility`` job. These run everywhere:

- **Contrast (1.4.3, 1.4.11).** Every text colour of the style against
  every background it can sit on is at least 4.5:1, and the focus outline
  at least 3:1 against every background, computed from the style itself
  (axe cannot decide many cells, whose backgrounds overlap).
- **Theme.** The document declares ``color-scheme: light`` and sets its
  own background, so a dark preference cannot put dark text on a dark
  canvas.
- **Character key shortcuts (2.1.4).** ``n``/``p`` act only while focus is
  in a source listing.
- **Target size (2.5.8).** Line-number links are at least 24 by 24 CSS px.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sv0cov.formats.html import SCRIPT, STYLE  # noqa: E402


def luminance(hex_color: str) -> float:
    rgb = [int(hex_color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    lin = [c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4 for c in rgb]
    return 0.2126 * lin[0] + 0.7152 * lin[1] + 0.0722 * lin[2]


def contrast(a: str, b: str) -> float:
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def tokens() -> dict[str, str]:
    root = re.search(r":root\{([^}]*)\}", STYLE).group(1)
    return dict(re.findall(r"(--[\w-]+):(#[0-9a-fA-F]{6})", root))


class ContrastTest(unittest.TestCase):
    def test_every_text_colour_on_every_background(self) -> None:
        t = tokens()
        links = set(re.findall(r"a\{color:(#[0-9a-fA-F]{6})\}", STYLE))
        self.assertTrue(links)
        texts = {"--fg": t["--fg"], "--muted": t["--muted"], **{f"link {c}": c for c in links}}
        backgrounds = {"page": "#ffffff", **{k: t[k] for k in ("--cov", "--par", "--unc", "--exc")}}
        self.assertIn("background:#fff", STYLE)
        for tn, tc in texts.items():
            for bn, bc in backgrounds.items():
                with self.subTest(text=tn, background=bn):
                    self.assertGreaterEqual(contrast(tc, bc), 4.5, f"{tc} on {bc}")

    def test_the_focus_outline_against_every_background(self) -> None:
        t = tokens()
        for bn, bc in {"page": "#ffffff", **{k: t[k] for k in ("--cov", "--par", "--unc", "--exc")}}.items():
            with self.subTest(background=bn):
                self.assertGreaterEqual(contrast(t["--focus"], bc), 3.0)
        self.assertIn("outline:3px solid var(--focus)", STYLE)

    def test_the_formula(self) -> None:
        self.assertAlmostEqual(contrast("#000000", "#ffffff"), 21.0, places=6)
        self.assertAlmostEqual(contrast("#777777", "#ffffff"), 4.478, places=2)

    def test_the_theme_is_fixed_light(self) -> None:
        self.assertIn("color-scheme:light", STYLE)
        self.assertRegex(STYLE, r"body\{[^}]*background:#fff")


class InteractionTest(unittest.TestCase):
    def test_single_key_shortcuts_act_only_in_a_source_listing(self) -> None:
        handler = SCRIPT[SCRIPT.index('addEventListener("keydown"'):]
        guard = handler.index('closest(".wrap")')
        self.assertLess(guard, handler.index("move(1)"))

    def test_line_number_targets_are_24_px(self) -> None:
        self.assertIn(".src th a{display:inline-block;min-width:24px;min-height:24px;line-height:24px}", STYLE)

    def test_the_chain_sees_outcomes_in_note_rows(self) -> None:
        self.assertIn('note.querySelector(".o-u")', SCRIPT)
        self.assertNotIn("if (!block) { return; }", SCRIPT)  # the keys work with one context (no data block)


if __name__ == "__main__":
    unittest.main()
