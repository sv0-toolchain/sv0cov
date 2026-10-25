// SPDX-License-Identifier: MIT OR Apache-2.0
// SPDX-FileCopyrightText: 2026 Sasank Vishnubhatla
//
// axe-core WCAG 2.2 AA checks of every HTML report in a directory (CV-408;
// SPEC 21.2, R1-G8, COV-REP-007). Each report is opened from a file URL in
// headless Chromium with the network blocked, in light and dark preference,
// at a desktop and a 320 CSS-pixel width; a report with a context filter is
// also checked after each context is chosen. Any violation of the wcag2a,
// wcag2aa, wcag21a, wcag21aa or wcag22aa rules fails; results axe could not
// decide ("incomplete") are listed for the manual review.
//
//   node tools/accessibility/axe_check.mjs REPORT_DIR

import { readFileSync, readdirSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { chromium } from "playwright";

const require = createRequire(import.meta.url);
const axeSource = readFileSync(require.resolve("axe-core/axe.min.js"), "utf8");
const TAGS = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"];
const dir = resolve(process.argv[2]);
const files = readdirSync(dir).filter((f) => f.endsWith(".html")).sort();

const browser = await chromium.launch();
let failures = 0;
const incomplete = new Map();
let runs = 0;

async function audit(page, label) {
  // The report's CSP admits only its own hashed script; axe is evaluated through the
  // automation protocol, which a page's CSP does not govern, so the report is unchanged.
  await page.evaluate(axeSource);
  const result = await page.evaluate((tags) => window.axe.run(document, { runOnly: { type: "tag", values: tags }, resultTypes: ["violations", "incomplete"] }), TAGS);
  runs += 1;
  for (const v of result.violations) {
    failures += 1;
    console.error(`axe: FAIL ${label}: ${v.id} (${v.impact}) ${v.help}: ${v.nodes.slice(0, 3).map((n) => n.target.join(" ")).join(" | ")}`);
  }
  for (const i of result.incomplete) {
    incomplete.set(i.id, (incomplete.get(i.id) || 0) + i.nodes.length);
  }
}

for (const file of files) {
  for (const scheme of ["light", "dark"]) {
    for (const width of [1280, 320]) {
      const context = await browser.newContext({ colorScheme: scheme, viewport: { width, height: 900 }, javaScriptEnabled: true });
      await context.route("**/*", (route) => (route.request().url().startsWith("file:") ? route.continue() : route.abort()));
      const page = await context.newPage();
      await page.goto(pathToFileURL(join(dir, file)).href);
      const label = `${file} [${scheme}, ${width}px]`;
      await audit(page, label);
      const options = await page.$$eval("#sv0cov-context option", (os) => os.map((o) => o.value));
      for (const value of options) {
        await page.selectOption("#sv0cov-context", value);
        await audit(page, `${label} context ${value}`);
      }
      await context.close();
    }
  }
}
// Keyboard (WCAG 2.1.1, 2.1.2, 2.1.4, 2.4.1, 2.4.3, 2.4.7): checked on every report that has a
// source listing with an uncovered place.
async function keyboard(file) {
  const fail = (what) => { failures += 1; console.error(`keyboard: FAIL ${file}: ${what}`); };
  const context = await browser.newContext({ viewport: { width: 1280, height: 900 } });
  await context.route("**/*", (route) => (route.request().url().startsWith("file:") ? route.continue() : route.abort()));
  const page = await context.newPage();
  await page.goto(pathToFileURL(join(dir, file)).href);
  const active = () => page.evaluate(() => {
    const a = document.activeElement;
    const note = a.nextElementSibling;
    return { tag: a.tagName, id: a.id, row: a.matches(".src tbody tr[id]"),
             stop: a.matches("tr.l-u, tr.l-p") || !!(note && note.className === "note" && note.querySelector(".o-u")),
             outline: getComputedStyle(a).outlineStyle, inSource: !!a.closest(".wrap") };
  });
  // The server-side chain: every line row followed by a note holding a "next uncovered" link.
  const chain = await page.$$eval(".src tbody tr[id]", (rows) => rows.filter((r) => {
    const n = r.nextElementSibling; return n && n.className === "note" && n.querySelector("a.nx");
  }).map((r) => r.id));
  if ((await page.$$(".wrap")).length === 0 || chain.length === 0) { await context.close(); return 0; }
  // 2.1.4: outside a source listing the single-key shortcuts do nothing.
  await page.keyboard.press("n");
  if ((await active()).tag !== "BODY") fail("n moved focus while no source listing had focus");
  // 2.4.1: the first Tab stop is the skip link, and it leads into main.
  await page.keyboard.press("Tab");
  const skip = await page.evaluate(() => ({ cls: document.activeElement.className, href: document.activeElement.getAttribute("href") }));
  if (skip.cls !== "skip") fail(`the first Tab stop is not the skip link (${JSON.stringify(skip)})`);
  if (!(await page.evaluate((h) => !!document.querySelector(h) && !!document.querySelector(h).closest("main, [role=main]") || document.querySelector(h)?.tagName === "MAIN", skip.href))) fail(`the skip link target ${skip.href} is not main`);
  // Following the skip link moves the Tab sequence into main.
  await page.keyboard.press("Enter");
  await page.keyboard.press("Tab");
  if (!(await page.evaluate(() => !!document.activeElement.closest("main")))) fail("after the skip link, Tab does not continue inside main");
  // The context filter works from the keyboard alone and announces what it shows (4.1.3).
  if (await page.$("#sv0cov-context")) {
    await page.focus("#sv0cov-context");
    await page.keyboard.type("c");  // type-ahead picks the first "context ..." option, the same on every platform
    const shown = await page.evaluate(() => ({ value: document.getElementById("sv0cov-context").value,
      status: document.querySelector("[role=status]")?.textContent || "" }));
    if (shown.value === "0" || !shown.status.includes("context")) fail(`the context select did not change from the keyboard (${JSON.stringify(shown)})`);
    if (!(await page.evaluate(() => document.querySelector("[role=status]")?.contains(document.getElementById("sv0cov-shown"))))) fail("the shown context is not in a status region");
    await page.selectOption("#sv0cov-context", "0");
  }
  // 2.1.4 inside a listing: n and p walk the chain of uncovered places, focus stays visible (2.4.7).
  await page.focus(".wrap");
  await page.keyboard.press("n");
  const first = await active();
  if (!first.row || !first.stop || !first.inSource) fail(`n from a source listing did not reach an uncovered place (${JSON.stringify(first)})`);
  if (first.outline === "none") fail("the focused line has no visible outline");
  await page.keyboard.press("n");
  await page.keyboard.press("p");
  const back = await page.evaluate(() => document.activeElement.id);
  await page.focus(".wrap"); await page.keyboard.press("n");
  if (back !== (await page.evaluate(() => document.activeElement.id))) fail("n then p did not return to the same place");
  // n walks exactly the server-side chain, in order, and wraps around.
  const walked = [first.id];
  for (let i = 0; i < chain.length; i += 1) {
    await page.keyboard.press("n");
    walked.push(await page.evaluate(() => document.activeElement.id));
  }
  if (walked.slice(0, chain.length).join(",") !== chain.join(",") || walked[chain.length] !== chain[0]) {
    fail(`n walked ${walked.join(",")}, the chain is ${chain.join(",")}`);
  }
  // 2.1.1 / 2.1.2 / 2.4.3: Tab reaches every focusable element in document order and leaves the page.
  await page.goto(pathToFileURL(join(dir, file)).href);  // a fresh page: Tab starts at the top
  const order = await page.evaluate(() => [...document.querySelectorAll("a[href], select, [tabindex='0']")].map((e, i) => { e.dataset.k = String(i); return String(i); }));
  const seen = [];
  for (let i = 0; i < order.length + 2; i += 1) {
    await page.keyboard.press("Tab");
    const k = await page.evaluate(() => document.activeElement.dataset ? document.activeElement.dataset.k : undefined);
    if (k === undefined) break;
    seen.push(k);
  }
  if (seen.join(",") !== order.join(",")) fail(`Tab order ${seen.slice(0, 8)}... is not document order ${order.slice(0, 8)}... (${seen.length}/${order.length})`);
  await context.close();
  return 1;
}
let keyboardRuns = 0;
for (const file of files) keyboardRuns += await keyboard(file);
if (keyboardRuns === 0) { failures += 1; console.error("keyboard: FAIL no report had a source listing to check"); }
console.log(`keyboard: ${keyboardRuns} reports checked`);

await browser.close();
for (const [id, n] of [...incomplete].sort()) {
  console.log(`axe: needs manual review: ${id} (${n} nodes)`);
}
if (failures) {
  console.error(`axe: ${failures} violation(s) in ${runs} audits`);
  process.exit(1);
}
console.log(`axe: OK (${files.length} reports, ${runs} audits, rules ${TAGS.join(" ")}; axe-core ${JSON.parse(readFileSync(require.resolve("axe-core/package.json"), "utf8")).version})`);
