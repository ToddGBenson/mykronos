import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

/**
 * The v2 palette (TheHub #61135): one teal accent for anything you can press,
 * a six-state status scale, four severity colours, and every text pair at
 * WCAG AA (4.5:1) in both themes.
 *
 * Read from `app/globals.css` itself rather than from a copy, so a token
 * changed by hand is measured the day it changes, not the day someone thinks
 * to check it.
 */

const CSS = readFileSync(
  fileURLToPath(new URL("../app/globals.css", import.meta.url)),
  "utf8",
);

/** The `--color-*` declarations in the first `{...}` after `marker`. */
function tokens(marker: string): Record<string, string> {
  const start = CSS.indexOf(marker);
  if (start < 0) throw new Error(`no block at ${marker}`);
  const open = CSS.indexOf("{", start + marker.length - 1);
  const close = CSS.indexOf("}", open);
  const body = CSS.slice(open + 1, close);
  const out: Record<string, string> = {};
  for (const match of body.matchAll(/--color-([a-z0-9-]+):\s*(#[0-9a-fA-F]{6})\s*;/g)) {
    out[match[1]] = match[2].toLowerCase();
  }
  return out;
}

const LIGHT = tokens("@theme {");
const DARK_OS = tokens(':root:not([data-theme="light"]) {');
const DARK = tokens(':root[data-theme="dark"] {');
const PRINT = tokens(":root:has([data-print-report]) {");

function luminance(hex: string): number {
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a: string, b: string): number {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}

/** Tokens that carry text. Each must be readable on every ground. */
const TEXT = [
  "ink",
  "ink-2",
  "ink-3",
  "accent",
  "critical",
  "high",
  "medium",
  "low",
  "info",
  "pass",
  "ok",
  "warn",
  "fail",
  "stale",
  "ready",
  "accepted",
];
const GROUNDS = ["paper", "paper-2", "paper-3"];

/** Tokens used as a solid fill (a tile, a pill, a count) with `on-fill` text. */
const FILLS = [
  "accent",
  "critical",
  "high",
  "medium",
  "pass",
  "ok",
  "warn",
  "fail",
  "stale",
  "ready",
  "accepted",
];

/** A wash is a tinted ground, read with its own colour on top. */
const WASHES: [string, string][] = [
  ["critical", "critical-wash"],
  ["high", "high-wash"],
  ["pass", "pass-wash"],
  ["accent", "accent-wash"],
];

const THEMES: [string, Record<string, string>][] = [
  ["light", LIGHT],
  ["dark", DARK],
];

describe("the v2 palette (TheHub #61135)", () => {
  it("declares every token in both themes", () => {
    for (const name of [...new Set([...TEXT, ...GROUNDS, ...FILLS, "on-fill"])]) {
      expect(LIGHT[name], `light --color-${name}`).toMatch(/^#/);
      expect(DARK[name], `dark --color-${name}`).toMatch(/^#/);
    }
  });

  it("uses a teal accent that is not the hex of 'high' in either theme (P10)", () => {
    for (const [theme, t] of THEMES) {
      expect(t.accent, theme).not.toBe(t.high);
      expect(t.accent, theme).not.toBe(t.warn);
    }
    expect(LIGHT.accent).toBe("#0b6e80");
    expect(DARK.accent).toBe("#3fc1d4");
  });

  it("keeps the six states and four severities distinct from one another", () => {
    for (const [theme, t] of THEMES) {
      const states = ["ok", "fail", "stale", "warn", "ready", "accepted"].map((n) => t[n]);
      expect(new Set(states).size, `${theme} states`).toBe(6);
      const severities = ["critical", "high", "medium", "low"].map((n) => t[n]);
      expect(new Set(severities).size, `${theme} severities`).toBe(4);
    }
  });

  for (const [theme, t] of THEMES) {
    describe(`${theme} theme, WCAG AA`, () => {
      for (const text of TEXT) {
        for (const ground of GROUNDS) {
          it(`${text} on ${ground} is at least 4.5:1`, () => {
            expect(contrast(t[text], t[ground])).toBeGreaterThanOrEqual(4.5);
          });
        }
      }
      for (const fill of FILLS) {
        it(`on-fill text inside ${fill} is at least 4.5:1`, () => {
          expect(contrast(t["on-fill"], t[fill])).toBeGreaterThanOrEqual(4.5);
        });
      }
      for (const [text, wash] of WASHES) {
        it(`${text} on ${wash} is at least 4.5:1`, () => {
          expect(contrast(t[text], t[wash])).toBeGreaterThanOrEqual(4.5);
          expect(contrast(t.ink, t[wash])).toBeGreaterThanOrEqual(4.5);
        });
      }
    });
  }

  it("gives the dark OS default and the explicit dark choice the same palette", () => {
    expect(DARK_OS).toEqual(DARK);
  });

  it("prints the light palette, not an older one", () => {
    for (const [name, value] of Object.entries(PRINT)) {
      // Print forces a white page; every other printed token is the light one.
      if (name === "paper" || name === "paper-2") continue;
      expect(value, `print --color-${name}`).toBe(LIGHT[name]);
    }
  });
});
