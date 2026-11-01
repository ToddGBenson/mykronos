import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { StatusPill } from "../components/status";
import { STATUS, STATUS_ORDER } from "../lib/status";

/**
 * Every state pairs its colour with an icon and a word (TheHub #61135), so
 * nothing on the board or the run sheet is carried by colour alone.
 */
describe("the status scale", () => {
  it("has the six board states first, then the run-sheet ones", () => {
    expect(STATUS_ORDER.slice(0, 6)).toEqual([
      "healthy",
      "failing",
      "stale",
      "never",
      "accepted",
      "overdue",
    ]);
  });

  it("gives every state its own word, and every board state its own icon", () => {
    const words = STATUS_ORDER.map((s) => STATUS[s].word);
    expect(new Set(words).size).toBe(STATUS_ORDER.length);
    const icons = STATUS_ORDER.slice(0, 6).map((s) => STATUS[s].icon);
    expect(new Set(icons).size).toBe(6);
  });

  it("colours each state from a palette token, never a literal", () => {
    for (const s of STATUS_ORDER) {
      expect(STATUS[s].token).toMatch(/^(ok|fail|stale|warn|ready|accepted|ink-3)$/);
    }
  });

  it("renders the word, and hides the icon from screen readers", () => {
    for (const s of STATUS_ORDER) {
      const html = renderToStaticMarkup(createElement(StatusPill, { status: s }));
      expect(html).toContain(STATUS[s].word);
      expect(html).toMatch(/<svg[^>]*aria-hidden="true"/);
    }
  });

  it("draws never-scanned as a dashed outline with no fill", () => {
    const html = renderToStaticMarkup(createElement(StatusPill, { status: "never" }));
    expect(html).toContain("border-dashed");
    expect(html).not.toMatch(/bg-(ok|fail|stale|warn|ready|accepted)/);
  });

  it("can show a label in place of the word, and keeps the word for screen readers", () => {
    const html = renderToStaticMarkup(
      createElement(StatusPill, { status: "failing", label: "3h" }),
    );
    expect(html).toContain("3h");
    expect(html).toContain("failing");
  });
});
