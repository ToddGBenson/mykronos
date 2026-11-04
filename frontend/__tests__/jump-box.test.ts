/**
 * The Ctrl+K jump box (TheHub #60976): open -> type -> select -> navigate,
 * driven through the same reducer the component dispatches to, and rendered
 * at each step to hold the dialog's ARIA contract (role=dialog, a listbox, and
 * aria-activedescendant naming the highlighted option).
 *
 * The suite runs in node with no DOM, so the component's markup is rendered
 * with `renderToStaticMarkup` from the state the reducer produced, which is
 * exactly what the live component renders from.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.mock("next/navigation", () => ({ useRouter: () => ({ push: () => undefined }) }));

import { JumpBoxView } from "../components/jump-box";
import {
  INITIAL,
  LISTBOX_ID,
  isJumpShortcut,
  jumpReducer,
  keyAction,
  optionId,
  searchUrl,
  type JumpAction,
  type JumpResult,
  type JumpState,
} from "../lib/jump-box";

const RESULTS: JumpResult[] = [
  { kind: "repo", title: "acme/payments-api", subtitle: "Repository", href: "/repos/r-1" },
  {
    kind: "finding",
    title: "SQL injection",
    subtitle: "acme/payments-api · critical · open · 3f2a9c",
    href: "/repos/r-1/findings/3f2a9c",
  },
  { kind: "page", title: "Triage queue", subtitle: "/triage", href: "/triage" },
];

function run(state: JumpState, ...actions: (JumpAction | null)[]): JumpState {
  return actions.reduce<JumpState>((s, a) => {
    if (a === null) throw new Error("a key the box should handle was let through");
    return jumpReducer(s, a);
  }, state);
}

function render(state: JumpState): string {
  return renderToStaticMarkup(
    createElement(JumpBoxView, {
      state,
      dispatch: () => undefined,
      inputRef: { current: null },
    }),
  );
}

describe("the shortcut", () => {
  it("is Ctrl+K and Cmd+K", () => {
    expect(isJumpShortcut({ key: "k", ctrlKey: true })).toBe(true);
    expect(isJumpShortcut({ key: "k", metaKey: true })).toBe(true);
    expect(isJumpShortcut({ key: "K", ctrlKey: true })).toBe(true);
  });

  it("is not a bare k, or Ctrl+Shift+K", () => {
    expect(isJumpShortcut({ key: "k" })).toBe(false);
    expect(isJumpShortcut({ key: "k", ctrlKey: true, shiftKey: true })).toBe(false);
    expect(isJumpShortcut({ key: "j", ctrlKey: true })).toBe(false);
  });
});

describe("open -> type -> select -> navigate", () => {
  it("goes where the highlighted result points", () => {
    // Closed: nothing rendered at all, so the page underneath is untouched.
    expect(render(INITIAL)).toBe("");

    let state = run(INITIAL, { type: "open" });
    let html = render(state);
    expect(html).toContain('role="dialog"');
    expect(html).toContain('aria-modal="true"');
    expect(html).toContain(`role="listbox"`);
    expect(html).toContain(`id="${LISTBOX_ID}"`);

    state = run(state, { type: "type", query: "pay" });
    expect(state.loading).toBe(true);
    expect(searchUrl(state.query)).toBe("/api/search?q=pay&limit=20");

    state = run(state, { type: "results", query: "pay", results: RESULTS });
    html = render(state);
    expect(html).toContain(`aria-activedescendant="${optionId(0)}"`);
    expect(html).toContain(`id="${optionId(0)}" role="option" aria-selected="true"`);

    // Arrow down twice, up once: the second result.
    state = run(
      state,
      keyAction({ key: "ArrowDown" }),
      keyAction({ key: "ArrowDown" }),
      keyAction({ key: "ArrowUp" }),
    );
    expect(state.active).toBe(1);
    expect(render(state)).toContain(`aria-activedescendant="${optionId(1)}"`);

    state = run(state, keyAction({ key: "Enter" }));
    expect(state.navigateTo).toBe("/repos/r-1/findings/3f2a9c");
    expect(state.open).toBe(false);

    // The component navigates, then clears the request so it fires once.
    state = run(state, { type: "navigated" });
    expect(state.navigateTo).toBeNull();
  });

  it("closes on Escape without navigating", () => {
    const state = run(
      INITIAL,
      { type: "open" },
      { type: "type", query: "tri" },
      { type: "results", query: "tri", results: RESULTS },
      keyAction({ key: "Escape" }),
    );

    expect(state.open).toBe(false);
    expect(state.navigateTo).toBeNull();
    expect(render(state)).toBe("");
  });

  it("wraps around at either end", () => {
    const state = run(
      INITIAL,
      { type: "open" },
      { type: "type", query: "pa" },
      { type: "results", query: "pa", results: RESULTS },
      keyAction({ key: "ArrowUp" }),
    );

    expect(state.active).toBe(RESULTS.length - 1);
  });

  it("does not search one character, which the backend refuses", () => {
    const state = run(INITIAL, { type: "open" }, { type: "type", query: "p" });

    expect(state.loading).toBe(false);
    expect(state.results).toEqual([]);
  });

  it("drops a slow answer to a query the person has typed past", () => {
    const state = run(
      INITIAL,
      { type: "open" },
      { type: "type", query: "pa" },
      { type: "type", query: "pay" },
      { type: "results", query: "pa", results: RESULTS },
    );

    expect(state.results).toEqual([]);
    expect(state.loading).toBe(true);
  });

  it("Enter with nothing to choose stays put", () => {
    const state = run(INITIAL, { type: "open" }, keyAction({ key: "Enter" }));

    expect(state.open).toBe(true);
    expect(state.navigateTo).toBeNull();
  });

  it("names the kind of each result", () => {
    const html = render(
      run(
        INITIAL,
        { type: "open" },
        { type: "type", query: "pa" },
        { type: "results", query: "pa", results: RESULTS },
      ),
    );

    expect(html).toContain("Repo");
    expect(html).toContain("Finding");
    expect(html).toContain("Page");
  });
});

describe("where it lives", () => {
  it("is mounted from the root layout, so every page has it", () => {
    const layout = readFileSync(
      fileURLToPath(new URL("../app/layout.tsx", import.meta.url)),
      "utf8",
    );

    expect(layout).toMatch(/import \{ JumpBox \} from "@\/components\/jump-box"/);
    expect(layout).toContain("<JumpBox />");
  });

  it("reaches the backend through this server's proxy", () => {
    const route = readFileSync(
      fileURLToPath(new URL("../app/api/search/route.ts", import.meta.url)),
      "utf8",
    );

    expect(route).toContain('"/api/dashboard/search"');
  });
});
