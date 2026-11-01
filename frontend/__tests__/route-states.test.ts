import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

/**
 * Loading and error states (TheHub #61143, P9). Every page here is dynamic and
 * reads the backend, so a slow answer was a blank main column and a thrown
 * one was Next's own error screen. One root `loading.tsx` and `error.tsx`
 * cover every route below the layout; `global-error.tsx` covers the layout.
 * And one heading scale: every page title is the same size.
 */

vi.mock("next/navigation", () => ({ useRouter: () => ({ refresh: vi.fn() }) }));

const CSS = readFileSync(fileURLToPath(new URL("../app/globals.css", import.meta.url)), "utf8");

describe("loading", () => {
  it("announces that the page is loading and draws a skeleton", async () => {
    const { default: Loading } = await import("../app/loading");
    const html = renderToStaticMarkup(createElement(Loading));
    expect(html).toMatch(/role="status"/);
    expect(html).toContain("Loading this page");
    expect(html).toMatch(/aria-busy="true"/);
    expect(html).toContain("animate-pulse");
  });
});

describe("a page that throws", () => {
  it("says it could not load, offers to retry and names the error's reference", async () => {
    const { default: RouteError } = await import("../app/error");
    const error = Object.assign(new Error("secret backend detail"), { digest: "4130982431" });
    const html = renderToStaticMarkup(createElement(RouteError, { error, retry: () => {} }));
    expect(html).toMatch(/<h1[^>]*>This page could not load<\/h1>/);
    expect(html).toMatch(/<button[^>]*>Try again<\/button>/);
    expect(html).toContain("4130982431");
    expect(html).toMatch(/role="alert"/);
    // The message of a server error is never shown: Next replaces it in
    // production, and a client one may carry what it should not.
    expect(html).not.toContain("secret backend detail");
  });

  it("copes with a thrown value that is not an Error", async () => {
    const { default: RouteError } = await import("../app/error");
    const html = renderToStaticMarkup(
      createElement(RouteError, { error: "a string", retry: () => {} }),
    );
    expect(html).toContain("This page could not load");
    expect(html).not.toContain("reference");
  });

  it("has a boundary for the root layout too, with its own document", async () => {
    const { default: GlobalError } = await import("../app/global-error");
    const html = renderToStaticMarkup(
      createElement(GlobalError, { error: new Error("x"), retry: () => {} }),
    );
    expect(html).toMatch(/^<html lang="en">/);
    expect(html).toContain("MyKronos could not load");
  });
});

describe("one heading scale", () => {
  it("sizes every page title the same, outranking the utilities on each h1", () => {
    // Unlayered, so it beats Tailwind's layered `text-xl`, `text-sm` and
    // `text-[20px]` on the twenty page titles without editing each one.
    const rule = CSS.match(/\nmain h1 \{([^}]*)\}/);
    expect(rule, "an unlayered `main h1` rule").not.toBeNull();
    expect(rule![1]).toMatch(/font-size:\s*var\(--text-page-title\)/);
    expect(CSS).toMatch(/--text-page-title:\s*1\.375rem/);
    const before = CSS.slice(0, CSS.indexOf("\nmain h1 {"));
    const opened = (before.match(/@layer[^{]*\{/g) ?? []).length;
    expect(opened, "the rule must not sit inside an @layer").toBe(0);
  });
});
