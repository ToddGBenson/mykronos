import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NAV } from "../lib/nav";
import { activeHref } from "../lib/nav-active";

/**
 * The accessibility half of the v2 palette story (TheHub #61135): a skip link,
 * "you are here" on the nav (P5), 44px targets, and group labels that are not
 * dimmed below AA (P10).
 */

const pathname = vi.fn(() => "/");
vi.mock("next/navigation", () => ({ usePathname: () => pathname() }));

const LAYOUT = readFileSync(
  fileURLToPath(new URL("../app/layout.tsx", import.meta.url)),
  "utf8",
);

const HREFS = NAV.flatMap((group) => group.items.map((item) => item.href));

describe("activeHref", () => {
  it("marks Portfolio only on the home page", () => {
    expect(activeHref("/", HREFS)).toBe("/");
    expect(activeHref("/trends", HREFS)).toBe("/trends");
  });

  it("prefers the longest matching item, so a child item wins over its parent", () => {
    expect(activeHref("/briefing/weekly", HREFS)).toBe("/briefing/weekly");
    expect(activeHref("/briefing", HREFS)).toBe("/briefing");
  });

  it("keeps a section active on its sub-pages", () => {
    expect(activeHref("/product-owner/review-queue/abc", HREFS)).toBe("/product-owner");
  });

  it("does not match on a shared prefix that is not a path segment", () => {
    expect(activeHref("/remediate-x", ["/remediate"])).toBeNull();
  });

  it("ignores the query and hash in an item's href", () => {
    expect(activeHref("/product-owner", ["/product-owner?tab=review"])).toBe(
      "/product-owner?tab=review",
    );
  });

  it("returns null for a page no item covers", () => {
    expect(activeHref("/repos/abc", HREFS)).toBeNull();
  });
});

describe("the nav rail", () => {
  beforeEach(() => pathname.mockReset());

  async function render(path: string): Promise<string> {
    pathname.mockReturnValue(path);
    const { NavRail } = await import("../components/nav-rail");
    return renderToStaticMarkup(createElement(NavRail));
  }

  it("marks exactly the current page with aria-current", async () => {
    const html = await render("/trends");
    expect(html.match(/aria-current="page"/g)).toHaveLength(1);
    expect(html).toMatch(/<a[^>]*aria-current="page"[^>]*href="\/trends"|<a[^>]*href="\/trends"[^>]*aria-current="page"/);
  });

  it("gives every link a 44px target", async () => {
    const html = await render("/");
    const links = html.match(/<a [^>]*>/g) ?? [];
    expect(links.length).toBe(HREFS.length);
    for (const link of links) expect(link).toContain("min-h-11");
  });

  it("does not dim the group labels below AA", async () => {
    const html = await render("/");
    expect(html).not.toMatch(/opacity-\d/);
  });

  it("labels the rail as navigation", async () => {
    const html = await render("/");
    expect(html).toMatch(/<nav[^>]*aria-label="Sections"/);
  });
});

describe("the layout", () => {
  it("opens with a skip link to the main landmark", () => {
    expect(LAYOUT).toMatch(/href="#main"[^>]*>\s*Skip to content/);
    expect(LAYOUT).toMatch(/<main[^>]*id="main"/);
    // The skip link must come before the header, or it is not the first stop.
    expect(LAYOUT.indexOf('href="#main"')).toBeLessThan(LAYOUT.indexOf("<header"));
  });

  it("renders the nav through the rail, so aria-current is computed", () => {
    expect(LAYOUT).toContain("<NavRail");
  });
});
