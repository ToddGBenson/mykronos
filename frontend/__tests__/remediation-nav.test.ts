import { describe, expect, it, vi } from "vitest";

import { NAV } from "../lib/nav";
import { RETIRED_ROUTES, retiredRoute } from "../lib/retired-routes";

// `permanentRedirect` throws in Next to abort the render; the mock records the
// destination and throws the same way, so the page is exercised as it runs.
const permanentRedirect = vi.fn((url: string): never => {
  throw new Error(`NEXT_REDIRECT ${url}`);
});
vi.mock("next/navigation", () => ({ permanentRedirect }));

const items = NAV.flatMap((group) => group.items);

describe("the nav rail has one remediation entry", () => {
  it("is Remediate today, at /remediate", () => {
    const remediation = items.filter((item) => /remediat/i.test(item.label));
    expect(remediation).toEqual([{ label: "Remediate today", href: "/remediate" }]);
  });

  it("no longer links the retired library page", () => {
    expect(items.map((item) => item.href)).not.toContain("/remediation");
    expect(items.map((item) => item.label)).not.toContain("Remediation library");
  });

  it("links no retired route at all", () => {
    for (const item of items) {
      expect(Object.hasOwn(RETIRED_ROUTES, item.href)).toBe(false);
    }
  });

  it("has no two labels leading to one place", () => {
    const hrefs = items.map((item) => item.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
  });
});

describe("retiredRoute", () => {
  it("sends /remediation to the library section of Remediate today", () => {
    expect(retiredRoute("/remediation")).toBe("/remediate#library");
  });

  it("refuses a path that was never retired, and inherited keys", () => {
    expect(() => retiredRoute("/remediate")).toThrow();
    expect(() => retiredRoute("toString")).toThrow();
  });
});

describe("/remediation", () => {
  it("redirects permanently to /remediate#library", async () => {
    const { default: RemediationPage } = await import("../app/remediation/page");
    expect(() => RemediationPage()).toThrow("NEXT_REDIRECT");
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/remediate#library");
  });
});
