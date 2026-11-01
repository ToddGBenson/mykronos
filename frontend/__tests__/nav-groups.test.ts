import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { prerender } from "react-dom/static";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NAV } from "../lib/nav";
import { RETIRED_ROUTES, retiredRoute } from "../lib/retired-routes";

/**
 * The nav, regrouped by job (TheHub #61137, P2 and P5): Work, Platform,
 * Reading. Approvals sits first, and "Decisions", which read as "approvals"
 * but meant the scoring policy, is called Risk policy.
 */

const permanentRedirect = vi.fn((url: string): never => {
  throw new Error(`NEXT_REDIRECT ${url}`);
});
vi.mock("next/navigation", () => ({ permanentRedirect }));

const getReviewQueue = vi.fn();
vi.mock("@/lib/po-console", () => ({ getReviewQueue, getPoEstate: vi.fn() }));
vi.mock("@/lib/server", () => ({ getPullRequests: vi.fn() }));
vi.mock("@/components/worklist", () => ({ WorklistKeys: () => null }));

const items = NAV.flatMap((group) => group.items);

beforeEach(() => {
  vi.clearAllMocks();
  getReviewQueue.mockResolvedValue({
    ok: true,
    data: {
      counts: { pending: 0, unreviewed: 0, overdue: 0, ready_to_merge: 0 },
      pending: [],
      ready_to_merge: [],
      reviewer: { mode: "advisory", agreement: null },
    },
  });
});

describe("the nav is grouped by job (TheHub #61137)", () => {
  it("has three groups: Work, Platform, Reading", () => {
    expect(NAV.map((group) => group.section)).toEqual(["Work", "Platform", "Reading"]);
  });

  it("puts Approvals first, then Portfolio", () => {
    expect(NAV[0].items.slice(0, 2)).toEqual([
      { label: "Approvals", href: "/approvals" },
      { label: "Portfolio", href: "/" },
    ]);
  });

  it("files every page where its job is", () => {
    const where = (label: string) =>
      NAV.find((group) => group.items.some((item) => item.label === label))?.section;
    for (const label of [
      "Approvals",
      "Portfolio",
      "Triage queue",
      "Vulnerability management",
      "Remediate today",
      "Product Owner",
    ]) {
      expect(where(label), label).toBe("Work");
    }
    for (const label of ["Risk policy", "MyKronos Health"]) expect(where(label), label).toBe("Platform");
    for (const label of [
      "Briefing",
      "Weekly intelligence",
      "Threat intelligence",
      "Libraries",
      "Trends",
      "Retros",
    ]) {
      expect(where(label), label).toBe("Reading");
    }
  });

  it("calls the scoring policy Risk policy, not Decisions", () => {
    expect(items).toContainEqual({ label: "Risk policy", href: "/risk-policy" });
    expect(items.map((item) => item.label)).not.toContain("Decisions");
    expect(items.map((item) => item.href)).not.toContain("/decisions");
  });

  it("keeps one label per place, and links no retired route", () => {
    const hrefs = items.map((item) => item.href);
    expect(new Set(hrefs).size).toBe(hrefs.length);
    for (const href of hrefs) expect(Object.hasOwn(RETIRED_ROUTES, href), href).toBe(false);
  });
});

describe("the old routes redirect permanently", () => {
  it("maps /decisions to Risk policy and the review queue to Approvals", () => {
    expect(retiredRoute("/decisions")).toBe("/risk-policy");
    expect(retiredRoute("/product-owner/review-queue")).toBe("/approvals");
  });

  it("/decisions redirects to /risk-policy", async () => {
    const { default: DecisionsPage } = await import("../app/decisions/page");
    expect(() => DecisionsPage()).toThrow("NEXT_REDIRECT");
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/risk-policy");
  });

  it("/product-owner/review-queue redirects to /approvals", async () => {
    const { default: ReviewQueuePage } = await import("../app/product-owner/review-queue/page");
    expect(() => ReviewQueuePage()).toThrow("NEXT_REDIRECT");
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/approvals");
  });

  it("/product-owner?tab=review redirects to /approvals", async () => {
    const { default: ProductOwnerPage } = await import("../app/product-owner/page");
    await expect(
      ProductOwnerPage({ searchParams: Promise.resolve({ tab: "review" }) }),
    ).rejects.toThrow("NEXT_REDIRECT");
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/approvals");
  });
});

describe("Risk policy", () => {
  it("is the page's own title, not only the nav label", () => {
    const source = readFileSync(
      fileURLToPath(new URL("../app/risk-policy/page.tsx", import.meta.url)),
      "utf8",
    );
    expect(source).toMatch(/>\s*Risk policy\s*<\/h1>/);
  });
});

describe("/approvals", () => {
  it("is titled Approvals and shows the pending decisions", async () => {
    const { default: ApprovalsPage } = await import("../app/approvals/page");
    const { prelude } = await prerender(await ApprovalsPage());
    const html = await new Response(prelude).text();
    expect(html).toContain("Approvals</h1>");
    expect(html).toContain("Pending decisions");
    expect(getReviewQueue).toHaveBeenCalledOnce();
  });
});
