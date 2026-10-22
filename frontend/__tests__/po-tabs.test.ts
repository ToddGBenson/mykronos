import { prerender } from "react-dom/static";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { NAV } from "../lib/nav";
import { PO_TABS, isPoTab, poTabHref } from "../lib/po-tabs";
import { RETIRED_ROUTES, retiredRoute } from "../lib/retired-routes";

// `permanentRedirect` throws in Next to abort the render; the mock records the
// destination and throws the same way, so the page is exercised as it runs.
const permanentRedirect = vi.fn((url: string): never => {
  throw new Error(`NEXT_REDIRECT ${url}`);
});
vi.mock("next/navigation", () => ({ permanentRedirect }));

// The tabs read the backend through `server-only` modules; the mocks hand
// each one a result so the page renders in node.
const getPoEstate = vi.fn();
const getReviewQueue = vi.fn();
const getPullRequests = vi.fn();
vi.mock("@/lib/po-console", () => ({ getPoEstate, getReviewQueue }));
vi.mock("@/lib/server", () => ({ getPullRequests }));
// Keyboard movement needs the App Router's client context, which a static
// render does not have; it renders nothing anyway.
vi.mock("@/components/worklist", () => ({ WorklistKeys: () => null }));

const items = NAV.flatMap((group) => group.items);

beforeEach(() => {
  vi.clearAllMocks();
  getPoEstate.mockResolvedValue({
    ok: true,
    data: {
      rows: [],
      totals: {
        repos: 0,
        declared: 0,
        declares_no_process: 0,
        invalid_or_unreadable: 0,
        sprint_done: 0,
        sprint_committed: 0,
        needs_human: 0,
        rows_without_hub: 0,
      },
    },
  });
  getReviewQueue.mockResolvedValue({
    ok: true,
    data: {
      counts: { pending: 0, unreviewed: 0, overdue: 0, ready_to_merge: 0 },
      pending: [],
      ready_to_merge: [],
      reviewer: { mode: "advisory", agreement: null },
    },
  });
  getPullRequests.mockResolvedValue({
    ok: true,
    data: {
      pull_requests: [
        {
          repo_full_name: "acme/shop",
          number: 7,
          title: "Bump lodash",
          summary: "Fixes a prototype pollution finding",
          detail: null,
          kind: "fix",
          url: "https://github.com/acme/shop/pull/7",
          draft: true,
          human_edited: false,
          checks: { total: 1, passed: 1, failed: 0, pending: 0 },
          opened_at: "2026-10-20T10:00:00Z",
          branch: "patchwork/lodash",
          changed_files: null,
          capabilities: [],
        },
      ],
      unreachable: [],
    },
  });
});

async function render(query: Record<string, string> = {}): Promise<string> {
  const { default: ProductOwnerPage } = await import("../app/product-owner/page");
  // `prerender` rather than `renderToStaticMarkup`: each tab is an async
  // server component, and only the streaming renderer waits for them.
  const { prelude } = await prerender(
    await ProductOwnerPage({ searchParams: Promise.resolve(query) }),
  );
  return new Response(prelude).text();
}

describe("the nav rail has one Product Owner entry (TheHub #60884)", () => {
  it("is Product Owner, at /product-owner", () => {
    const po = items.filter((item) => item.href.startsWith("/product-owner"));
    expect(po).toEqual([{ label: "Product Owner", href: "/product-owner" }]);
  });

  it("no longer carries Review queue or Pull requests", () => {
    const labels = items.map((item) => item.label);
    expect(labels).not.toContain("Review queue");
    expect(labels).not.toContain("Pull requests");
    expect(items.map((item) => item.href)).not.toContain("/pull-requests");
  });
});

describe("poTabHref", () => {
  it("lands Estate on the bare path and the others on ?tab=", () => {
    expect(poTabHref("estate")).toBe("/product-owner");
    expect(poTabHref("review")).toBe("/product-owner?tab=review");
    expect(poTabHref("pull-requests")).toBe("/product-owner?tab=pull-requests");
  });

  it("carries a selected pull request after the tab", () => {
    expect(poTabHref("pull-requests", { pr: "7" })).toBe(
      "/product-owner?tab=pull-requests&pr=7",
    );
  });

  it("knows exactly three tabs, and refuses inherited keys", () => {
    expect(PO_TABS.map((entry) => entry.id)).toEqual(["estate", "review", "pull-requests"]);
    expect(isPoTab("review")).toBe(true);
    expect(isPoTab("review-queue")).toBe(false);
    expect(isPoTab("toString")).toBe(false);
  });
});

describe("/product-owner renders three tabs", () => {
  it("opens on Estate, with all three tabs linked", async () => {
    const html = await render();
    expect(html).toContain("Product Owner</h1>");
    expect(html).toContain("Product Owner · estate");
    expect(html).toContain('href="/product-owner?tab=review"');
    expect(html).toContain('href="/product-owner?tab=pull-requests"');
    expect(html).toMatch(/aria-current="page"[^>]*>Estate</);
    expect(getReviewQueue).not.toHaveBeenCalled();
  });

  it("shows the review queue on ?tab=review", async () => {
    const html = await render({ tab: "review" });
    expect(html).toContain("Review queue</h2>");
    expect(html).toContain("Pending decisions");
    expect(html).toMatch(/aria-current="page"[^>]*>Review queue</);
  });

  it("shows the pull requests on ?tab=pull-requests, rows linking within the tab", async () => {
    const html = await render({ tab: "pull-requests" });
    expect(html).toContain("Pull requests</h2>");
    expect(html).toContain("Bump lodash");
    expect(html).toContain('href="/product-owner?tab=pull-requests&amp;pr=7"');
  });

  it("refuses an unknown tab rather than rendering Estate", async () => {
    const html = await render({ tab: "nope" });
    expect(html).toContain("No such tab");
    expect(getPoEstate).not.toHaveBeenCalled();
  });
});

describe("retired paths redirect permanently to their tab", () => {
  it("maps both in RETIRED_ROUTES", () => {
    expect(retiredRoute("/product-owner/review-queue")).toBe("/product-owner?tab=review");
    expect(retiredRoute("/pull-requests")).toBe("/product-owner?tab=pull-requests");
    for (const item of items) expect(Object.hasOwn(RETIRED_ROUTES, item.href)).toBe(false);
  });

  it("/product-owner/review-queue goes to the Review queue tab", async () => {
    const { default: ReviewQueuePage } = await import("../app/product-owner/review-queue/page");
    expect(() => ReviewQueuePage()).toThrow("NEXT_REDIRECT");
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/product-owner?tab=review");
  });

  it("/pull-requests goes to the Pull requests tab", async () => {
    const { default: PullRequestsPage } = await import("../app/pull-requests/page");
    await expect(PullRequestsPage({ searchParams: Promise.resolve({}) })).rejects.toThrow(
      "NEXT_REDIRECT",
    );
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith("/product-owner?tab=pull-requests");
  });

  it("/pull-requests?pr=7 keeps the selected row", async () => {
    const { default: PullRequestsPage } = await import("../app/pull-requests/page");
    await expect(PullRequestsPage({ searchParams: Promise.resolve({ pr: "7" }) })).rejects.toThrow(
      "NEXT_REDIRECT",
    );
    expect(permanentRedirect).toHaveBeenCalledExactlyOnceWith(
      "/product-owner?tab=pull-requests&pr=7",
    );
  });
});
