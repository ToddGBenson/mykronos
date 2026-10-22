/**
 * The /briefing page (TheHub #60864).
 *
 * Each section status renders as itself: `ok` with its lines grouped by the
 * work they become, `partial` and `unavailable` with their reason, and
 * `not_available` named and empty on purpose. An unreadable section must
 * never render like an empty one that is fine. Lines link to what their ref
 * names, and the product switcher points at `?repo_id=`.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { BriefingSectionCard, BriefingView } from "@/components/briefing";
import {
  briefingHref,
  groupByWork,
  refLink,
  statusMeta,
  workCounts,
  type BriefingLine,
  type BriefingSection,
  type DailyBriefing,
} from "@/lib/briefing";

const REPO_IDS = { "o/thehub": "repo-1", "o/mykronos": "repo-2" };

function line(overrides: Partial<BriefingLine> = {}): BriefingLine {
  return {
    what: "Something changed",
    so_what: "It matters",
    work: "story",
    repo_full_name: "",
    ref: "",
    ...overrides,
  };
}

function section(overrides: Partial<BriefingSection> = {}): BriefingSection {
  return {
    key: "risk_delta",
    title: "Risk delta",
    status: "ok",
    source: "lake findings",
    as_of: "2026-10-21T13:00:00",
    reason: "",
    lines: [],
    data: {},
    ...overrides,
  };
}

function render(value: BriefingSection): string {
  return renderToStaticMarkup(
    createElement(BriefingSectionCard, { section: value, repoIds: REPO_IDS }),
  );
}

describe("a section, by status", () => {
  it("ok: shows source, as-of and its lines grouped merge, decision, story", () => {
    const html = render(
      section({
        lines: [
          line({ what: "KEV introduced", work: "story" }),
          line({ what: "Approved fix", work: "merge" }),
          line({ what: "Acceptance expiring", work: "decision" }),
        ],
      }),
    );
    expect(html).toContain('data-status="ok"');
    expect(html).toContain(">Read<");
    expect(html).toContain("source: lake findings");
    expect(html).toContain("2026-10-21 13:00 UTC");
    expect(html).not.toContain('role="note"');
    const order = ["merge", "decision", "story"].map((work) =>
      html.indexOf(`data-group="${work}"`),
    );
    expect(order.every((index) => index >= 0)).toBe(true);
    expect([...order].sort((a, b) => a - b)).toEqual(order);
    expect(html).toContain("Merge · 1");
  });

  it("ok and empty: says nothing needs you", () => {
    const html = render(section());
    expect(html).toContain("Nothing here needs you.");
  });

  it("partial: shows the reason and the lines it could read", () => {
    const html = render(
      section({
        status: "partial",
        reason: "Threat intelligence (KEV/EPSS) could not be read.",
        lines: [line({ what: "2 critical findings introduced" })],
      }),
    );
    expect(html).toContain(">Partial<");
    expect(html).toContain('role="note"');
    expect(html).toContain("Threat intelligence (KEV/EPSS) could not be read.");
    expect(html).toContain("2 critical findings introduced");
  });

  it("unavailable: names the reason and never reads as all-clear", () => {
    const html = render(
      section({
        status: "unavailable",
        as_of: null,
        reason: "The lake could not be read: catalog locked.",
      }),
    );
    expect(html).toContain(">Unavailable<");
    expect(html).toContain("The lake could not be read: catalog locked.");
    expect(html).toContain("not read");
    expect(html).toContain("Nothing shown, because nothing was read.");
    expect(html).not.toContain("Nothing here needs you.");
  });

  it("not_available: named, empty on purpose, with why", () => {
    const html = render(
      section({
        key: "sprint_health",
        title: "Sprint health",
        status: "not_available",
        as_of: null,
        reason: "Reads TheHub's board: B3 (TheHub #60861).",
      }),
    );
    expect(html).toContain(">Not built yet<");
    expect(html).toContain("B3 (TheHub #60861)");
    expect(html).not.toContain("Nothing here needs you.");
  });

  it("a status the API adds later still renders, in its own word", () => {
    expect(statusMeta("stale").word).toBe("stale");
  });
});

describe("links", () => {
  it("a line links its repository and what its ref names", () => {
    const html = render(
      section({
        lines: [
          line({
            work: "merge",
            repo_full_name: "o/thehub",
            ref: "https://github.com/o/thehub/pull/42",
          }),
        ],
      }),
    );
    expect(html).toContain('href="/repos/repo-1"');
    expect(html).toContain('href="https://github.com/o/thehub/pull/42"');
    expect(html).toContain("PR #42");
    expect(html).toContain('rel="noreferrer"');
  });

  it("maps each kind of ref to its page", () => {
    expect(refLink("TheHub #60864", "", REPO_IDS)).toEqual({
      href: "/product-owner",
      label: "TheHub #60864",
      external: false,
    });
    expect(refLink("/api/risk-acceptances/ra-1", "o/thehub", REPO_IDS)?.href).toBe(
      "/repos/repo-1/risk/ra-1",
    );
    expect(refLink("/api/risk-acceptances/ra-1", "", REPO_IDS)?.href).toBe("/decisions");
    expect(refLink("/api/dashboard/scan-runs/s-9", "o/mykronos", REPO_IDS)?.href).toBe(
      "/repos/repo-2/scan-runs/s-9",
    );
    expect(refLink("abc123def", "o/thehub", REPO_IDS)?.href).toBe(
      "/repos/repo-1/findings/abc123def",
    );
    expect(refLink("upgrade:lodash@4.17.21", "o/thehub", REPO_IDS)?.href).toBe("/remediate");
    // An API route with no page is text, not a link to JSON.
    expect(refLink("/api/exposure", "", REPO_IDS)).toBeNull();
    expect(refLink("", "o/thehub", REPO_IDS)).toBeNull();
    // A finding in a repository that is not onboarded has nowhere to go.
    expect(refLink("abc123def", "o/elsewhere", REPO_IDS)).toBeNull();
  });

  it("a ref with no page is shown as text", () => {
    const html = render(section({ lines: [line({ ref: "/api/exposure" })] }));
    expect(html).toContain("/api/exposure");
    expect(html).not.toContain('href="/api/exposure"');
  });
});

describe("the page", () => {
  const overall: DailyBriefing = {
    generated_at: "2026-10-21T14:00:00",
    scope: "overall",
    repo_full_name: null,
    sections: [
      section({
        key: "needs_you_today",
        title: "Needs you today",
        status: "not_available",
        as_of: null,
        reason: "B3",
      }),
      section({
        key: "production_truth",
        title: "Production truth",
        lines: [line({ work: "merge", what: "Fix approved" })],
      }),
      section({
        key: "trust",
        title: "Can we trust our signals",
        status: "unavailable",
        as_of: null,
        reason: "lake",
      }),
      section({
        key: "suggested_focus",
        title: "Suggested focus",
        status: "partial",
        reason: "B3",
        lines: [line({ work: "merge", what: "Fix approved" })],
      }),
    ],
  };

  const products = [
    { repoId: "repo-1", repoFullName: "o/thehub" },
    { repoId: "repo-2", repoFullName: "o/mykronos" },
  ];

  it("renders every section in the order the API gave", () => {
    const html = renderToStaticMarkup(
      createElement(BriefingView, { briefing: overall, products, selectedRepoId: null }),
    );
    const keys = [...html.matchAll(/data-section="([a-z_]+)"/g)].map((match) => match[1]);
    expect(keys).toEqual(["needs_you_today", "production_truth", "trust", "suggested_focus"]);
    expect(html).toContain("Morning briefing");
    expect(html).toContain("data-print-report");
    expect(html).toContain(
      "Needs you: 1 merge, 0 decisions, 0 stories. Not read: Needs you today, Can we trust our signals.",
    );
  });

  it("offers every product, marking the one shown", () => {
    const html = renderToStaticMarkup(
      createElement(BriefingView, {
        briefing: { ...overall, scope: "product", repo_full_name: "o/thehub" },
        products,
        selectedRepoId: "repo-1",
      }),
    );
    expect(html).toContain("Briefing: o/thehub");
    expect(html).toContain('href="/briefing"');
    expect(html).toContain('href="/briefing?repo_id=repo-2"');
    expect(html).toMatch(/aria-current="page"[^>]*href="\/briefing\?repo_id=repo-1"|href="\/briefing\?repo_id=repo-1"[^>]*aria-current="page"/);
  });
});

describe("helpers", () => {
  it("groups by work and drops empty groups", () => {
    const groups = groupByWork([line({ work: "story" }), line({ work: "merge" })]);
    expect(groups.map((group) => group.work)).toEqual(["merge", "story"]);
    expect(groupByWork(undefined)).toEqual([]);
  });

  it("counts each line once and leaves the focus list out", () => {
    const shared = line({ work: "decision", what: "Renew RA-1", ref: "x" });
    expect(
      workCounts([
        section({ key: "acceptances", lines: [shared, line({ work: "story" })] }),
        section({ key: "other", lines: [shared] }),
        section({ key: "suggested_focus", lines: [shared, line({ work: "merge" })] }),
      ]),
    ).toEqual({ merge: 0, decision: 1, story: 1 });
  });

  it("builds the switcher's links", () => {
    expect(briefingHref(null)).toBe("/briefing");
    expect(briefingHref("a b")).toBe("/briefing?repo_id=a%20b");
  });
});
