/**
 * The Report tab (TheHub #60885): the executive summary, then the consult
 * answers it does not already give, then one "What we can't answer".
 */
import { readFileSync } from "node:fs";

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { Report } from "../components/report";
import { REPO_TABS, canonicalTab, retiredTabRedirect } from "../lib/repo-tabs";
import { COVERED_BY_SUMMARY, reportAnswers } from "../lib/report";
import type { ConsultView, ExecutiveSummary } from "../lib/server";

const executive = {
  repo_full_name: "acme/shop",
  generated_at: "2026-10-21T09:00:00Z",
  history_since: "2026-08-11T02:16:42Z",
  open_by_severity: { critical: 1, high: 2, medium: 3, low: 0, info: 0 },
  open_total: 6,
  trend: [
    { days_ago: 7, available: true, open_by_severity: { critical: 1 }, open_total: 5 },
    { days_ago: 30, available: true, open_by_severity: { critical: 0 }, open_total: 4 },
  ],
  drivers: [],
  drivers_basis: "critical_high",
  drivers_basis_total: 3,
  basis_by_capability: {},
  fixability: [
    { key: "fixable_now", findings: 2, serious: 1 },
    { key: "needs_review", findings: 1, serious: 0 },
    { key: "no_vendor_fix", findings: 3, serious: 2 },
  ],
  closing_on_their_own: 0,
  accepted: {
    findings: 4,
    serious: 1,
    decisions_active: 2,
    next_expiries: [],
    nearest_decision_expiry: null,
    overdue: 1,
    no_review_date: 0,
    now_fixable: 0,
  },
  lanes: [
    {
      capability: "sast",
      status: "ok",
      last_run_at: "2026-10-21T08:00:00Z",
      last_success_at: "2026-10-21T08:00:00Z",
      open_findings: 6,
    },
  ],
  progress: {
    days: 30,
    window_starts: null,
    fixed: 3,
    fixed_serious: 1,
    false_positive: 0,
    accepted: 1,
    new: 2,
    new_serious: 0,
    reidentified: 0,
  },
  decisions: [],
  gaps: ["No DAST lane is enabled, so nothing here covers the running application."],
} as unknown as ExecutiveSummary;

const consult = {
  repo_full_name: "acme/shop",
  answers: [
    { key: "open", question: "What is outstanding here?", answer: "6 findings open.", tab: "findings", evidence: [] },
    { key: "ownership", question: "Who is answerable for this?", answer: "Everything open here has an owner.", tab: "findings", evidence: [] },
    { key: "accepted", question: "What have we decided to live with?", answer: "4 findings accepted.", tab: "decisions", evidence: [] },
    { key: "testing", question: "What testing does this have?", answer: "2 of 5 kinds.", tab: "harness", evidence: [] },
  ],
  cannot_answer: [
    { question: "Why did that test fail?", why: "The test lanes record suite totals." },
  ],
  note: "Answered from records.",
} as unknown as ConsultView;

function render(props: Partial<Parameters<typeof Report>[0]> = {}): string {
  return renderToStaticMarkup(
    createElement(Report, {
      repoId: "r1",
      executive,
      executiveError: null,
      consult,
      consultError: null,
      ...props,
    }),
  );
}

function count(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

describe("the repository page has twelve tabs, one of them Report", () => {
  it("is twelve, with Report second and no Consult or Executive report", () => {
    const ids = REPO_TABS.map((entry) => entry.id);
    expect(ids).toHaveLength(12);
    expect(ids[1]).toBe("report");
    expect(ids).not.toContain("consult");
    expect(ids).not.toContain("executive");
    expect(REPO_TABS[1].label).toBe("Report");
  });

  it("follows the old ids to Report", () => {
    expect(canonicalTab("consult")).toBe("report");
    expect(canonicalTab("executive")).toBe("report");
  });

  it("redirects an old tab URL to Report, keeping the other parameters", () => {
    expect(retiredTabRedirect("r1", { tab: "executive" })).toBe("/repos/r1?tab=report");
    expect(retiredTabRedirect("r1", { tab: "consult", view: "x" })).toBe(
      "/repos/r1?tab=report&view=x",
    );
    expect(retiredTabRedirect("r1", { tab: "report" })).toBeNull();
    expect(retiredTabRedirect("r1", {})).toBeNull();
    expect(retiredTabRedirect("r1", { tab: "toString" })).toBeNull();
  });
});

describe("reportAnswers drops what the summary already says", () => {
  it("drops accepted risk and the open/lane answer, and nothing else", () => {
    expect(Object.keys(COVERED_BY_SUMMARY).sort()).toEqual(["accepted", "open"]);
    expect(reportAnswers(consult.answers).map((a) => a.key)).toEqual(["ownership", "testing"]);
  });
});

describe("the Report", () => {
  it("reads executive summary, then consult Q&A, then what we can't answer", () => {
    const html = render();
    const summary = html.indexOf("Security posture report");
    const qa = html.indexOf("What this platform knows");
    const cannot = html.indexOf("What we can&#x27;t answer");
    expect(summary).toBeGreaterThan(-1);
    expect(qa).toBeGreaterThan(summary);
    expect(cannot).toBeGreaterThan(qa);
    expect(html).toContain("Who is answerable for this?");
  });

  it("says accepted risk and lane health once, in the summary's version", () => {
    const html = render();
    expect(html).not.toContain("What have we decided to live with?");
    expect(html).not.toContain("What is outstanding here?");
    expect(count(html, "Accepted risk:")).toBe(1);
    expect(count(html, ">Coverage<")).toBe(1);
  });

  it("puts the summary's gaps under the one can't-answer heading", () => {
    const html = render();
    expect(html).not.toContain("What this report cannot tell you");
    const cannot = html.indexOf("What we can&#x27;t answer");
    expect(html.indexOf("No DAST lane is enabled")).toBeGreaterThan(cannot);
    expect(html.indexOf("Why did that test fail?")).toBeGreaterThan(cannot);
  });

  it("keeps the summary when consult fails, with its own gaps", () => {
    const html = render({ consult: null, consultError: "backend down" });
    expect(html).toContain("Security posture report");
    expect(html).toContain("Consult unavailable");
    expect(html).toContain("What this report cannot tell you");
  });

  it("keeps the consult answers when the summary fails", () => {
    const html = render({ executive: null, executiveError: "backend down" });
    expect(html).toContain("Executive summary unavailable");
    expect(html).toContain("Who is answerable for this?");
  });
});

describe("the Report prints as one document", () => {
  it("marks the whole tab, once, for the print rules", () => {
    const html = render();
    expect(count(html, "data-print-report")).toBe(1);
    expect(html.startsWith("<div data-print-report")).toBe(true);
    expect(html).toContain("print / save as PDF");
  });

  it("hides the 'check it on' links on paper", () => {
    const html = render();
    const links = html.match(/<a [^>]*>check it on/g) ?? [];
    expect(links.length).toBe(2);
    for (const link of links) expect(link).toContain("print:hidden");
  });

  it("still scopes the print stylesheet to that marker", () => {
    const css = readFileSync(new URL("../app/globals.css", import.meta.url), "utf8");
    expect(css).toContain(":root:has([data-print-report]) [data-chrome]");
    expect(css).toMatch(/\[data-print-report\]\s*\{\s*zoom: 0\.8;/);
  });
});
