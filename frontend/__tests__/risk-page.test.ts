/**
 * The Risk page (TheHub #61139, design v2 P4/P6): one row per product, with
 * gate, prod lag, severity counts, oldest high+ against its target, overdue,
 * lanes, acceptances and needs-you, an estate row, and an age chart.
 *
 * Two rules run through every cell. A read that failed is "unknown", never a
 * zero or a pass. And every cell is a link to the filtered view behind it.
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { RiskMatrix, AgeChart } from "@/components/risk-page";
import {
  acceptedCell,
  ageBuckets,
  buildRiskPage,
  gateCell,
  lagCell,
  lanesCell,
  needsYouCell,
  oldestCell,
  overdueCell,
  severityCell,
  targetDays,
  type RiskGroup,
  type RiskInputs,
  type RiskRepoInput,
  type RiskRepoReads,
} from "@/lib/risk-page";

const NOW = Date.parse("2026-11-01T12:00:00Z");

function ok<T>(data: T) {
  return { ok: true as const, data };
}
const FAILED = { ok: false as const, error: "HTTP 500" };

function repo(overrides: Partial<RiskRepoInput> = {}): RiskRepoInput {
  return {
    repo_id: "r1",
    repo_full_name: "o/beacon",
    status: "active",
    synthetic: false,
    severity_counts: { critical: 0, high: 0, medium: 0 },
    enabled_capabilities: ["sast", "sca"],
    capability_states: [
      { capability: "sast", has_scanned: true, last_scan_at: "2026-11-01T10:00:00" },
      { capability: "sca", has_scanned: true, last_scan_at: "2026-11-01T09:00:00" },
    ],
    last_scan_at: "2026-11-01T10:00:00",
    ...overrides,
  };
}

function group(overrides: Partial<RiskGroup> = {}): RiskGroup {
  return {
    severity: "high",
    occurrences: 1,
    age_days: 3,
    first_seen_at: "2026-10-29T12:00:00",
    due_at: "2026-11-28T12:00:00",
    due_state: "on_track",
    ...overrides,
  };
}

function reads(overrides: Partial<RiskRepoReads> = {}): RiskRepoReads {
  return {
    gate: ok({ found: true, commit_sha: "a".repeat(40), effective_recommendation: "go" }),
    highPlus: ok([]),
    overdue: ok([]),
    acceptances: ok([]),
    ...overrides,
  };
}

describe("gateCell: the newest commit gate on main", () => {
  it("reads GO", () => {
    const cell = gateCell("r1", reads().gate);
    expect(cell.text).toBe("GO");
    expect(cell.tone).toBe("ok");
    expect(cell.href).toBe("/repos/r1?tab=decisions");
  });

  it("reads NO-GO with the blocking count when the commit introduced blocking findings", () => {
    const cell = gateCell(
      "r1",
      ok({
        found: true,
        commit_sha: "b".repeat(40),
        effective_recommendation: "review_recommended",
        introduced: { critical: 1, high: 2, medium: 4 },
        introduced_blocking: true,
      }),
    );
    expect(cell.text).toBe("NO-GO · 3 blocking");
    expect(cell.tone).toBe("fail");
    expect(cell.label).toContain("bbbbbbb");
  });

  it("an override that accepted the commit stands", () => {
    const cell = gateCell(
      "r1",
      ok({
        found: true,
        commit_sha: "c".repeat(40),
        effective_recommendation: "go",
        overridden: true,
        introduced: { high: 1 },
        introduced_blocking: true,
      }),
    );
    expect(cell.text).toBe("GO");
    expect(cell.label).toContain("overridden");
  });

  it("an effective no_go is NO-GO and review is its own word", () => {
    expect(gateCell("r1", ok({ found: true, commit_sha: "d", effective_recommendation: "no_go" })).tone).toBe("fail");
    const review = gateCell("r1", ok({ found: true, commit_sha: "d", effective_recommendation: "review_recommended" }));
    expect(review.text).toBe("REVIEW");
    expect(review.tone).toBe("warn");
  });

  it("no decision is 'not assessed', never a pass", () => {
    expect(gateCell("r1", ok(null)).text).toBe("not assessed");
    expect(gateCell("r1", ok(null)).tone).toBe("never");
    expect(gateCell("r1", ok({ found: false, commit_sha: "e" })).tone).toBe("never");
  });

  it("a failed read is unknown", () => {
    const cell = gateCell("r1", FAILED);
    expect(cell.text).toBe("unknown");
    expect(cell.tone).toBe("stale");
    expect(cell.label).toContain("HTTP 500");
  });
});

describe("lagCell: production against its branch, from /deployments", () => {
  it("at head is 0, behind is N commits, diverged is a failure", () => {
    const deployments = ok({
      "o/a": { status: "at_head", branch: "main", behind_by: 0 },
      "o/b": { status: "behind", branch: "main", behind_by: 4 },
      "o/c": { status: "diverged", branch: "main", behind_by: 2, not_on_branch: 1 },
      "o/d": { status: "unknown", branch: "main", detail: "probe 503" },
      "o/e": null,
    });
    expect(lagCell("r", deployments, "o/a")).toMatchObject({ text: "0", tone: "ok" });
    expect(lagCell("r", deployments, "o/b")).toMatchObject({ text: "4 commits", tone: "warn" });
    expect(lagCell("r", deployments, "o/b").label).toContain("4 commits behind main");
    expect(lagCell("r", deployments, "o/c").tone).toBe("fail");
    expect(lagCell("r", deployments, "o/d")).toMatchObject({ text: "unknown", tone: "stale" });
    expect(lagCell("r", deployments, "o/e")).toMatchObject({ text: "no probe", tone: "never" });
    expect(lagCell("r", deployments, "o/missing").tone).toBe("never");
  });

  it("1 commit, not 1 commits", () => {
    expect(lagCell("r", ok({ "o/a": { status: "behind", behind_by: 1 } }), "o/a").text).toBe("1 commit");
  });

  it("a failed /deployments read is unknown on every row", () => {
    expect(lagCell("r", FAILED, "o/a")).toMatchObject({ text: "unknown", tone: "stale" });
  });
});

describe("severityCell", () => {
  it("links to the findings filtered to that severity, and greys zero", () => {
    const cell = severityCell("r1", "critical", { critical: 2 });
    expect(cell).toMatchObject({ value: 2, tone: "crit" });
    expect(cell.href).toBe("/repos/r1?tab=findings&severity=critical");
    expect(severityCell("r1", "medium", {}).tone).toBe("zero");
    expect(severityCell("r1", "high", { high: 7 }).tone).toBe("high");
  });
});

describe("targetDays and oldestCell", () => {
  it("the target is the window from first seen to due", () => {
    expect(targetDays(group({ first_seen_at: "2026-10-01T00:00:00", due_at: "2026-10-08T00:00:00" }))).toBe(7);
    expect(targetDays(group({ first_seen_at: "2026-10-01T00:00:00Z", due_at: "2026-10-31" }))).toBe(30);
    expect(targetDays(group({ due_at: null }))).toBeNull();
  });

  it("names the oldest high or critical against its own target", () => {
    const cell = oldestCell(
      "r1",
      ok([
        group({ age_days: 3 }),
        group({
          age_days: 9,
          first_seen_at: "2026-10-23T12:00:00",
          due_at: "2026-10-30T12:00:00",
          due_state: "overdue",
        }),
      ]),
    );
    expect(cell.text).toBe("9d / 7d");
    expect(cell.tone).toBe("warn");
    expect(cell.href).toBe("/repos/r1?tab=findings&severity=critical%2Chigh&sort=oldest");
  });

  it("inside its target is ok; no target says so", () => {
    expect(oldestCell("r1", ok([group({ age_days: 12, first_seen_at: "2026-10-20T00:00:00", due_at: "2026-11-19T00:00:00" })]))).toMatchObject({ text: "12d / 30d", tone: "ok" });
    expect(oldestCell("r1", ok([group({ age_days: 5, due_at: null })])).text).toBe("5d / no target");
  });

  it("nothing open is a dash; a failed read is unknown", () => {
    expect(oldestCell("r1", ok([]))).toMatchObject({ text: "—", tone: "never" });
    expect(oldestCell("r1", FAILED).tone).toBe("stale");
  });
});

describe("overdueCell", () => {
  it("adds the occurrences of the overdue groups", () => {
    const cell = overdueCell("r1", ok([group({ occurrences: 2 }), group({ occurrences: 1 })]));
    expect(cell).toMatchObject({ value: 3, tone: "warn" });
    expect(cell.href).toBe("/repos/r1?tab=findings&due=overdue");
    expect(overdueCell("r1", ok([])).tone).toBe("zero");
    expect(overdueCell("r1", FAILED)).toMatchObject({ value: null, tone: "unknown" });
  });
});

describe("lanesCell", () => {
  it("all reporting is n/n", () => {
    expect(lanesCell(repo(), NOW)).toMatchObject({ text: "2/2", tone: "ok" });
  });

  it("one red links to that lane's run history", () => {
    const cell = lanesCell(
      repo({
        capability_states: [
          { capability: "sast", has_scanned: true, last_run_failed: true, last_scan_at: "2026-11-01T10:00:00" },
          { capability: "sca", has_scanned: true, last_scan_at: "2026-11-01T09:00:00" },
        ],
      }),
      NOW,
    );
    expect(cell.text).toBe("1/2 · 1 red");
    expect(cell.tone).toBe("fail");
    expect(cell.href).toBe("/repos/r1/checks/sast");
  });

  it("an enabled lane with no report in 7 days is silent", () => {
    const cell = lanesCell(
      repo({
        capability_states: [
          { capability: "sast", has_scanned: true, last_scan_at: "2026-10-20T10:00:00" },
          { capability: "sca", has_scanned: false },
        ],
      }),
      NOW,
    );
    expect(cell.text).toBe("0/2 · 2 silent");
    expect(cell.tone).toBe("stale");
  });

  it("nothing enabled is never scanned", () => {
    expect(lanesCell(repo({ enabled_capabilities: [], capability_states: [] }), NOW)).toMatchObject({ text: "0/0", tone: "never" });
  });
});

describe("acceptedCell", () => {
  it("counts acceptances in force and the ones expiring, and links to them", () => {
    const cell = acceptedCell(
      "r1",
      ok([
        { id: "a1", state: "active", days_left: 90 },
        { id: "a2", state: "expiring", days_left: 7 },
        { id: "a3", state: "expiring", days_left: 1 },
        { id: "a4", state: "closed", days_left: null },
        { id: "a5", state: "premise_failed", days_left: 40 },
      ]),
    );
    expect(cell.text).toBe("4 · 2 expiring");
    expect(cell.tone).toBe("acc");
    expect(cell.label).toContain("soonest in 1 day");
    expect(cell.href).toBe("/repos/r1?tab=risk&state=expiring");
  });

  it("none is never; a failed read is unknown", () => {
    expect(acceptedCell("r1", ok([]))).toMatchObject({ text: "0", tone: "never", href: "/repos/r1?tab=risk" });
    expect(acceptedCell("r1", FAILED).tone).toBe("stale");
  });
});

describe("needsYouCell", () => {
  const approvals = ok([
    { id: "p1", duty: "pull_request_merge", subject_ref: "o/beacon#12@abc", expires_at: "2026-11-05T00:00:00Z" },
    { id: "p2", duty: "pull_request_merge", subject_ref: "o/beacon-api#3@abc", expires_at: "2026-11-05T00:00:00Z" },
    { id: "p3", duty: "risk_acceptance", subject_ref: "a2", expires_at: "2026-11-05T00:00:00Z" },
    { id: "p4", duty: "pull_request_merge", subject_ref: "o/beacon#13@def", expires_at: "2026-10-30T00:00:00Z" },
  ]);

  it("counts this product's pull requests and acceptances awaiting a decision, not lapsed ones", () => {
    const cell = needsYouCell("o/beacon", ok([{ id: "a2", state: "pending_approval", days_left: null }]), approvals, NOW);
    expect(cell.value).toBe(2);
    expect(cell.href).toBe("/product-owner?tab=review");
  });

  it("a failed approvals read is unknown", () => {
    expect(needsYouCell("o/beacon", ok([]), FAILED, NOW).tone).toBe("unknown");
  });
});

describe("ageBuckets", () => {
  it("bands open high and critical by age, weighted by occurrences", () => {
    const buckets = ageBuckets([
      group({ severity: "critical", age_days: 2 }),
      group({ severity: "high", age_days: 7, occurrences: 3 }),
      group({ severity: "high", age_days: 8 }),
      group({ severity: "high", age_days: 45 }),
      group({ severity: "high", age_days: 91 }),
      group({ severity: "medium", age_days: 91 }),
    ]);
    expect(buckets.map((b) => [b.label, b.critical, b.high])).toEqual([
      ["0–7 days", 1, 3],
      ["8–30 days", 0, 1],
      ["31–90 days", 0, 1],
      ["over 90 days", 0, 1],
    ]);
  });
});

function inputs(overrides: Partial<RiskInputs> = {}): RiskInputs {
  return {
    repos: [
      repo({ repo_id: "r1", repo_full_name: "o/beacon", severity_counts: { critical: 1, high: 7, medium: 9 } }),
      repo({ repo_id: "r2", repo_full_name: "o/relay", severity_counts: { high: 3, medium: 14 } }),
      repo({ repo_id: "r3", repo_full_name: "o/bench", synthetic: true, severity_counts: { critical: 50 } }),
      repo({ repo_id: "r4", repo_full_name: "o/gone", status: "removed" }),
    ],
    deployments: ok({ "o/beacon": { status: "at_head", behind_by: 0 }, "o/relay": { status: "behind", behind_by: 4 } }),
    reads: {
      r1: reads({
        gate: ok({ found: true, commit_sha: "f".repeat(40), effective_recommendation: "go", introduced: { critical: 1 }, introduced_blocking: true }),
        highPlus: ok([group({ severity: "critical", age_days: 9, first_seen_at: "2026-10-23T12:00:00", due_at: "2026-10-30T12:00:00", due_state: "overdue" })]),
        overdue: ok([group({ occurrences: 3 })]),
      }),
      r2: reads({ highPlus: ok([group({ age_days: 12 })]) }),
      r3: reads(),
    },
    approvals: ok([
      { id: "p1", duty: "pull_request_merge", subject_ref: "o/relay#2@abc", expires_at: "2026-11-05T00:00:00Z" },
      { id: "p2", duty: "finding_disposition", subject_ref: "f-123", expires_at: "2026-11-05T00:00:00Z" },
    ]),
    ...overrides,
  };
}

describe("buildRiskPage", () => {
  it("one row per active product, benchmark and removed left out, problems first", () => {
    const page = buildRiskPage(inputs(), { now: NOW });
    expect(page.rows.map((r) => r.name)).toEqual(["o/beacon", "o/relay"]);
    expect(page.rows[0].problem).toBe(true);
  });

  it("includes the benchmark when asked", () => {
    const page = buildRiskPage(inputs(), { now: NOW, benchmark: true });
    expect(page.rows.map((r) => r.name)).toContain("o/bench");
  });

  it("problems only drops the quiet rows", () => {
    const quiet = inputs({
      deployments: ok({ "o/beacon": { status: "at_head", behind_by: 0 }, "o/relay": { status: "at_head", behind_by: 0 } }),
      approvals: ok([]),
    });
    quiet.repos[1].severity_counts = { medium: 2 };
    const page = buildRiskPage(quiet, { now: NOW, problemsOnly: true });
    expect(page.rows.map((r) => r.name)).toEqual(["o/beacon"]);
  });

  it("the estate row adds the rows up, and needs-you counts every pending request", () => {
    const { estate } = buildRiskPage(inputs(), { now: NOW });
    expect(estate.gate.text).toBe("1 no-go");
    expect(estate.lag.text).toBe("1 behind");
    expect(estate.critical.value).toBe(1);
    expect(estate.high.value).toBe(10);
    expect(estate.medium.value).toBe(23);
    expect(estate.oldest.text).toBe("12d oldest");
    expect(estate.oldest.tone).toBe("warn");
    expect(estate.overdue.value).toBe(3);
    expect(estate.needs.value).toBe(2);
  });

  it("says how many products were scanned in the last 24 hours, and which reads failed", () => {
    const failing = inputs();
    failing.reads.r2 = reads({ overdue: FAILED });
    failing.repos[1].last_scan_at = "2026-10-30T00:00:00";
    const page = buildRiskPage(failing, { now: NOW });
    expect(page.scannedRecently).toBe(1);
    expect(page.products).toBe(2);
    expect(page.incomplete).toEqual(["o/relay"]);
    expect(page.estate.overdue.label).toContain("at least");
  });

  it("a product with no reads at all is unknown everywhere, not clean", () => {
    const missing = inputs();
    delete missing.reads.r2;
    const row = buildRiskPage(missing, { now: NOW }).rows.find((r) => r.name === "o/relay")!;
    expect(row.gate.tone).toBe("stale");
    expect(row.overdue.tone).toBe("unknown");
  });
});

describe("RiskMatrix and AgeChart render", () => {
  const page = buildRiskPage(inputs(), { now: NOW });
  const html = renderToStaticMarkup(createElement(RiskMatrix, { page }));

  it("has the eleven columns of the design", () => {
    for (const heading of [
      "Product",
      "Gate (newest commit)",
      "Prod lag",
      "Crit",
      "High",
      "Med",
      "Oldest high+ / target",
      "Overdue",
      "Lanes",
      "Accepted · expiring",
      "Needs you",
    ]) {
      expect(html).toContain(`>${heading}</th>`);
    }
    expect(html).toContain('scope="row"');
    expect(html).toContain(">Estate</th>");
  });

  it("every cell is a link with the state in words for a screen reader", () => {
    expect(html).toContain('href="/repos/r1?tab=decisions"');
    expect(html).toContain('href="/repos/r1?tab=findings&amp;due=overdue"');
    expect(html).toContain('href="/repos/r1?tab=findings&amp;severity=critical"');
    expect(html).toContain('href="/product-owner?tab=review"');
    expect(html).toMatch(/aria-label="o\/beacon gate: failing[^"]*"/);
    expect(html).toContain("NO-GO · 1 blocking");
  });

  it("each state draws an icon as well as a colour", () => {
    expect(html).toContain('data-tone="fail"');
    expect(html).toContain('data-icon="cross"');
    expect(html).toContain('data-icon="tick"');
  });

  it("the age chart labels its bands and its counts", () => {
    const chart = renderToStaticMarkup(createElement(AgeChart, { buckets: page.buckets }));
    expect(chart).toContain("0–7 days");
    expect(chart).toContain("over 90 days");
    expect(chart).toContain('aria-label="8–30 days: 1 critical, 1 high"');
    expect(chart).toContain('aria-label="0–7 days: 0 critical, 0 high"');
  });
});

// -- Review of #1080: unknown is never a green zero ------------------------

function allFailed(): RiskInputs {
  return inputs({
    deployments: FAILED,
    approvals: FAILED,
    reads: {
      r1: reads({ gate: FAILED, highPlus: FAILED, overdue: FAILED, acceptances: FAILED }),
      r2: reads({ gate: FAILED, highPlus: FAILED, overdue: FAILED, acceptances: FAILED }),
    },
  });
}

describe("the estate row when reads fail", () => {
  it("every read failing is unknown in every estate cell, never a green zero", () => {
    const page = buildRiskPage(allFailed(), { now: NOW });
    const { estate } = page;
    for (const cell of [estate.gate, estate.lag, estate.oldest, estate.accepted]) {
      expect(cell.tone).toBe("stale");
      expect(cell.text).not.toMatch(/^0\b/);
      expect(cell.label).toContain("could not be read");
    }
    expect(estate.gate.text).not.toBe("0 no-go");
    expect(estate.lag.text).not.toBe("0 behind");
    expect(estate.accepted.text).not.toBe("0 expiring");
    expect(page.ageCoverage.unread).toEqual(["o/beacon", "o/relay"]);
  });

  it("the age chart says it could not be read, and draws no zero bars", () => {
    const page = buildRiskPage(allFailed(), { now: NOW });
    const chart = renderToStaticMarkup(
      createElement(AgeChart, { buckets: page.buckets, coverage: page.ageCoverage }),
    );
    expect(chart).toContain("could not be read");
    expect(chart).not.toContain('aria-label="0–7 days: 0 critical, 0 high"');
  });

  it("one product unread: a no-go elsewhere still shows, as a floor", () => {
    const partial = inputs();
    partial.reads.r2 = reads({ gate: FAILED });
    const { estate } = buildRiskPage(partial, { now: NOW });
    expect(estate.gate.text).toBe("1 no-go");
    expect(estate.gate.tone).toBe("fail");
    expect(estate.gate.label).toContain("at least");
  });

  it("one product unread and the rest go: unknown, not ok", () => {
    const partial = inputs();
    partial.reads.r1 = reads();
    partial.reads.r2 = reads({ gate: FAILED });
    const { estate } = buildRiskPage(partial, { now: NOW });
    expect(estate.gate.tone).toBe("stale");
    expect(estate.gate.text).toContain("1 unknown");
  });

  it("a partial age chart says its totals are floors", () => {
    const partial = inputs();
    partial.reads.r2 = reads({ highPlus: FAILED });
    const page = buildRiskPage(partial, { now: NOW });
    expect(page.estate.oldest.label).toContain("at least");
    const chart = renderToStaticMarkup(
      createElement(AgeChart, { buckets: page.buckets, coverage: page.ageCoverage }),
    );
    expect(chart).toContain("at least");
    expect(chart).toContain("o/relay");
  });
});

describe("a read truncated at its limit is a floor", () => {
  const capped = {
    groups: [group({ occurrences: 2000, due_state: "overdue", age_days: 40 })],
    matching: 2000,
    shown: 2000,
    truncated: true,
  };

  it("overdue reads `matching` and says 'at least' when truncated", () => {
    const cell = overdueCell("r1", ok(capped));
    expect(cell.value).toBe(2000);
    expect(cell.floor).toBe(true);
    expect(cell.label).toContain("at least");
  });

  it("an untruncated overdue read is exact", () => {
    const cell = overdueCell("r1", ok({ ...capped, truncated: false }));
    expect(cell.floor).toBeFalsy();
    expect(cell.label).not.toContain("at least");
  });

  it("oldest is a floor when the high+ read was cut short, or matched more than it showed", () => {
    for (const read of [capped, { ...capped, truncated: false, matching: 2500 }]) {
      const cell = oldestCell("r1", ok(read));
      expect(cell.text.startsWith("≥")).toBe(true);
      expect(cell.label).toContain("at least");
    }
  });

  it("the estate row, the count link and the age chart carry the floor through", () => {
    const cut = inputs();
    cut.reads.r2 = reads({ highPlus: ok(capped), overdue: ok(capped) });
    const page = buildRiskPage(cut, { now: NOW });
    expect(page.estate.overdue.floor).toBe(true);
    expect(page.estate.overdue.label).toContain("at least");
    expect(page.ageCoverage.truncated).toEqual(["o/relay"]);
    const html = renderToStaticMarkup(createElement(RiskMatrix, { page }));
    expect(html).toContain("≥2003");
    const chart = renderToStaticMarkup(
      createElement(AgeChart, { buckets: page.buckets, coverage: page.ageCoverage }),
    );
    expect(chart).toContain("at least");
  });
});

describe("acceptances: estate in force, and what 'in force' counts", () => {
  it("the estate cell shows in force and expiring, like a product row", () => {
    const withAcc = inputs();
    withAcc.reads.r1 = reads({
      acceptances: ok([
        { id: "a1", state: "active", days_left: 50 },
        { id: "a2", state: "expiring", days_left: 9 },
      ]),
    });
    const { estate } = buildRiskPage(withAcc, { now: NOW });
    expect(estate.accepted.text).toBe("2 · 1 expiring");
  });

  it("the tooltip says when needs-review or premise-failed acceptances are counted", () => {
    const cell = acceptedCell(
      "r1",
      ok([
        { id: "a1", state: "active", days_left: 50 },
        { id: "a2", state: "needs_review", days_left: 20 },
        { id: "a3", state: "premise_failed", days_left: 20 },
      ]),
    );
    expect(cell.label).toContain("needs review");
    expect(cell.label).toContain("premise failed");
  });
});

describe("the gate column names what it reads", () => {
  it("decision records carry no branch, so the heading does not claim main", () => {
    const html = renderToStaticMarkup(
      createElement(RiskMatrix, { page: buildRiskPage(inputs(), { now: NOW }) }),
    );
    expect(html).not.toContain(">Gate (main)</th>");
    expect(html).toContain(">Gate (newest commit)</th>");
    expect(gateCell("r1", ok(null)).label).not.toContain("default branch");
  });
});
