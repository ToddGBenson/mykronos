/**
 * The Risk management tab's derivations: the words an acceptance is described
 * in, when its expiry reads red, and how the summary strip's counts filter.
 */
import { describe, expect, it } from "vitest";

import {
  REASON_LABEL,
  STRIP_STATES,
  auditActionLabel,
  controlText,
  daysLeftText,
  evidenceAgeText,
  expiryIsRed,
  filterHref,
  interimReviewText,
  premiseLabel,
  premiseTally,
  reasonLabel,
  reviewDueLabel,
  severityCounts,
  stateLabel,
  stateTone,
  verdictTone,
} from "../lib/risk-acceptances";

describe("reasonLabel", () => {
  it("reads the codes the lake stamps", () => {
    expect(reasonLabel("no_vendor_fix")).toBe("No vendor fix");
    expect(reasonLabel("compensating_control")).toBe(REASON_LABEL.compensating_control);
  });
  it("shows an unknown code as itself rather than hiding it", () => {
    expect(reasonLabel("brand_new_code")).toBe("brand_new_code");
  });
  it("shows a missing code as a dash", () => {
    expect(reasonLabel("")).toBe("—");
    expect(reasonLabel(null)).toBe("—");
  });
});

describe("states", () => {
  it("strips the five states Todd asked for, in order", () => {
    expect([...STRIP_STATES]).toEqual([
      "active",
      "expiring",
      "expired",
      "premise_failed",
      "revoked",
    ]);
  });
  it("labels and colours them", () => {
    expect(stateLabel("premise_failed")).toBe("Premise failed");
    expect(stateLabel("something_new")).toBe("something new");
    expect(stateTone("premise_failed")).toBe("critical");
    expect(stateTone("expired")).toBe("critical");
    expect(stateTone("expiring")).toBe("warn");
    expect(stateTone("active")).toBe("pass");
    expect(stateTone("revoked")).toBe("muted");
  });
});

describe("premises", () => {
  it("never colours unverified as good news", () => {
    expect(verdictTone("holds")).toBe("pass");
    expect(verdictTone("failed")).toBe("critical");
    expect(verdictTone("unverified")).toBe("warn");
  });
  it("tallies verdicts, counting anything unknown as unverified", () => {
    expect(
      premiseTally([
        { status: "holds" },
        { status: "failed" },
        { status: "unverified" },
        { status: "weird" },
      ]),
    ).toEqual({ holds: 1, failed: 1, unverified: 2 });
  });
  it("names premise types", () => {
    expect(premiseLabel("port_not_published")).toBe("Port not published");
    expect(premiseLabel("future_type")).toBe("future type");
    expect(premiseLabel("")).toBe("untyped premise");
  });
  it("says how old the evidence is, or that there is none", () => {
    expect(evidenceAgeText(null)).toBe("no evidence");
    expect(evidenceAgeText(undefined)).toBe("no evidence");
    expect(evidenceAgeText(0.4)).toBe("evidence under a day old");
    expect(evidenceAgeText(1.2)).toBe("evidence 1 day old");
    expect(evidenceAgeText(6.6)).toBe("evidence 7 days old");
  });
});

describe("expiry", () => {
  it("counts days either side of the date", () => {
    expect(daysLeftText(12)).toBe("12 days left");
    expect(daysLeftText(1)).toBe("1 day left");
    expect(daysLeftText(0)).toBe("expires today");
    expect(daysLeftText(-3)).toBe("3 days past");
    expect(daysLeftText(null)).toBe("no expiry yet");
  });
  it("is red once past, or when a premise has failed", () => {
    const ok = { days_left: 40, state: "active", premises: [{ status: "holds" }] };
    expect(expiryIsRed(ok)).toBe(false);
    expect(expiryIsRed({ ...ok, days_left: -1 })).toBe(true);
    expect(expiryIsRed({ ...ok, premises: [{ status: "failed" }] })).toBe(true);
    expect(expiryIsRed({ ...ok, state: "premise_failed" })).toBe(true);
    expect(expiryIsRed({ ...ok, state: "expired" })).toBe(true);
    // Unverified is amber on the premise, not red on the date.
    expect(expiryIsRed({ ...ok, premises: [{ status: "unverified" }] })).toBe(false);
    expect(expiryIsRed({ ...ok, days_left: null, state: "pending_approval" })).toBe(false);
  });
});

describe("filterHref", () => {
  it("sets a filter on the risk tab", () => {
    expect(filterHref("r1", {}, "state", "expiring")).toBe("/repos/r1?tab=risk&state=expiring");
  });
  it("keeps the other filters, so state and severity combine", () => {
    expect(filterHref("r1", { state: "active" }, "severity", "high")).toBe(
      "/repos/r1?tab=risk&state=active&severity=high",
    );
    expect(filterHref("r1", { severity: "high" }, "effective", "low")).toBe(
      "/repos/r1?tab=risk&severity=high&effective=low",
    );
  });
  it("clears a filter that is already lit", () => {
    expect(filterHref("r1", { state: "expired", severity: "high" }, "state", "expired")).toBe(
      "/repos/r1?tab=risk&severity=high",
    );
  });
  it("replaces a filter with another value", () => {
    expect(filterHref("r1", { state: "expired" }, "state", "revoked")).toBe(
      "/repos/r1?tab=risk&state=revoked",
    );
  });
});

describe("severityCounts", () => {
  it("lists non-zero severities worst first, unknown words last", () => {
    expect(severityCounts({ low: 2, critical: 1, medium: 0, odd: 3, high: 4 })).toEqual([
      ["critical", 1],
      ["high", 4],
      ["low", 2],
      ["odd", 3],
    ]);
  });
  it("is empty when nothing is counted", () => {
    expect(severityCounts({ critical: 0 })).toEqual([]);
  });
});

describe("controlText", () => {
  it("leads with the control's name and keeps the rest", () => {
    expect(controlText({ control: "WAF rule 942100", owner: "ops" })).toBe(
      "WAF rule 942100 · owner: ops",
    );
  });
  it("reads milestones the same way", () => {
    expect(controlText({ title: "Check the vendor", due: "2026-10-26", ends_weakness: false })).toBe(
      "Check the vendor · due: 2026-10-26 · ends_weakness: false",
    );
  });
  it("falls back to the JSON for an empty object", () => {
    expect(controlText({})).toBe("{}");
  });
});

describe("auditActionLabel", () => {
  it("drops the entity prefix", () => {
    expect(auditActionLabel("risk_acceptance.premise_failed")).toBe("premise failed");
    expect(auditActionLabel("finding.reopened_by_premise")).toBe("finding.reopened by premise");
  });
});

describe("interim review (TheHub #60817)", () => {
  it("is a red state once it lapses", () => {
    // Off the five-state strip; it shows beside it, red, whenever one exists.
    expect(stateLabel("needs_review")).toBe("Needs review");
    expect(stateTone("needs_review")).toBe("critical");
    expect(STRIP_STATES).not.toContain("needs_review");
  });
  it("says where the review stands, or nothing when none is owed", () => {
    expect(interimReviewText({ interim_review: "none" })).toBeNull();
    expect(
      interimReviewText({ interim_review: "scheduled", interim_review_by: "2026-11-20" }),
    ).toBe("due 2026-11-20");
    expect(
      interimReviewText({ interim_review: "lapsed", interim_review_by: "2026-11-20" }),
    ).toContain("lapsed");
    expect(
      interimReviewText({
        interim_review: "done",
        interim_reviewed_at: "2026-11-22T10:00:00",
        interim_reviewed_by: "admin",
      }),
    ).toBe("recorded 2026-11-22 by admin");
  });
  it("names which review the pill means", () => {
    expect(reviewDueLabel({ interim_review: "due" })).toBe("interim review due");
    expect(reviewDueLabel({ interim_review: "lapsed" })).toBe("interim review due");
    expect(reviewDueLabel({ interim_review: "none" })).toBe("review due");
  });
});
