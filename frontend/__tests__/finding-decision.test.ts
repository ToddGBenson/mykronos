/**
 * The finding page's decision panel and the risk-acceptance form (TheHub
 * #61140, P7), run rather than read.
 *
 * The rules the form mirrors are the backend's (`risk_acceptance.py`): the
 * server still refuses on its own, and these exist so the form says why
 * before the round trip, in the same words.
 */
import { describe, expect, it } from "vitest";

import {
  acceptanceActionProblem,
  buildProposal,
  defaultScope,
  effectiveResidual,
  dispositionProblem,
  interimReviewOwed,
  maxDurationDays,
  proposalProblems,
  recommendAction,
  residualSeverity,
  type AcceptanceDraft,
} from "../lib/finding-decision";

describe("dispositionProblem", () => {
  it("refuses a disposition without a reason", () => {
    expect(dispositionProblem("false_positive", "")).toBe(
      "Say why. A disposition without a reason cannot be saved.",
    );
    expect(dispositionProblem("suppressed", "   \n ")).not.toBeNull();
  });

  it("accepts one with a reason", () => {
    expect(dispositionProblem("false_positive", "generated code")).toBeNull();
  });
});

describe("residualSeverity", () => {
  it("maps likelihood x impact as the backend's 4x4 matrix does", () => {
    expect(residualSeverity("low", "low")).toBe("low");
    expect(residualSeverity("low", "moderate")).toBe("low");
    expect(residualSeverity("moderate", "moderate")).toBe("medium");
    expect(residualSeverity("low", "very_high")).toBe("medium");
    expect(residualSeverity("high", "high")).toBe("high");
    expect(residualSeverity("very_high", "high")).toBe("high");
    expect(residualSeverity("very_high", "very_high")).toBe("critical");
  });
});

describe("maxDurationDays", () => {
  it("is the default policy's cap per residual severity", () => {
    expect(maxDurationDays("critical")).toBe(30);
    expect(maxDurationDays("high")).toBe(90);
    expect(maxDurationDays("medium")).toBe(180);
    expect(maxDurationDays("low")).toBe(365);
  });
});

describe("defaultScope", () => {
  it("scopes a container finding to its image, never to every image (D-127)", () => {
    expect(
      defaultScope({
        capability: "containers",
        rule_id: "CVE-2026-1",
        raw_finding_json: { image: "library/postgres:17" },
      }),
    ).toEqual({ capability: "containers", image: "library/postgres:17" });
  });

  it("scopes a code finding to its rule and file", () => {
    expect(
      defaultScope({ capability: "sast", rule_id: "py.sqli", file_path: "app/db.py" }),
    ).toEqual({ capability: "sast", rule_ids: ["py.sqli"], file_paths: ["app/db.py"] });
    expect(defaultScope({ capability: "dependencies", rule_id: "GHSA-x" })).toEqual({
      capability: "dependencies",
      rule_ids: ["GHSA-x"],
    });
  });
});

describe("interimReviewOwed", () => {
  it("is owed for a risk adjustment nothing watches", () => {
    expect(interimReviewOwed("risk_adjustment", [], ["no_fixed_version"])).toBe(true);
    expect(interimReviewOwed("operational_requirement", [], [])).toBe(true);
    expect(interimReviewOwed("risk_adjustment", [{ control_id: "c1" }], [])).toBe(true);
  });

  it("is not owed for a vendor dependency, which re-opens when a fix ships", () => {
    expect(interimReviewOwed("vendor_dependency", [], [])).toBe(false);
  });

  it("is not owed when a premise that can re-open it is monitored", () => {
    expect(interimReviewOwed("risk_adjustment", [], ["not_internet_facing"])).toBe(false);
    // path_unreachable is affirm-only: it cannot re-open anything.
    expect(interimReviewOwed("risk_adjustment", [], ["path_unreachable"])).toBe(true);
  });
});

function draft(overrides: Partial<AcceptanceDraft> = {}): AcceptanceDraft {
  return {
    repo: "acme/beacon",
    scope: { capability: "containers", image: "library/postgres:17" },
    deviation_type: "vendor_dependency",
    justification: "No upstream fix; the parser is never loaded.",
    residual_likelihood: "low",
    residual_impact: "moderate",
    risk_owner: "operator",
    requested_until: "2026-12-01",
    premises: ["no_fixed_version"],
    control_id: "",
    milestone_title: "Upgrade the base image when Debian ships a fix",
    milestone_due: "2026-11-30",
    response: "accept",
    ...overrides,
  };
}

const TODAY = "2026-11-01";

describe("proposalProblems", () => {
  it("passes a complete draft", () => {
    expect(proposalProblems(draft(), TODAY)).toEqual([]);
  });

  it("requires a reason, an owner who is a person, an expiry and a way out", () => {
    const problems = proposalProblems(
      draft({ justification: " ", risk_owner: "agent:claude/x", milestone_title: "" }),
      TODAY,
    );
    expect(problems).toContain("Give the reason this risk is acceptable.");
    expect(problems).toContain(
      "Name the person who answers for it. An agent is not a risk owner.",
    );
    expect(problems).toContain(
      "Say how it ends: a milestone that ends the weakness, with a due date.",
    );
  });

  it("refuses an expiry past the cap for the residual severity", () => {
    expect(
      proposalProblems(
        draft({
          residual_likelihood: "very_high",
          residual_impact: "very_high",
          deviation_type: "risk_adjustment",
          requested_until: "2026-12-15",
        }),
        TODAY,
      ),
    ).toContain("A critical acceptance runs at most 30 days, so it expires by 2026-12-01.");
  });

  it("refuses an expiry in the past", () => {
    expect(proposalProblems(draft({ requested_until: "2026-10-01" }), TODAY)).toContain(
      "The expiry must be after today.",
    );
  });

  it("requires a checkable premise for a risk adjustment", () => {
    expect(
      proposalProblems(draft({ deviation_type: "risk_adjustment", premises: [] }), TODAY),
    ).toContain("A risk adjustment names at least one premise the platform can check.");
  });

  it("refuses a critical operational requirement", () => {
    expect(
      proposalProblems(
        draft({
          deviation_type: "operational_requirement",
          residual_likelihood: "very_high",
          residual_impact: "very_high",
          requested_until: "2026-11-20",
        }),
        TODAY,
      ),
    ).toContain(
      "A critical residual risk cannot be an operational requirement: that is a conversation about the architecture, not an acceptance.",
    );
  });
});

describe("buildProposal", () => {
  it("builds the body POST /api/risk-acceptances takes", () => {
    expect(buildProposal(draft({ control_id: "ctl-waf" }))).toEqual({
      repo: "acme/beacon",
      scope: { capability: "containers", image: "library/postgres:17" },
      deviation_type: "vendor_dependency",
      justification: "No upstream fix; the parser is never loaded.",
      residual_likelihood: "low",
      residual_impact: "moderate",
      risk_owner: "operator",
      requested_until: "2026-12-01",
      premises: [{ type: "no_fixed_version" }],
      compensating_controls: [{ control_id: "ctl-waf" }],
      milestones: [
        {
          title: "Upgrade the base image when Debian ships a fix",
          due: "2026-11-30",
          ends_weakness: true,
        },
      ],
      response: "accept",
    });
  });

  it("sends no compensating control when none is chosen, and trims text", () => {
    const body = buildProposal(draft({ justification: "  why  ", risk_owner: " me " }));
    expect(body.compensating_controls).toEqual([]);
    expect(body.justification).toBe("why");
    expect(body.risk_owner).toBe("me");
  });
});

describe("recommendAction", () => {
  it("says it is decided when the finding is not open", () => {
    expect(recommendAction({ status: "accepted_risk", fixable: false, fixedVersion: null, hasFix: false })).toEqual({
      kind: "decided",
      text: "Already accepted risk. Nothing to decide unless it re-opens.",
    });
  });

  it("recommends the upgrade when a fix is published", () => {
    expect(
      recommendAction({ status: "open", fixable: true, fixedVersion: "2.13.1", hasFix: true }),
    ).toEqual({ kind: "fix", text: "Fix it: a fixed version (2.13.1) is published." });
  });

  it("recommends a formal acceptance when no fix exists and no remediation covers it", () => {
    expect(
      recommendAction({ status: "open", fixable: false, fixedVersion: null, hasFix: false, isPackage: true }),
    ).toEqual({
      kind: "accept",
      text: "No fix is published. Accept it formally until one ships, or say why it does not apply.",
    });
  });

  it("recommends the grouped remediation when there is one", () => {
    expect(
      recommendAction({ status: "open", fixable: false, fixedVersion: null, hasFix: true }).kind,
    ).toBe("fix");
  });

  it("asks for a decision when nothing points either way", () => {
    expect(
      recommendAction({ status: "open", fixable: false, fixedVersion: null, hasFix: false }),
    ).toEqual({ kind: "decide", text: "Fix it, accept it formally, or say why it does not apply." });
  });
});

describe("acceptanceActionProblem", () => {
  it("requires a reason to revoke, a note for an interim review, and a reason and date to renew", () => {
    expect(acceptanceActionProblem("revoke", { text: "" })).toBe(
      "Say why it is revoked. Its findings re-open.",
    );
    expect(acceptanceActionProblem("interim-review", { text: "" })).toBe(
      "Say what you checked and why it still stands.",
    );
    expect(acceptanceActionProblem("renew", { text: "still no fix", until: "" })).toBe(
      "Choose the new expiry.",
    );
    expect(acceptanceActionProblem("renew", { text: "", until: "2026-12-01" })).toBe(
      "Say why it should run longer.",
    );
    expect(acceptanceActionProblem("renew", { text: "still no fix", until: "2026-12-01" })).toBeNull();
  });
});

describe("effectiveResidual", () => {
  // risk_acceptance.propose: for any deviation but a risk adjustment, the
  // residual is never below the worst covered finding's own severity.
  it("floors a vendor dependency or an operational requirement at the finding's severity", () => {
    expect(effectiveResidual(draft({ finding_severity: "high" }))).toBe("high");
    expect(
      effectiveResidual(
        draft({ deviation_type: "operational_requirement", finding_severity: "critical" }),
      ),
    ).toBe("critical");
  });

  it("does not floor a risk adjustment, which is the one that argues it lower", () => {
    expect(
      effectiveResidual(draft({ deviation_type: "risk_adjustment", finding_severity: "critical" })),
    ).toBe("low");
  });

  it("is the matrix alone when the finding's severity is not known", () => {
    expect(effectiveResidual(draft())).toBe("low");
  });
});

describe("proposalProblems with the finding's severity", () => {
  it("caps a vendor dependency on a high finding at 90 days, not the matrix's 365", () => {
    expect(
      proposalProblems(draft({ finding_severity: "high", requested_until: "2027-03-01" }), TODAY),
    ).toContain("A high acceptance runs at most 90 days, so it expires by 2027-01-30.");
  });

  it("refuses an operational requirement on a critical finding, whatever residual is chosen", () => {
    expect(
      proposalProblems(
        draft({
          deviation_type: "operational_requirement",
          finding_severity: "critical",
          requested_until: "2026-11-20",
        }),
        TODAY,
      ),
    ).toContain(
      "A critical residual risk cannot be an operational requirement: that is a conversation about the architecture, not an acceptance.",
    );
  });

  it("never sends the finding's severity: the server reads it from the lake", () => {
    expect(buildProposal(draft({ finding_severity: "high" }))).not.toHaveProperty(
      "finding_severity",
    );
  });
});
