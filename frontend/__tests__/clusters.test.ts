import { describe, expect, it } from "vitest";

import {
  clusterDispositionBody,
  clusterSpread,
  dispositionOutcomeLine,
} from "@/lib/clusters";

describe("clusterSpread", () => {
  it("names findings, repositories and images", () => {
    expect(clusterSpread({ count: 3, repos: ["a/b", "c/d"], images: ["x", "y", "z"] })).toBe(
      "3 findings · 2 repositories · 3 images",
    );
  });

  it("leaves images out when there are none and uses the singular", () => {
    expect(clusterSpread({ count: 1, repos: ["a/b"], images: [] })).toBe(
      "1 finding · 1 repository",
    );
  });
});

describe("clusterDispositionBody", () => {
  it("carries exactly the members the person was shown", () => {
    const result = clusterDispositionBody("false_positive", "  checked the manifest ", ["f1", "f2"]);
    expect(result).toEqual({
      ok: true,
      body: { status: "false_positive", reason: "checked the manifest", member_ids: ["f1", "f2"] },
    });
  });

  it("refuses a blank reason", () => {
    expect(clusterDispositionBody("suppressed", "   ", ["f1"]).ok).toBe(false);
  });

  it("refuses a verdict the page does not offer", () => {
    expect(clusterDispositionBody("accepted_risk", "reason", ["f1"]).ok).toBe(false);
    expect(clusterDispositionBody("fixed", "reason", ["f1"]).ok).toBe(false);
  });
});

describe("dispositionOutcomeLine", () => {
  it("says nothing closed while an approval is pending", () => {
    expect(dispositionOutcomeLine({ outcome: "pending_approval", tier: "high" })).toMatch(
      /Waiting for approval \(high tier\)/,
    );
  });

  it("counts applied and refused members", () => {
    expect(
      dispositionOutcomeLine({ outcome: "applied", applied: ["a", "b"], refused: { c: "no" } }),
    ).toBe("2 members closed, 1 refused.");
  });
});
