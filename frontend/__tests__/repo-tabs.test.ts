import { describe, expect, it } from "vitest";

import { canonicalTab, closableToday } from "../lib/repo-tabs";

describe("canonicalTab", () => {
  it("sends the retired Remediation tab to Remediate today (#60820)", () => {
    expect(canonicalTab("remediation")).toBe("remediate");
  });

  it("leaves a live id alone", () => {
    expect(canonicalTab("remediate")).toBe("remediate");
    expect(canonicalTab("findings")).toBe("findings");
    expect(canonicalTab("executive")).toBe("executive");
  });

  it("falls back to Dashboard when no tab is given", () => {
    expect(canonicalTab(undefined)).toBe("dashboard");
    expect(canonicalTab("")).toBe("dashboard");
  });

  it("does not invent a tab for an unknown id — the page still refuses it", () => {
    expect(canonicalTab("supply-chain")).toBe("supply-chain");
  });

  it("is not fooled by inherited object keys", () => {
    expect(canonicalTab("toString")).toBe("toString");
    expect(canonicalTab("constructor")).toBe("constructor");
  });
});

describe("closableToday", () => {
  it("counts only config and upgrade fixes", () => {
    expect(
      closableToday([
        { effort: "config", findings: 3 },
        { effort: "upgrade", findings: 2 },
        { effort: "code", findings: 7 },
        { effort: "judgement", findings: 1 },
      ]),
    ).toBe(5);
  });

  it("is zero for nothing", () => {
    expect(closableToday([])).toBe(0);
  });
});
