/**
 * The "Rule vectors" section never lets a proposal read as a score
 * (TheHub #60832, D3).
 */
import { describe, expect, it } from "vitest";

import {
  fromWord,
  ruleStateLine,
  scopeWord,
  statusTone,
  statusWord,
  unscoredSummary,
  type RuleVectorRow,
} from "../lib/rule-vectors";

const proposal: RuleVectorRow = {
  id: "rv-1",
  status: "proposed",
  scope: "repository",
  vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
  base_score: 6.1,
  proposed_from: "cwe-vector-templates-v1:CWE-79",
  asserted_by: "agent:claude-opus-5.5:abc12345",
  asserted_at: "2026-10-18T12:00:00",
  confirmed_by: null,
  confirmed_at: null,
};

describe("statusWord", () => {
  it("says a proposal is not scored", () => {
    expect(statusWord("proposed")).toBe("proposed, not scored");
    expect(statusTone("proposed")).toBe("warn");
  });

  it("says a confirmed vector is scored", () => {
    expect(statusWord("confirmed")).toBe("confirmed, scored");
    expect(statusTone("confirmed")).toBe("pass");
  });

  it("passes an unknown state through rather than guessing", () => {
    expect(statusWord("odd")).toBe("odd");
    expect(statusTone("retired")).toBe("muted");
  });
});

describe("ruleStateLine", () => {
  it("names who confirmed the vector the findings are scored from", () => {
    const confirmed = {
      ...proposal,
      status: "confirmed",
      confirmed_by: "todd",
      confirmed_at: "2026-10-18T13:00:00",
    };
    expect(ruleStateLine({ findings: 2, applies: confirmed, vectors: [confirmed] })).toBe(
      "2 open findings scored from a vector todd confirmed on 2026-10-18 (base 6.1).",
    );
  });

  it("never reads a proposal as a score", () => {
    const line = ruleStateLine({ findings: 1, applies: null, vectors: [proposal] });
    expect(line).toContain("1 open finding unscored");
    expect(line).toContain("waits for a person to confirm it");
    expect(line).not.toContain("scored from");
  });

  it("says why nothing is there", () => {
    expect(ruleStateLine({ findings: 3, applies: null, vectors: [] })).toBe(
      "3 open findings unscored: no CVE, so no published vector, and none proposed.",
    );
  });
});

describe("small words", () => {
  it("names the template or says it was typed", () => {
    expect(fromWord("cwe-vector-templates-v1:CWE-798")).toBe("CWE-798 template");
    expect(fromWord("")).toBe("typed by hand");
  });

  it("names the scope", () => {
    expect(scopeWord("estate")).toBe("every repository");
    expect(scopeWord("repository")).toBe("this repository");
  });

  it("summarises what is unscored", () => {
    expect(unscoredSummary(1, 1)).toBe("1 rule (1 finding) unscored");
    expect(unscoredSummary(3, 41)).toBe("3 rules (41 findings) unscored");
    expect(unscoredSummary(0, 0)).toBe("every listed rule has a confirmed vector");
  });
});
