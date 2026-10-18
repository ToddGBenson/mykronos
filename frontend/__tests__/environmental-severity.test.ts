/**
 * Environmental severity wording and links (TheHub #60828): the finding page's
 * facts, the Findings summary's rescoring chips, the Threat Model coverage line.
 */
import { describe, expect, it } from "vitest";

import {
  NOBODY_STATED,
  coverageLine,
  factOutcome,
  factSource,
  factsHeadline,
  notRescoredLine,
  rescoreChips,
  rescoreSentence,
  shift,
  splitFacts,
  vectorProvenance,
  type EnvFact,
} from "../lib/environmental-severity";

function fact(overrides: Partial<EnvFact> = {}): EnvFact {
  return {
    metric: "MAV",
    value: "A",
    direction: "lower",
    source_kind: "surface",
    source_id: "s-api",
    tier: "declared",
    asserted_by: "alice",
    applied: false,
    not_applied_reason: "unverified: a declaration cannot lower exploitability",
    because: "entry point 'API' is internal",
    ...overrides,
  };
}

describe("vectorProvenance", () => {
  it("names NVD and the version", () => {
    expect(vectorProvenance({ vector_source: "nvd", vector_version: "3.1" })).toBe("NVD v3.1");
    expect(vectorProvenance({ vector_source: "nvd", vector_version: "3.0" })).toBe("NVD v3.0");
  });

  it("names the scanner's advisory and an analyst", () => {
    expect(vectorProvenance({ vector_source: "advisory", vector_version: "3.0" })).toBe(
      "scanner advisory v3.0",
    );
    expect(vectorProvenance({ vector_source: "analyst", vector_version: "3.1" })).toBe(
      "analyst v3.1",
    );
  });

  it("says when nobody recorded the source rather than guessing NVD", () => {
    expect(vectorProvenance({})).toBe("source not recorded");
  });
});

describe("shift", () => {
  it("compares the words", () => {
    expect(shift("high", "medium")).toBe("down");
    expect(shift("medium", "critical")).toBe("up");
    expect(shift("high", "high")).toBe("same");
  });

  it("is never a move when either word is missing", () => {
    expect(shift("high", null)).toBe("same");
  });
});

describe("facts", () => {
  it("splits applied from not applied, keeping order", () => {
    const a = fact({ metric: "CR", value: "H", applied: true, not_applied_reason: null });
    const b = fact();
    expect(splitFacts([b, a])).toEqual({ applied: [a], notApplied: [b] });
  });

  it("gives every unapplied fact a reason, even an unrecorded one", () => {
    expect(factOutcome(fact())).toBe(
      "not applied: unverified: a declaration cannot lower exploitability",
    );
    expect(factOutcome(fact({ not_applied_reason: null }))).toBe(
      "not applied: no reason recorded",
    );
    expect(factOutcome(fact({ applied: true }))).toBe("applied");
  });

  it("says nobody has stated anything when there are no facts", () => {
    expect(factsHeadline([])).toBe(`${NOBODY_STATED}.`);
  });

  it("distinguishes stated-but-not-evidence from applied", () => {
    expect(factsHeadline([fact(), fact({ metric: "MPR" })])).toBe(
      "2 statements about this environment, none of them evidence enough to apply.",
    );
    expect(factsHeadline([fact(), fact({ applied: true })])).toBe("1 applied, 1 not applied.");
  });
});

describe("factSource", () => {
  it("links a surface and a control to their anchors on the Threat Model tab", () => {
    expect(factSource("r1", fact()).href).toBe("/repos/r1?tab=threat-model#surface-s-api");
    expect(
      factSource("r1", fact({ source_kind: "control", source_id: "c-9" })).href,
    ).toBe("/repos/r1?tab=threat-model#control-c-9");
  });

  it("links the risk profile to the Risk Decision tab", () => {
    expect(factSource("r1", fact({ source_kind: "risk_profile", source_id: "7" })).href).toBe(
      "/repos/r1?tab=decisions#risk-profile",
    );
  });

  it("links an observation to the surface it is about, else the tab", () => {
    const scoped = fact({ source_kind: "observation", source_id: "csp", scope: "s-web" });
    expect(factSource("r1", scoped)).toEqual({
      label: "observation (csp)",
      href: "/repos/r1?tab=threat-model#surface-s-web",
    });
    expect(factSource("r1", { ...scoped, scope: null }).href).toBe("/repos/r1?tab=threat-model");
  });

  it("does not link the scanner's own tag anywhere", () => {
    expect(factSource("r1", fact({ source_kind: "adapter_tag" })).href).toBeNull();
  });

  it("escapes ids", () => {
    expect(factSource("r 1", fact({ source_id: "a/b" })).href).toBe(
      "/repos/r%201?tab=threat-model#surface-a%2Fb",
    );
  });
});

describe("rescoreChips", () => {
  const counts = { down: 3, up: 1, unchanged: 5, not_rescorable: 12 };

  it("reads N rescored down (verified), M rescored up, K not rescorable", () => {
    expect(rescoreSentence(counts)).toBe(
      "3 rescored down (verified), 1 rescored up, 12 not rescorable",
    );
  });

  it("marks the applied filter and leaves unchanged out", () => {
    const chips = rescoreChips(counts, { rescored: "up" });
    expect(chips.map((c) => c.value)).toEqual(["down", "up", "not_rescorable"]);
    expect(chips.find((c) => c.value === "up")?.active).toBe(true);
  });

  it("zeroes a response from before the field existed", () => {
    expect(rescoreSentence(undefined)).toBe(
      "0 rescored down (verified), 0 rescored up, 0 not rescorable",
    );
  });
});

describe("coverageLine", () => {
  it("links when findings are unplaced", () => {
    const line = coverageLine({
      open_findings: 10,
      unplaced: 4,
      surfaces: 2,
      located_surfaces: 1,
    });
    expect(line.text).toBe("4 open findings map to no component");
    expect(line.link).toBe(true);
  });

  it("is singular for one", () => {
    expect(
      coverageLine({ open_findings: 3, unplaced: 1, surfaces: 1, located_surfaces: 1 }).text,
    ).toBe("1 open finding maps to no component");
  });

  it("explains why when nothing is declared", () => {
    const line = coverageLine({ open_findings: 5, unplaced: 5, surfaces: 0, located_surfaces: 0 });
    expect(line.detail).toMatch(/No surface is declared/);
  });

  it("says when surfaces exist but none has selectors", () => {
    const line = coverageLine({ open_findings: 5, unplaced: 5, surfaces: 2, located_surfaces: 0 });
    expect(line.detail).toMatch(/No declared surface has selectors/);
  });

  it("says so, unlinked, when every finding is placed", () => {
    const line = coverageLine({ open_findings: 5, unplaced: 0, surfaces: 2, located_surfaces: 2 });
    expect(line.link).toBe(false);
    expect(line.detail).toBe("Every one of 5 open findings is in a declared surface.");
  });
});

describe("notRescoredLine (TheHub #60824, D1)", () => {
  it("is null for a rescored vector", () => {
    expect(notRescoredLine({ rescored: true, base: 9.8, vector_version: "3.1" })).toBeNull();
  });

  it("is null for a response from before the field existed", () => {
    expect(notRescoredLine({ base: 9.8 })).toBeNull();
  });

  it("says v4.0 base X, not rescored", () => {
    expect(notRescoredLine({ rescored: false, base: 9.3, vector_version: "4.0" })).toBe(
      "v4.0 base 9.3, not rescored",
    );
  });

  it("does not invent a score nobody published", () => {
    expect(notRescoredLine({ rescored: false, base: null, vector_version: "4.0" })).toBe(
      "v4.0, no base score published, not rescored",
    );
  });
});
