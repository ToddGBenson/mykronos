/**
 * Rank term wording on the triage queue (TheHub #60829): the environmental
 * term's line and the caveat about what the order is made of.
 */
import { describe, expect, it } from "vitest";

import {
  environmentalLine,
  rankTermLine,
  rankingCaveat,
  signedPoints,
} from "../lib/rank-terms";

describe("signedPoints", () => {
  it("signs every value, zero included", () => {
    expect(signedPoints(25)).toBe("+25");
    expect(signedPoints(-10)).toBe("−10");
    expect(signedPoints(0)).toBe("±0");
    expect(signedPoints(16.0004)).toBe("+16");
  });
});

describe("rankTermLine", () => {
  it("leaves the other terms' details as the backend wrote them", () => {
    expect(rankTermLine({ key: "in_kev", points: 25, detail: "listed in CISA KEV" })).toEqual({
      points: "+25",
      detail: "listed in CISA KEV",
      environmental: null,
    });
  });

  it("renders the environmental summary with its direction", () => {
    const line = rankTermLine({
      key: "environmental",
      points: -10,
      detail: "rescored down 1 band: MAV:L from observed 'api' is bound to loopback, 3d ago",
    });
    expect(line.points).toBe("−10");
    expect(line.environmental).toBe("down");
    expect(line.detail).toBe(
      "environment: rescored down 1 band: MAV:L from observed 'api' is bound to loopback, 3d ago",
    );
  });

  it("shows a zero environmental term as an answer, not a blank", () => {
    const line = rankTermLine({
      key: "environmental",
      points: 0,
      detail: "no environmental score: no CVSS 3.x vector for this finding, or no rescore has reached it yet",
    });
    expect(line.points).toBe("±0");
    expect(line.environmental).toBe("none");
    expect(line.detail).toMatch(/^environment: no environmental score/);
  });

  it("marks a raise as up", () => {
    expect(rankTermLine({ key: "environmental", points: 20, detail: "rescored up 2 bands" }).environmental).toBe(
      "up",
    );
  });
});

describe("rankingCaveat", () => {
  it("keeps the old sentence for a backend without the block", () => {
    expect(rankingCaveat(undefined)).toBe(
      "This order is severity and threat intelligence, not business risk.",
    );
  });

  it("says no score is in force when none is", () => {
    expect(
      rankingCaveat({ weight_per_band: 10, scored: 0, lapsed: 1, unscored: 4, description: "" }),
    ).toBe(
      "This order is severity and threat intelligence, not business risk: no open finding has an environmental score in force.",
    );
  });

  it("counts how much of the order business context reaches", () => {
    expect(
      rankingCaveat({ weight_per_band: 10, scored: 3, lapsed: 1, unscored: 6, description: "" }),
    ).toBe(
      "Business context reaches this order only through environmental scores, which 3 of 10 open findings have.",
    );
  });
});

describe("environmentalLine", () => {
  const block = {
    weight_per_band: 10,
    scored: 3,
    lapsed: 0,
    unscored: 6,
    description:
      "environmental severity: 10 points per CVSS band the environment moved a finding's stored score (down subtracts, up adds), from scores in force only; 3 of 9 open findings have one",
  };

  it("is the backend's description, as a sentence", () => {
    expect(environmentalLine(block)).toBe(
      "Environmental severity: 10 points per CVSS band the environment moved a finding's stored score (down subtracts, up adds), from scores in force only; 3 of 9 open findings have one.",
    );
  });

  it("names lapsed scores", () => {
    expect(environmentalLine({ ...block, lapsed: 2 })).toMatch(
      / 2 set aside until rescored: a fact they rest on expired\.$/,
    );
  });

  it("is nothing without the block", () => {
    expect(environmentalLine(null)).toBeNull();
  });
});
