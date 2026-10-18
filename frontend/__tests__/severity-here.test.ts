/**
 * "Severity here" names its vector and never presents v4.0 as rescored
 * (TheHub #60824, D1).
 */
import { describe, expect, it } from "vitest";

import { notRescoredLine, vectorProvenance } from "../lib/severity-here";

describe("vectorProvenance", () => {
  it("names NVD and the version", () => {
    expect(vectorProvenance({ vector_source: "nvd", vector_version: "3.0" })).toBe("NVD v3.0");
  });

  it("names the scanner's advisory", () => {
    expect(vectorProvenance({ vector_source: "advisory", vector_version: "3.1" })).toBe(
      "scanner advisory v3.1",
    );
  });
});

describe("notRescoredLine", () => {
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
