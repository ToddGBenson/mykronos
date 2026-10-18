/**
 * Surface selectors and CVSS requirement overrides on the Threat Model tab
 * (TheHub #60825). The fixture is a surface as GET /surfaces serves it.
 */
import { describe, expect, it } from "vitest";

import {
  requirementsLabel,
  selectorChips,
  selectorCount,
  selectorsFromInputs,
  splitList,
} from "../lib/selectors";

const served = {
  paths: ["backend/mykronos/db/**"],
  images: ["library/postgres"],
  addresses: ["10.0.0.5:5433"],
  hostnames: [],
};

describe("splitList", () => {
  it("trims, drops empties and duplicates, keeps order", () => {
    expect(splitList(" a, b ,,a, c ")).toEqual(["a", "b", "c"]);
  });

  it("is empty for an empty input", () => {
    expect(splitList("")).toEqual([]);
  });
});

describe("selectorsFromInputs", () => {
  it("sends nothing when nothing was typed", () => {
    expect(selectorsFromInputs({ paths: " , " })).toBeUndefined();
  });

  it("sends every kind, empty lists included, once anything was typed", () => {
    expect(selectorsFromInputs({ paths: "backend/**", addresses: "*:22" })).toEqual({
      paths: ["backend/**"],
      images: [],
      addresses: ["*:22"],
      hostnames: [],
    });
  });
});

describe("selectorChips", () => {
  it("labels each selector with its kind, in the API's order", () => {
    expect(selectorChips(served)).toEqual([
      { kind: "paths", value: "backend/mykronos/db/**" },
      { kind: "images", value: "library/postgres" },
      { kind: "addresses", value: "10.0.0.5:5433" },
    ]);
    expect(selectorCount(served)).toBe(3);
  });

  it("has nothing to show for a surface nobody located", () => {
    expect(selectorChips(undefined)).toEqual([]);
    expect(selectorCount(null)).toBe(0);
  });
});

describe("requirementsLabel", () => {
  it("names each override and dashes the rest", () => {
    expect(requirementsLabel({ cr: "H", ir: null, ar: "L" })).toBe("CR:H IR:– AR:L");
  });

  it("is empty when nothing is overridden", () => {
    expect(requirementsLabel({ cr: null, ir: null, ar: null })).toBe("");
  });
});
