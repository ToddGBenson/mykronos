/**
 * The Findings tab summary (TheHub #60821), run rather than read.
 *
 * The fixture is the backend's `outstanding` repo as the open-findings
 * endpoint serves it: seven open findings in four deduplicated rows. The
 * summary must agree with that list occurrence for occurrence.
 */
import { describe, expect, it } from "vitest";

import { findingsSummary, SEVERITY_ORDER } from "../lib/findings-summary";

type Location = { finding_id: string; capability: string; severity: string };

/** The rows the list renders, each carrying every occurrence it collapsed. */
const groups: { rule_id: string; locations: Location[] }[] = [
  {
    rule_id: "CWE-79",
    locations: ["a", "b", "c"].map((id) => ({
      finding_id: `xss-${id}`,
      capability: "sast",
      severity: "high",
    })),
  },
  {
    rule_id: "CVE-2024-4812",
    locations: [
      { finding_id: "dep", capability: "atlas", severity: "high" },
      { finding_id: "img", capability: "containers", severity: "critical" },
    ],
  },
  { rule_id: "CWE-89", locations: [{ finding_id: "sqli", capability: "sast", severity: "critical" }] },
  { rule_id: "CWE-306", locations: [{ finding_id: "auth", capability: "sast", severity: "medium" }] },
];

const page = {
  total: 7,
  by_severity: { critical: 2, high: 4, medium: 1, low: 0, info: 0 },
  by_capability: { sast: 5, atlas: 1, containers: 1 },
};

const labels: Record<string, string> = {
  sast: "Static analysis (SAST)",
  atlas: "Dependencies (SCA)",
  containers: "Container scanning",
};
const label = (capability: string) => labels[capability] ?? capability;

function tally(key: "capability" | "severity"): Record<string, number> {
  const out: Record<string, number> = {};
  for (const location of groups.flatMap((group) => group.locations)) {
    out[location[key]] = (out[location[key]] ?? 0) + 1;
  }
  return out;
}

describe("findingsSummary", () => {
  it("matches the list it sits above, occurrence for occurrence", () => {
    const summary = findingsSummary(page, {}, label);
    const occurrences = groups.flatMap((group) => group.locations).length;

    expect(summary.total).toBe(occurrences);
    const severities = tally("severity");
    for (const entry of summary.bySeverity) {
      expect(entry.count).toBe(severities[entry.value] ?? 0);
    }
    const capabilities = tally("capability");
    expect(Object.fromEntries(summary.byCapability.map((e) => [e.value, e.count]))).toEqual(
      capabilities,
    );
    expect(summary.bySeverity.reduce((n, e) => n + e.count, 0)).toBe(summary.total);
    expect(summary.byCapability.reduce((n, e) => n + e.count, 0)).toBe(summary.total);
  });

  it("lists every severity worst first, zeros included", () => {
    const summary = findingsSummary(page, {}, label);
    expect(summary.bySeverity.map((e) => [e.value, e.count])).toEqual([
      ["critical", 2],
      ["high", 4],
      ["medium", 1],
      ["low", 0],
      ["info", 0],
    ]);
    expect(summary.bySeverity.map((e) => e.value)).toEqual([...SEVERITY_ORDER]);
  });

  it("names scan types the way the rest of the UI does, most first", () => {
    const summary = findingsSummary(page, {}, label);
    expect(summary.byCapability.map((e) => [e.label, e.count])).toEqual([
      ["Static analysis (SAST)", 5],
      // A tie falls back to the capability id (atlas before containers).
      ["Dependencies (SCA)", 1],
      ["Container scanning", 1],
    ]);
  });

  it("marks the applied filters, and keeps an applied scan type with no findings visible", () => {
    const summary = findingsSummary(page, { severity: "high", capability: "dast" }, label);
    expect(summary.bySeverity.filter((e) => e.active).map((e) => e.value)).toEqual(["high"]);
    expect(summary.byCapability.at(-1)).toEqual({
      value: "dast",
      label: "dast",
      count: 0,
      active: true,
    });
  });

  it("says which status it counts", () => {
    expect(findingsSummary(page, {}).status).toBe("open");
    expect(findingsSummary(page, { status: "accepted_risk" }).status).toBe("accepted risk");
  });

  it("tolerates a backend that does not send by_capability yet", () => {
    const summary = findingsSummary({ total: 0, by_severity: {} }, {});
    expect(summary.byCapability).toEqual([]);
    expect(summary.bySeverity.every((e) => e.count === 0)).toBe(true);
  });
});
