/**
 * DORA metrics per repository on the Delivery view (TheHub #60912).
 *
 * Each metric shows its value, or "not enough data" with the input it
 * lacks. Never a 0 that means "not measured".
 */

import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";

import { DoraView } from "@/components/po-console";
import type { PoDora } from "@/lib/po-console";

function metric(value: number | null, unit: string, lacks: string | null = null, sample = 3) {
  return { value, unit, sample, lacks, detail: null };
}

const DORA = {
  repo_full_name: "o/thehub",
  deploy_source: "TheHub deploy record",
  windows: [
    {
      days: 30,
      deploy_frequency: metric(1.4, "per week"),
      lead_time: metric(5.25, "hours"),
      change_failure_rate: metric(0, "percent"),
      recovery_time: metric(null, "hours", "no change failure in this window, so nothing to recover from", 0),
    },
    {
      days: 90,
      deploy_frequency: metric(null, "per week", "TheHub's deploy record reaches back only to 2026-10-21", 0),
      lead_time: metric(null, "hours", "TheHub's deploy record reaches back only to 2026-10-21", 0),
      change_failure_rate: metric(null, "percent", "TheHub's deploy record reaches back only to 2026-10-21", 0),
      recovery_time: metric(null, "hours", "TheHub's deploy record reaches back only to 2026-10-21", 0),
    },
  ],
  definitions: {},
} as unknown as PoDora;

describe("DoraView", () => {
  const html = renderToStaticMarkup(createElement(DoraView, { data: DORA }));

  it("names the four metrics for each window", () => {
    for (const name of ["Deploy frequency", "Lead time", "Change failure rate", "Recovery time"]) {
      expect(html).toContain(name);
    }
    expect(html).toContain("30 days");
    expect(html).toContain("90 days");
  });

  it("draws a measured value with its unit, including a measured zero", () => {
    expect(html).toContain("1.4 per week");
    expect(html).toContain("5.3 h");
    expect(html).toContain("0%");
  });

  it("an uncomputable metric says not enough data and what it lacks, never 0", () => {
    expect(html).toContain("not enough data");
    expect(html).toContain("reaches back only to 2026-10-21");
    expect(html).toContain("nothing to recover from");
    // Four null metrics in the 90-day window, one in the 30-day window.
    expect(html.match(/not enough data/g)?.length).toBe(5);
  });
});
