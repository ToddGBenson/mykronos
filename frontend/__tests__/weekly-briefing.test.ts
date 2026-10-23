import { describe, expect, it } from "vitest";

import {
  flashes,
  newThisWeek,
  sourceLink,
  weeklyHref,
  type WeeklyItem,
  type WeeklyPage,
} from "@/lib/weekly-briefing";

function item(overrides: Partial<WeeklyItem>): WeeklyItem {
  return {
    what: "CVE-2026-1 in x",
    so_what: "s",
    action: "a",
    confidence: "observed",
    confidence_reason: "r",
    source: "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
    severity: "high",
    new_this_week: false,
    flash: false,
    flash_reason: "",
    key: "k",
    ...overrides,
  };
}

const page: WeeklyPage = {
  repo_full_name: "o/r",
  repo_id: "id-1",
  week_of: "2026-10-19",
  generated_at: "2026-10-22T15:00:00",
  sections: [
    {
      key: "advisories",
      title: "Advisories",
      status: "ok",
      source: "lake",
      as_of: null,
      items: [item({ flash: true, key: "a" }), item({ new_this_week: true, key: "b" })],
    },
    { key: "standards", title: "Standards", status: "not_available", source: "none", as_of: null },
  ],
};

describe("weekly briefing", () => {
  it("links an advisory out and a MyKronos record in, and nothing else", () => {
    expect(sourceLink("https://osv.dev/vulnerability/MAL-1")).toEqual({
      href: "https://osv.dev/vulnerability/MAL-1",
      external: true,
    });
    expect(sourceLink("/repos/id-1/findings/f1")).toEqual({
      href: "/repos/id-1/findings/f1",
      external: false,
    });
    expect(sourceLink("javascript:alert(1)")).toBeNull();
  });

  it("counts flash and new items across sections", () => {
    expect(flashes(page).map((i) => i.key)).toEqual(["a"]);
    expect(newThisWeek(page)).toBe(1);
  });

  it("builds the page link", () => {
    expect(weeklyHref(null)).toBe("/briefing/weekly");
    expect(weeklyHref("id 1")).toBe("/briefing/weekly?repo_id=id%201");
  });
});
