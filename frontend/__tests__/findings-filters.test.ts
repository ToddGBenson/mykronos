/**
 * The Findings tab's filter pills and clickable summary, as query strings.
 *
 * Every click on the tab is a link built here, so these are the behaviours a
 * person sees: toggling a value on and off, several values in one filter,
 * clearing one pill or all of them, and old single-value links still reading
 * the way they always did.
 */
import { describe, expect, it } from "vitest";

import {
  BUILTIN_VIEWS,
  SAVED_VIEWS_KEY,
  activeFilterCount,
  clearAll,
  exportQuery,
  findingsApiQuery,
  findingsHref,
  hasNarrowingFilters,
  isCurrentView,
  loadSavedViews,
  normalizeQuery,
  pillValue,
  readValues,
  setValues,
  sortGroups,
  storeSavedViews,
  toggleValue,
  valuesOf,
  viewPatch,
  viewQueryString,
  withSavedView,
} from "../lib/findings-filters";
import { findingsSummary } from "../lib/findings-summary";

const params = (href: string) => new URL(href, "http://x").searchParams;

describe("reading the URL", () => {
  it("accepts a single value, as every older link carries", () => {
    expect(readValues("high")).toEqual(["high"]);
    expect(normalizeQuery({ severity: "high" })).toEqual({ severity: "high" });
  });

  it("accepts comma-separated and repeated values alike", () => {
    expect(readValues("critical,high")).toEqual(["critical", "high"]);
    expect(normalizeQuery({ severity: ["critical", "high"] })).toEqual({
      severity: "critical,high",
    });
    expect(normalizeQuery({ severity: ["critical", "high,critical"] }).severity).toBe(
      "critical,high",
    );
  });

  it("drops blanks and takes the first value of a single-value key", () => {
    expect(readValues(" , ,")).toEqual([]);
    expect(normalizeQuery({ severity: ",", rule_id: ["CWE-89", "CWE-79"] })).toEqual({
      rule_id: "CWE-89",
    });
  });

  it("ignores keys the tab does not own", () => {
    expect(normalizeQuery({ tab: "findings", view: "x", severity: "low" })).toEqual({
      tab: "findings",
      severity: "low",
    });
  });
});

describe("toggling a value", () => {
  it("turns a value on, then off again", () => {
    const on = toggleValue({}, "severity", "high");
    expect(on.severity).toBe("high");
    const off = toggleValue({ severity: "high" }, "severity", "high");
    expect(off.severity).toBeUndefined();
  });

  it("adds to the values already applied rather than replacing them", () => {
    expect(toggleValue({ severity: "critical" }, "severity", "high").severity).toBe(
      "critical,high",
    );
    expect(toggleValue({ severity: "critical,high" }, "severity", "critical").severity).toBe(
      "high",
    );
  });

  it("clears the selected row, which the new list may not contain", () => {
    const patch = toggleValue({ group: "g", finding: "f" }, "capability", "sast");
    const href = findingsHref("r1", { group: "g", finding: "f" }, patch);
    expect(params(href).get("group")).toBeNull();
    expect(params(href).get("finding")).toBeNull();
  });

  it("keeps every other filter", () => {
    const query = { severity: "high", exposure: "internet", sort: "newest" };
    const href = findingsHref("r1", query, toggleValue(query, "capability", "atlas"));
    const search = params(href);
    expect(search.get("tab")).toBe("findings");
    expect(search.get("severity")).toBe("high");
    expect(search.get("exposure")).toBe("internet");
    expect(search.get("capability")).toBe("atlas");
    expect(search.get("sort")).toBe("newest");
  });
});

describe("the pill dialogs' Apply", () => {
  it("writes several values comma-separated", () => {
    const href = findingsHref("r1", {}, setValues("due", ["overdue", "due_soon"]));
    expect(params(href).get("due")).toBe("overdue,due_soon");
    expect(href).toContain("due=overdue%2Cdue_soon");
  });

  it("removes the parameter when nothing is chosen", () => {
    expect(setValues("severity", []).severity).toBeUndefined();
  });

  it("treats status=open alone as the default it is", () => {
    expect(setValues("status", ["open"]).status).toBeUndefined();
    expect(setValues("status", ["open", "accepted_risk"]).status).toBe("open,accepted_risk");
  });
});

describe("clearing", () => {
  const query = {
    status: "fixed",
    severity: "critical,high",
    path: "web/",
    kev_only: "1",
    min_epss: "0.5",
    older_than_days: "30",
    sort: "oldest",
    group: "g",
  };

  it("clear all removes every filter and the selection, keeping the sort", () => {
    const search = params(findingsHref("r1", query, clearAll()));
    expect([...search.keys()].sort()).toEqual(["sort", "tab"]);
  });

  it("counts a pill once, however many keys it owns", () => {
    // status, severity, path, threat intel (two keys), first seen.
    expect(activeFilterCount(query)).toBe(5);
    expect(activeFilterCount({})).toBe(0);
  });

  it("knows when only the status is narrowing", () => {
    expect(hasNarrowingFilters({ status: "fixed" })).toBe(false);
    expect(hasNarrowingFilters({ status: "fixed", owner: "unclaimed" })).toBe(true);
  });
});

describe("what a pill says", () => {
  const label = (value: string) => value.toUpperCase();
  it("reads any, then the values, then the first and a count", () => {
    expect(pillValue([], label)).toBe("any");
    expect(pillValue(["critical", "high"], label)).toBe("CRITICAL, HIGH");
    expect(pillValue(["a", "b", "c", "d"], label)).toBe("A +3");
  });
});

describe("views", () => {
  it("a view replaces the filters rather than adding to them", () => {
    const internet = BUILTIN_VIEWS.find((view) => view.id === "internet-high")!;
    const href = findingsHref(
      "r1",
      { owner: "@org/a", sort: "due" },
      viewPatch(internet.query),
    );
    const search = params(href);
    expect(search.get("owner")).toBeNull();
    expect(search.get("exposure")).toBe("internet");
    expect(search.get("severity")).toBe("critical,high");
    expect(search.get("sort")).toBe("due");
  });

  it("recognises the current view whatever order its values are in", () => {
    const internet = BUILTIN_VIEWS.find((view) => view.id === "internet-high")!;
    expect(isCurrentView({ severity: "high,critical", exposure: "internet" }, internet.query)).toBe(
      true,
    );
    expect(isCurrentView({ severity: "high", exposure: "internet" }, internet.query)).toBe(false);
    expect(isCurrentView({}, "")).toBe(true);
  });

  it("saves only the filters, not the selection or the sort", () => {
    expect(viewQueryString({ severity: "high", group: "g", sort: "due", tab: "findings" })).toBe(
      "severity=high",
    );
  });

  it("saved views survive storage being absent, broken or refusing", () => {
    expect(loadSavedViews(null)).toEqual([]);
    const broken = {
      getItem: () => "{not json",
      setItem: () => {
        throw new Error("QuotaExceededError");
      },
    };
    expect(loadSavedViews(broken)).toEqual([]);
    expect(storeSavedViews(broken, [])).toBe(false);
    const throwing = {
      getItem: () => {
        throw new Error("SecurityError");
      },
      setItem: () => undefined,
    };
    expect(loadSavedViews(throwing)).toEqual([]);
  });

  it("round-trips through storage, a same-named view replacing the old one", () => {
    const store = new Map<string, string>();
    const storage = {
      getItem: (key: string) => store.get(key) ?? null,
      setItem: (key: string, value: string) => void store.set(key, value),
    };
    let views = withSavedView([], "Mine", "owner=%40org%2Fa");
    views = withSavedView(views, "Mine", "owner=%40org%2Fb");
    views = withSavedView(views, "  ", "ignored");
    expect(storeSavedViews(storage, views)).toBe(true);
    expect(store.has(SAVED_VIEWS_KEY)).toBe(true);
    const loaded = loadSavedViews(storage);
    expect(loaded.map((view) => [view.label, view.query])).toEqual([
      ["Mine", "owner=%40org%2Fb"],
    ]);
    store.set(SAVED_VIEWS_KEY, JSON.stringify([{ id: 1 }, { id: "a", label: "A", query: "" }]));
    expect(loadSavedViews(storage)).toEqual([{ id: "a", label: "A", query: "" }]);
  });
});

describe("the API query", () => {
  it("sends multi-value filters as lists and drops what is unset", () => {
    const api = findingsApiQuery(
      normalizeQuery({
        status: "open,accepted_risk",
        severity: ["critical", "high"],
        exposure: "internet",
        path: "web/",
        older_than_days: "30",
        kev_only: "1",
        min_epss: "0.5",
        fixable: "1",
      }),
    );
    expect(api.finding_status).toEqual(["open", "accepted_risk"]);
    expect(api.severity).toEqual(["critical", "high"]);
    expect(api.exposure).toEqual(["internet"]);
    expect(api.capability).toBeUndefined();
    expect(api.path).toBe("web/");
    expect(api.older_than_days).toBe(30);
    expect(api.newer_than_days).toBeUndefined();
    expect(api.kev_only).toBe(true);
    expect(api.min_epss).toBe(0.5);
    expect(api.fixable).toBe(true);
  });

  it("ignores an age or EPSS that is not a number", () => {
    const api = findingsApiQuery({ older_than_days: "soon", min_epss: "lots" });
    expect(api.older_than_days).toBeUndefined();
    expect(api.min_epss).toBeUndefined();
  });

  it("passes an old single-value link straight through", () => {
    const api = findingsApiQuery(normalizeQuery({ severity: "high", component: "none" }));
    expect(api.severity).toEqual(["high"]);
    expect(api.component).toEqual(["none"]);
  });
});

describe("exports", () => {
  it("carries single values and names what it cannot carry", () => {
    const one = exportQuery({ severity: "high", capability: "sast", rule_id: "CWE-89" });
    expect(one.params.toString()).toBe(
      "severity=high&capability=sast&finding_status=open&rule_id=CWE-89",
    );
    expect(one.unexported).toEqual([]);

    const many = exportQuery({ severity: "critical,high", exposure: "internet", path: "x" });
    expect(many.params.get("severity")).toBeNull();
    expect(many.unexported).toEqual(["more than one severity", "exposure", "path"]);
  });
});

describe("sorting", () => {
  const groups = [
    { id: "a", severity: "critical", occurrences: 1, age_days: 3, due_at: null },
    { id: "b", severity: "high", occurrences: 5, age_days: 40, due_at: "2026-11-01T00:00:00" },
    { id: "c", severity: "high", occurrences: 2, age_days: 10, due_at: "2026-10-25T00:00:00" },
  ];
  const ids = (sort?: string) => sortGroups(groups, sort).map((group) => group.id);

  it("keeps the backend's worst-first order by default", () => {
    expect(ids()).toEqual(["a", "b", "c"]);
    expect(ids("nonsense")).toEqual(["a", "b", "c"]);
  });

  it("orders by age, occurrences or deadline", () => {
    expect(ids("newest")).toEqual(["a", "c", "b"]);
    expect(ids("oldest")).toEqual(["b", "c", "a"]);
    expect(ids("occurrences")).toEqual(["b", "c", "a"]);
    expect(ids("due")).toEqual(["c", "b", "a"]);
  });
});

describe("the clickable summary", () => {
  const page = {
    total: 7,
    by_severity: { critical: 2, high: 4, medium: 1, low: 0, info: 0 },
    by_capability: { sast: 5, atlas: 1, containers: 1 },
  };

  it("outlines every applied severity, not just one", () => {
    const summary = findingsSummary(page, { severity: "critical,high" });
    expect(summary.bySeverity.filter((entry) => entry.active).map((entry) => entry.value)).toEqual(
      ["critical", "high"],
    );
  });

  it("a segment's link toggles only its own value", () => {
    const query = { severity: "critical,high" };
    const high = findingsSummary(page, query).bySeverity.find((entry) => entry.value === "high")!;
    const href = findingsHref("r1", query, toggleValue(query, "severity", high.value));
    expect(valuesOf(normalizeQuery(Object.fromEntries(params(href))), "severity")).toEqual([
      "critical",
    ]);
  });

  it("keeps an applied scan type visible at zero, for each one applied", () => {
    const summary = findingsSummary(page, { capability: "dast,sast" });
    expect(summary.byCapability.find((entry) => entry.value === "dast")).toMatchObject({
      count: 0,
      active: true,
    });
    expect(summary.byCapability.find((entry) => entry.value === "sast")?.active).toBe(true);
  });

  it("names every status the counts cover", () => {
    expect(findingsSummary(page, {}).status).toBe("open");
    expect(findingsSummary(page, { status: "open,accepted_risk" }).status).toBe(
      "open + accepted risk",
    );
  });
});
