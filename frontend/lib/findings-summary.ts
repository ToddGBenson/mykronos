/**
 * The summary at the top of the Findings tab (TheHub #60821): how many, how
 * bad, and which scan found them.
 *
 * Every number comes from the open-findings response itself — `total`,
 * `by_severity` and `by_capability`, which the backend counts with the same
 * status clause the list uses and before any other filter. Nothing is counted
 * off the page of groups here: that page is deduplicated and capped, so a
 * count taken from it would disagree with the list the moment either kicked
 * in.
 */

import { readValues } from "./findings-filters";

/** Worst first, every level always present — a zero is an answer. */
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export type SummaryCount = {
  /** The query value: `high`, `atlas`. */
  value: string;
  /** What the reader sees: `high`, `Dependencies (SCA)`. */
  label: string;
  count: number;
  /** Whether this count's value is among those currently applied. */
  active: boolean;
};

export type FindingsSummary = {
  total: number;
  /** "open", "accepted risk" — the status the counts describe. */
  status: string;
  bySeverity: SummaryCount[];
  byCapability: SummaryCount[];
};

export function findingsSummary(
  page: {
    total: number;
    by_severity: Record<string, number>;
    by_capability?: Record<string, number>;
  },
  query: { status?: string; severity?: string; capability?: string },
  capabilityLabel: (capability: string) => string = (capability) => capability,
): FindingsSummary {
  // Each filter may carry several values (`severity=critical,high`).
  const severities = readValues(query.severity);
  const capabilities = readValues(query.capability);
  const statuses = readValues(query.status);
  const byCapability = Object.entries(page.by_capability ?? {})
    .filter(([, count]) => count > 0)
    // Most first, then by name so equal counts do not reshuffle between loads.
    .sort(([a, x], [b, y]) => y - x || a.localeCompare(b))
    .map(([value, count]) => ({
      value,
      label: capabilityLabel(value),
      count,
      active: capabilities.includes(value),
    }));
  // A capability filter arriving from a link elsewhere still gets its chip,
  // at zero, so the applied filter is always visible and removable here.
  for (const capability of capabilities) {
    if (!byCapability.some((entry) => entry.value === capability)) {
      byCapability.push({
        value: capability,
        label: capabilityLabel(capability),
        count: 0,
        active: true,
      });
    }
  }
  return {
    total: page.total,
    status: (statuses.length ? statuses : ["open"])
      .map((status) => status.replace(/_/g, " "))
      .join(" + "),
    bySeverity: SEVERITY_ORDER.map((value) => ({
      value,
      label: value,
      count: page.by_severity[value] ?? 0,
      active: severities.includes(value),
    })),
    byCapability,
  };
}
