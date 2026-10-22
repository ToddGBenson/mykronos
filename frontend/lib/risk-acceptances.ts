/**
 * Words and derivations for accepted risk, shared by the estate-wide list on
 * Vulnerability management and the repository's Risk management tab, so the
 * two never describe the same acceptance differently.
 *
 * Pure, so the vitest suite runs it without rendering either page.
 */

/** The row-level reason code a finding carries, in words (spec 24 §3). */
export const REASON_LABEL: Record<string, string> = {
  no_vendor_fix: "No vendor fix",
  not_exploitable_here: "Not exploitable here",
  compensating_control: "Compensating control",
  cost_exceeds_risk: "Cost exceeds risk",
  other: "Other",
};

export function reasonLabel(code: string | null | undefined): string {
  if (!code) return "—";
  return REASON_LABEL[code] ?? code;
}

/** The derived states the backend returns, in the order the strip shows them. */
export const STRIP_STATES = [
  "active",
  "expiring",
  "expired",
  "premise_failed",
  "revoked",
] as const;

export const STATE_LABEL: Record<string, string> = {
  active: "Active",
  expiring: "Expiring",
  expired: "Expired",
  needs_review: "Needs review",
  premise_failed: "Premise failed",
  revoked: "Revoked",
  pending_approval: "Awaiting approval",
  closed: "Closed",
};

export function stateLabel(state: string): string {
  return STATE_LABEL[state] ?? state.replaceAll("_", " ");
}

export type Tone = "critical" | "warn" | "pass" | "muted" | "accent";

/** A failed premise or a lapsed date is red; an approaching one amber. */
export function stateTone(state: string): Tone {
  if (state === "premise_failed" || state === "expired" || state === "needs_review") {
    return "critical";
  }
  if (state === "expiring" || state === "pending_approval") return "warn";
  if (state === "active") return "pass";
  return "muted";
}

export const PREMISE_LABEL: Record<string, string> = {
  no_fixed_version: "No fixed version",
  port_not_published: "Port not published",
  firewall_scope: "Firewall scope",
  image_role: "Image role",
  container_command: "Container command",
  not_internet_facing: "Not internet-facing",
  not_kev_listed: "Not KEV-listed",
  epss_below: "EPSS below threshold",
  path_unreachable: "Path unreachable",
};

export function premiseLabel(type: string): string {
  return PREMISE_LABEL[type] ?? (type ? type.replaceAll("_", " ") : "untyped premise");
}

/** `unverified` is never good news (spec 33 §4.2), so it is amber, not grey. */
export function verdictTone(status: string): Tone {
  if (status === "holds") return "pass";
  if (status === "failed") return "critical";
  return "warn";
}

/** "evidence 3.2 days old", or why there is no age to give. */
export function evidenceAgeText(ageDays: number | null | undefined): string {
  if (ageDays === null || ageDays === undefined) return "no evidence";
  if (ageDays < 1) return "evidence under a day old";
  const days = Math.round(ageDays);
  return `evidence ${days} day${days === 1 ? "" : "s"} old`;
}

/**
 * Where the interim review an acceptance nothing watches owes stands
 * (TheHub #60817), in words; null when it owes none.
 */
export function interimReviewText(row: {
  interim_review: string;
  interim_review_by?: string | null;
  interim_reviewed_at?: string | null;
  interim_reviewed_by?: string | null;
}): string | null {
  const by = row.interim_review_by ?? "";
  switch (row.interim_review) {
    case "scheduled":
      return `due ${by}`;
    case "due":
      return `due since ${by}`;
    case "lapsed":
      return `lapsed — due ${by}, never recorded`;
    case "done":
      return `recorded ${(row.interim_reviewed_at ?? "").slice(0, 10)}${
        row.interim_reviewed_by ? ` by ${row.interim_reviewed_by}` : ""
      }`;
    default:
      return null;
  }
}

/** The "review due" pill's words: which review is owed. */
export function reviewDueLabel(row: { interim_review: string }): string {
  return row.interim_review === "due" || row.interim_review === "lapsed"
    ? "interim review due"
    : "review due";
}

/** "12 days left", "due today", "3 days past". Null expiry is a pending record. */
export function daysLeftText(daysLeft: number | null | undefined): string {
  if (daysLeft === null || daysLeft === undefined) return "no expiry yet";
  if (daysLeft === 0) return "expires today";
  if (daysLeft > 0) return `${daysLeft} day${daysLeft === 1 ? "" : "s"} left`;
  const past = -daysLeft;
  return `${past} day${past === 1 ? "" : "s"} past`;
}

/** The expiry cell is red when the date has passed or a premise has failed. */
export function expiryIsRed(row: {
  days_left?: number | null;
  state: string;
  premises: readonly { status: string }[];
}): boolean {
  return (
    (row.days_left !== null && row.days_left !== undefined && row.days_left < 0) ||
    row.state === "premise_failed" ||
    row.state === "expired" ||
    row.premises.some((premise) => premise.status === "failed")
  );
}

/** Holds / unverified / failed, counted. */
export function premiseTally(premises: readonly { status: string }[]): {
  holds: number;
  unverified: number;
  failed: number;
} {
  const tally = { holds: 0, unverified: 0, failed: 0 };
  for (const premise of premises) {
    if (premise.status === "holds") tally.holds += 1;
    else if (premise.status === "failed") tally.failed += 1;
    else tally.unverified += 1;
  }
  return tally;
}

export type RiskFilters = {
  state?: string;
  severity?: string;
  effective?: string;
};

/**
 * The tab URL with one filter set, or cleared when it is already the one set
 * (clicking a lit count turns it off). The other filters are kept, so state
 * and severity combine.
 */
export function filterHref(
  repoId: string,
  current: RiskFilters,
  key: keyof RiskFilters,
  value: string,
): string {
  const next: RiskFilters = { ...current, [key]: current[key] === value ? undefined : value };
  const params = new URLSearchParams({ tab: "risk" });
  for (const name of ["state", "severity", "effective"] as const) {
    const set = next[name];
    if (set) params.set(name, set);
  }
  return `/repos/${repoId}?${params.toString()}`;
}

/** Severity words, worst first, as the strip lists them. */
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** A count map's non-zero entries, worst first, unknown words last. */
export function severityCounts(counts: Record<string, number>): [string, number][] {
  const known = SEVERITY_ORDER.filter((s) => (counts[s] ?? 0) > 0).map(
    (s) => [s, counts[s]] as [string, number],
  );
  const other = Object.entries(counts).filter(
    ([s, n]) => n > 0 && !(SEVERITY_ORDER as readonly string[]).includes(s),
  );
  return [...known, ...other];
}

/** A compensating control is free-form JSON; this is its one-line reading. */
export function controlText(control: Record<string, unknown>): string {
  const name =
    control.control ?? control.name ?? control.title ?? control.description ?? control.id;
  const rest = Object.entries(control)
    .filter(([key]) => !["control", "name", "title", "description", "id"].includes(key))
    .map(([key, value]) => `${key}: ${typeof value === "string" ? value : JSON.stringify(value)}`);
  const head = name === undefined ? "" : String(name);
  return [head, ...rest].filter(Boolean).join(" · ") || JSON.stringify(control);
}

/** "risk_acceptance.premise_failed" -> "premise failed". */
export function auditActionLabel(action: string): string {
  return action.replace(/^risk_acceptance\./, "").replaceAll("_", " ");
}
