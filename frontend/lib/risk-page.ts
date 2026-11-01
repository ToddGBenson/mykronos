/**
 * The Risk page (TheHub #61139; design v2, P4 and P6): products as rows,
 * health as columns, an estate row, and open high and critical by age.
 *
 * Columns run from "can it ship" on the left to "what is old" on the right:
 * the gate on main, production's lag, the severity counts, the oldest high or
 * critical against its own target, overdue, lanes, acceptances, and the
 * requests waiting on a person.
 *
 * Two rules hold for every cell:
 * - **A failed read is unknown, never zero.** An empty cell that looks clean
 *   because the backend did not answer is the failure this page exists to
 *   prevent. Unknown is drawn as stale, with the reason in its label.
 * - **Every cell is a link** to the filtered view behind its number.
 *
 * Built from existing endpoints only (`lib/server-risk.ts` does the reads).
 * Pure, so the vitest suite runs it.
 */

import { cellState, type CapabilityRun } from "./capability-cell";
import { findingsHref } from "./findings-filters";
import type { DeployLag } from "./prod-lag";

export type Read<T> = { ok: true; data: T } | { ok: false; error: string };

/** The six states, as the Portfolio board draws them (v2 palette). */
export type Tone = "ok" | "fail" | "warn" | "stale" | "never" | "acc";

export type StateCell = {
  text: string;
  tone: Tone;
  href: string;
  /** The state in words: the hover text and the accessible name. */
  label: string;
};

export type CountTone = "crit" | "high" | "med" | "warn" | "zero" | "unknown";

export type CountCell = {
  /** Null when the read behind it failed. */
  value: number | null;
  tone: CountTone;
  href: string;
  label: string;
};

/** `/api/oracle/decisions/by-commit/{sha}`'s body, the fields this page reads. */
export type CommitGate = {
  found: boolean;
  commit_sha: string;
  recommendation?: string | null;
  effective_recommendation?: string | null;
  overridden?: boolean;
  introduced?: Record<string, number>;
  introduced_blocking?: boolean;
};

/** One deduplicated row of `/open-findings`. */
export type RiskGroup = {
  severity: string;
  occurrences: number;
  age_days?: number | null;
  first_seen_at?: string | null;
  due_at?: string | null;
  due_state?: string;
};

export type RiskAcceptanceLite = { id: string; state: string; days_left: number | null };

export type ApprovalLite = {
  id: string;
  duty: string;
  subject_ref: string;
  expires_at?: string | null;
};

/** The portfolio row's fields this page reads. */
export type RiskRepoInput = {
  repo_id: string;
  repo_full_name: string;
  status: string;
  synthetic?: boolean;
  severity_counts: Record<string, number>;
  enabled_capabilities: string[];
  capability_states: (CapabilityRun & { enabled?: boolean })[];
  last_scan_at?: string | null;
};

export type RiskRepoReads = {
  /** Null data: the repository has no commit-gate decision to ask about. */
  gate: Read<CommitGate | null>;
  /** Open critical and high groups. */
  highPlus: Read<RiskGroup[]>;
  /** Open groups past their target, any severity. */
  overdue: Read<RiskGroup[]>;
  /** Every acceptance on the repository, any state. */
  acceptances: Read<RiskAcceptanceLite[]>;
};

export type RiskInputs = {
  repos: RiskRepoInput[];
  /** `/api/dashboard/deployments`, as lag by repository full name. */
  deployments: Read<Record<string, DeployLag | null>>;
  /** By repo id. A repository missing here was not read at all. */
  reads: Record<string, RiskRepoReads>;
  /** `/api/approvals?state=pending`. */
  approvals: Read<ApprovalLite[]>;
};

export type RiskRow = {
  repoId: string;
  name: string;
  synthetic: boolean;
  gate: StateCell;
  lag: StateCell;
  critical: CountCell;
  high: CountCell;
  medium: CountCell;
  oldest: StateCell;
  overdue: CountCell;
  lanes: StateCell;
  accepted: StateCell;
  /** Acceptances expiring within 30 days. */
  expiring: number;
  needs: CountCell;
  /** Anything on the row that wants a look, unknowns included. */
  problem: boolean;
};

export type AgeBucket = { label: string; critical: number; high: number; total: number };

export type RiskPage = {
  rows: RiskRow[];
  estate: Omit<RiskRow, "repoId" | "name" | "synthetic" | "problem" | "expiring">;
  buckets: AgeBucket[];
  /** Products shown. */
  products: number;
  /** Of those, how many reported a scan in the last 24 hours. */
  scannedRecently: number;
  /** Products with at least one read that failed, by name. */
  incomplete: string[];
};

const DAY_MS = 86_400_000;
const SILENT_AFTER_DAYS = 7;
const REVIEW_HREF = "/product-owner?tab=review";
const NOT_READ: Read<never> = { ok: false, error: "not read" };

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/** A timestamp or a bare date, in UTC. NaN when it is neither. */
export function parseUtc(value: string | null | undefined): number {
  if (!value) return Number.NaN;
  if (/^\d{4}-\d{2}-\d{2}$/.test(value)) return Date.parse(`${value}T00:00:00Z`);
  const zoned = /([zZ]|[+-]\d{2}:?\d{2})$/.test(value) ? value : `${value}Z`;
  return Date.parse(zoned);
}

function unknown(href: string, what: string, error: string): StateCell {
  return { text: "unknown", tone: "stale", href, label: `${what}: could not be read (${error})` };
}

// -- Gate --------------------------------------------------------------------

/**
 * The verdict on the newest commit the gate judged on the default branch.
 *
 * The gate refuses a commit that introduced an open critical or high
 * (`introduced_blocking`, #735), whatever the backlog-wide recommendation
 * says; a recorded override is the human decision and stands.
 */
export function gateCell(repoId: string, read: Read<CommitGate | null>): StateCell {
  const href = `/repos/${repoId}?tab=decisions`;
  if (!read.ok) return unknown(href, "gate", read.error);
  const gate = read.data;
  if (!gate || !gate.found) {
    return {
      text: "not assessed",
      tone: "never",
      href,
      label: "not assessed: no commit-gate decision is recorded for the default branch",
    };
  }
  const sha = gate.commit_sha.slice(0, 7);
  const effective = gate.effective_recommendation ?? gate.recommendation ?? "";
  const intro = gate.introduced ?? {};
  const blocking = (intro.critical ?? 0) + (intro.high ?? 0);
  const overridden = gate.overridden ? ", overridden by a person" : "";
  if (effective === "no_go") {
    return { text: "NO-GO", tone: "fail", href, label: `failing: no-go at ${sha}${overridden}` };
  }
  if (gate.introduced_blocking && !gate.overridden) {
    return {
      text: `NO-GO · ${blocking} blocking`,
      tone: "fail",
      href,
      label: `failing: ${sha} introduced ${plural(blocking, "open critical or high finding")}, which the gate refuses`,
    };
  }
  if (effective === "review_recommended") {
    return { text: "REVIEW", tone: "warn", href, label: `review recommended at ${sha}${overridden}` };
  }
  if (effective === "go") {
    return { text: "GO", tone: "ok", href, label: `healthy: go at ${sha}${overridden}` };
  }
  return { text: effective || "unknown", tone: "stale", href, label: `recorded "${effective}" at ${sha}` };
}

// -- Prod lag ----------------------------------------------------------------

export function lagCell(
  repoId: string,
  deployments: Read<Record<string, DeployLag | null>>,
  fullName: string,
): StateCell {
  const href = `/repos/${repoId}`;
  if (!deployments.ok) return unknown(href, "prod lag", deployments.error);
  const lag = deployments.data[fullName];
  if (!lag) {
    return { text: "no probe", tone: "never", href, label: "no deployment probe: nothing says what production runs" };
  }
  const branch = lag.branch || "its branch";
  const behind = lag.behind_by ?? 0;
  const running = lag.deployed_revision ? lag.deployed_revision.slice(0, 7) : "an unknown revision";
  if (lag.status === "at_head") {
    return { text: "0", tone: "ok", href, label: `healthy: production runs ${running}, the head of ${branch}` };
  }
  if (lag.status === "behind") {
    return {
      text: plural(behind, "commit"),
      tone: "warn",
      href,
      label: `production runs ${running}, ${plural(behind, "commit")} behind ${branch}`,
    };
  }
  if (lag.status === "diverged") {
    return {
      text: `${behind} behind, off ${branch}`,
      tone: "fail",
      href,
      label: `failing: production runs ${running}, which ${branch} does not contain`,
    };
  }
  return {
    text: "unknown",
    tone: "stale",
    href,
    label: `prod lag unknown: ${lag.detail || "no reason recorded"}`,
  };
}

// -- Severity counts ---------------------------------------------------------

const SEVERITY_TONE: Record<string, CountTone> = { critical: "crit", high: "high", medium: "med" };

export function severityCell(
  repoId: string,
  severity: "critical" | "high" | "medium",
  counts: Record<string, number>,
): CountCell {
  const value = counts[severity] ?? 0;
  return {
    value,
    tone: value > 0 ? SEVERITY_TONE[severity] : "zero",
    href: findingsHref(repoId, {}, { severity }),
    label: `${value} open ${severity}`,
  };
}

// -- Oldest high+ against its target -----------------------------------------

/** A finding's remediation window in days: first seen to due. */
export function targetDays(group: RiskGroup): number | null {
  const first = parseUtc(group.first_seen_at);
  const due = parseUtc(group.due_at);
  if (!Number.isFinite(first) || !Number.isFinite(due)) return null;
  return Math.round((due - first) / DAY_MS);
}

function oldestOf(groups: RiskGroup[]): RiskGroup | null {
  let oldest: RiskGroup | null = null;
  for (const g of groups) {
    if (typeof g.age_days !== "number") continue;
    if (!oldest || g.age_days > (oldest.age_days ?? -1)) oldest = g;
  }
  return oldest;
}

function isLate(group: RiskGroup): boolean {
  if (group.due_state === "overdue") return true;
  const target = targetDays(group);
  return target !== null && (group.age_days ?? 0) > target;
}

export function oldestCell(repoId: string, read: Read<RiskGroup[]>): StateCell {
  const href = findingsHref(repoId, {}, { severity: "critical,high", sort: "oldest" });
  if (!read.ok) return unknown(href, "oldest high or critical", read.error);
  const oldest = oldestOf(read.data);
  if (!oldest) {
    return { text: "—", tone: "never", href, label: "no open high or critical finding" };
  }
  const age = oldest.age_days ?? 0;
  const target = targetDays(oldest);
  const late = isLate(oldest);
  const against = target === null ? "no target" : `${target}d`;
  return {
    text: `${age}d / ${against}`,
    tone: late ? "warn" : "ok",
    href,
    label: `${late ? "overdue: " : ""}oldest open ${oldest.severity} is ${plural(age, "day")} old, ${
      target === null ? "with no remediation target" : `against a ${target}-day target`
    }`,
  };
}

// -- Overdue -----------------------------------------------------------------

export function overdueCell(repoId: string, read: Read<RiskGroup[]>): CountCell {
  const href = findingsHref(repoId, {}, { due: "overdue" });
  if (!read.ok) {
    return { value: null, tone: "unknown", href, label: `overdue: could not be read (${read.error})` };
  }
  const value = read.data.reduce((sum, g) => sum + g.occurrences, 0);
  return { value, tone: value > 0 ? "warn" : "zero", href, label: `${value} open past their target` };
}

// -- Lanes -------------------------------------------------------------------

/**
 * Reporting lanes over enabled lanes. Red is a failed or refused lane; silent
 * is an enabled one that never reported, or not in the last seven days.
 * One red lane links to its run history, since that is the thing to open.
 */
export function lanesCell(repo: RiskRepoInput, now: number): StateCell {
  const enabled = new Set(repo.enabled_capabilities);
  let ok = 0;
  const red: string[] = [];
  const silent: string[] = [];
  for (const run of repo.capability_states) {
    const isEnabled = enabled.has(run.capability) || run.enabled === true;
    const state = cellState({ enabled: isEnabled, pending: false, run });
    if (state === "failed" || state === "refused") red.push(run.capability);
    else if (state === "silent") silent.push(run.capability);
    else if (state === "reporting") {
      const last = parseUtc(run.last_scan_at);
      if (Number.isFinite(last) && now - last > SILENT_AFTER_DAYS * DAY_MS) silent.push(run.capability);
      else ok += 1;
    }
  }
  for (const capability of enabled) {
    if (!repo.capability_states.some((r) => r.capability === capability)) silent.push(capability);
  }
  const total = enabled.size;
  const parts = [`${ok}/${total}`];
  if (red.length) parts.push(`${red.length} red`);
  if (silent.length) parts.push(`${silent.length} silent`);
  const href =
    red.length === 1 ? `/repos/${repo.repo_id}/checks/${red[0]}` : `/repos/${repo.repo_id}`;
  const tone: Tone = total === 0 ? "never" : red.length ? "fail" : silent.length ? "stale" : "ok";
  const words = [`${ok} of ${total} enabled lanes reporting`];
  if (red.length) words.push(`failing: ${red.join(", ")}`);
  if (silent.length) words.push(`silent: ${silent.join(", ")}`);
  return { text: parts.join(" · "), tone, href, label: words.join("; ") };
}

// -- Acceptances -------------------------------------------------------------

/** Acceptances that are in force: the ones a finding is hidden behind. */
const IN_FORCE = new Set(["active", "expiring", "needs_review", "premise_failed"]);

export function acceptedCell(repoId: string, read: Read<RiskAcceptanceLite[]>): StateCell {
  const base = `/repos/${repoId}?tab=risk`;
  if (!read.ok) return unknown(base, "acceptances", read.error);
  const live = read.data.filter((a) => IN_FORCE.has(a.state));
  const expiring = live.filter((a) => a.state === "expiring");
  if (live.length === 0) {
    return { text: "0", tone: "never", href: base, label: "no risk acceptance in force" };
  }
  const soonest = expiring
    .map((a) => a.days_left)
    .filter((d): d is number => typeof d === "number")
    .sort((a, b) => a - b)[0];
  return {
    text: `${live.length} · ${expiring.length} expiring`,
    tone: "acc",
    href: expiring.length ? `${base}&state=expiring` : base,
    label: `accepted: ${plural(live.length, "acceptance")} in force, ${expiring.length} expiring${
      soonest !== undefined ? `, soonest in ${plural(soonest, "day")}` : ""
    }`,
  };
}

// -- Needs you ---------------------------------------------------------------

function liveApprovals(approvals: ApprovalLite[], now: number): ApprovalLite[] {
  return approvals.filter((a) => {
    const expires = parseUtc(a.expires_at);
    return !Number.isFinite(expires) || expires > now;
  });
}

/** `owner/repo#12@sha` names its repository; nothing else in a ref does. */
function prRepo(subjectRef: string): string | null {
  const match = /^(.+?)#\d+@/.exec(subjectRef);
  return match ? match[1] : null;
}

/**
 * Requests awaiting a person's decision that belong to this product: its
 * pull requests, and its risk acceptances. A finding disposition names only
 * a finding, so it is counted in the estate total, not on a row.
 */
export function needsYouCell(
  fullName: string,
  acceptances: Read<RiskAcceptanceLite[]>,
  approvals: Read<ApprovalLite[]>,
  now: number,
): CountCell {
  if (!approvals.ok) {
    return { value: null, tone: "unknown", href: REVIEW_HREF, label: `requests: could not be read (${approvals.error})` };
  }
  const ids = new Set(acceptances.ok ? acceptances.data.map((a) => a.id) : []);
  const mine = liveApprovals(approvals.data, now).filter(
    (a) => prRepo(a.subject_ref) === fullName || ids.has(a.subject_ref),
  );
  const value = mine.length;
  return {
    value,
    tone: value > 0 ? "high" : "zero",
    href: REVIEW_HREF,
    label: `${plural(value, "request")} waiting on a person`,
  };
}

// -- Age chart ---------------------------------------------------------------

const BANDS: { label: string; max: number }[] = [
  { label: "0–7 days", max: 7 },
  { label: "8–30 days", max: 30 },
  { label: "31–90 days", max: 90 },
  { label: "over 90 days", max: Number.POSITIVE_INFINITY },
];

/** Open critical and high by age, the bands Vulnerability management uses. */
export function ageBuckets(groups: RiskGroup[]): AgeBucket[] {
  const buckets = BANDS.map((b) => ({ label: b.label, critical: 0, high: 0, total: 0 }));
  for (const g of groups) {
    if (g.severity !== "critical" && g.severity !== "high") continue;
    if (typeof g.age_days !== "number") continue;
    const index = BANDS.findIndex((b) => (g.age_days as number) <= b.max);
    const bucket = buckets[index];
    if (g.severity === "critical") bucket.critical += g.occurrences;
    else bucket.high += g.occurrences;
    bucket.total += g.occurrences;
  }
  return buckets;
}

// -- The page ----------------------------------------------------------------

function isProblem(row: Omit<RiskRow, "problem">): boolean {
  const states = [row.gate, row.lag, row.oldest, row.lanes];
  if (states.some((c) => c.tone === "fail" || c.tone === "warn" || c.tone === "stale")) return true;
  if (row.accepted.tone === "stale" || row.expiring > 0) return true;
  if ((row.critical.value ?? 0) > 0) return true;
  if ([row.overdue, row.needs].some((c) => c.tone === "unknown" || (c.value ?? 0) > 0)) return true;
  return false;
}

function rank(row: RiskRow): [number, number, number, number] {
  return [
    row.problem ? 0 : 1,
    row.gate.tone === "fail" ? 0 : 1,
    -(row.critical.value ?? 0),
    -(row.high.value ?? 0),
  ];
}

function sum(cells: CountCell[]): { value: number; partial: boolean } {
  return {
    value: cells.reduce((s, c) => s + (c.value ?? 0), 0),
    partial: cells.some((c) => c.value === null),
  };
}

function total(cells: CountCell[], tone: CountTone, href: string, what: string): CountCell {
  const { value, partial } = sum(cells);
  return {
    value,
    tone: value > 0 ? tone : partial ? "unknown" : "zero",
    href,
    label: `${partial ? "at least " : ""}${value} ${what}${partial ? " (some products could not be read)" : ""}`,
  };
}

export function buildRiskPage(
  inputs: RiskInputs,
  options: { now: number; benchmark?: boolean; problemsOnly?: boolean },
): RiskPage {
  const { now } = options;
  const products = inputs.repos.filter(
    (r) => r.status === "active" && (options.benchmark || !r.synthetic),
  );
  const incomplete: string[] = [];
  const highPlus: RiskGroup[] = [];

  const all: RiskRow[] = products.map((repo) => {
    const reads = inputs.reads[repo.repo_id] ?? {
      gate: NOT_READ,
      highPlus: NOT_READ,
      overdue: NOT_READ,
      acceptances: NOT_READ,
    };
    if (!reads.gate.ok || !reads.highPlus.ok || !reads.overdue.ok || !reads.acceptances.ok) {
      incomplete.push(repo.repo_full_name);
    }
    if (reads.highPlus.ok) highPlus.push(...reads.highPlus.data);
    const row = {
      repoId: repo.repo_id,
      name: repo.repo_full_name,
      synthetic: Boolean(repo.synthetic),
      gate: gateCell(repo.repo_id, reads.gate),
      lag: lagCell(repo.repo_id, inputs.deployments, repo.repo_full_name),
      critical: severityCell(repo.repo_id, "critical", repo.severity_counts),
      high: severityCell(repo.repo_id, "high", repo.severity_counts),
      medium: severityCell(repo.repo_id, "medium", repo.severity_counts),
      oldest: oldestCell(repo.repo_id, reads.highPlus),
      overdue: overdueCell(repo.repo_id, reads.overdue),
      lanes: lanesCell(repo, now),
      accepted: acceptedCell(repo.repo_id, reads.acceptances),
      expiring: reads.acceptances.ok
        ? reads.acceptances.data.filter((a) => a.state === "expiring").length
        : 0,
      needs: needsYouCell(repo.repo_full_name, reads.acceptances, inputs.approvals, now),
    };
    return { ...row, problem: isProblem(row) };
  });

  all.sort((a, b) => {
    const [x, y] = [rank(a), rank(b)];
    for (let i = 0; i < x.length; i++) if (x[i] !== y[i]) return x[i] - y[i];
    return a.name.localeCompare(b.name);
  });
  const rows = options.problemsOnly ? all.filter((r) => r.problem) : all;

  const noGo = all.filter((r) => r.gate.tone === "fail").length;
  const behind = all.filter((r) => r.lag.tone === "warn" || r.lag.tone === "fail").length;
  const oldestDays = Math.max(-1, ...highPlus.map((g) => g.age_days ?? -1));
  const red = all.filter((r) => r.lanes.tone === "fail").length;
  const silent = all.filter((r) => r.lanes.tone === "stale").length;
  const expiring = all.reduce((s, r) => s + r.expiring, 0);
  const pending = inputs.approvals.ok ? liveApprovals(inputs.approvals.data, now).length : null;

  const estate: RiskPage["estate"] = {
    gate: {
      text: `${noGo} no-go`,
      tone: noGo ? "fail" : "ok",
      href: "/decisions",
      label: `${plural(noGo, "product")} the gate refuses on main`,
    },
    lag: {
      text: `${behind} behind`,
      tone: behind ? "warn" : "ok",
      href: "/platform-health",
      label: `${plural(behind, "product")} with production behind its branch`,
    },
    critical: total(all.map((r) => r.critical), "crit", "/triage", "open critical"),
    high: total(all.map((r) => r.high), "high", "/triage", "open high"),
    medium: total(all.map((r) => r.medium), "med", "/triage", "open medium"),
    oldest: {
      text: oldestDays >= 0 ? `${oldestDays}d oldest` : "—",
      tone: all.some((r) => r.oldest.tone === "warn") ? "warn" : oldestDays >= 0 ? "ok" : "never",
      href: "/vulnerability-management",
      label:
        oldestDays >= 0
          ? `the oldest open high or critical is ${plural(oldestDays, "day")} old`
          : "no open high or critical finding",
    },
    overdue: total(all.map((r) => r.overdue), "warn", "/vulnerability-management", "open past their target"),
    lanes: {
      text: `${red} red · ${silent} silent`,
      tone: red ? "fail" : silent ? "stale" : "ok",
      href: "/platform-health",
      label: `${plural(red, "product")} with a failing lane, ${silent} with a silent one`,
    },
    accepted: {
      text: `${expiring} expiring`,
      tone: "acc",
      href: "/vulnerability-management",
      label: `${plural(expiring, "acceptance")} expiring within 30 days`,
    },
    needs: {
      value: pending,
      tone: pending === null ? "unknown" : pending > 0 ? "high" : "zero",
      href: REVIEW_HREF,
      label:
        pending === null
          ? "requests: could not be read"
          : `${plural(pending, "request")} waiting on a person, across the estate`,
    },
  };

  const scannedRecently = products.filter((r) => {
    const last = parseUtc(r.last_scan_at);
    return Number.isFinite(last) && now - last <= DAY_MS;
  }).length;

  return {
    rows,
    estate,
    buckets: ageBuckets(highPlus),
    products: products.length,
    scannedRecently,
    incomplete,
  };
}
