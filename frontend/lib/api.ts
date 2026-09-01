/**
 * Typed access to the Mykronos backend.
 *
 * The admin token never reaches the browser. Every call from a client
 * component goes to a Next route handler on this server, which attaches the
 * token from a server-only environment variable and forwards the request.
 *
 * That matters more than it looks. The Phase 1 auth stub is a single bearer
 * token with full admin rights (spec 12 §3 replaces it with SSO). Shipping
 * that token to the browser would put a credential that can offboard repos
 * into localStorage, one XSS away from anyone. Proxying keeps it server-side
 * and costs one hop.
 */

import createClient from "openapi-fetch";
import type { paths } from "./api-types";

/** Server-side only. Never import this from a client component. */
export function backendClient() {
  const baseUrl = process.env.MYKRONOS_API_URL ?? "http://127.0.0.1:8100";
  const token = process.env.MYKRONOS_ADMIN_TOKEN ?? "";
  // The perimeter gate (backend `mykronos/gate.py`), when one is configured.
  // Sent from here rather than forwarded from the browser: this server calls
  // the backend over localhost, so it needs its own copy regardless of how
  // the visitor got past the gate at the edge.
  const gate = process.env.MYKRONOS_GATE_TOKEN ?? "";

  const headers: Record<string, string> = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (gate) headers["X-Hub-Token"] = gate;

  return createClient<paths>({ baseUrl, headers });
}

export type Portfolio =
  paths["/api/dashboard/portfolio"]["get"]["responses"]["200"]["content"]["application/json"];
export type PortfolioRow = Portfolio["repos"][number];
export type PortfolioSummary = Portfolio["summary"];
export type FindingsPage =
  paths["/api/dashboard/repos/{repo_id}/findings"]["get"]["responses"]["200"]["content"]["application/json"];
/**
 * The outstanding-work view: open findings only, one row per problem rather
 * than per report, with the toxic combinations named.
 */
export type OpenFindingsPage =
  paths["/api/dashboard/repos/{repo_id}/open-findings"]["get"]["responses"]["200"]["content"]["application/json"];
export type FindingGroup = OpenFindingsPage["groups"][number];
export type FindingLocation = FindingGroup["locations"][number];
export type ToxicCombination = OpenFindingsPage["toxic_combinations"][number];
export type RepoList =
  paths["/api/repos"]["get"]["responses"]["200"]["content"]["application/json"];
export type RepoDetail =
  paths["/api/repos/{repo_id}"]["get"]["responses"]["200"]["content"]["application/json"];
/** What this application is, as an asset (spec 21 §1). */
export type RiskProfile =
  paths["/api/repos/{repo_id}/risk-profile"]["get"]["responses"]["200"]["content"]["application/json"];
export type InsiderRiskPage =
  paths["/api/dashboard/repos/{repo_id}/insider-risk"]["get"]["responses"]["200"]["content"]["application/json"];
export type InsiderRiskSignal = InsiderRiskPage["signals"][number];
export type SscsPage =
  paths["/api/dashboard/repos/{repo_id}/sscs"]["get"]["responses"]["200"]["content"]["application/json"];
export type SscsEvidence = SscsPage["evidence"][number];
export type CiPage =
  paths["/api/dashboard/repos/{repo_id}/ci"]["get"]["responses"]["200"]["content"]["application/json"];
// `jobs` is optional in the generated type (it has a server-side default),
// so index it through NonNullable rather than widening every use site.
export type CiJob = NonNullable<CiPage["jobs"]>[number];
export type CiReporting = NonNullable<CiPage["reporting"]>[number];
export type CiStage = NonNullable<CiPage["stages"]>[number];
export type WorkflowsPage =
  paths["/api/repos/{repo_id}/workflows"]["get"]["responses"]["200"]["content"]["application/json"];
export type WorkflowState = WorkflowsPage["workflows"][number];
export type ThreatIntelEntry =
  paths["/api/dashboard/threat-intel"]["get"]["responses"]["200"]["content"]["application/json"][number];
/** A STRIDE-categorized attack-surface inventory for one repo (spec 18 §6). */
/** A repository's change-governance posture (spec 30 §2). */
export type GovernancePosture =
  paths["/api/dashboard/repos/{repo_id}/governance"]["get"]["responses"]["200"]["content"]["application/json"];

export type ThreatModelPage =
  paths["/api/dashboard/repos/{repo_id}/threat-model"]["get"]["responses"]["200"]["content"]["application/json"];
export type ThreatModelCategory = ThreatModelPage["categories"][number];
/** A declared mitigation (spec 28 §3). Declared, never verified — the
 *  distinction is the whole point of the register. */
export type ThreatModelControl = NonNullable<
  ThreatModelCategory["controls"]
>[number];

/** The shape `signal_breakdown` carries when an admin is allowed to see it. */
export type SignalBreakdown = {
  signals: { key: string; score: number; capped_at: number | null; rationale: string }[];
  raw_total: number;
  clamped: boolean;
  thresholds: { review: number; block: number };
  ai_authorship:
    | { evaluated: false; reason: string }
    | {
        evaluated: true;
        likely_ai_and_undisclosed: boolean;
        disclosure_required: boolean;
      };
  signals_not_reported: string[];
  signals_rejected: string[];
  contributing_count: number;
};

export type KnowledgeEntries =
  paths["/api/knowledge/entries"]["get"]["responses"]["200"]["content"]["application/json"];
export type KnowledgeEntry = KnowledgeEntries["entries"][number];

/**
 * Hand-typed: the retro and trend endpoints return rows assembled at request
 * time, so their OpenAPI schema is an open object. Writing the shape once
 * here beats spreading casts through the page.
 */
export type RetroReport = {
  period_start: string;
  period_end: string;
  quiet: boolean;
  new_entries: LearningRow[];
  reconfirmed: LearningRow[];
  decaying: LearningRow[];
  unreasoned: number;
  promotion_candidates: PromotionCandidate[];
};

export type LearningRow = {
  entry_id: string;
  subject: string;
  source_type: string;
  repo_full_name: string | null;
  text: string;
  observations: number;
  confidence: number;
  last_confirmed_at: string;
  reasons: string[];
};

export type PromotionCandidate = {
  subject: string;
  source_type: string;
  from_tier: string;
  to_tier: string;
  repos: string[];
  project_count: number;
  total_observations: number;
  mean_confidence: number;
  reasons: string[];
};

export type TrendReport = {
  periods: number;
  period_days: number;
  direction: "rising" | "falling" | "flat" | "unknown";
  points: {
    period_start: string;
    period_end: string;
    new_entries: number;
    reconfirmations: number;
    with_reasons: number;
    overrides: number;
    dismissals: number;
  }[];
};

export type RemediationPage =
  paths["/api/patchwork/repos/{repo_id}"]["get"]["responses"]["200"]["content"]["application/json"];
export type RemediationEvent = RemediationPage["events"][number];

/**
 * Hand-typed: both endpoints assemble their rows at request time, so the
 * generated schema is an open object.
 */
export type RegressionCoverage = {
  /** False when nothing has ever been fixed here — an empty denominator, not
   *  a failing grade. */
  available: boolean;
  fixed_findings: number;
  covered: number;
  demonstrated: number;
  asserted: number;
  /** Links whose lane has not run green in 30 days. Reported beside the
   *  headline rather than folded into it (spec 31 §3). */
  stale: number;
  ratio: number | null;
  note: string;
};

export type TrendSeries = {
  scope: string;
  days: number;
  mean_time_to_fix_days: number | null;
  /** Not windowed by `days`: every other number here is a rate over a period,
   *  while this is a standing property of everything ever fixed. */
  regression_coverage: RegressionCoverage;
  points: {
    at: string;
    open_critical: number;
    open_high: number;
    open_total: number;
    risk_score: number | null;
    trust_score: number | null;
  }[];
  note: string;
};

export type MaturityCriterion = {
  key: string;
  label: string;
  why: string;
  threshold: string;
  measured: string;
  passed: boolean;
};

export type MaturityRepo = {
  repo_full_name: string;
  tier_id: string;
  tier_name: string;
  tier_summary: string;
  tier_index: number;
  total_tiers: number;
  next_tier_name: string | null;
  criteria: MaturityCriterion[];
  blocking: MaturityCriterion[];
};

export type MaturityReport = {
  model_version: string;
  tiers: { id: string; name: string; summary: string }[];
  repos: MaturityRepo[];
};

/**
 * The management half of vulnerability management (spec 27, B-010).
 *
 * Hand-declared, like `MaturityReport` above: the endpoint returns a plain
 * dict so the generated schema types it as `unknown`, and a page cannot be
 * written against that.
 */
export type VulnerabilityManagement = {
  scope: string;
  aging: {
    severity: string;
    capability: string;
    age_band: string;
    count: number;
  }[];
  accepted_risk: { capability: string; severity: string; count: number }[];
  accepted_risk_detail: {
    finding_id: string;
    capability: string;
    severity: string;
    title: string;
    package_name: string;
    accepted_reason_code: string;
    /** Null is an indefinite acceptance, which is a decision, not an omission. */
    accepted_until: string | null;
    first_seen_at: string | null;
    fixed_version: string;
    /** Accepted for want of a fix, and a fix now exists. */
    now_fixable: boolean;
  }[];
  oldest_open: {
    finding_id: string;
    severity: string;
    capability: string;
    title: string;
    first_seen_at: string | null;
  }[];
  toxic_combinations: number;
};

export type TriageQueue =
  paths["/api/dashboard/triage"]["get"]["responses"]["200"]["content"]["application/json"];
export type TriageItem = TriageQueue["items"][number];

export type PullRequestsPage =
  paths["/api/dashboard/pull-requests"]["get"]["responses"]["200"]["content"]["application/json"];
export type PullRequestRow = PullRequestsPage["pull_requests"][number];

/** Oracle's verdicts, worst first — the order the UI sorts and colours by. */
export const RECOMMENDATIONS = ["no_go", "review_recommended", "go"] as const;
export type Recommendation = (typeof RECOMMENDATIONS)[number];

/**
 * Decision history for one repo.
 *
 * Hand-typed rather than generated: the endpoint returns rows straight out of
 * the lake, so its OpenAPI schema is an open object. Writing the shape here
 * keeps the guessing in one place instead of spreading casts through the page.
 */
export type RiskDecision = {
  decision_id: string;
  decision_type: string;
  pr_number?: number | null;
  release_tag?: string | null;
  commit_sha?: string | null;
  overall_risk_score: number;
  recommendation: Recommendation;
  reasoning: string;
  policy_version: string;
  evaluated_at: string;
  gate_outcome?: string | null;
  github_check_run_id?: string | null;
  human_override?: {
    overridden_by: string;
    overridden_at: string;
    reason: string;
    original_recommendation: string;
    accepted_recommendation: string;
  } | null;
  inputs_snapshot?: {
    terms?: { label: string; detail: string; contribution: number }[];
    totals?: { raw_score: number; overall_risk_score: number; clamped: boolean };
  } | null;
};

export type ShadowModeReport = {
  window_days: number;
  since: string;
  decisions_with_a_known_outcome: number;
  merged: number;
  closed_unmerged: number;
  would_have_blocked: number;
  would_have_blocked_and_overridden: number;
  by_recommendation: Record<string, Record<string, number>>;
  interpretation: string;
};

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export const SEVERITY_ORDER: Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
];

/**
 * A finding row as the dashboard returns it.
 *
 * Loosely typed on purpose: the API omits `code_snippet` and
 * `raw_finding_json` entirely for viewer roles (spec 12 §5), so the shape
 * genuinely differs by caller and pretending otherwise would mean lying to
 * the type checker about fields that may not be there.
 */
export type Finding = {
  finding_id: string;
  capability: string;
  rule_id: string;
  title: string;
  description?: string | null;
  severity: Severity;
  cvss_score?: number | null;
  file_path?: string | null;
  line_start?: number | null;
  line_end?: number | null;
  symbol?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  status: string;
  fingerprint_version?: string | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  resolved_at?: string | null;
  code_snippet?: string | null;
  raw_finding_json?: unknown;
};

export type ScanHealth = {
  repo_full_name: string;
  capabilities: {
    capability: string;
    runs: number;
    succeeded: number;
    failed: number;
    no_applicable_targets: number;
    failure_rate: number;
    last_run_at: string | null;
    peak_findings: number;
    /** The most recent run's own one-line message, if it had one (spec 19 §1.2). */
    detail: string | null;
    /** Same commit, disagreeing status, on the last two runs (spec 19 §1.3). */
    flaky: boolean;
    /**
     * Coverage from the most recent run that reported it (spec 31 §4). Null
     * means no run has reported any — a different fact from 0, which means a
     * runner measured and found none.
     *
     * Explicitly **not a security metric**, and labelled that way wherever it
     * is shown: it is context that stops a green pass rate being read as more
     * than it is.
     */
    line_coverage: number | null;
    branch_coverage: number | null;
    coverage_at: string | null;
  }[];
};

/**
 * One bucket of a lane's pass rate over time (spec 19 §1.1). Hand-typed for
 * the same reason `ScanHealth` is: the endpoint returns rows shaped in
 * Python, so its OpenAPI schema is an open object.
 */
export type ScanRunTrendPoint = {
  at: string;
  runs: number;
  /** Null for a window with no runs — a coverage gap, not a zero pass rate. */
  success_rate: number | null;
};

export type ScanRunTrend = {
  repo_full_name: string;
  capability: string;
  points: ScanRunTrendPoint[];
};

/** Backend unreachable is a normal state here, not an exception. */
export class BackendUnavailable extends Error {
  constructor(readonly detail: string) {
    super(detail);
    this.name = "BackendUnavailable";
  }
}
