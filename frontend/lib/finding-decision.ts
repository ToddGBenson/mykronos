/**
 * The finding page's decision panel and its risk-acceptance form (TheHub
 * #61140, P7).
 *
 * The page used to open on identification and severity, put the actions
 * halfway down, and send dispositions to another tab. The decision now comes
 * first, and stays in view while the evidence scrolls past.
 *
 * The rules below mirror `backend/mykronos/risk_acceptance.py` and the default
 * approval policy. The server still enforces every one of them; these exist so
 * the form can say what is missing before the round trip, in the same words.
 * If the policy file changes a cap, the server's refusal is the one that
 * counts, and it is shown verbatim.
 */

/** `risk_acceptance.LEVELS`. */
export const LEVELS = ["low", "moderate", "high", "very_high"] as const;
export type Level = (typeof LEVELS)[number];

export const LEVEL_LABEL: Record<Level, string> = {
  low: "Low",
  moderate: "Moderate",
  high: "High",
  very_high: "Very high",
};

/** `risk_acceptance.DEVIATION_TYPES`, with what each one means. */
export const DEVIATION_TYPES = [
  {
    value: "vendor_dependency",
    label: "Waiting on the vendor",
    hint: "No fix is published. It re-opens the day a scan reports one.",
  },
  {
    value: "risk_adjustment",
    label: "Lower risk here",
    hint: "Real in general, less so here. Name a premise the platform can check.",
  },
  {
    value: "operational_requirement",
    label: "Needed to operate",
    hint: "Fixing it would break something the business needs. Never for a critical residual.",
  },
] as const;
export type DeviationType = (typeof DEVIATION_TYPES)[number]["value"];

/**
 * The premise types a person can choose without parameters. The others
 * (`port_not_published`, `firewall_scope`, `epss_below`, ...) take values the
 * form does not collect yet; propose those through the API.
 */
export const SIMPLE_PREMISES = [
  {
    value: "no_fixed_version",
    label: "No fixed version is published",
    hint: "Read from the scanner. Not monitored on its own: the finding re-opens when a fix ships.",
  },
  {
    value: "not_internet_facing",
    label: "Not internet facing",
    hint: "Monitored daily. If exposure is observed, the acceptance re-opens.",
  },
  {
    value: "not_kev_listed",
    label: "Not on the KEV list",
    hint: "Monitored daily. If CISA lists the CVE, the acceptance re-opens.",
  },
] as const;

/** `premise_monitor.REOPENS`: monitored, and able to re-open the acceptance. */
const REOPENS = new Set([
  "port_not_published",
  "firewall_scope",
  "not_internet_facing",
  "epss_below",
  "not_kev_listed",
]);

/** `InterimReview.reason_codes`, and `days` from the default policy. */
const INTERIM_REASON_CODES = new Set([
  "not_exploitable_here",
  "compensating_control",
  "cost_exceeds_risk",
]);
export const INTERIM_REVIEW_DAYS = 30;

/** `RiskAcceptanceLimits.max_duration_days`, the default policy. */
const MAX_DAYS: Record<string, number> = { critical: 30, high: 90, medium: 180, low: 365 };

export function residualSeverity(likelihood: Level, impact: Level): string {
  const score = LEVELS.indexOf(likelihood) + LEVELS.indexOf(impact);
  if (score <= 1) return "low";
  if (score <= 3) return "medium";
  if (score <= 5) return "high";
  return "critical";
}

const SEVERITIES = ["low", "medium", "high", "critical"] as const;

/**
 * The residual the server governs by, as far as the form can know it.
 * `risk_acceptance.propose` floors every deviation but a risk adjustment at
 * the worst covered finding's own severity: waiting on a vendor, or needing
 * the thing to run, says nothing about how bad it is. The form knows this
 * finding's severity; a wider scope, an unverified control or a combination
 * can floor it further, and the server says so when it does.
 */
export function effectiveResidual(
  d: Pick<
    AcceptanceDraft,
    "deviation_type" | "residual_likelihood" | "residual_impact" | "finding_severity"
  >,
): string {
  const matrix = residualSeverity(d.residual_likelihood, d.residual_impact);
  const floor = (d.finding_severity ?? "").toLowerCase();
  if (d.deviation_type === "risk_adjustment" || !SEVERITIES.includes(floor as never)) {
    return matrix;
  }
  return SEVERITIES.indexOf(floor as never) > SEVERITIES.indexOf(matrix as never)
    ? floor
    : matrix;
}

export function maxDurationDays(residual: string): number {
  return MAX_DAYS[residual] ?? 30;
}

/** `risk_acceptance.reason_code_for`. */
function reasonCodeFor(deviation: string, controls: unknown[]): string {
  if (deviation === "vendor_dependency") return "no_vendor_fix";
  if (deviation === "operational_requirement") return "cost_exceeds_risk";
  return controls.length ? "compensating_control" : "not_exploitable_here";
}

/** `risk_acceptance.interim_review_owed`: does anything watch this acceptance? */
export function interimReviewOwed(
  deviation: string,
  controls: unknown[],
  premises: string[],
): boolean {
  if (!INTERIM_REASON_CODES.has(reasonCodeFor(deviation, controls))) return false;
  return !premises.some((p) => REOPENS.has(p));
}

export type ScopeSource = {
  capability: string;
  rule_id: string;
  file_path?: string | null;
  raw_finding_json?: unknown;
};

/**
 * The scope of a decision about this one finding. A container scope names its
 * image (D-127) and its CVE: `match_scope` filters container findings by
 * `rule_ids` too, and without them the proposal would cover every open
 * finding on the image, take the worst one's severity as its floor, and be
 * refused as a vendor dependency whenever any other one has a fix (review of
 * #1065). A code scope names its rule and, when it has one, its file, because
 * a scope matching a whole repository is refused.
 */
export function defaultScope(f: ScopeSource): Record<string, unknown> {
  if (f.capability === "containers") {
    const raw = (f.raw_finding_json ?? {}) as Record<string, unknown>;
    const image = typeof raw.image === "string" ? raw.image : "";
    return { capability: f.capability, image, rule_ids: [f.rule_id] };
  }
  return {
    capability: f.capability,
    rule_ids: [f.rule_id],
    ...(f.file_path ? { file_paths: [f.file_path] } : {}),
  };
}

export function dispositionProblem(_status: string, reason: string): string | null {
  return reason.trim() ? null : "Say why. A disposition without a reason cannot be saved.";
}

export type AcceptanceDraft = {
  repo: string;
  scope: Record<string, unknown>;
  deviation_type: DeviationType;
  justification: string;
  residual_likelihood: Level;
  residual_impact: Level;
  risk_owner: string;
  requested_until: string;
  premises: string[];
  /** A declared control's id, or "" for none. Free text is refused (#60902). */
  control_id: string;
  milestone_title: string;
  milestone_due: string;
  response: "accept" | "transfer";
  /** This finding's own severity, the floor `effectiveResidual` applies.
   *  Never sent: the server reads the covered findings from the lake. */
  finding_severity?: string;
};

function addDays(isoDate: string, days: number): string {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

/** What stops the draft from being proposed, in the order the form asks. */
export function proposalProblems(d: AcceptanceDraft, today: string): string[] {
  const problems: string[] = [];
  const residual = effectiveResidual(d);
  if (!d.justification.trim()) problems.push("Give the reason this risk is acceptable.");
  if (
    d.deviation_type === "operational_requirement" &&
    residual === "critical"
  ) {
    problems.push(
      "A critical residual risk cannot be an operational requirement: that is a conversation about the architecture, not an acceptance.",
    );
  }
  if (d.deviation_type === "risk_adjustment" && d.premises.length === 0) {
    problems.push("A risk adjustment names at least one premise the platform can check.");
  }
  const owner = d.risk_owner.trim();
  if (!owner || owner.startsWith("agent:")) {
    problems.push("Name the person who answers for it. An agent is not a risk owner.");
  }
  if (!d.requested_until) {
    problems.push("Choose when it expires.");
  } else if (d.requested_until <= today) {
    problems.push("The expiry must be after today.");
  } else {
    const cap = maxDurationDays(residual);
    const latest = addDays(today, cap);
    if (d.requested_until > latest) {
      problems.push(
        `A ${residual} acceptance runs at most ${cap} days, so it expires by ${latest}.`,
      );
    }
  }
  if (!d.milestone_title.trim() || !d.milestone_due) {
    problems.push("Say how it ends: a milestone that ends the weakness, with a due date.");
  }
  if (d.scope.capability === "containers" && !d.scope.image) {
    problems.push("This container finding names no image, so it cannot be scoped. Use the API.");
  }
  return problems;
}

/** The body `POST /api/risk-acceptances` takes. */
export function buildProposal(d: AcceptanceDraft) {
  return {
    repo: d.repo,
    scope: d.scope,
    deviation_type: d.deviation_type,
    justification: d.justification.trim(),
    residual_likelihood: d.residual_likelihood,
    residual_impact: d.residual_impact,
    risk_owner: d.risk_owner.trim(),
    requested_until: d.requested_until,
    premises: d.premises.map((type) => ({ type })),
    compensating_controls: d.control_id ? [{ control_id: d.control_id }] : [],
    milestones: [
      { title: d.milestone_title.trim(), due: d.milestone_due, ends_weakness: true },
    ],
    response: d.response,
  };
}

export type Recommendation = { kind: "decided" | "fix" | "accept" | "decide"; text: string };

/** The panel's first line: what to do, before the evidence for it. */
export function recommendAction(f: {
  status: string;
  fixable: boolean;
  fixedVersion: string | null;
  hasFix: boolean;
  isPackage?: boolean;
}): Recommendation {
  if (f.status !== "open") {
    return {
      kind: "decided",
      text: `Already ${f.status.replace(/_/g, " ")}. Nothing to decide unless it re-opens.`,
    };
  }
  if (f.fixable) {
    return {
      kind: "fix",
      text: `Fix it: a fixed version${f.fixedVersion ? ` (${f.fixedVersion})` : ""} is published.`,
    };
  }
  if (f.hasFix) return { kind: "fix", text: "Fix it: a grouped remediation covers this rule." };
  if (f.isPackage) {
    return {
      kind: "accept",
      text: "No fix is published. Accept it formally until one ships, or say why it does not apply.",
    };
  }
  return { kind: "decide", text: "Fix it, accept it formally, or say why it does not apply." };
}

export type AcceptanceAction = "renew" | "revoke" | "interim-review";

export function acceptanceActionProblem(
  action: AcceptanceAction,
  input: { text: string; until?: string },
): string | null {
  const text = input.text.trim();
  if (action === "revoke") return text ? null : "Say why it is revoked. Its findings re-open.";
  if (action === "interim-review") {
    return text ? null : "Say what you checked and why it still stands.";
  }
  if (!input.until) return "Choose the new expiry.";
  return text ? null : "Say why it should run longer.";
}
