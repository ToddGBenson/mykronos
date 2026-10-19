/**
 * Words for the "Rule vectors" section (TheHub #60832, D3).
 *
 * SAST, DAST and secrets findings name a rule, not a CVE, so nothing publishes
 * a CVSS vector for them and they have no environmental score. A person can
 * record one per rule. Three states, and the wording never lets the first
 * read like the second: a proposal scores nothing; only a confirmed vector,
 * confirmed by a person, does.
 *
 * Pure, so the vitest suite runs it without rendering the tab.
 */

export type RuleVectorRow = {
  id: string;
  status: string;
  scope: string;
  vector: string;
  base_score?: number | null;
  proposed_from: string;
  asserted_by: string;
  asserted_at: string;
  confirmed_by?: string | null;
  confirmed_at?: string | null;
};

export type RuleRow = {
  findings: number;
  applies: RuleVectorRow | null;
  vectors: RuleVectorRow[];
};

const STATUS_WORDS: Record<string, string> = {
  proposed: "proposed, not scored",
  confirmed: "confirmed, scored",
  retired: "retired",
};

/** The pill: a proposal always says it is not scored. */
export function statusWord(status: string): string {
  return STATUS_WORDS[status] ?? status;
}

export function statusTone(status: string): "pass" | "warn" | "muted" {
  if (status === "confirmed") return "pass";
  if (status === "proposed") return "warn";
  return "muted";
}

/** `this repository` or `every repository`: where a vector applies. */
export function scopeWord(scope: string): string {
  return scope === "estate" ? "every repository" : "this repository";
}

/** `CWE-79 template` from `cwe-vector-templates-v1:CWE-79`; `typed by hand`
 *  when nothing pre-filled it. */
export function fromWord(proposedFrom: string): string {
  if (!proposedFrom) return "typed by hand";
  const cwe = proposedFrom.split(":").pop();
  return `${cwe} template`;
}

function plural(n: number, word: string): string {
  return `${n} ${word}${n === 1 ? "" : "s"}`;
}

/**
 * The one line under a rule: whether its findings are scored, and on whose
 * say-so. Never claims a score that a proposal has not earned.
 */
export function ruleStateLine(rule: RuleRow): string {
  const findings = plural(rule.findings, "open finding");
  if (rule.applies) {
    const who = rule.applies.confirmed_by ?? "a person";
    const day = (rule.applies.confirmed_at ?? "").slice(0, 10);
    const base =
      typeof rule.applies.base_score === "number"
        ? ` (base ${rule.applies.base_score.toFixed(1)})`
        : "";
    return `${findings} scored from a vector ${who} confirmed${day ? ` on ${day}` : ""}${base}.`;
  }
  const pending = rule.vectors.find((v) => v.status === "proposed");
  if (pending) {
    return `${findings} unscored: a vector is proposed by ${pending.asserted_by} and waits for a person to confirm it.`;
  }
  return `${findings} unscored: no CVE, so no published vector, and none proposed.`;
}

/** The header count, e.g. `3 rules (41 findings) unscored`. */
export function unscoredSummary(rules: number, findings: number): string {
  if (rules === 0) return "every listed rule has a confirmed vector";
  return `${plural(rules, "rule")} (${plural(findings, "finding")}) unscored`;
}

/** Hover text for the confirm button. */
export const CONFIRM_TITLE =
  "Record that you checked this vector against the findings. From then on they are scored from it, with you named as the person who confirmed it.";

/** Hover text for the propose button. */
export const PROPOSE_TITLE =
  "Record a proposal. It changes no score until a person confirms it.";
