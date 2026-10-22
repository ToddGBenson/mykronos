/**
 * How the dashboard words an auto-triage action (TheHub #60888, D-169).
 *
 * Pure, so the wording is pinned by a test: an action the platform took by
 * itself has to say which rule took it and on what evidence, or the undo
 * beside it is a button nobody can judge.
 */

export type AutoTriageRule = "fix_verified" | "vex_not_affected" | "exact_duplicate" | "unreachable";

export const AUTO_TRIAGE_RULE_LABEL: Record<AutoTriageRule, string> = {
  fix_verified: "fix verified",
  vex_not_affected: "vendor: not affected",
  exact_duplicate: "duplicate of a decision",
  unreachable: "unreachable code",
};

export function ruleLabel(rule: string): string {
  return AUTO_TRIAGE_RULE_LABEL[rule as AutoTriageRule] ?? rule;
}

/** "fix verified → fixed" — the rule and what it set. */
export function actionHeadline(action: { rule: string; new_status: string }): string {
  return `${ruleLabel(action.rule)} → ${action.new_status.replace(/_/g, " ")}`;
}

/** Whether the undo is still on offer: not already undone. Whether the
 *  finding still holds the status is the backend's call (it answers 409). */
export function undoable(action: { undone_at?: string | null }): boolean {
  return !action.undone_at;
}

/** The undo body, or why it cannot be sent yet. */
export function undoBody(reason: string): { ok: true; body: { reason: string } } | { ok: false; error: string } {
  const trimmed = reason.trim();
  if (!trimmed) return { ok: false, error: "Say why the platform's verdict does not stand." };
  return { ok: true, body: { reason: trimmed } };
}

/** "3 closed in the last 24 hours: 2 fix verified, 1 unreachable code." */
export function digestLine(digest: {
  total: number;
  hours: number;
  undone: number;
  by_rule: Record<string, number>;
}): string {
  if (digest.total === 0) return `Nothing closed by the platform in the last ${digest.hours} hours.`;
  const parts = Object.entries(digest.by_rule)
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([rule, count]) => `${count} ${ruleLabel(rule)}`);
  const undone = digest.undone ? ` ${digest.undone} undone since.` : "";
  return `${digest.total} closed in the last ${digest.hours} hours: ${parts.join(", ")}.${undone}`;
}
