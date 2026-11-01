/**
 * The approval packet's wording and order (TheHub #61136, v2 P3). Pure, so
 * the vitest suite runs it.
 *
 * Review-PendingApprovals.ps1 was the only place a person could see the
 * verification check, concur with the reviewer, decide an estate-wide request
 * or skip a superseded one. These are the rules it applied, so the packet in
 * the dashboard applies the same ones.
 */

export type EvidenceField = { key: string; label: string; value: string };

type Review = {
  verdict: string;
  rationale: string;
  model: string | null;
  reviewed_at: string | null;
  delegable: boolean;
};

type Verification = { holds: boolean | null; ran_at: string | null; lines: unknown[] };

function scalar(value: unknown): string | null {
  if (value === null || value === undefined) return "—";
  if (typeof value === "boolean") return value ? "yes" : "no";
  if (typeof value === "string" || typeof value === "number" || typeof value === "bigint") {
    return String(value);
  }
  return null;
}

function count(value: unknown): string {
  if (Array.isArray(value)) return value.length === 1 ? "1 item" : `${value.length} items`;
  const n = Object.keys(value as object).length;
  return n === 1 ? "1 field" : `${n} fields`;
}

/**
 * The frozen evidence as labelled fields, in its own order, instead of a JSON
 * dump (P3). One level of an object is unfolded into `parent · child` fields,
 * because that is where a finding's severity and rule live; anything deeper,
 * and every list, is summarised by its size. The raw JSON stays one click
 * away on the page, for the cases this leaves out.
 */
export function evidenceFields(evidence: Record<string, unknown>): EvidenceField[] {
  const fields: EvidenceField[] = [];
  for (const [key, value] of Object.entries(evidence)) {
    const flat = scalar(value);
    if (flat !== null) {
      fields.push({ key, label: key, value: flat });
    } else if (Array.isArray(value)) {
      fields.push({ key, label: key, value: count(value) });
    } else {
      for (const [child, inner] of Object.entries(value as Record<string, unknown>)) {
        const innerFlat = scalar(inner);
        fields.push({
          key: `${key}.${child}`,
          label: `${key} · ${child}`,
          value: innerFlat ?? count(inner),
        });
      }
    }
  }
  return fields;
}

/**
 * The rationale a person records when they concur with the platform reviewer,
 * or null when concurring is not offered.
 *
 * It says, in as many words, that the decision rests on the reviewer's review
 * and the check, and quotes the reviewer's first three lines: the record is
 * the person's decision, not a rationale written for them. Not offered on a
 * procedural reject from a tier only a person may approve, because there the
 * reviewer was told to reject so that a person decides (`reviewerStanding`).
 */
export function concurRationale(
  review: Review | null,
  verification: Verification | null,
): string | null {
  if (!review) return null;
  if (!review.delegable && review.verdict !== "approve") return null;
  const reasoning = review.rationale
    .split("\n")
    .map((line) => line.trim())
    .filter(Boolean)
    .slice(0, 3)
    .join(" ");
  const check =
    verification === null
      ? "I read its review"
      : `I read its review and the verification check, which ${
          verification.holds === true
            ? "held"
            : verification.holds === false
              ? "failed"
              : "could not be completed"
        }`;
  return (
    `Concur with the platform reviewer (${review.model ?? "model not recorded"}, ` +
    `${review.reviewed_at ?? "time not recorded"}): ${review.verdict}. ${check}. ` +
    `Its reasoning: ${reasoning}`
  );
}

/** A decision needs a rationale; the engine refuses one without, and so does the page. */
export function canRecord(rationale: string): boolean {
  return rationale.trim().length > 0;
}

/**
 * Where "Record and next" goes: the pending request after this one, or back
 * to Approvals after the last. A packet opened from outside the list (a
 * superseded request, or a stale link) goes to the first.
 */
export function nextRequestHref(pendingIds: readonly string[], current: string): string {
  const at = pendingIds.indexOf(current);
  const next = at < 0 ? pendingIds[0] : pendingIds[at + 1];
  return next ? `/product-owner/review-queue/${encodeURIComponent(next)}` : "/approvals";
}

/** "go to 3 of 4", or "return to Approvals" after the last. */
export function nextLabel(pendingIds: readonly string[], current: string): string {
  const at = pendingIds.indexOf(current);
  const nextIndex = at < 0 ? 0 : at + 1;
  return nextIndex < pendingIds.length
    ? `go to ${nextIndex + 1} of ${pendingIds.length}`
    : "return to Approvals";
}

/** `2026-11-08 05:48`, to the minute, as the queue writes it. */
export function packetTime(value: string | null | undefined): string | null {
  return value ? value.slice(0, 16).replace("T", " ") : null;
}

/** The verification section's line: when the check ran, or that it did not. */
export function checkDetail(verification: { ran_at?: string | null } | null | undefined): string {
  const at = packetTime(verification?.ran_at);
  if (at) return `run by the platform when this page opened, ${at}`;
  return verification
    ? "run by the platform when this page opened"
    : "not run: the backend returned no check";
}

const INDEPENDENCE: Record<string, string> = {
  distinct_principal: "a different principal",
  distinct_instance: "a different agent instance",
  outside_lineage: "outside the requester\u2019s lineage",
  fresh_context: "working from a fresh context",
  different_family: "from a different model family",
  human: "a human",
};

type TierNeeds = {
  approvers?: { kind?: string; delegation_required?: boolean }[];
  quorum?: number;
  independence?: string[];
  cooling_off_hours?: number | null;
};

function either(words: string[]): string {
  if (words.length <= 1) return words[0] ?? "";
  return `${words.slice(0, -1).join(", ")} or ${words[words.length - 1]}`;
}

function both(words: string[]): string {
  if (words.length <= 1) return words[0] ?? "";
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1]}`;
}

/**
 * What the policy asks of this tier, as a sentence: "This tier needs 2
 * approvals, from a human or a delegated agent; each approver must be a
 * different principal; and a 24-hour cooling-off."
 */
export function tierNeeds(needs: TierNeeds | null | undefined): string | null {
  if (!needs) return null;
  const quorum = needs.quorum ?? 1;
  const who = (needs.approvers ?? []).map((a) => {
    const kind = a.kind === "agent" ? "agent" : (a.kind ?? "approver");
    const article = /^[aeiou]/.test(kind) ? "an" : "a";
    return a.delegation_required ? `a delegated ${kind}` : `${article} ${kind}`;
  });
  const clauses = [
    `This tier needs ${quorum} approval${quorum === 1 ? "" : "s"}${who.length ? `, from ${either(who)}` : ""}`,
  ];
  const rules = (needs.independence ?? []).map((rule) => INDEPENDENCE[rule] ?? rule.replace(/_/g, " "));
  if (rules.length) clauses.push(`each approver must be ${both(rules)}`);
  if (needs.cooling_off_hours) clauses.push(`a ${needs.cooling_off_hours}-hour cooling-off`);
  if (clauses.length === 1) return `${clauses[0]}.`;
  return `${clauses.slice(0, -1).join("; ")}; and ${clauses[clauses.length - 1]}.`;
}
