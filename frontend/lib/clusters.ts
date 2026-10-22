/**
 * How the Triage page words a cluster (TheHub #60887, D-168).
 *
 * Pure, so the wording is pinned by a test rather than by eyeballing a page:
 * a cluster row is a promise about what one decision covers, and the numbers
 * in it have to be the ones the disposition will act on.
 */

export type ClusterKind = "advisory" | "location" | "single";

export const CLUSTER_KIND_LABEL: Record<ClusterKind, string> = {
  advisory: "same advisory",
  location: "same weakness, same place",
  single: "on its own",
};

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/** "3 findings · 2 repositories · 3 images" — what the decision spans. */
export function clusterSpread(cluster: {
  count: number;
  repos: string[];
  images?: string[];
}): string {
  const parts = [
    plural(cluster.count, "finding", "findings"),
    plural(cluster.repos.length, "repository", "repositories"),
  ];
  if (cluster.images && cluster.images.length > 0) {
    parts.push(plural(cluster.images.length, "image", "images"));
  }
  return parts.join(" · ");
}

/** The verdicts a cluster disposition offers from this page. `accepted_risk`
 *  needs a review date and a reason code per acceptance, which belong on the
 *  finding page rather than in a one-line form. */
export const CLUSTER_VERDICTS = [
  { value: "false_positive", label: "false positive" },
  { value: "suppressed", label: "suppress" },
] as const;

export type ClusterVerdict = (typeof CLUSTER_VERDICTS)[number]["value"];

/**
 * The body the disposition proxy forwards, or why it cannot be sent yet.
 *
 * `member_ids` is always the set the person was shown: the backend refuses
 * the disposition if the cluster has changed since, so a decision covers what
 * was looked at and nothing that arrived afterwards.
 */
export function clusterDispositionBody(
  verdict: string,
  reason: string,
  memberIds: string[],
):
  | { ok: true; body: { status: ClusterVerdict; reason: string; member_ids: string[] } }
  | { ok: false; error: string } {
  const known = CLUSTER_VERDICTS.find((entry) => entry.value === verdict);
  if (!known) return { ok: false, error: `'${verdict}' is not a verdict offered here.` };
  const trimmed = reason.trim();
  if (!trimmed) {
    return { ok: false, error: "A reason is required; it is recorded on every member." };
  }
  if (memberIds.length === 0) return { ok: false, error: "This cluster has no members." };
  return { ok: true, body: { status: known.value, reason: trimmed, member_ids: [...memberIds] } };
}

/** What the backend's answer means, in a line. */
export function dispositionOutcomeLine(result: {
  outcome: string;
  applied?: string[];
  refused?: Record<string, string>;
  tier?: string | null;
}): string {
  if (result.outcome === "pending_approval") {
    return `Waiting for approval (${result.tier ?? "governed"} tier). Nothing is closed until someone independent approves.`;
  }
  const applied = result.applied?.length ?? 0;
  const refused = Object.keys(result.refused ?? {}).length;
  return refused
    ? `${plural(applied, "member", "members")} closed, ${refused} refused.`
    : `${plural(applied, "member", "members")} closed.`;
}
