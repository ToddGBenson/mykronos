/**
 * The review queue's wording (D-163). Pure, so the vitest suite runs it.
 *
 * Every label says what is true and, when something is missing, what. "Ready"
 * appears only when the backend's `ready` is true: that is the row the
 * operator merges.
 */

export type Tone = "pass" | "warn" | "critical" | "muted";
export type Label = { tone: Tone; word: string };

export function mergeReadiness(row: {
  github_state: string;
  check_posted: boolean;
  ready: boolean;
}): Label {
  if (row.ready) return { tone: "pass", word: "ready to merge" };
  if (row.github_state === "new_commits") {
    return { tone: "warn", word: "new commits since approval: needs a new request" };
  }
  if (row.github_state === "unknown") return { tone: "muted", word: "GitHub not read" };
  if (!row.check_posted) return { tone: "warn", word: "approved, check not on GitHub yet" };
  return { tone: "muted", word: row.github_state };
}

/**
 * The one-line banner for a reviewer whose model key the hourly probe has
 * found refused or unreachable (TheHub #61614), or null while it works or has
 * never been probed. `unavailable_since` comes from the backend, already
 * formatted; this never invents a time.
 */
export function reviewerBanner(reviewer: { unavailable_since?: string | null }): string | null {
  const since = reviewer.unavailable_since;
  if (!since) return null;
  return `Platform reviewer unavailable since ${since}: production-tier requests will not progress`;
}

/**
 * The platform reviewer's verdict, as advice. A shadow verdict counts for
 * nothing; on a tier only a person may approve the reviewer is told to reject
 * so a person decides, so that reject is procedural (the same rule as
 * `scripts/review_inbox.py`, #841).
 */
export function reviewerStanding(
  review: { verdict: string; counts: boolean; delegable: boolean } | null,
): Label {
  if (!review) return { tone: "muted", word: "not reviewed" };
  const suffix = review.counts ? "" : " (shadow: does not count)";
  if (!review.delegable && review.verdict !== "approve") {
    return { tone: "muted", word: `${review.verdict}: goes to a person by rule${suffix}` };
  }
  const tone: Tone =
    review.verdict === "approve" ? "pass" : review.verdict === "reject" ? "critical" : "warn";
  return { tone, word: `${review.verdict}${suffix}` };
}
