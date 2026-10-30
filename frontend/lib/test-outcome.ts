/**
 * A test lane's latest outcome, as words (TheHub #60922).
 *
 * "Evidenced" answers whether a kind of testing is happening; this answers
 * whether it is passing. On 2026-10-21 every functional run on main failed and
 * the tests view said only that the lane was reporting runs, which read as
 * healthy. The outcome is shown next to presence so neither stands in for the
 * other.
 */

export type Outcome = "passing" | "failing" | "unknown";

export interface OutcomeLane {
  outcome: Outcome;
  outcome_branch?: string | null;
  latest_status?: string | null;
  last_passed_at?: string | null;
  window_days: number;
  window_runs: number;
  window_passed: number;
  window_failed: number;
}

export interface OutcomeText {
  tone: "pass" | "critical" | "muted";
  word: string;
  /** One sentence: recent counts and when it last passed. */
  detail: string;
}

export function outcomeText(lane: OutcomeLane): OutcomeText {
  const where = lane.outcome_branch ? ` on ${lane.outcome_branch}` : "";
  const window =
    lane.window_runs > 0
      ? `last ${lane.window_days} days: ${lane.window_passed} passed, ${lane.window_failed} failed`
      : `no runs in the last ${lane.window_days} days`;

  if (lane.outcome === "failing") {
    const since = lane.last_passed_at
      ? `last passed ${lane.last_passed_at.slice(0, 10)}`
      : "has never passed here";
    return {
      tone: "critical",
      word: "Failing",
      detail: `Latest run${where} failed; ${since}. ${capitalise(window)}.`,
    };
  }
  if (lane.outcome === "passing") {
    return {
      tone: "pass",
      word: "Passing",
      detail: `Latest run${where} passed. ${capitalise(window)}.`,
    };
  }
  const why =
    lane.latest_status === "no_applicable_targets"
      ? `Latest run${where} found nothing to test`
      : `No run${where} to read an outcome from`;
  return { tone: "muted", word: "Unknown", detail: `${why}. ${capitalise(window)}.` };
}

function capitalise(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}
