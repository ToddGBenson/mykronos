/**
 * What the Report tab keeps from Consult (TheHub #60885). Pure, so the vitest
 * suite runs it.
 *
 * The Report is the executive summary followed by the consult answers, and two
 * of those answers say again, more thinly, what the summary has just said.
 * Each subject appears once, in its richer version:
 *
 * - `accepted` — "What have we decided to live with?" gives a count and
 *   whether reasons exist. The summary's accepted-risk paragraph gives the
 *   count, how much of it is critical or high, the decisions behind it, the
 *   next review dates, and which acceptances are overdue, undated or now
 *   fixable.
 * - `open` — "What is outstanding here?" gives the open count and whether a
 *   lane is down. The summary gives the count by severity against a week and
 *   a month ago, and a Coverage table with every lane's state and last run.
 *
 * Every other answer (ownership, testing, adherence, dependencies, drift, the
 * risk profile) is something the summary does not say, and stays.
 */
export const COVERED_BY_SUMMARY: Readonly<Record<string, string>> = {
  accepted: "Accepted risk, under Can it be fixed?",
  open: "Open risk by severity, and Coverage",
};

/** The consult answers the Report shows: those the summary does not give. */
export function reportAnswers<T extends { key: string }>(answers: readonly T[]): T[] {
  return answers.filter((answer) => !Object.hasOwn(COVERED_BY_SUMMARY, answer.key));
}
