/**
 * Tab ids on the repository page that have been retired, and where their
 * links now land. Pure, so the vitest suite runs it.
 *
 * A retired id still arrives: in bookmarks, in Slack threads, in specs and
 * reports written while it existed. The page refuses an id it does not know
 * (B-006) — rightly, since a wrong link that renders Dashboard looks like a
 * working one — so a retired id has to be mapped here rather than simply
 * deleted, or every old link becomes "No such tab".
 */
export const RETIRED_TABS: Readonly<Record<string, string>> = {
  // #60820: "Remediation" and "Remediate today" answered the same question
  // twice. Remediate today kept the fix list and gained the Patchwork history.
  remediation: "remediate",
};

/** The tab a `?tab=` value selects, with retired ids followed to their heir. */
export function canonicalTab(raw: string | undefined, fallback = "dashboard"): string {
  const tab = raw || fallback;
  return Object.hasOwn(RETIRED_TABS, tab) ? RETIRED_TABS[tab] : tab;
}

/**
 * Findings a person can close today without a judgement call: the ones under
 * a fix whose effort is a config value or a version bump. The same sum the
 * backend's `/guidance` endpoint returns as `actionable_findings`, computed
 * here from the briefing's fixes so one request serves the whole tab.
 */
export function closableToday(fixes: readonly { effort: string; findings: number }[]): number {
  return fixes
    .filter((fix) => fix.effort === "config" || fix.effort === "upgrade")
    .reduce((total, fix) => total + fix.findings, 0);
}
