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
  // #60885: Consult and Executive report are one Report tab.
  consult: "report",
  executive: "report",
};

/** The tab a `?tab=` value selects, with retired ids followed to their heir. */
export function canonicalTab(raw: string | undefined, fallback = "dashboard"): string {
  const tab = raw || fallback;
  return Object.hasOwn(RETIRED_TABS, tab) ? RETIRED_TABS[tab] : tab;
}

/**
 * Where a request for a retired tab goes, with every other parameter kept, or
 * null when `?tab=` is not retired. The page redirects (308) to it.
 */
export function retiredTabRedirect(
  repoId: string,
  query: Readonly<Record<string, string | string[] | undefined>>,
): string | null {
  const raw = query.tab;
  if (typeof raw !== "string" || !Object.hasOwn(RETIRED_TABS, raw)) return null;
  const next = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    for (const one of Array.isArray(value) ? value : [value]) next.append(key, one);
  }
  next.set("tab", RETIRED_TABS[raw]);
  return `/repos/${repoId}?${next.toString()}`;
}

/**
 * Twelve tabs on the repository page, in this order (spec 18 §2; Product
 * Owner is spec 35, and the Report the one written for a reader outside the
 * team). Here rather than in the page so the vitest suite can count them.
 *
 * `Dashboard` is what spec 18's first pass called "Harness" — enable/disable,
 * scan health, enabled jobs — promoted to the default landing tab rather than
 * duplicated into a second one. It carries no findings; that is what the
 * Findings tab is for. `Harness` is now specifically a test-running tab
 * (`TestHarnessTab`) — unit/functional/QA execution, not general scan health.
 */
export const REPO_TABS = [
  { id: "dashboard", label: "Dashboard" },
  // Second, because it is the tab somebody opens *instead of* the others.
  // It was two (TheHub #60885): Consult answered the operator's questions and
  // Executive report the executive's, and both said what was accepted and
  // which lanes were down. One tab now: the executive summary first, printable
  // as it was, then the consult answers it does not already give, then what
  // neither can answer. `?tab=consult` and `?tab=executive` redirect here.
  { id: "report", label: "Report" },
  { id: "findings", label: "Findings" },
  // Directly after Findings, because it is the same backlog asked the next
  // question. Findings says what is outstanding here; this says which of it is
  // work today — and it is the estate page's reasoning applied to one
  // repository rather than a second, quietly different, ranking.
  //
  // The only remediation tab (#60820). A separate "Remediation" tab showed the
  // same fix list again beside Patchwork's history; the history is a section
  // of this one now, and `?tab=remediation` lands here (`lib/repo-tabs.ts`).
  { id: "remediate", label: "Remediate today" },
  { id: "harness", label: "Harness" },
  { id: "threat-model", label: "Threat Model" },
  { id: "sscs", label: "Supply chain" },
  { id: "insider", label: "Insider Threat" },
  { id: "decisions", label: "Risk Decision" },
  // Beside Risk Decision and not part of it: that tab is Oracle's ship/no-ship
  // score; this is the register of risks accepted rather than fixed, and
  // whether what each acceptance rests on still holds.
  { id: "risk", label: "Risk management" },
  // Last, because it is the only tab nobody opens to do work: it answers
  // "what can we show an assessor" rather than "what should I fix". Its own
  // tab rather than a panel under Insider Threat — that tab is about who
  // merged what, and adherence is a different question with a different
  // reader.
  { id: "adherence", label: "Adherence" },
  // The one tab about the work rather than the code (spec 35, D-135): this
  // repository's declared process, its backlog and its sprint, read from its
  // own `.sdlc/process.yaml` and from TheHub. After Adherence because both
  // answer "how is this repository run", and this one is the operator's.
  { id: "product-owner", label: "Product Owner" },
] as const;

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
